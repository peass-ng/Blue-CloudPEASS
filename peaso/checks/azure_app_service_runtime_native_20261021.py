"""Selected App Service lifecycle reads through the existing ARM transport.

Unregistered integration candidate. Credentials remain exclusively owned by the
provider transport; full site/config responses are never returned as evidence.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import quote

from . import runtime_routes as bounds
from . import runtime_support as support

SCHEMA = 'azure-app-service-runtime-native-v1'
_RUNTIME = re.compile(r'[A-Za-z][A-Za-z0-9.]{0,31}\|[A-Za-z0-9._-]{1,64}\Z')


def _project(body, operation):
    if type(body) is not dict:
        raise ValueError('native_object_required')
    if operation == 'site':
        properties = body.get('properties')
        return {**{key: body[key] for key in ('id', 'type', 'kind', 'location') if key in body},
                'properties': {'reserved': properties.get('reserved')}
                if isinstance(properties, dict) else None}
    if operation == 'config':
        properties = body.get('properties')
        runtime = properties.get('linuxFxVersion') if isinstance(properties, dict) else None
        if type(runtime) is not str or _RUNTIME.fullmatch(runtime) is None:
            raise ValueError('supported_literal_runtime_required')
        return {**{key: body[key] for key in ('id', 'type') if key in body},
                'properties': {'linuxFxVersion': runtime}}
    if type(body.get('value')) is not list:
        raise ValueError('native_stack_list_required')
    entries = []
    for entry in body['value']:
        if type(entry) is not dict or type(entry.get('properties')) is not dict:
            raise ValueError('native_stack_required')
        majors = entry['properties'].get('majorVersions')
        if type(majors) is not list:
            raise ValueError('native_major_versions_required')
        projected_majors = []
        for major in majors:
            if type(major) is not dict or type(major.get('minorVersions')) is not list:
                raise ValueError('native_minor_versions_required')
            minors = []
            for minor in major['minorVersions']:
                if type(minor) is not dict:
                    raise ValueError('native_minor_required')
                settings = minor.get('stackSettings')
                linux = settings.get('linuxRuntimeSettings') if type(settings) is dict else None
                if linux is not None and type(linux) is not dict:
                    raise ValueError('native_linux_settings_required')
                selected = ({k: linux[k] for k in ('runtimeVersion', 'isDeprecated', 'isPreview',
                    'isEarlyAccess', 'endOfLifeDate') if k in linux} if linux is not None else None)
                minors.append({'stackSettings': {'linuxRuntimeSettings': selected}})
            projected_majors.append({'minorVersions': minors})
        entries.append({**{key: entry[key] for key in ('id', 'name', 'type', 'location') if key in entry},
                        'properties': {'majorVersions': projected_majors}})
    return {'value': entries, **({'nextLink': body['nextLink']} if 'nextLink' in body else {})}


def collect(reader, request, *, site_id, scope, selected=False, as_of=None):
    """No credentials or requests on disabled/foreign selection; GET reads only.

    ``request`` is the existing authenticated ARM transport.request method.
    ``reader.call`` supplies existing cancellation, deadline, retry and call caps.
    Hashes describe safe projected DTOs, explicitly not original wire bytes.
    """
    out = {'schema': SCHEMA, 'check_id': support.CHECK_ID, 'status': 'UNKNOWN',
           'complete': False, 'reason': 'unselected', 'source_requests': []}
    if selected is not True:
        return out
    match = bounds.SITE_RE.fullmatch(site_id) if type(site_id) is str else None
    if (not match or type(scope) is not str or scope.casefold() !=
            ('/subscriptions/' + match.group(1)).casefold() or
            any(x in ('.', '..') or any(c in x for c in '%?#\\\x00\r\n') for x in match.groups()[1:])):
        out['reason'] = 'invalid_or_foreign_selection'
        return out
    now = as_of or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.utcoffset() is None:
        out['reason'] = 'invalid_observation_time'
        return out
    out.update(scope=scope, asset_id=site_id, observed_at=now.astimezone(timezone.utc).isoformat())
    total = 0

    def fetch(operation, url, path, page=1):
        nonlocal total
        if not bounds._valid_url(url, path, continuation=page > 1):
            raise ValueError('untrusted_native_url')
        body = reader.call(request, url, max_response_bytes=bounds.MAX_PAGE_BYTES)
        # Native transport enforces wire limits. This separately bounds memory
        # before interpreting the decoded DTO, including fake/custom transports.
        raw = json.dumps(body, allow_nan=False, separators=(',', ':')).encode()
        total += len(raw)
        if len(raw) > bounds.MAX_PAGE_BYTES or total > bounds.MAX_TOTAL_BYTES:
            raise ValueError('native_response_limit')
        projected = _project(body, operation)
        out['source_requests'].append({'method': 'GET', 'url': url, 'operation': operation,
            'scope': scope, 'page': page, 'status': 'collected', 'read_only': True,
            'projection_sha256': hashlib.sha256(json.dumps(projected, sort_keys=True,
                separators=(',', ':'), allow_nan=False).encode()).hexdigest()})
        return projected

    try:
        site = fetch('site', bounds._url(site_id), site_id)
        if str(site.get('id', '')).casefold() != site_id.casefold():
            raise ValueError('foreign_site')
        props = site.get('properties')
        kind, location = site.get('kind'), site.get('location')
        if (type(props) is not dict or props.get('reserved') is not True or
                type(kind) is not str or 'app' not in {s.strip().casefold() for s in kind.split(',')} or
                any(s in kind.casefold() for s in ('functionapp', 'container')) or
                type(location) is not str or re.fullmatch(r'[A-Za-z0-9 ]{2,80}', location) is None or
                not location.strip()):
            raise ValueError('unsupported_linux_site')
        config_path = site_id + '/config/web'
        config = fetch('config', bounds._url(config_path), config_path)
        if str(config.get('id', '')).casefold() != config_path.casefold():
            raise ValueError('foreign_config')
        region = location.replace(' ', '').lower()
        path = '/providers/Microsoft.Web/locations/' + quote(region, safe='') + '/webAppStacks'
        url, seen, pages = bounds._url(path), set(), []
        for page in range(1, bounds.MAX_PAGES + 1):
            if url in seen:
                raise ValueError('continuation_cycle')
            seen.add(url)
            body = fetch('regional_web_app_stacks', url, path, page)
            pages.append({'status': 200, 'body': body})
            nxt = body.get('nextLink')
            if nxt is None:
                break
            if not bounds._valid_url(nxt, path, continuation=True):
                raise ValueError('foreign_continuation')
            url = nxt
        verdict = support.evaluate({'status': 200, 'body': site},
            {'status': 200, 'body': config}, pages, as_of=now)
        out.update(status=verdict['status'], complete=verdict['status'] in ('PASS', 'FAIL'),
                   reason=None if verdict['status'] in ('PASS', 'FAIL') else 'native_runtime_unresolved',
                   evidence=verdict['evidence'])
        if out['complete']:
            out['runtime'] = config['properties']['linuxFxVersion']
    except Exception:
        out['reason'] = 'native_runtime_unavailable'
    return out
