"""Bounded, uncached Cloud Logging observation for one selected terminal Build."""
from datetime import datetime, timedelta
import hashlib
import json
import re
import time

from . import gcp_selected_object_secret_indicators as objects
from .gcp_composer_source_secret_indicators import _pairs
from peaso.secret_evidence import scan_with_source, target_source
from peaso.secret_scanning import scan_content, merge_leaks

ENDPOINT = 'https://logging.googleapis.com/v2/entries:list'
SCHEMA = 'gcp-cloudbuild-logging-entries-v1'
MAX_PAGES = 3
PAGE_SIZE = 100
MAX_RESPONSE_BYTES = 1048576
MAX_TOTAL_BYTES = 4194304
MAX_ENTRIES = 300
Incomplete = objects.Incomplete


def _literal(value):
    return json.dumps(value, ensure_ascii=True)


def _request(transport, state, scope, body, ident):
    """POST is the read-only entries.list RPC; no response is cached."""
    objects._check(transport, state)
    receipt = {'scope': scope, 'method': 'POST', 'operation': 'logging.entries.list.cloudbuild',
               'resource_id': ident, 'status': 'unavailable'}
    response = None
    try:
        with transport.lock:
            if state['calls'] >= objects.MAX_CALLS or transport.max_calls is not None and transport.calls >= transport.max_calls:
                raise Incomplete('call_limit')
            state['calls'] += 1
            transport.calls += 1
        headers = dict(transport.credentials.headers())
        headers.update({'Accept-Encoding': 'identity', 'Content-Type': 'application/json'})
        if transport.options.get('quota_project'):
            headers['X-Goog-User-Project'] = transport.options['quota_project']
        from .gcp import native_header_session
        response = native_header_session(transport).request('POST', ENDPOINT, data=json.dumps(body, separators=(',', ':')),
            headers=headers, stream=True, allow_redirects=False, timeout=objects._remaining(transport, state))
        receipt['http_status'] = response.status_code
        if response.status_code != 200:
            raise Incomplete('logging_denied' if response.status_code in (401, 403) else 'logging_unavailable')
        hdr = {k.lower(): v for k, v in response.headers.items()}
        length = hdr.get('content-length')
        if hdr.get('content-encoding', 'identity').lower() != 'identity' or 'content-range' in hdr or (length is not None and
                (not isinstance(length, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', length) or int(length) > MAX_RESPONSE_BYTES)):
            raise Incomplete('logging_encoding_or_limit')
        chunks, count = [], 0
        while True:
            objects._check(transport, state)
            sock = getattr(getattr(getattr(getattr(response.raw, '_fp', None), 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(objects._remaining(transport, state))
            part = response.raw.read(min(16384, MAX_RESPONSE_BYTES - count + 1), decode_content=False)
            if not part:
                break
            if not isinstance(part, bytes):
                raise Incomplete('malformed_logging_response')
            count += len(part)
            if count > MAX_RESPONSE_BYTES:
                raise Incomplete('logging_byte_limit')
            chunks.append(part)
        if length is not None and int(length) != count:
            raise Incomplete('truncated_logging_response')
        result = json.loads(b''.join(chunks).decode('utf-8'), object_pairs_hook=_pairs)
        if not isinstance(result, dict) or set(result) - {'entries', 'nextPageToken'}:
            raise Incomplete('malformed_logging_response')
        receipt.update(status='collected', bytes=count)
        return result
    except Incomplete:
        raise
    except Exception:
        raise Incomplete('logging_unavailable') from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        with transport.lock:
            receipt['id'] = 'request-' + str(len(transport.evidence) + 1)
            transport.evidence.append(receipt)


def collect(transport, state, scope, name, build, project, ident, get_build, bind_build):
    """Return public redacted evidence after complete bounded selected-window paging."""
    bind_build(build, name, project)
    project_id = project['projectId']
    build_id = build['id']
    created = datetime.fromisoformat(build['createTime'].replace('Z', '+00:00'))
    finished = datetime.fromisoformat(build['finishTime'].replace('Z', '+00:00'))
    lower_time, upper_time = created - timedelta(minutes=5), finished + timedelta(minutes=5)
    lower = lower_time.isoformat().replace('+00:00', 'Z')
    upper = upper_time.isoformat().replace('+00:00', 'Z')
    log_name = 'projects/' + project_id + '/logs/cloudbuild'
    filt = ('resource.type="build" AND resource.labels.project_id=' + _literal(project_id)
            + ' AND resource.labels.build_id=' + _literal(build_id)
            + ' AND logName=' + _literal(log_name)
            + ' AND timestamp>=' + _literal(lower) + ' AND timestamp<=' + _literal(upper))
    base = {'resourceNames': ['projects/' + project_id], 'filter': filt,
            'orderBy': 'timestamp asc', 'pageSize': PAGE_SIZE}
    token, seen_tokens, entries, total, pages = None, set(), 0, 0, 0
    all_leaks, engines = [], None
    try:
      for page in range(MAX_PAGES):
        body = dict(base)
        if token is not None:
            body['pageToken'] = token
        data = _request(transport, state, scope, body, ident)
        pages += 1
        rows = data.get('entries', [])
        if not isinstance(rows, list) or entries + len(rows) > MAX_ENTRIES:
            raise Incomplete('logging_entry_limit')
        for row in rows:
            objects._check(transport, state)
            resource = row.get('resource') if isinstance(row, dict) else None
            labels = resource.get('labels') if isinstance(resource, dict) else None
            if (not isinstance(row, dict) or row.get('logName') != log_name
                    or not isinstance(resource, dict) or set(resource) != {'type', 'labels'}
                    or resource.get('type') != 'build' or not isinstance(labels, dict)
                    or set(labels) - {'project_id', 'build_id', 'build_trigger_id'}
                    or labels.get('project_id') != project_id or labels.get('build_id') != build_id
                    or 'build_trigger_id' in labels and not isinstance(labels['build_trigger_id'], str)):
                raise Incomplete('foreign_logging_entry')
            stamp = row.get('timestamp')
            if not isinstance(stamp, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', stamp):
                raise Incomplete('foreign_logging_entry')
            observed_time = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            if not lower_time <= observed_time <= upper_time:
                raise Incomplete('foreign_logging_entry')
            if set(row) - {'logName', 'resource', 'timestamp', 'receiveTimestamp', 'insertId', 'severity', 'textPayload', 'labels', 'trace', 'spanId'} or not isinstance(row.get('textPayload'), str):
                raise Incomplete('unsupported_logging_entry')
            payload = row['textPayload'].encode('utf-8')
            if not payload:
                raise Incomplete('empty_logging_entry')
            if total + len(payload) > MAX_TOTAL_BYTES or len(payload) > objects.MAX_OBJECT_BYTES:
                raise Incomplete('logging_byte_limit')
            objects._text(payload)
            total += len(payload)
            remaining = objects.MAX_SECONDS - (time.monotonic() - state['started'])
            outcome = scan_with_source(scan_content, payload, 'logging.entry', timeout=min(5, remaining / 2),
                source=target_source({'project_scope': scope, 'name': name}, resource_id=ident, scope=scope,
                                     path='logging.entry', location_kind='log'))
            del payload
            if engines is None:
                engines = outcome['engines']
            elif engines != outcome['engines'] and outcome['complete']:
                raise Incomplete('detector_drift')
            elif not outcome['complete']:
                prior = {e['engine']: e for e in engines}
                engines = [prior[e['engine']] if prior[e['engine']]['status'] == 'complete' else e
                           for e in outcome['engines']]
            all_leaks.extend(outcome['leaks'])
            entries += 1
            objects._check(transport, state)
            if not outcome['complete']:
                raise Incomplete('detector_unavailable')
        token = data.get('nextPageToken')
        if token is None:
            break
        if not isinstance(token, str) or not token or len(token) > 4096 or token in seen_tokens:
            raise Incomplete('invalid_page_token')
        seen_tokens.add(token)
      else:
          raise Incomplete('logging_page_limit')
      if entries == 0:
          raise Incomplete('empty_logging_window')
      after = get_build()
      bind_build(after, name, project)
      if after != build:
          raise Incomplete('build_identity_changed')
    except Incomplete as exc:
        reason = str(exc)
        # A foreign or malformed entry taints the page. Preserve only findings
        # already tied to this Build when a later read or detector failed.
        recoverable = {'logging_denied', 'logging_unavailable', 'logging_encoding_or_limit',
            'logging_byte_limit', 'truncated_logging_response', 'malformed_logging_response',
            'content_deadline', 'call_limit', 'detector_unavailable', 'logging_page_limit',
            'metadata_denied', 'metadata_unavailable', 'metadata_encoding_or_limit',
            'metadata_byte_limit', 'truncated_metadata'}
        if reason not in recoverable or not all_leaks or pages < 1:
            raise
        leaks = merge_leaks(all_leaks)
        if len(leaks) > objects.MAX_LEAKS or sum(len(x['locations']) for x in leaks) > objects.MAX_LOCATIONS:
            raise Incomplete('finding_limit')
        return {'schema': SCHEMA, 'complete': False, 'reason': reason, 'window_start': lower,
            'window_end': upper, 'entries': entries, 'pages': pages, 'bytes': total,
            'engines': engines, 'leaks': leaks, 'verification': 'not_attempted',
            'filter_sha256': hashlib.sha256(filt.encode()).hexdigest()}
    leaks = merge_leaks(all_leaks)
    if len(leaks) > objects.MAX_LEAKS or sum(len(x['locations']) for x in leaks) > objects.MAX_LOCATIONS:
        raise Incomplete('finding_limit')
    return {'schema': SCHEMA, 'complete': True, 'reason': 'complete', 'window_start': lower,
            'window_end': upper, 'entries': entries, 'pages': pages,
            'bytes': total, 'engines': engines, 'leaks': leaks, 'verification': 'not_attempted',
            'filter_sha256': hashlib.sha256(filt.encode()).hexdigest()}
