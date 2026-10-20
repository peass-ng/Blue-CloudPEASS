"""Brief single-leak observations from preserved native source assertions."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

PROFILES = {
    'azure.review.function.selected_package_source_secret_indicators':
        ('azure', 'package_source_assertions', 'the selected stored deployment package'),
    'gcp.review.function.literal_environment_secret_indicators':
        ('gcp', 'function_secret_pairs', 'the function’s literal environment values'),
}


def observation(finding):
    try:
        cid = finding.get('check_id')
        profile = PROFILES.get(cid)
        if (not profile or finding.get('provider') != profile[0] or finding.get('status') != 'FAIL'
                or finding.get('linked_check_ids') != [cid]):
            return None
        fingerprint = finding['secret_fingerprint']
        if (not re.fullmatch('[0-9a-f]{64}', fingerprint)
                or finding.get('resource_id') != 'secret:' + fingerprint):return None
        e = finding['evidence']
        if e.get('credential_validation') != 'not_attempted':return None
        records = e[profile[1]]
        if not isinstance(records, list) or not 1 <= len(records) <= 1024:return None
        leaks, incomplete = [], e.get('complete') is False
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        for record in records:
            scope, resource = record['scope'], record['resource_id']
            if record['check_id'] != cid or type(record['complete']) is not bool:return None
            incomplete |= not record['complete'] or record.get('inventory_complete') is False
            if profile[0] == 'azure':
                if (not re.fullmatch(r'/subscriptions/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', scope)
                        or not re.fullmatch(r'sha256:[0-9a-f]{64}', resource)
                        or record.get('cloud_authenticity') != 'not_established'
                        or record.get('credential_validation') != 'not_attempted'
                        or record.get('coverage') != 'selected_configured_stored_package_only'
                        or record.get('runtime_bytes') != 'unknown'):return None
                sections, field = record['parts'], 'leaks'
            else:
                if (record.get('schema') != 'gcp-function-literal-secrets-v2'
                        or not re.fullmatch(r'projects/[A-Za-z0-9_-]+', scope)
                        or not re.fullmatch(re.escape(scope) + r'/locations/[a-z0-9-]+/functions/[A-Za-z0-9_-]+', resource)
                        or record['surface'] not in ('serviceConfig', 'buildConfig')):return None
                sections, field = [record], 'secret_leaks'
            if not isinstance(sections, list) or not 1 <= len(sections) <= 128:return None
            for section in sections:
                engines = section['engines']
                if (type(section['complete']) is not bool or len(engines) != 2
                        or {r['engine'] for r in engines} != set(versions)
                        or any(set(r) != {'engine', 'version', 'status'} or r['version'] != versions[r['engine']]
                               or r['status'] not in ('complete', 'unavailable') for r in engines)):return None
                completed = {r['engine'] for r in engines if r['status'] == 'complete'}
                if section['complete'] != (len(completed) == 2) or record['complete'] and not section['complete']:return None
                local = section[field]
                if not local or merge_leaks(local) != local:return None
                for leak in local:
                    if leak['fingerprint'] != fingerprint or any(d['engine'] not in completed for d in leak['detectors']):return None
                    copy = deepcopy(leak)
                    for loc in copy['locations']:
                        if set(loc) - {'path', 'line'}:return None
                        if profile[0] == 'gcp':
                            if loc['path'] != record['surface'] + '.environmentVariables':return None
                        elif (loc['path'] != section['path'] or not re.fullmatch(
                                r'azure_storage_selected_source:[0-9a-f]{64}\.file-[1-9][0-9]{0,2}', loc['path'])):return None
                        loc.update(scope=scope, resource_id=resource)
                    leaks.append(copy)
        if merge_leaks(leaks) != e['secret_leaks'] or len(e['secret_leaks']) != 1:return None
        if e.get('complete') is True and incomplete:return None
        return (f'A likely secret was detected in {profile[2]}. Its value is hidden and was not validated'
                + ('; inspection is incomplete.' if incomplete else '.'))
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return None
