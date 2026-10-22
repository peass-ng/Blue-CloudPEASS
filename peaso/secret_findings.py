"""One redacted finding per secret, independent of detector/check/asset."""
from copy import deepcopy
from .secret_scanning import merge_leaks


def deduplicate_secret_findings(findings):
    output, grouped = [], {}
    for finding in findings:
        evidence = finding.get('evidence', {})
        leaks = evidence.get('secret_leaks') if isinstance(evidence, dict) else None
        if finding.get('status') != 'FAIL' or not isinstance(leaks, list) or not leaks:
            output.append(finding)
            continue
        try:
            merged = merge_leaks(leaks)
        except (KeyError, TypeError, ValueError):
            output.append(dict(finding, status='UNKNOWN', evidence={
                'observed': 'Secret detector evidence is malformed; this result could not be assessed.'}))
            continue
        for leak in merged:
            key = (finding['provider'], leak['fingerprint'])
            row = grouped.get(key)
            locations = [dict(loc, resource_id=finding.get('native_resource_id') or finding['resource_id'],
                              scope=finding['scope']) for loc in leak['locations']]
            safe = dict(leak, locations=locations)
            if row is None:
                row = deepcopy(finding)
                row.update(id='secret-' + leak['fingerprint'], secret_fingerprint=leak['fingerprint'],
                           title='Exposed secret in scanned content', linked_check_ids=[],
                           resource_id='secret:' + leak['fingerprint'],
                           resource_name='Exposed secret')
                row.pop('native_resource_id', None)
                row['evidence'] = {'secret_leaks': [], 'credential_validation': 'not_attempted'}
                grouped[key] = row
            row['evidence']['secret_leaks'] = merge_leaks(row['evidence']['secret_leaks'] + [safe])
            if evidence.get('complete') is False:
                # A trusted positive is still decisive when another detector
                # could not finish. Grouping must preserve that coverage limit.
                row['evidence']['complete'] = False
                row['evidence']['coverage'] = 'incomplete'
            row['frameworks'] = sorted(set(row.get('frameworks', [])) | set(finding.get('frameworks', [])))
            row['linked_check_ids'] = sorted(set(row['linked_check_ids']) | {finding['check_id']})
            row['evidence']['observed'] = 'The same secret was detected in %d scanned location(s). Its value is hidden.' % len(row['evidence']['secret_leaks'][0]['locations'])
            if row['evidence'].get('complete') is False:
                row['evidence']['observed'] += ' Coverage is incomplete.'
            row['evidence_summary'] = row['evidence']['observed']
    return output + [grouped[key] for key in sorted(grouped)]
