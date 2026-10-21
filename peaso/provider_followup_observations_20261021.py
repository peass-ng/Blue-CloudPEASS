"""Brief observations for four explicitly reviewed provider controls; no I/O."""
import re

STORAGE = 'azure_storage_account_10_3_4_7_02943e9'
RUNTIME = 'azure.review.app_service.runtime_support_declared'
GCP = 'gcp.review.cloud_run.selected_job_image_vulnerabilities'
AWS = 'aws.review.ecr.selected_image_vulnerabilities'
_TOKEN = re.compile(r'[A-Za-z0-9@][A-Za-z0-9._:/+@~=-]{0,160}\Z')
_RUNTIME = re.compile(r'[A-Za-z][A-Za-z0-9.]{0,31}\|[A-Za-z0-9._-]{1,64}\Z')


def evidence_summary(finding):
    if type(finding) is not dict or type(finding.get('evidence')) is not dict:
        return None
    cid, status, evidence = finding.get('check_id'), finding.get('status'), finding['evidence']
    if status not in ('PASS', 'FAIL', 'UNKNOWN', 'DENIED'):
        return None
    if cid == 'aws.claude_a.accessanalyzer.active_without_findings' and finding.get('provider') == 'aws':
        rows = evidence.get('access_analyzer_findings')
        if status == 'FAIL' and isinstance(rows, list) and rows:
            unused = [row for row in rows if isinstance(row, dict) and str(row.get('findingType', '')).startswith('Unused')]
            if unused:
                types = {'UnusedIAMRole': ('role', 'roles'), 'UnusedIAMUserAccessKey': ('access key', 'access keys'),
                         'UnusedIAMUserPassword': ('console password', 'console passwords'), 'UnusedPermission': ('permission finding', 'permission findings')}
                counts = []
                for kind, labels in types.items():
                    count = sum(row.get('findingType') == kind for row in unused)
                    if count:
                        counts.append(f'{count} {labels[0] if count == 1 else labels[1]}')
                counts = ', '.join(counts) or f'{len(unused)} unused-access findings'
                return (f'AWS Access Analyzer reports unused access: {counts}. '
                        'The affected principals, permissions, configured analysis windows and available last-use dates are listed below. '
                        'This access remains available to its principals despite the reported lack of use.')
        if status == 'PASS' and evidence.get('findings') == 0:
            return 'The active regional IAM Access Analyzers returned no active findings after complete collection.'
    if cid == STORAGE and finding.get('provider') == 'azure':
        if status in ('UNKNOWN', 'DENIED'):
            return 'Native container metadata did not establish an effective inherited default retention policy.'
        return _storage_observation(finding)
    if cid == RUNTIME and finding.get('provider') == 'azure':
        if status in ('UNKNOWN', 'DENIED'):
            return 'The declared Linux web app runtime could not be matched to complete regional lifecycle metadata.'
        runtime = evidence.get('runtime')
        if type(runtime) is not str or not _RUNTIME.fullmatch(runtime):
            return None
        if status == 'FAIL':
            return f'The web app declares {runtime}; regional stack metadata marks it as deprecated or past its stated end of life.'
        return f'The web app declares {runtime}; regional stack metadata marks it as not deprecated and any stated end of life is in the future.'
    if cid == GCP and finding.get('provider') == 'gcp':
        return _image_observation(status, evidence)
    if cid == AWS and finding.get('provider') == 'aws':
        return _image_observation(status, {
            'vulnerabilities': evidence.get('Vulnerabilities'),
            'coverage_status': evidence.get('Coverage')})
    return None


def _image_observation(status, evidence):
    if status in ('UNKNOWN', 'DENIED'):
        return 'The selected immutable image could not be fully assessed for HIGH or CRITICAL package vulnerabilities.'
    rows = evidence.get('vulnerabilities')
    if type(rows) is not list or len(rows) > 1000:
        return None
    if status == 'PASS':
        if rows or evidence.get('coverage_status') != 'COMPLETE':
            return None
        return 'No HIGH or CRITICAL package vulnerabilities were detected in the selected immutable image.'
    if not rows:
        return None
    names = []
    for row in rows:
        if type(row) is not dict or row.get('severity') not in ('HIGH', 'CRITICAL'):
            return None
        fields = [row.get(k) for k in ('vulnerability_id', 'package', 'version')]
        if any(type(value) is not str or not _TOKEN.fullmatch(value) for value in fields):
            return None
        names.append(f'{fields[0]} ({fields[1]} {fields[2]})')
    examples = ', '.join(names[:8])
    suffix = f', and {len(names)-8} more' if len(names) > 8 else ''
    text = f'The selected immutable image has {len(rows)} HIGH or CRITICAL package vulnerabilities: {examples}{suffix}.'
    if evidence.get('coverage_status') != 'COMPLETE':
        text += ' Image coverage is incomplete.'
    return text

def _storage_observation(finding):
    """Render only this successor's measured rows, never infer a locked policy."""
    if not isinstance(finding, dict) or finding.get('check_id') != STORAGE:
        return None
    if finding.get('status') not in {'PASS', 'FAIL'}:
        return None
    evidence = finding.get('evidence')
    if not isinstance(evidence, dict):
        return None
    rows = evidence.get('observed_default_policies')
    bad = evidence.get('containers_without_effective_default_retention')
    if not isinstance(rows, list) or not rows or not isinstance(bad, list):
        return None
    seen = set()
    calculated_bad = []
    for row in rows:
        if not isinstance(row, dict):
            return None
        cid, state = row.get('container_id'), row.get('state')
        days, inherited = row.get('retention_days'), row.get('new_writes_inherit')
        if (not isinstance(cid, str) or not cid or cid in seen or
            state not in {'Locked', 'Unlocked', 'Disabled', 'Absent'} or
            type(days) is not int or days < 0 or type(inherited) is not bool):
            return None
        seen.add(cid)
        if state in {'Disabled', 'Absent'} or days == 0 or not inherited:
            calculated_bad.append(cid)
    if bad != calculated_bad or (finding['status'] == 'FAIL') != bool(bad):
        return None
    if bad:
        return ('New writes lack a positive inherited default retention policy in: '
                + ', '.join(bad) + '.')
    text = f'New writes inherit a positive default retention period in all {len(rows)} observed Blob containers.'
    if any(row['state'] == 'Unlocked' for row in rows):
        text += ' At least one default policy is unlocked and can still be changed.'
    return text
