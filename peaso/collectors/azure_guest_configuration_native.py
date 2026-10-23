"""Resolve approved Guest Configuration baselines from native latest reports.

Only read-only ARM operations run. A policy identifies an approved baseline;
it never supplies compliance results, timestamps or guest measurements.
"""
from __future__ import annotations

import json
import re

from .azure_guest_reports import ARM, VERSION, project_report

KIND = 'azure_sw18_evidence'
BASELINES = {
    'azure.gap.network_security_group_rdp_access_restricted': 'userRightsBaseline',
    'azure.other.clock_sync': 'timeSyncBaseline',
}


def _policy(options, scope):
    root = options.get('compliance_policy', {})
    named = root.get('sw18') if isinstance(root, dict) else None
    if (isinstance(named, dict) and named.get('status') == 'collected'
            and str(named.get('scope', '')).casefold() == scope.casefold()
            and isinstance(root, dict) and root.get('status') == 'collected'
            and str(root.get('scope', '')).casefold() == scope.casefold()):
        root = {**named, **root}
    value = (root if root.get('status') == 'collected' and 'scope' in root else root.get('sw18', root)) if isinstance(root, dict) else {}
    if not value:
        from .azure import AzureReadError
        raise AzureReadError('approved_guest_baseline_policy_unavailable')
    if not isinstance(value, dict) or value.get('status') != 'collected' or str(value.get('scope', '')).casefold() != scope.casefold():
        raise ValueError('approved guest baseline policy unavailable')
    return value


def _parameters(guest):
    values = guest.get('configurationParameter')
    if not isinstance(values, list):
        raise ValueError('effective guest baseline parameters unavailable')
    result = {}
    for entry in values:
        if not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or not isinstance(entry.get('value'), str) or entry['name'] in result:
            raise ValueError('malformed effective guest parameters')
        result[entry['name']] = entry['value']
    return result


def _measurement(native, baseline):
    """Keep only the approved setting/reason and bounded time-sync fields."""
    details = native.get('properties', {}).get('details')
    resources = details.get('resources') if isinstance(details, dict) else None
    if not isinstance(resources, list):
        raise ValueError('guest measurement resources unavailable')
    selected = [r for r in resources if isinstance(r, dict) and r.get('resourceId', r.get('properties', {}).get('ResourceId')) == baseline.get('measurementResourceId')]
    if len(selected) != 1 or not isinstance(selected[0].get('reasons'), list):
        raise ValueError('approved guest measurement resource unavailable')
    reasons = [r for r in selected[0]['reasons'] if isinstance(r, dict) and r.get('code') == baseline.get('measurementReasonCode')]
    if len(reasons) != 1 or not isinstance(reasons[0].get('phrase'), str) or len(reasons[0]['phrase']) > 4096:
        raise ValueError('approved guest measurement reason unavailable')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate guest measurement key')
            result[key] = value
        return result
    measured = json.loads(reasons[0]['phrase'], object_pairs_hook=unique)
    if (not isinstance(measured, dict) or set(measured) != {'sourceId', 'synchronized', 'driftExceeded'}
            or not isinstance(measured['sourceId'], str) or not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,256}', measured['sourceId'])
            or type(measured['synchronized']) is not bool or type(measured['driftExceeded']) is not bool):
        raise ValueError('invalid time synchronization measurement')
    return {'resourceId': baseline['measurementResourceId'], 'reasons': [
        {'code': baseline['measurementReasonCode'], 'phrase': json.dumps(measured, separators=(',', ':'))}]}


def collect(reader, request, scopes, wanted, options):
    if KIND not in wanted:
        return
    from .azure import AzureReadError
    jobs = []
    for scope in scopes:
        sources = [c for c in reader.collections if c['type'] == 'vm' and c['scope'].casefold() == scope.casefold()]
        def fetch(scope=scope, sources=sources):
            policy = _policy(options, scope)
            if len(sources) != 1 or sources[0]['status'] not in ('collected', 'empty'):
                raise AzureReadError('guest_baseline_vm_inventory_incomplete')
            for vm in sources[0]['items']:
                vm_id = vm.get('id')
                if (not isinstance(vm_id, str) or not re.fullmatch(re.escape(scope) + r'/resourceGroups/[^/?#%]+/providers/Microsoft.Compute/virtualMachines/[^/?#%]+', vm_id, re.I)):
                    raise ValueError('foreign guest baseline VM')
                assignments = vm.get('guestConfigurationAssignments')
                if vm.get('_coverage', {}).get('guestConfigurationAssignments', {}).get('status') not in ('collected', 'empty') or not isinstance(assignments, list):
                    raise AzureReadError('guest_baseline_assignments_incomplete')
                for cid, key in BASELINES.items():
                    baseline = policy.get(key)
                    if not isinstance(baseline, dict):
                        continue
                    if cid == next(iter(BASELINES)) and vm.get('properties', {}).get('storageProfile', {}).get('osDisk', {}).get('osType') == 'Linux':
                        continue
                    matches = [a for a in assignments if isinstance(a, dict) and a.get('properties', {}).get('guestConfiguration', {}).get('name') == baseline.get('name') and a.get('properties', {}).get('guestConfiguration', {}).get('version') == baseline.get('version')]
                    if len(matches) != 1:
                        continue  # Missing baseline remains UNKNOWN, never invented FAIL.
                    assignment = matches[0]
                    aid, name = assignment.get('id'), assignment.get('name')
                    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or not isinstance(aid, str) or aid.casefold() != (vm_id + '/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/' + name).casefold():
                        raise ValueError('foreign guest baseline assignment')
                    parameters = _parameters(assignment['properties']['guestConfiguration'])
                    if parameters != baseline.get('parameters'):
                        continue
                    latest = assignment['properties'].get('latestReportId')
                    if not isinstance(latest, str):
                        raise ValueError('guest latest report unavailable')
                    rid = latest if latest.startswith('/') else aid + '/reports/' + latest
                    if not rid.casefold().startswith((aid + '/reports/').casefold()) or not re.fullmatch(r'[A-Za-z0-9_.-]+', rid[len(aid + '/reports/'):]):
                        raise ValueError('foreign guest baseline report')
                    native = reader.call(request, ARM + rid + '?api-version=' + VERSION)
                    report = project_report(native, rid, vm_id, assignment)
                    props = native['properties']
                    if props.get('reportId') != rid.rsplit('/', 1)[-1]:
                        raise ValueError('guest report native reportId differs')
                    details = props.get('details')
                    if not isinstance(details, dict):
                        raise ValueError('guest report full details unavailable')
                    for field, expected in (('jobId', props['reportId']), ('complianceStatus', props.get('complianceStatus')), ('endTime', props.get('endTime'))):
                        if field in details and details[field] != expected:
                            raise ValueError('guest report detail binding differs')
                    report['_provenance'].update(representation='full', projection='approved_guest_baseline_metadata')
                    if key == 'timeSyncBaseline':
                        report['properties']['details']['resources'] = [_measurement(native, baseline)]
                    row = {'id': vm_id + '#sw18:' + cid, 'scope': scope, 'subject_id': vm_id,
                        'check_id': cid, 'assignment_id': aid, 'effective_parameters': parameters,
                        'coverage': {'assignments': True, 'reports': True, 'parameters': True},
                        'report': report, '_provenance': {'read_only': True, 'adapter': 'sw18-resolved-v1',
                            'source_ids': [aid, rid], 'source_operation': 'GuestConfigurationAssignmentReports_Get',
                            'api_version': VERSION}}
                    # Assignment parent provenance is derived from the validated ARM path.
                    assignment['parent_id'] = vm_id
                    yield [row]
        jobs.append((KIND, scope, 'Microsoft.GuestConfiguration', fetch))
    reader.run(jobs)
