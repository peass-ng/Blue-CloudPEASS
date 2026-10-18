"""Signed Azure VM compliance predicates over scoped, read-only snapshot facts.

Additional fact contracts and normalization rules are documented in the sw17
collector requests. No evaluator makes API calls or infers safety from absence.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import ipaddress
import itertools
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects, memoized, optional

from .compliance_new_sw17_specs import SPECS, PROPOSED_SPEC_SHA256
from peaso.collectors.azure_wave_compute_native import evaluate_vm_patch_installation

PREFIX = 'azure.gap.compute_vm_'
VM_ARM = re.compile(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Compute/virtualMachines/[^/]+', re.I)
KINDS = {
    'vm': 'Microsoft.Compute/virtualMachines', 'nic': 'Microsoft.Network/networkInterfaces',
    'nsg': 'Microsoft.Network/networkSecurityGroups', 'public_ip': 'Microsoft.Network/publicIPAddresses',
    'load_balancer': 'Microsoft.Network/loadBalancers', 'sql_vm': 'Microsoft.SqlVirtualMachine/sqlVirtualMachines',
}


def _scope(index):
    context = get(index, 'context', dict)
    scope = get(context, 'scope', str)
    if get(context, 'provider', str) != 'azure' or not re.fullmatch(r'/subscriptions/[^/]+', scope, re.I):
        raise Unavailable('Azure subscription scope authority unavailable')
    return scope.casefold()


def _arm(value, scope, kind=None):
    if not isinstance(value, str) or not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/(?:[^/]+/[^/]+)(?:/[^/]+/[^/]+)*', value, re.I):
        raise Unavailable('malformed ARM resource identity')
    if not value.casefold().startswith(scope + '/resourcegroups/'):
        raise Unavailable('foreign subscription resource identity')
    if kind in KINDS and not re.fullmatch(re.escape(scope) + r'/resourcegroups/[^/]+/providers/' + re.escape(KINDS[kind]) + r'/[^/]+', value, re.I):
        raise Unavailable('ARM resource type does not match snapshot kind')
    if kind == 'subnet' and not re.fullmatch(re.escape(scope) + r'/resourcegroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+/subnets/[^/]+', value, re.I):
        raise Unavailable('malformed subnet identity')
    return value.casefold()


def _inventory(index, kind):
    def compute():
        scope = _scope(index)
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or not envelopes:
            raise Unavailable('missing collection: ' + kind)
        for envelope in envelopes:
            escope = get(envelope, 'scope', str).casefold()
            # Azure child lists (e.g. subnets) are scoped to the parent ARM ID.
            if get(envelope, 'type', str) != kind or not (escope == scope or escope.startswith(scope + '/')):
                raise Unavailable('foreign or malformed collection scope: ' + kind)
        rows = complete_items(index, kind)
        listed = []
        for envelope in envelopes:
            values = list_of_objects(get(envelope, 'items', list))
            if get(envelope, 'status', str) == 'empty' and values:
                raise Unavailable('empty inventory conflicts with listed rows: ' + kind)
            listed.extend(values)
        if len(listed) != len(rows) or sorted(get(row, 'id', str).casefold() for row in listed) != sorted(get(row, 'id', str).casefold() for row in rows):
            raise Unavailable('native index differs from complete collection inventory: ' + kind)
        for wrapper in get(index, kind, list):
            wscope = get(wrapper, 'scope', str).casefold()
            if get(wrapper, 'type', str) != kind or not (wscope == scope or wscope.startswith(scope + '/')):
                raise Unavailable('foreign or malformed resource wrapper: ' + kind)
        identities = set()
        for row in rows:
            rid = get(row, 'id', str)
            if kind in KINDS or kind == 'subnet':
                rid = _arm(rid, scope, kind)
            elif not rid or not rid.casefold().startswith(scope + '/'):
                raise Unavailable('foreign or missing fact identity: ' + kind)
            else:
                rid = rid.casefold()
            if rid in identities:
                raise Unavailable('duplicate resource identity: ' + kind)
            identities.add(rid)
        return rows
    return memoized(index, ('sw17_inventory', kind), compute)


def _vm(item, index):
    scope = _scope(index)
    rid = _arm(get(item, 'id', str), scope, 'vm')
    rows = [row for row in _inventory(index, 'vm') if get(row, 'id', str).casefold() == rid]
    if len(rows) != 1 or rows[0] != item:
        raise Unavailable('VM differs from complete scoped VM inventory')
    return rid


def _os(item):
    value = get(item, 'properties.storageProfile.osDisk.osType', str)
    if value not in ('Windows', 'Linux'):
        raise Unavailable('VM operating system unknown')
    return value


def _map_value(mapping, key):
    guard(mapping)
    translated = {'value': mapping[key]} if key in mapping else {}
    coverage = mapping.get('_coverage', {})
    if key in coverage:
        translated['_coverage'] = {'value': coverage[key]}
    return get(translated, 'value', dict)


def _policy(index, check_id):
    policy = get(index, 'context.metadata.compliance_policy', dict)
    if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str).casefold() != _scope(index):
        raise Unavailable('policy unavailable or foreign scope')
    checks = get(policy, 'checks', dict)
    return _map_value(checks, check_id)


def _time(value):
    if not isinstance(value, str):
        raise Unavailable('timestamp missing')
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None or dt.utcoffset() is None:
            raise ValueError('timezone missing')
        return dt
    except ValueError as exc:
        raise Unavailable('malformed timestamp') from exc


def _fresh(at, index, policy):
    maximum = get(policy, 'maxReportAgeSeconds', int)
    if maximum <= 0:
        raise Unavailable('report age policy malformed')
    elapsed = (_time(get(index, 'context.created_at', str)) - _time(at)).total_seconds()
    if not 0 <= elapsed <= maximum:
        raise Unavailable('report stale or future dated')


def _observed(row, index, policy):
    provenance = get(row, '_provenance', dict)
    if get(provenance, 'read_only', bool) is not True or not get(provenance, 'source_operation', str):
        raise Unavailable('read-only observation provenance unavailable')
    _fresh(get(provenance, 'observed_at', str), index, policy)
    # A fresh API read cannot refresh the underlying vulnerability report.
    if provenance.get('source_operation') == 'SubAssessments_ListAll':
        _fresh(get(row, 'properties.timeGenerated', str), index, policy)


def _strings(value, *, empty=False):
    if not isinstance(value, list) or (not value and not empty) or any(not isinstance(x, str) or not x.strip() for x in value):
        raise Unavailable('required string set missing or malformed')
    normalized = [x.casefold() for x in value]
    if len(normalized) != len(set(normalized)):
        raise Unavailable('duplicate set member')
    return set(normalized)


def _fact(index, kind, vm_id, policy, *, check_id=None):
    rows = _inventory(index, kind)
    matched = []
    for row in rows:
        bound = _arm(get(row, 'vm_id', str), _scope(index), 'vm')
        if bound == vm_id and (check_id is None or get(row, 'check_id', str) == check_id):
            matched.append(row)
    if len(matched) != 1:
        raise Unavailable('fact missing or ambiguous: ' + kind)
    _observed(matched[0], index, policy)
    return matched[0]


def _applicable(index, vm_id, policy, check_id):
    fact = _fact(index, 'vm_compliance_applicability', vm_id, policy, check_id=check_id)
    if not get(fact, 'basis', str):
        raise Unavailable('applicability basis absent')
    return get(fact, 'applicable', bool)


def _na(reason):
    return 'NOT_APPLICABLE', {'reason': reason}


def _assignment(item, index, policy):
    coverage = get(item, '_coverage.guestConfigurationAssignments', dict)
    if get(coverage, 'status', str) not in ('collected', 'empty'):
        raise Unavailable('assignment inventory incomplete')
    rows = list_of_objects(get(item, 'guestConfigurationAssignments', list))
    if coverage['status'] == 'empty' and rows:
        raise Unavailable('empty assignment inventory conflicts with rows')
    expected_name = get(policy, 'assignmentName', str)
    baseline, version = get(policy, 'configurationName', str), get(policy, 'configurationVersion', str)
    if not all((expected_name, baseline, version)):
        raise Unavailable('baseline identity missing')
    candidates, seen = [], set()
    vm_id = get(item, 'id', str).casefold()
    for row in rows:
        name = get(row, 'name', str)
        rid = get(row, 'id', str).casefold()
        if rid != vm_id + '/providers/microsoft.guestconfiguration/guestconfigurationassignments/' + name.casefold() or rid in seen:
            raise Unavailable('assignment identity foreign, malformed or duplicate')
        seen.add(rid)
        if name == expected_name:
            config = get(row, 'properties.guestConfiguration', dict)
            if get(config, 'name', str) != baseline or get(config, 'version', str) != version:
                raise Unavailable('assignment baseline/version differs from policy')
            candidates.append(row)
    if len(candidates) > 1:
        raise Unavailable('assignment ambiguous')
    if not candidates:
        _observed(coverage, index, policy)
        return None
    return candidates[0]


def _parameter(assignment, name, expected):
    params = list_of_objects(get(assignment, 'properties.guestConfiguration.configurationParameter', list))
    found, seen = [], set()
    for param in params:
        key = get(param, 'name', str)
        if not key or key in seen:
            raise Unavailable('assignment parameter ambiguous')
        seen.add(key)
        if key == name:
            # Array-valued policy inputs are canonically JSON-encoded by the
            # purpose-built assignment, rather than split on ambiguous commas.
            import json
            try:
                value = json.loads(get(param, 'value', str))
            except ValueError as exc:
                raise Unavailable('assignment parameter is not a JSON string set') from exc
            found.append(_strings(value, empty=True))
    if len(found) != 1 or found[0] != expected:
        raise Unavailable('assignment parameter binding differs from policy')


def _report(item, index, policy, assignment):
    latest = get(assignment, 'properties.latestReportId', str)
    aid = get(assignment, 'id', str)
    if not latest:
        raise Unavailable('latest report ID absent')
    expected_id = latest if latest.startswith('/') else aid + '/reports/' + latest
    if not expected_id.casefold().startswith(aid.casefold() + '/reports/') or '/' in expected_id[len(aid + '/reports/'):]:
        raise Unavailable('latest report identity malformed or foreign')
    rows = _inventory(index, 'guest_configuration_report')
    matching = [row for row in rows if get(row, 'id', str).casefold() == expected_id.casefold()]
    if len(matching) != 1:
        raise Unavailable('latest guest report absent or ambiguous')
    report = matching[0]
    _observed(report, index, policy)
    if (get(report, 'properties.vm.id', str).casefold() != get(item, 'id', str).casefold()
            or get(report, 'properties.assignment.name', str) != get(assignment, 'name', str)
            or get(report, 'properties.assignment.configuration.name', str) != get(policy, 'configurationName', str)
            or get(report, 'properties.assignment.configuration.version', str) != get(policy, 'configurationVersion', str)):
        raise Unavailable('report VM/assignment/baseline identity mismatch')
    _fresh(get(report, 'properties.endTime', str), index, policy)
    if 'operationStatus' in report.get('properties', {}):
        if get(report, 'properties.operationStatus', str) != 'Succeeded':
            raise Unavailable('guest report operation not successful')
    else:
        # The native 2024-04-05 report has no operationStatus. Require a
        # completed, measured report with consistent chronology and identity.
        if (get(report, '_provenance.native_report_schema', bool) is not True or
                get(report, '_provenance.api_version', str) != '2024-04-05' or
                get(report, '_provenance.source_operation', str) != 'GuestConfigurationAssignmentReports_Get'):
            raise Unavailable('native guest report source unavailable')
        status = _status(report, 'properties.complianceStatus')
        if _status(report, 'properties.details.complianceStatus') != status:
            raise Unavailable('guest report aggregate status inconsistent')
        props = get(report, 'properties', dict)
        details = get(props, 'details', dict)
        if (get(props, 'reportId', str) != expected_id.rsplit('/', 1)[-1] or
                get(details, 'jobId', str) != props['reportId'] or
                get(details, 'operationType', str) not in ('Consistency', 'Initial') or
                _time(get(props, 'startTime', str)) > _time(props['endTime']) or
                _time(get(details, 'startTime', str)) != _time(props['startTime']) or
                _time(get(details, 'endTime', str)) != _time(props['endTime'])):
            raise Unavailable('guest report completion chronology or identity inconsistent')
    coverage = get(report, '_coverage.resources', dict)
    if get(coverage, 'status', str) != 'collected':
        raise Unavailable('guest report resources incomplete')
    resources = list_of_objects(get(report, 'properties.details.resources', list))
    if not resources:
        raise Unavailable('guest report lacks resource details')
    seen = set()
    for resource in resources:
        key = get(resource, 'resourceId', str)
        if not key or key in seen:
            raise Unavailable('guest report resource identity missing or ambiguous')
        seen.add(key)
    return report, resources


def _status(row, path='complianceStatus'):
    value = get(row, path, str)
    if value not in ('Compliant', 'NonCompliant'):
        raise Unavailable('compliance status not measured')
    return value


def _exact(left, right):
    """Type-preserving JSON value equality, including frozen snapshot containers."""
    if isinstance(left, dict) and isinstance(right, dict):
        return set(left) == set(right) and all(_exact(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_exact(a, b) for a, b in zip(left, right))
    return type(left) is type(right) and left == right


def _guest(check_id, item, index):
    _vm(item, index)
    suffix = check_id.removeprefix(PREFIX)
    required_os = 'Linux' if suffix == 'password_file_permissions_0644_linux' else 'Windows'
    if _os(item) != required_os:
        return _na('VM operating system outside this baseline')
    policy = _policy(index, check_id)
    # Read all policy inputs before considering a missing assignment adverse.
    member_field = {
        'administrators_group_with_extra_accounts_windows': 'approvedAdministrators',
        'administrators_group_with_no_specified_members_windows': 'requiredAdministrators',
        'administrators_group_with_specified_members_windows': 'prohibitedAdministrators',
        'with_no_specified_certificates_in_trusted_root_windows': 'requiredThumbprints',
    }.get(suffix)
    expected = _strings(get(policy, member_field, list), empty=member_field == 'requiredThumbprints') if member_field else None
    if member_field == 'requiredThumbprints' and not expected and get(policy, 'emptyRequiredSetApproved', bool) is not True:
        raise Unavailable('empty required certificate set lacks explicit policy approval')
    if member_field == 'requiredThumbprints' and any(not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', x) for x in expected):
        raise Unavailable('certificate thumbprint malformed')
    settings = get(policy, 'requiredSettings', dict) if suffix == 'meet_firewall_properties_windows' else None
    if settings is not None:
        # All named settings are required, across each frozen category. Three
        # profile enablement booleans alone cannot satisfy this baseline.
        categories = {'firewallState', 'inboundConnections', 'outboundConnections', 'ruleManagement', 'notifications'}
        actual_categories = set()
        if not settings:
            raise Unavailable('firewall baseline empty')
        for key, setting in settings.items():
            if not key or not isinstance(setting, dict) or get(setting, 'category', str) not in categories:
                raise Unavailable('firewall baseline malformed')
            if type(get(setting, 'expected')) not in (str, bool, int):
                raise Unavailable('firewall expected value is not a typed scalar')
            actual_categories.add(setting['category'])
        if actual_categories != categories:
            raise Unavailable('firewall baseline omits frozen setting categories')
    assignment = _assignment(item, index, policy)
    if assignment is None:
        if suffix in ('administrators_group_with_extra_accounts_windows', 'password_file_permissions_0644_linux'):
            return result(True, reason='complete current inventory proves required assignment absent')
        return unknown('required guest assignment absent')
    if member_field:
        _parameter(assignment, member_field, expected)
    if suffix == 'meet_firewall_properties_windows':
        import json
        params = list_of_objects(get(assignment, 'properties.guestConfiguration.configurationParameter', list))
        bound = [get(p, 'value', str) for p in params if get(p, 'name', str) == 'requiredSettings']
        if len(bound) != 1 or not _exact(json.loads(bound[0]), settings):
            raise Unavailable('firewall settings not bound to exact assignment')
    if suffix == 'password_file_permissions_0644_linux':
        _parameter(assignment, 'filePaths', {'/etc/passwd'})
        _parameter(assignment, 'requiredModes', {'0644'})
    report, resources = _report(item, index, policy, assignment)
    bad, uncertain, measured = [], [], set()
    for row in resources:
        try:
            props = get(row, 'properties', dict)
            if member_field and member_field != 'requiredThumbprints':
                if get(props, 'group', str) != 'Administrators':
                    continue
                if get(props, 'membershipComplete', bool) is not True:
                    raise Unavailable('membership observation incomplete')
                observed = _strings(get(props, 'observedMembers', list), empty=True)
                compliance = _status(row)
                measured.add('Administrators')
                violations = observed - expected if member_field == 'approvedAdministrators' else expected - observed if member_field == 'requiredAdministrators' else observed & expected
                if violations or member_field == 'approvedAdministrators' and compliance == 'NonCompliant':
                    bad.append(row['resourceId'])
                elif compliance != 'Compliant':
                    uncertain.append(row['resourceId'])
            elif member_field == 'requiredThumbprints':
                if get(props, 'store', str) != 'LocalMachine\\Root':
                    continue
                if get(props, 'certificateSetComplete', bool) is not True:
                    raise Unavailable('certificate store observation incomplete')
                observed = _strings(get(props, 'observedThumbprints', list), empty=True)
                if any(not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', x) for x in observed):
                    raise Unavailable('observed certificate thumbprint malformed')
                measured.add('LocalMachine\\Root')
                compliance = _status(row)
                if expected - observed:
                    bad.append(row['resourceId'])
                elif compliance != 'Compliant':
                    uncertain.append(row['resourceId'])
            elif settings is not None:
                key = get(props, 'settingName', str)
                if key not in settings:
                    continue
                if key in measured:
                    raise Unavailable('duplicate firewall setting observation')
                measured.add(key)
                if not _exact(get(props, 'expected'), get(settings[key], 'expected')):
                    raise Unavailable('firewall setting expected value differs from policy')
                if _status(row) == 'NonCompliant':
                    bad.append(row['resourceId'])
                elif not _exact(get(props, 'observed'), settings[key]['expected']):
                    uncertain.append(row['resourceId'])
            elif suffix == 'password_file_permissions_0644_linux':
                if get(props, 'path', str) != '/etc/passwd':
                    continue
                mode = get(props, 'mode', str)
                if not re.fullmatch(r'0[0-7]{3}', mode):
                    raise Unavailable('file mode malformed')
                measured.add('/etc/passwd')
                if mode != '0644':
                    bad.append(row['resourceId'])
                elif _status(row) != 'Compliant':
                    uncertain.append(row['resourceId'])
        except Unavailable:
            uncertain.append(row['resourceId'])
    if bad:
        return result(True, violating_resources=bad)
    required = set(settings) if settings is not None else {'LocalMachine\\Root'} if member_field == 'requiredThumbprints' else {'Administrators'} if member_field else {'/etc/passwd'}
    if uncertain or measured != required:
        return unknown('required guest resource details missing or unmeasured', uncertain_resources=uncertain)
    if member_field == 'prohibitedAdministrators' and _status(assignment, 'properties.complianceStatus') != 'Compliant':
        return unknown('assigned prohibited-members baseline is not Compliant')
    if suffix == 'administrators_group_with_extra_accounts_windows' and _status(report, 'properties.details.complianceStatus') != 'Compliant':
        return unknown('approved-members report summary contradicts resource results')
    return result(False, evaluated_resources=sorted(measured))


def _assessments(index, vm_id, keys, policy):
    matches = {key: [] for key in keys}
    for row in _inventory(index, 'security_assessment'):
        key = get(row, 'name', str).casefold()
        bound = _arm(get(row, 'properties.resourceDetails.id', str), _scope(index))
        if bound == vm_id and key in keys:
            # The extension resource path and payload must identify the same
            # assessed VM. A Healthy row from another resource is not proof.
            if (not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}', key) or
                    get(row, 'id', str).casefold() !=
                    vm_id + '/providers/microsoft.security/assessments/' + key):
                raise Unavailable('assessment native identity differs from assessed VM/key')
            matches[key].append(row)
    bad, uncertain = [], []
    for key, rows in matches.items():
        if len(rows) != 1:
            uncertain.append(key)
            continue
        try:
            _observed(rows[0], index, policy)
            status = get(rows[0], 'properties.status.code', str)
            if status == 'Unhealthy':
                bad.append(key)
            elif status != 'Healthy':
                uncertain.append(key)
        except Unavailable:
            uncertain.append(key)
    return bad, uncertain


_DOCKER_ASSESSMENT_KEY = '0677209d-e675-2c6f-e91a-54cef2878663'
_DOCKER_POLICY_ID = '/providers/Microsoft.Authorization/policyDefinitions/e8cbc669-f12d-49eb-93e7-9273119e9933'


def _docker_native_unhealthy(index, vm_id, policy):
    """A bound built-in GET can prove a required failure, not host coverage."""
    if _DOCKER_ASSESSMENT_KEY not in _strings(get(policy, 'assessmentKeys', list)):
        return False
    scope = _scope(index)
    matches = []
    for row in _inventory(index, 'security_assessment'):
        if get(row, 'name', str).casefold() != _DOCKER_ASSESSMENT_KEY:
            continue
        if _arm(get(row, 'properties.resourceDetails.id', str), scope) == vm_id:
            matches.append(row)
    if not matches:
        return False
    if len(matches) != 1:
        raise Unavailable('Docker assessment native identity ambiguous')
    row = matches[0]
    origin = get(row, '_provenance', dict)
    # Plain LIST rows retain the independently applicable legacy path.
    if get(origin, 'source_operation', str) != 'Assessments_Get':
        return False
    if (get(row, 'type', str).casefold() != 'microsoft.security/assessments'
            or get(row, 'id', str).casefold() != vm_id + '/providers/microsoft.security/assessments/' + _DOCKER_ASSESSMENT_KEY
            or get(row, 'properties.resourceDetails.source', str) != 'Azure'):
        raise Unavailable('Docker assessment native VM identity unverified')
    if (get(origin, 'read_only', bool) is not True
            or get(origin, 'api_version', str) != '2020-01-01'
            or get(origin, 'representation', str) != 'metadata'
            or get(origin, 'metadata_expanded', bool) is not True
            or get(origin, 'scope', str).casefold() != scope):
        raise Unavailable('Docker assessment expanded GET provenance unavailable')
    context = get(index, 'context.metadata', dict)
    if get(context, 'context_binding', str) != 'scan_local':
        raise Unavailable('Docker assessment scan-local context unavailable')
    for name in ('credential_context_id', 'customer_context_id'):
        value = get(context, name, str)
        if not value or get(origin, name, str) != value:
            raise Unavailable('Docker assessment capture/customer binding differs')
        for envelope in get(index, 'collections', dict)['security_assessment']:
            if get(envelope, 'scope', str).casefold() == scope:
                collection_origin = get(envelope, '_provenance', dict)
                if name in collection_origin and collection_origin[name] != value:
                    raise Unavailable('Docker assessment collection capture/customer binding differs')
    _observed(row, index, policy)
    if (get(row, 'properties.metadata.assessmentType', str) != 'BuiltIn'
            or get(row, 'properties.metadata.policyDefinitionId', str).casefold() != _DOCKER_POLICY_ID.casefold()):
        raise Unavailable('Docker assessment is not the approved Microsoft built-in')
    return get(row, 'properties.status.code', str) == 'Unhealthy'


def _adaptive_native_diagnostic(index, vm_id, policy):
    """Project bounded recommendation metadata; no field proves enforcement."""
    kind = 'adaptive_network_hardening_native'
    scope = _scope(index)
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1 or get(envelopes[0], 'scope', str).casefold() != scope:
        raise Unavailable('native adaptive recommendation subscription inventory absent or ambiguous')
    rows = _inventory(index, kind)
    if len(rows) > 2048:
        raise Unavailable('native adaptive recommendation resource limit exceeded')
    known_vms = {_arm(get(vm, 'id', str), scope, 'vm') for vm in _inventory(index, 'vm')}
    matched = []
    rule_count = 0
    association_count = 0
    for row in rows:
        parent = _arm(get(row, 'vm_id', str), scope, 'vm')
        if parent not in known_vms:
            raise Unavailable('native adaptive recommendation parent absent from VM roster')
        name = get(row, 'name', str)
        rid = get(row, 'id', str).casefold()
        if not name or '/' in name or rid != parent + '/providers/microsoft.security/adaptivenetworkhardenings/' + name.casefold():
            raise Unavailable('native adaptive recommendation child identity differs from parent/name')
        provenance = get(row, '_provenance', dict)
        if (get(provenance, 'source_operation', str) != 'AdaptiveNetworkHardenings_ListByExtendedResource'
                or get(provenance, 'api_version', str) != '2020-01-01'
                or get(provenance, 'representation', str) != 'native_recommendation_metadata'
                or get(provenance, 'read_only', bool) is not True
                or get(provenance, 'endpoint', str).casefold() !=
                ('https://management.azure.com' + parent + '/providers/microsoft.security/adaptivenetworkhardenings?api-version=2020-01-01')):
            raise Unavailable('native adaptive recommendation operation or endpoint unverified')
        _observed(row, index, policy)
        _fresh(get(row, 'rules_calculation_time', str), index, policy)
        rules = list_of_objects(get(row, 'recommended_rules', list))
        associations = list_of_objects(get(row, 'effective_nsg_associations', list))
        rule_count += len(rules)
        association_count += len(associations)
        if rule_count > 16384 or association_count > 32768:
            raise Unavailable('native adaptive recommendation raw reference limit exceeded')
        for rule in rules:
            if (not get(rule, 'name', str) or get(rule, 'direction', str) not in ('Inbound', 'Outbound')
                    or not isinstance(get(rule, 'destinationPort'), int)
                    or not isinstance(get(rule, 'ipAddresses', list), list)
                    or not isinstance(get(rule, 'protocols', list), list)):
                raise Unavailable('native adaptive recommendation rule metadata malformed')
        for association in associations:
            _arm(get(association, 'network_interface_id', str), scope, 'nic')
            nsgs = get(association, 'network_security_group_ids', list)
            if not isinstance(nsgs, list) or len(nsgs) != len(set(str(value).casefold() for value in nsgs)):
                raise Unavailable('native adaptive recommendation NSG references ambiguous')
            for nsg in nsgs:
                _arm(nsg, scope, 'nsg')
        if parent == vm_id:
            matched.append((rid, get(row, 'rules_calculation_time', str)))
    matched.sort()
    return {'native_recommendation_count': len(matched),
            'native_recommendation_ids': [rid for rid, _ in matched[:16]],
            'native_rules_calculation_times': [at for _, at in matched[:16]],
            'native_recommendation_ids_truncated': len(matched) > 16,
            'native_source_operation': 'AdaptiveNetworkHardenings_ListByExtendedResource'}


def _adaptive_native_observation(index, vm_id, policy):
    try:
        return _adaptive_native_diagnostic(index, vm_id, policy)
    except Unavailable as exc:
        return {'native_recommendation_status': 'unavailable', 'native_recommendation_reason': str(exc)}


def _allowlist_attestation(index, vm_id, check_id, policy):
    """Require independent current deployment and alert test observations.

    Retired applicationWhitelistings group recommendations are not deployment
    or unknown-application alert evidence.
    """
    trusted = _strings(get(policy, 'trustedAllowlistAttestationIssuers', list))
    rows = _inventory(index, 'application_allowlist_attestation')
    matching = []
    scope = _scope(index)
    for row in rows:
        bound = _arm(get(row, 'vm_id', str), scope, 'vm')
        if bound == vm_id and get(row, 'check_id', str) == check_id:
            matching.append(row)
    if len(matching) != 1:
        raise Unavailable('current allowlist attestation missing or ambiguous')
    row = matching[0]
    _observed(row, index, policy)
    origin = get(row, '_provenance', dict)
    if (get(origin, 'source_operation', str) != 'ExternalAllowlistAttestation_Read'
            or get(origin, 'issuer', str).casefold() not in trusted
            or not get(origin, 'evidence_uri', str).startswith('https://')):
        raise Unavailable('allowlist attestation authority unavailable')
    capture = get(row, 'capture_id', str)
    if not capture or not get(row, 'policy_revision', str):
        raise Unavailable('allowlist capture or policy revision unavailable')
    _fresh(get(row, 'captured_at', str), index, policy)
    group = get(row, 'group_id', str).casefold()
    if not re.fullmatch(re.escape(scope) + r'/providers/microsoft\.security/locations/[^/]+/applicationwhitelistings/[^/]+', group):
        raise Unavailable('allowlist group identity malformed or foreign')
    policy_id = get(row, 'policy_id', str).casefold()
    if not policy_id or '/' in policy_id:
        raise Unavailable('external allowlist policy identity missing or malformed')
    observations = []
    for name in ('policy_observation', 'alert_observation'):
        observation = get(row, name, dict)
        _observed(observation, index, policy)
        if (get(observation, 'capture_id', str) != capture
                or _arm(get(observation, 'vm_id', str), scope, 'vm') != vm_id
                or get(observation, 'group_id', str).casefold() != group
                or get(observation, 'policy_id', str).casefold() != policy_id
                or get(observation, 'policy_revision', str) != row['policy_revision']):
            raise Unavailable('allowlist observation differs from attested VM/group/policy/capture')
        if (get(observation, '_provenance.issuer', str).casefold() != get(origin, 'issuer', str).casefold()
                or get(observation, '_provenance.source_operation', str) != 'ExternalAllowlistAttestation_Read'
                or get(observation, '_provenance.evidence_uri', str) != get(origin, 'evidence_uri', str)):
            raise Unavailable('allowlist observation authority mismatch')
        observations.append(observation)
    deployed, alert = observations
    state = get(deployed, 'result', str)
    if state not in ('DeployedActive', 'NotDeployed', 'Inactive'):
        raise Unavailable('allowlist deployment result unresolved')
    if state == 'DeployedActive':
        if get(deployed, 'enforcement_mode', str) not in ('Audit', 'Enforce'):
            raise Unavailable('active allowlist mode unresolved')
        _strings(get(deployed, 'installed_rule_ids', list))
    alert_result = get(alert, 'result', str)
    if alert_result not in ('AlertObserved', 'NoAlertObserved'):
        raise Unavailable('unknown-application alert test result unresolved')
    if not get(alert, 'execution_id', str) or not get(alert, 'unknown_application_id', str):
        raise Unavailable('unknown-application execution proof missing')
    if alert_result == 'AlertObserved' and not get(alert, 'alert_id', str):
        raise Unavailable('unknown-application alert identity missing')
    return state, alert_result, group, policy_id


def _defender(check_id, item, index):
    vm_id = _vm(item, index)
    policy = _policy(index, check_id)
    suffix = check_id.removeprefix(PREFIX)
    native_adaptive = (_adaptive_native_observation(index, vm_id, policy)
                       if suffix == 'adaptive_network_hardening_recommendation_applied' else None)
    if suffix == 'container_security_configurations_vulnerabilities_remediated':
        if _docker_native_unhealthy(index, vm_id, policy):
            return result(True, unhealthy_assessment_keys=[_DOCKER_ASSESSMENT_KEY],
                          source_operation='Assessments_Get')
    if suffix == 'vulnerability_findings_resolved_for_sql_server':
        sqls = _inventory(index, 'sql_vm')
        joined = []
        for row in sqls:
            target = _arm(get(row, 'properties.virtualMachineResourceId', str), _scope(index), 'vm')
            if target == vm_id:
                joined.append(row)
        if len(joined) > 1:
            raise Unavailable('ambiguous SQL VM join')
        if not joined:
            return _na('complete SQL VM inventory proves VM is not a SQL VM')
    else:
        try:
            applicable = _applicable(index, vm_id, policy, check_id)
        except Unavailable:
            if native_adaptive is not None:
                return unknown('independent VM applicability unresolved; native recommendation is metadata only', **native_adaptive)
            raise
        if not applicable:
            return _na('current independent applicability evidence excludes VM')
    keys = _strings(get(policy, 'assessmentKeys', list))
    try:
        bad, uncertain = _assessments(index, vm_id, keys, policy)
    except Unavailable:
        if native_adaptive is not None:
            return unknown('independent assessment evidence unresolved; native recommendation is metadata only', **native_adaptive)
        raise
    if bad:
        return result(True, unhealthy_assessment_keys=bad)
    if suffix == 'container_security_configurations_vulnerabilities_remediated':
        return unknown('required Docker host assessments absent or not Healthy', uncertain_assessment_keys=uncertain) if uncertain else result(False, healthy_assessment_keys=sorted(keys))
    if suffix == 'adaptive_application_controls_enabled':
        if uncertain:
            return unknown('current assessment health unresolved; retired adaptive application controls cannot prove configuration')
        try:
            state, alert, group, policy_id = _allowlist_attestation(index, vm_id, check_id, policy)
        except Unavailable as exc:
            return unknown('current independent allowlist deployment and unknown-application alert attestation unavailable; Defender adaptive application controls retired', attestation_reason=str(exc))
        if state != 'DeployedActive':
            return result(True, reason='independently attested allowlist policy is not active on VM', group_id=group, policy_id=policy_id)
        if alert == 'NoAlertObserved':
            return result(True, reason='independent unknown-application test observed no alert', group_id=group, policy_id=policy_id)
        return result(False, healthy_assessment_keys=sorted(keys), group_id=group, policy_id=policy_id,
                      unknown_application_alerts_verified=True)
    if suffix == 'adaptive_network_hardening_recommendation_applied':
        try:
            evidence = _fact(index, 'adaptive_network_hardening', vm_id, policy)
        except Unavailable:
            return unknown('independent approved/applied/effective recommendation evidence unavailable', **native_adaptive)
        if not get(evidence, 'internetFacing', bool):
            return unknown('applicability conflicts with network evidence')
        rules = list_of_objects(get(evidence, 'requiredRules', list))
        if get(evidence, 'rulesComplete', bool) is not True:
            return unknown('required recommendation set incomplete')
        if not rules:
            return unknown('required recommendation rule details absent')
        nsgs = {get(row, 'id', str).casefold(): row for row in _inventory(index, 'nsg')}
        seen, unapplied, unresolved = set(), [], []
        associated = {get(nsg, 'id', str).casefold() for _, _, path in _network_paths(item, index) for nsg in path}
        for rule in rules:
            try:
                rule_id = get(rule, 'recommendationId', str)
                if not rule_id or rule_id in seen:
                    raise Unavailable('duplicate recommendation identity')
                seen.add(rule_id)
                nsg_id = _arm(get(rule, 'nsgId', str), _scope(index), 'nsg')
                if nsg_id not in nsgs or nsg_id not in associated:
                    raise Unavailable('recommended NSG is not joined to VM')
                if not get(rule, 'approved', bool):
                    raise Unavailable('required recommendation approval unresolved')
                applied = get(rule, 'applied', bool)
                effective = get(rule, 'effective', bool)
                if not applied or not effective:
                    unapplied.append(rule_id)
                elif get(rule, 'effectiveRuleEvidence.vm_id', str).casefold() != vm_id or get(rule, 'effectiveRuleEvidence.nsg_id', str).casefold() != nsg_id:
                    raise Unavailable('effective rule evidence is not VM/NSG bound')
                else:
                    proof = get(rule, 'effectiveRuleEvidence', dict)
                    _observed(proof, index, policy)
                    if get(proof, 'recommendationId', str) != rule_id or get(proof, 'matchesRecommendation', bool) is not True:
                        raise Unavailable('effective rule does not match recommendation')
            except Unavailable:
                unresolved.append(rule.get('recommendationId'))
        if unapplied:
            return result(True, unapplied_required_recommendations=unapplied)
        if uncertain or unresolved:
            return unknown('recommendation/assessment/effective-rule evidence incomplete')
        return result(False, applied_recommendations=sorted(seen))
    if suffix == 'vulnerability_findings_resolved_for_sql_server':
        required = _strings(get(policy, 'requiredFindingIds', list), empty=True)
        if get(policy, 'findingSetComplete', bool) is not True:
            raise Unavailable('applicable SQL finding identifiers not complete')
        rows = _inventory(index, 'security_subassessment')
        found, unresolved, unhealthy = set(), [], []
        for row in rows:
            bound = _arm(get(row, 'properties.resourceDetails.id', str), _scope(index))
            if bound != vm_id:
                continue
            try:
                key = get(row, 'assessment_key', str).casefold()
                finding = get(row, 'name', str).casefold()
                if key not in keys or finding in found:
                    raise Unavailable('SQL finding assessment key ambiguous')
                if (not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}', finding) or
                        get(row, 'id', str).casefold() != vm_id +
                        '/providers/microsoft.security/assessments/' + key +
                        '/subassessments/' + finding):
                    raise Unavailable('SQL finding native identity differs from assessed VM/key/name')
                found.add(finding)
                _observed(row, index, policy)
                status = get(row, 'properties.status.code', str)
                if status == 'Unhealthy':
                    unhealthy.append(finding)
                elif status != 'Healthy':
                    unresolved.append(finding)
            except Unavailable:
                unresolved.append(row.get('name'))
        if unhealthy:
            return result(True, unhealthy_finding_ids=unhealthy)
        if uncertain or unresolved or found != required:
            return unknown('complete current Healthy SQL assessment and finding coverage unavailable')
        return result(False, healthy_assessment_keys=sorted(keys), healthy_finding_ids=sorted(found))
    raise Unavailable('unsupported Defender predicate')


def _malware(check_id, item, index):
    vm_id = _vm(item, index)
    if _os(item) != 'Windows':
        return _na('VM is not Windows')
    policy = _policy(index, check_id)
    evidence = _fact(index, 'vm_antimalware_policy', vm_id, policy)
    agent = get(evidence, 'agent', str)
    if agent not in ('MicrosoftDefender', 'MicrosoftAntimalware', 'ThirdParty'):
        raise Unavailable('protection agent applicability ambiguous')
    if get(evidence, 'effectivePolicyComplete', bool) is not True:
        raise Unavailable('effective signature-update guest policy incomplete')
    if agent == 'ThirdParty':
        if get(evidence, 'vendorEvidenceVerified', bool) is not True or not get(evidence, 'vendor', str):
            return unknown('third-party agent vendor evidence unavailable')
    present, operational = get(evidence, 'agentPresent', bool), get(evidence, 'serviceOperational', bool)
    automatic = get(evidence, 'automaticSignatureUpdatesEnabled', bool)
    return result(not present or not operational or not automatic, agent=agent,
                  agent_present=present, service_operational=operational,
                  automatic_signature_updates_enabled=automatic)


def _rdp(check_id, item, index):
    vm_id = _vm(item, index)
    if _os(item) != 'Windows':
        return _na('VM is not Windows')
    policy = _policy(index, check_id)
    assignment = _assignment(item, index, policy)
    if assignment is None:
        return unknown('RDP service guest assignment absent')
    _, resources = _report(item, index, policy, assignment)
    states = []
    for row in resources:
        props = get(row, 'properties', dict)
        if get(props, 'serviceName', str) == 'TermService':
            states.append((get(props, 'state', str), row))
    if len(states) != 1 or states[0][0] not in ('Disabled', 'Enabled'):
        return unknown('TermService state missing, ambiguous or unrecognized')
    state, service_report = states[0]
    if state == 'Disabled':
        if _status(service_report) != 'Compliant':
            return unknown('TermService disabled state conflicts with guest compliance result')
        return result(False, term_service='Disabled')
    exceptions = _inventory(index, 'vm_rdp_exception')
    for envelope in get(index, 'collections', dict)['vm_rdp_exception']:
        _observed(envelope, index, policy)
    approvals = []
    for row in exceptions:
        if _arm(get(row, 'vm_id', str), _scope(index), 'vm') == vm_id:
            approvals.append(row)
    if len(approvals) > 1:
        return unknown('RDP exception register ambiguous')
    if not approvals:
        return result(True, reason='enabled TermService has no approval in complete exception register')
    approval = approvals[0]
    _observed(approval, index, policy)
    if not get(approval, 'approved', bool):
        return result(True, reason='enabled TermService exception explicitly unapproved')
    if not get(approval, 'officer', str):
        raise Unavailable('approving officer evidence absent')
    now = _time(get(index, 'context.created_at', str))
    start, end = _time(get(approval, 'valid_from', str)), _time(get(approval, 'valid_until', str))
    if not start <= now < end:
        return unknown('RDP exception is not current')
    logs = _fact(index, 'vm_remote_access_monitoring', vm_id, policy)
    enabled = get(logs, 'routingEnabled', bool)
    monitored = get(logs, 'monitoredAlerts', bool)
    if not enabled or not monitored:
        return result(True, reason='approved enabled RDP lacks required logging or monitored alerts')
    if not {'rdp-sign-in', 'rdp-session'} <= _strings(get(logs, 'eventCategories', list)):
        return unknown('required RDP log categories not completely evidenced')
    return result(False, term_service='Enabled', approval_officer=approval['officer'], monitored_remote_access_logs=True)


def _updates(check_id, item, index):
    vm_id = _vm(item, index)
    policy = _policy(index, check_id)
    def same_update_capture(row):
        # Opaque scan-local IDs bind current evidence; they are not guest state
        # or PCI applicability. Legacy captures without IDs retain old semantics.
        metadata = get(index, 'context.metadata', dict)
        proof = optional(row, '_provenance', {}, dict)
        if not isinstance(proof, dict):
            raise Unavailable('update source provenance malformed')
        for field in ('credential_context_id', 'customer_context_id'):
            if field in metadata or field in proof:
                expected = get(metadata, field, str)
                if not expected or get(proof, field, str) != expected:
                    raise Unavailable('update source capture differs')
    same_update_capture(item)
    if 'instanceView' in item:
        if get(item, '_coverage.instanceView.status', str) != 'collected':
            raise Unavailable('native VM instance view incomplete')
        summary = get(item, 'instanceView.patchStatus.availablePatchSummary', dict)
    else:
        summary = get(item, 'properties.instanceView.patchStatus.availablePatchSummary', dict)
    if get(summary, 'status', str) != 'Succeeded':
        return unknown('patch assessment did not succeed')
    _fresh(get(summary, 'lastModifiedTime', str), index, policy)
    count = get(summary, 'criticalAndSecurityPatchCount', int)
    if count < 0:
        raise Unavailable('negative patch count')
    if count > 0:
        return result(True, critical_and_security_patch_count=count)
    pci = get(policy, 'requirePciCompliance', bool)
    require_installation = optional(policy, 'requireActualInstallation', False, bool)
    if type(require_installation) is not bool:
        raise Unavailable('actual installation policy malformed')
    pci_details = {}
    if pci:
        record = _fact(index, 'vm_patch_installation_compliance', vm_id, policy)
        same_update_capture(record)
        operation_id = get(record, 'operationId', str)
        if not operation_id:
            raise Unavailable('patch installation operation identity absent')
        installed_at = get(record, 'installedAt', str)
        _fresh(installed_at, index, policy)
        patch = (get(item, 'instanceView.patchStatus', dict) if 'instanceView' in item
                 else get(item, 'properties.instanceView.patchStatus', dict))
        installation = get(patch, 'lastPatchInstallationSummary', dict)
        if get(installation, 'status', str) != 'Succeeded':
            return unknown('latest native patch installation did not succeed')
        latest_operation = get(installation, 'installationActivityId', str)
        if not latest_operation or operation_id != latest_operation:
            return unknown('PCI compliance record does not match latest native patch installation')
        started_at = get(installation, 'lastModifiedTime', str)
        _fresh(started_at, index, policy)
        if not _time(started_at) <= _time(installed_at) < _time(get(summary, 'lastModifiedTime', str)):
            return unknown('post-installation PCI assessment chronology unproven')
        status = get(record, 'status', str)
        if status not in ('COMPLIANT', 'NON_COMPLIANT'):
            return unknown('post-installation PCI compliance not measured')
        pci_details = {'post_installation_status': status, 'operation_id': operation_id}
        if status == 'NON_COMPLIANT':
            return result(True, critical_and_security_patch_count=count, **pci_details)
    if require_installation:
        try:
            installation_result = _fact(index, 'vm_patch_installation_result', vm_id, policy)
        except Unavailable:
            return unknown('completed Update Manager installation result unavailable')
        same_update_capture(installation_result)
        verdict = evaluate_vm_patch_installation(
            item, observed_at=get(index, 'context.created_at', str),
            max_age_seconds=get(policy, 'maxReportAgeSeconds', int),
            installation_result=installation_result)
        if verdict['state'] == 'UNKNOWN':
            return unknown(verdict['reason'])
        if verdict['state'] == 'FAIL':
            return result(True, reason=verdict['reason'], **verdict['proof'])
        return result(False, critical_and_security_patch_count=count,
                      require_pci_compliance=pci, **pci_details,
                      native_installation=verdict['proof'])
    return result(False, critical_and_security_patch_count=count,
                  require_pci_compliance=pci, **pci_details)


def _nullable(properties, key):
    if key in properties or key in properties.get('_coverage', {}):
        value = get(properties, key)
    elif properties.get('_provenance', {}).get('representation') == 'full':
        value = None
    else:
        raise Unavailable('association absence not measured: ' + key)
    if value is not None and not isinstance(value, dict):
        raise Unavailable('malformed association: ' + key)
    return value


def _join(rows, rid, index, kind):
    target = _arm(rid, _scope(index), kind)
    matches = [row for row in rows if get(row, 'id', str).casefold() == target]
    if len(matches) != 1:
        raise Unavailable('unresolved or ambiguous ARM join: ' + kind)
    return matches[0]


def _network_paths(item, index):
    vm_id = get(item, 'id', str).casefold()
    refs = list_of_objects(get(item, 'properties.networkProfile.networkInterfaces', list))
    if not refs:
        raise Unavailable('VM NIC associations absent')
    nics, subnets, nsgs = _inventory(index, 'nic'), _inventory(index, 'subnet'), _inventory(index, 'nsg')
    paths, seen = [], set()
    for ref in refs:
        nic = _join(nics, get(ref, 'id', str), index, 'nic')
        nic_id = get(nic, 'id', str).casefold()
        if nic_id in seen or get(nic, 'properties.virtualMachine.id', str).casefold() != vm_id:
            raise Unavailable('duplicate NIC or NIC/VM reverse join mismatch')
        seen.add(nic_id)
        configurations = list_of_objects(get(nic, 'properties.ipConfigurations', list))
        if not configurations:
            raise Unavailable('NIC IP configurations unavailable')
        config_seen = set()
        for config in configurations:
            cid = get(config, 'id', str).casefold()
            if not cid.startswith(nic_id + '/ipconfigurations/') or not cid[len(nic_id + '/ipconfigurations/'):] or '/' in cid[len(nic_id + '/ipconfigurations/'):] or cid in config_seen:
                raise Unavailable('IP configuration identity malformed or duplicate')
            config_seen.add(cid)
            subnet = _join(subnets, get(config, 'properties.subnet.id', str), index, 'subnet')
            associated = []
            for parent in (nic, subnet):
                link = _nullable(get(parent, 'properties', dict), 'networkSecurityGroup')
                if link is not None:
                    associated.append(_join(nsgs, get(link, 'id', str), index, 'nsg'))
            paths.append((nic, config, associated))
    return paths


def _public_nics(paths, index):
    pips = _inventory(index, 'public_ip')
    lbs = _inventory(index, 'load_balancer')
    facing = set()
    config_map = {get(config, 'id', str).casefold(): get(nic, 'id', str).casefold() for nic, config, _ in paths}
    def public(ref):
        if ref is None:
            return False
        pip = _join(pips, get(ref, 'id', str), index, 'public_ip')
        address = get(pip, 'properties.ipAddress', str)
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise Unavailable('public IP allocation unavailable') from exc
        if not ip.is_global:
            raise Unavailable('public-IP allocation is not an Internet address')
        return True
    for nic, config, _ in paths:
        if public(_nullable(get(config, 'properties', dict), 'publicIPAddress')):
            facing.add(get(config, 'id', str).casefold())
    for lb in lbs:
        props = get(lb, 'properties', dict)
        frontends = list_of_objects(get(props, 'frontendIPConfigurations', list))
        public_frontends = set()
        for front in frontends:
            if public(_nullable(get(front, 'properties', dict), 'publicIPAddress')):
                public_frontends.add(get(front, 'id', str).casefold())
        if not public_frontends:
            continue
        pools = list_of_objects(get(props, 'backendAddressPools', list))
        pool_map = {}
        for pool in pools:
            pool_id = get(pool, 'id', str).casefold()
            if pool_id in pool_map:
                raise Unavailable('duplicate LB backend pool')
            pprops = get(pool, 'properties', dict)
            # IP-based backends require both VNet identity and exact private IP.
            addresses = list_of_objects(get(pprops, 'loadBalancerBackendAddresses', list))
            members = [get(ref, 'id', str).casefold() for ref in list_of_objects(get(pprops, 'backendIPConfigurations', list))]
            for address in addresses:
                ap = get(address, 'properties', dict)
                vnet = _arm(get(ap, 'virtualNetwork.id', str), _scope(index))
                if not re.fullmatch(re.escape(_scope(index)) + r'/resourcegroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+', vnet, re.I):
                    raise Unavailable('IP-based LB backend VNet identity malformed')
                try:
                    ip = ipaddress.ip_address(get(ap, 'ipAddress', str))
                except ValueError as exc:
                    raise Unavailable('IP-based LB backend address malformed') from exc
                joined = [get(config, 'id', str).casefold() for _, config, _ in paths
                          if get(config, 'properties.subnet.id', str).casefold().rsplit('/subnets/', 1)[0] == vnet
                          and ipaddress.ip_address(get(config, 'properties.privateIPAddress', str)) == ip]
                if len(joined) > 1:
                    raise Unavailable('IP-based LB backend VM join ambiguous')
                members.extend(joined)
            pool_map[pool_id] = members
        rules = list_of_objects(get(props, 'loadBalancingRules', list))
        for rule in rules:
            rp = get(rule, 'properties', dict)
            front_id = get(rp, 'frontendIPConfiguration.id', str).casefold()
            if front_id not in {get(front, 'id', str).casefold() for front in frontends}:
                raise Unavailable('LB frontend unresolved')
            if front_id not in public_frontends:
                continue
            pool_id = get(rp, 'backendAddressPool.id', str).casefold()
            if pool_id not in pool_map:
                raise Unavailable('LB backend pool unresolved')
            for cid in pool_map[pool_id]:
                if cid in config_map:
                    facing.add(cid)
        for rule in list_of_objects(get(props, 'inboundNatRules', list)):
            rp = get(rule, 'properties', dict)
            if get(rp, 'frontendIPConfiguration.id', str).casefold() not in public_frontends:
                continue
            backend = _nullable(rp, 'backendIPConfiguration')
            if backend is None:
                raise Unavailable('LB NAT backend association unavailable')
            cid = get(backend, 'id', str).casefold()
            if cid in config_map:
                facing.add(cid)
        if get(props, 'inboundNatPools', list):
            raise Unavailable('LB NAT pool VM join unavailable')
    return facing


def _nsg_attached(check_id, item, index):
    _vm(item, index)
    paths = _network_paths(item, index)
    facing = _public_nics(paths, index)
    if not facing:
        return _na('complete direct-public-IP and load-balancer inventory proves no Internet-facing NIC')
    unprotected = []
    for nic, config, associated in paths:
        if get(config, 'id', str).casefold() in facing and not associated:
            unprotected.append(get(config, 'id', str))
    return result(bool(unprotected), internet_facing_ip_configurations=sorted(facing), unprotected_ip_configurations=unprotected)


def _ranges(properties, singular, plural, *, ports=False, tags=None, version=None):
    values = []
    if singular in properties or singular in properties.get('_coverage', {}):
        value = get(properties, singular, str)
        if value:
            values.append(value)
    if plural in properties or plural in properties.get('_coverage', {}):
        array = get(properties, plural, list)
        if any(not isinstance(v, str) or not v for v in array):
            raise Unavailable('malformed rule ranges')
        if values and array:
            raise Unavailable('ambiguous singular/plural rule range')
        values.extend(array)
    if not values:
        raise Unavailable('rule range unavailable')
    intervals = []
    for value in values:
        if ports:
            if value == '*':
                intervals.append((0, 65535))
                continue
            match = re.fullmatch(r'(\d{1,5})(?:-(\d{1,5}))?', value)
            if not match:
                raise Unavailable('malformed rule port range')
            lo, hi = int(match[1]), int(match[2] or match[1])
            if not 0 <= lo <= hi <= 65535:
                raise Unavailable('rule port out of range')
            intervals.append((lo, hi))
        else:
            if value in ('*', 'Any'):
                intervals.append((0, 2 ** (32 if version == 4 else 128) - 1))
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
                if network.version == version:
                    intervals.append((int(network.network_address), int(network.broadcast_address)))
            except ValueError:
                if tags is None or value not in tags:
                    raise Unavailable('unresolved NSG service tag or ASG: ' + value)
                tag = _map_value(tags, value)
                if get(tag, 'status', str) != 'collected':
                    raise Unavailable('service tag range inventory incomplete')
                prefixes = get(tag, 'prefixes', list)
                if not prefixes:
                    raise Unavailable('resolved service tag ranges absent')
                for prefix in prefixes:
                    try:
                        network = ipaddress.ip_network(prefix, strict=False)
                    except (ValueError, TypeError) as exc:
                        raise Unavailable('service tag prefix malformed') from exc
                    if network.version == version:
                        intervals.append((int(network.network_address), int(network.broadcast_address)))
    return intervals, any(value in ('*', 'Any', 'Internet') or value == ('0.0.0.0/0' if version == 4 else '::/0') for value in values)


def _subtract(box, blocker):
    overlap = tuple((max(a[0], b[0]), min(a[1], b[1])) for a, b in zip(box, blocker))
    if any(lo > hi for lo, hi in overlap):
        return [box]
    residual, core = [], list(box)
    for dimension, (lo, hi) in enumerate(overlap):
        if core[dimension][0] < lo:
            part = list(core)
            part[dimension] = (core[dimension][0], lo - 1)
            residual.append(tuple(part))
        if hi < core[dimension][1]:
            part = list(core)
            part[dimension] = (hi + 1, core[dimension][1])
            residual.append(tuple(part))
        core[dimension] = (lo, hi)
    return residual


def _permissive_nsg(nsg, destination):
    props = get(nsg, 'properties', dict)
    rules = list_of_objects(get(props, 'securityRules', list)) + list_of_objects(get(props, 'defaultSecurityRules', list))
    if not rules:
        raise Unavailable('NSG rule inventory absent')
    tags = get(props, 'resolvedServiceTags', dict) if 'resolvedServiceTags' in props else {}
    parsed, priorities = [], set()
    for row in rules:
        rp = get(row, 'properties', dict)
        direction = get(rp, 'direction', str)
        if direction not in ('Inbound', 'Outbound'):
            raise Unavailable('NSG direction unrecognized')
        if direction == 'Outbound':
            continue
        priority = get(rp, 'priority', int)
        if priority in priorities or not 100 <= priority <= 65535:
            raise Unavailable('NSG priority missing, duplicate or malformed')
        priorities.add(priority)
        access = get(rp, 'access', str)
        protocol = get(rp, 'protocol', str).casefold()
        if access not in ('Allow', 'Deny') or protocol not in ('*', 'tcp', 'udp', 'icmp', 'ah', 'esp'):
            raise Unavailable('NSG access or protocol unrecognized')
        for key in ('sourceApplicationSecurityGroups', 'destinationApplicationSecurityGroups'):
            if key in rp and get(rp, key, list):
                raise Unavailable('NSG ASG membership unresolved')
        sources, public = _ranges(rp, 'sourceAddressPrefix', 'sourceAddressPrefixes', tags=tags, version=destination.version)
        destinations, _ = _ranges(rp, 'destinationAddressPrefix', 'destinationAddressPrefixes', tags=tags, version=destination.version)
        source_ports, _ = _ranges(rp, 'sourcePortRange', 'sourcePortRanges', ports=True)
        dest_ports, _ = _ranges(rp, 'destinationPortRange', 'destinationPortRanges', ports=True)
        if not any(lo <= int(destination) <= hi for lo, hi in destinations):
            continue
        protocols = range(5) if protocol == '*' else [('tcp', 'udp', 'icmp', 'ah', 'esp').index(protocol)]
        boxes = [tuple(parts) for parts in itertools.product(sources, source_ports, dest_ports, [(p, p) for p in protocols])]
        parsed.append((priority, access, public, boxes))
    if not priorities:
        raise Unavailable('NSG inbound rule inventory absent')
    previous = []
    for priority, access, public, boxes in sorted(parsed):
        if access == 'Allow' and public:
            residual = list(boxes)
            for blocker in previous:
                residual = [part for box in residual for part in _subtract(box, blocker)]
                if len(residual) > 20000:
                    raise Unavailable('NSG effective-rule partition too complex')
                if not residual:
                    break
            if residual:
                return priority
        previous.extend(boxes)
    return None


def _public_rules(check_id, item, index):
    _vm(item, index)
    paths = _network_paths(item, index)
    bad, unresolved, unprotected = [], [], []
    for nic, config, associated in paths:
        if not associated:
            unprotected.append(get(config, 'id', str))
        try:
            destination = ipaddress.ip_address(get(config, 'properties.privateIPAddress', str))
        except ValueError as exc:
            raise Unavailable('NIC private IP missing or malformed') from exc
        for nsg in associated:
            try:
                priority = _permissive_nsg(nsg, destination)
                if priority is not None:
                    bad.append({'nsg_id': get(nsg, 'id', str), 'priority': priority, 'ip_configuration': config['id']})
            except Unavailable:
                unresolved.append(get(nsg, 'id', str))
    if bad:
        return result(True, permissive_associated_nsgs=bad)
    if unresolved or unprotected:
        return unknown('NSG rules unresolved or path has no NSG', unresolved_nsgs=sorted(set(unresolved)), unprotected_paths=unprotected)
    return result(False, evaluated_ip_configurations=len(paths))


GUEST_SUFFIXES = {
    'administrators_group_with_extra_accounts_windows',
    'administrators_group_with_no_specified_members_windows',
    'administrators_group_with_specified_members_windows',
    'meet_firewall_properties_windows', 'password_file_permissions_0644_linux',
    'with_no_specified_certificates_in_trusted_root_windows',
}
DEFENDER_SUFFIXES = {
    'adaptive_application_controls_enabled', 'adaptive_network_hardening_recommendation_applied',
    'container_security_configurations_vulnerabilities_remediated', 'vulnerability_findings_resolved_for_sql_server',
}
EVALUATORS = {}
REGISTERED_CHECKS = {}
DEPENDENCIES = {}
for _identifier, _spec in SPECS.items():
    _suffix = _identifier.removeprefix(PREFIX)
    if _suffix in GUEST_SUFFIXES:
        _function, _deps = _guest, ['vm', 'guest_configuration_report']
    elif _suffix in DEFENDER_SUFFIXES:
        _function, _deps = _defender, ['vm', 'security_assessment']
        if _suffix == 'vulnerability_findings_resolved_for_sql_server':
            _deps += ['sql_vm', 'security_subassessment']
        else:
            _deps += ['vm_compliance_applicability']
            if _suffix == 'adaptive_application_controls_enabled':
                _deps += ['application_allowlist_attestation']
            elif _suffix == 'adaptive_network_hardening_recommendation_applied':
                _deps += ['adaptive_network_hardening', 'adaptive_network_hardening_native', 'nic', 'subnet', 'nsg']
    elif _suffix == 'malware_agent_automatic_upgrade_enabled':
        _function, _deps = _malware, ['vm', 'vm_antimalware_policy']
    elif _suffix == 'rdp_service_disabled':
        _function, _deps = _rdp, ['vm', 'guest_configuration_report', 'vm_rdp_exception', 'vm_remote_access_monitoring']
    elif _suffix == 'system_updates_installed':
        _function, _deps = _updates, ['vm', 'vm_patch_installation_compliance', 'vm_patch_installation_result']
    elif _suffix == 'tcp_udp_access_restricted_internet':
        _function, _deps = _nsg_attached, ['vm', 'nic', 'subnet', 'nsg', 'public_ip', 'load_balancer']
    else:
        _function, _deps = _public_rules, ['vm', 'nic', 'subnet', 'nsg']
    DEPENDENCIES[_identifier] = tuple(_deps)
    # The legacy register validator accepts only five categories. Preserve the
    # signed category on this module's own immutable Check, as wave 1 does.
    _category = _spec['category'] if _spec['category'] in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'
    @register(_identifier, _spec['provider'], _category, _spec['resource_kind'],
              _spec['title'], _spec['severity'], 'CM-6', _spec['remediation_hint'], dependencies=_deps)
    def _evaluate(item, index, check_id=_identifier, evaluator=_function):
        return evaluator(check_id, item, index)
    _check = CHECKS[-1]
    if _check.id != _identifier:
        raise RuntimeError('unexpected registration order')
    if _category != _spec['category']:
        _check = replace(_check, category=_spec['category'])
        CHECKS[-1] = _check
    REGISTERED_CHECKS[_identifier] = _check
    EVALUATORS[_identifier] = _check.evaluate
