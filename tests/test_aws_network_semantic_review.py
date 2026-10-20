"""Offline network review and SDK-to-native regressions; no cloud connections.

Rebuild the compact ledger: .venv/bin/python -m tests.test_aws_network_semantic_review --write-report
Run this file with pytest for the separate execution receipt. Synthetic predicate
witnesses are explicitly separate from SDK -> real collector projection proofs.
"""
from collections import Counter
from copy import deepcopy
from functools import lru_cache
import hashlib
import inspect
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

import pytest

from scripts import audit_aws_native_contracts as native
from scripts import audit_aws_field_producers as fields
from tests.test_peaso_collectors_aws import sdk, IDENTITY, ACCOUNT, REGION

ROOT = Path(__file__).resolve().parents[1]
KINDS = {'security_group', 'network_acl', 'route_table', 'subnet', 'network_interface', 'vpc'}
LEDGER = ROOT / 'docs/aws-review/network-semantic-review.json'


@lru_cache(maxsize=1)
def cohort():
    active = native.active_ids()
    return tuple(c for c in native.registry() if c.id in active and c.kind in KINDS)


@lru_cache(maxsize=1)
def cases():
    return native.behavior_module().CASES


def state_index(case, state):
    return deepcopy(case.get(state + '_index', case.get('case_indices', {}).get(state, case.get('index', {}))))


# These are reviewed semantic boundaries, beyond the presence of a field. The
# exact per-ID port/service/boolean closure is recorded separately below.
NOTES = {
    '_sg_port_check': 'Prowler-style in-use ENI/VPC gate; TCP (name or 6) requested ports, either exact world family; no routing/listener claim.',
    '_turbot_check': 'Pinned SQL-style exact world CIDRs and listed port overlap, without protocol filter except explicit protocols variant (native names/numbers normalized); SSH IPv4 has its own TCP/6 validator.',
    '_nacl_prowler': 'Ordered ingress only, IPv4 and IPv6 independently; exact world CIDRs, first matching allow/deny; intentionally no SG applicability gate. Narrower CIDRs are outside this declaration question.',
    '_endpoint_check': 'Exact com.amazonaws.<region>.<service> presence in same VPC; endpoint state/type are intentionally outside the admitted literal criterion.',
    'sg_all_ports': 'In-use SG; world all-protocol or full 0..65535 interval. This does not require all protocols when a full TCP/UDP interval exists.',
    'sg_any_port': 'World declared ingress on in-use SG; all attached interfaces must be API Gateway/VPC endpoint types or amazon-elb owned.',
    'sg_any_port_from_ip': 'Specific globally routable CIDR, excluding rules with only world CIDRs; in-use SG; no end-to-end path model.',
    'sg_high_risk': 'In-use SG; TCP named/6 against explicit high-risk list; exact world source, ingress only.',
    'sg_wide_open': 'In-use SG; ingress plus egress global IPv4 with 0<prefix<24; /0 intentionally excluded.',
    'default_sg_prowler': 'Only default in-use groups; fail if any ingress or egress IpPermission entry exists.',
    'default_sg': 'Only default groups; any ingress or egress entry fails, including unused groups.',
    'sg_launch_wizard_name': 'Substring launch-wizard in GroupName; no usage or packet inference.',
    'sg_not_used': 'Non-default SG referenced by ENI, Lambda VpcConfig, Batch computeResources or another SG ingress pair passes; complete absence fails.',
    'sg_many_rules': 'Counts IpPermission entries per direction, not expanded CIDR/quota-weighted rules; threshold 50.',
    'sg_authorized_ports': 'IPv4 world port-only criterion: each range must be exactly 80 or 443; protocol intentionally not constrained by current catalog, despite legacy module note saying TCP.',
    'sg_associated_eni': 'GroupId join to complete ENI Groups; observed attachment passes.',
    'sg_unused_compliance': 'GroupId ENI or instance SecurityGroups join; observed use passes, complete absence fails.',
    'sg_launch_wizard_attached': 'Launch-wizard prefix gate; joins ENI GroupName rather than GroupId, matching pinned SQL.',
    'nacl_unused': 'Association list cardinality; no subnet configuration or traffic inference.',
    'nacl_unused_prowler': 'Default ACL is N/A; non-default requires a SubnetId association.',
    'nacl_remote_admin': 'Validated native entries; individual ingress world allow entries for TCP/UDP 22 or 3389 or -1 without PortRange; ignores rule precedence intentionally, unlike ordered Prowler variants.',
    'vpc_flow_logs': 'Owned VPC only; at least one matching ResourceId and every declared status ACTIVE. Foreign-owner VPC N/A.',
    'vpc_flow_logs_prowler': 'ENI-use gate; any flow-log ResourceId match passes regardless of log status.',
    'vpc_not_in_use': 'Any subnet with matching VpcId passes; no workload-use inference.',
    'vpc_multi_az': 'At least two distinct subnet AvailabilityZone strings in VPC; not workload redundancy.',
    'vpc_multi_az_prowler': 'Same subnet AZ count with ENI-use applicability gate.',
    'vpc_public_private': 'Explicit subnet route table, else VPC main; literal IPv4 default IGW OR NAT classed public, ignoring route State; needs both classes. NAT here is pinned SQL vocabulary, not inbound reachability.',
    'vpc_public_private_prowler': 'ENI-use gate; explicit subnet association else unique VPC main, IPv4 default IGW only; needs both flags; route State not modeled.',
    'subnet_auto_public': 'MapPublicIpOnLaunch boolean; IPv4 default allocation only, no existing interfaces or IPv6 question.',
    'subnet_auto_public_prowler': 'Same boolean under subnet ENI-use gate.',
    'rtb_igw': 'Typed optional native DestinationCidrBlock default and GatewayId prefix igw; denied coverage honored and definite bad row survives unrelated unavailable siblings. Does not read DestinationIpv6CidrBlock or route State. Current catalog explicitly limits to IPv4.',
    'vpc_ec2_endpoint_prowler': 'ENI-use gate; endpoint service name contains ec2, with no type/state test; literal upstream presence semantics.',
    'nfw_all_vpc': 'ENI-use gate; same-VPC firewall presence; no route traversal or effective inspection claim.',
    'eni_sdc': 'SourceDestCheck boolean on explicit interface-type allowlist; other types N/A.',
    'eni_public': 'Association.PublicIp optional native omission means no public IPv4 association when NetworkInterfaceId proves a row; no reachability or IPv6 claim.',
    'eni_unused': 'Native finite Status enum required; FAIL when available and optional Attachment.InstanceId absent; managed in-use ENIs need not have an instance ID.',
    'aws_ingress': 'Validated CIDR-only world ingress declaration, any recognized protocol; observed bad declaration survives malformed sibling ranges, otherwise unresolved is UNKNOWN.',
    'sg_common_ports': 'IPv4/IPv6 exact-world, COMMON20 literal port overlap via _turbot; no protocol or route filter.',
    'br_vpc_endpoints': 'ENI-use and regional Bedrock-activity gate; requires five available service-suffix endpoints; endpoint interface type not independently checked.',
    'dhcp': 'Vpc.DhcpOptionsId exact join to complete native DHCP inventory; exactly one domain-name-servers option whose value set equals AmazonProvidedDNS; partial join cannot PASS.',
    '_security_group': 'Scoped complete SG inventory; validated IPv6 world CIDR and TCP/name/6 ports for SSH/common variants, TCP/UDP/name/numeric or -1 for protocol variant; no IPv4/route inference.',
}

# Dict.get/optional derived joins are recorded explicitly in addition to the
# instrumented native accessor paths. These are source-reviewed, not all tested.
MANUAL_PATHS = {
    'security_group': ['GroupId', 'GroupName', 'VpcId', 'IpPermissions[].IpProtocol', 'IpPermissions[].FromPort', 'IpPermissions[].ToPort', 'IpPermissions[].IpRanges[].CidrIp', 'IpPermissions[].Ipv6Ranges[].CidrIpv6', 'IpPermissions[].UserIdGroupPairs[].GroupId', 'IpPermissionsEgress[].IpRanges[].CidrIp'],
    'network_acl': ['NetworkAclId', 'IsDefault', 'Associations[].SubnetId', 'Entries[].RuleNumber', 'Entries[].Egress', 'Entries[].RuleAction', 'Entries[].Protocol', 'Entries[].CidrBlock', 'Entries[].Ipv6CidrBlock', 'Entries[].PortRange.From', 'Entries[].PortRange.To', 'Entries[].IcmpTypeCode.Type', 'Entries[].IcmpTypeCode.Code'],
    'route_table': ['RouteTableId', 'VpcId', 'Associations[].Main', 'Associations[].SubnetId', 'Routes[].DestinationCidrBlock', 'Routes[].DestinationIpv6CidrBlock', 'Routes[].GatewayId', 'Routes[].NatGatewayId'],
    'subnet': ['SubnetId', 'VpcId', 'AvailabilityZone', 'MapPublicIpOnLaunch'],
    'network_interface': ['NetworkInterfaceId', 'VpcId', 'SubnetId', 'Groups[].GroupId', 'Groups[].GroupName', 'InterfaceType', 'SourceDestCheck', 'Association.PublicIp', 'Attachment.InstanceId', 'Attachment.InstanceOwnerId', 'Status'],
    'vpc': ['VpcId', 'OwnerId', 'DhcpOptionsId'],
}


def semantic_target(check):
    fn = inspect.unwrap(check.evaluate)
    if check.id.startswith('aws_security_group_'):
        from peaso.checks.batch_remaining_aws import _security_group
        return _security_group, '_security_group', {}
    if check.id == 'aws_vpc_uses_amazonprovided_dns':
        from peaso.checks.post_dfaf_aws import dhcp
        return dhcp, 'dhcp', {}
    name = fn.__qualname__.split('.')[0]
    parameters = inspect.getclosurevars(fn).nonlocals
    closed = {k: v for k, v in parameters.items() if isinstance(v, (str, int, bool, list, tuple, dict))}
    return fn, name, closed


def review_graph(check):
    from peaso.checks import claude_aws_a_common as common
    target, family, parameters = semantic_target(check)
    graph = fields.callback_graph(check)
    for fn in [target, *([common._validate_nacl_rule] if family == 'nacl_remote_admin' else []),
               *([common._sg_protocol] if family == '_turbot_check' and 'protocols' in parameters.get('kw', {}) else [])]:
        if fn not in graph:
            graph.append(fn)
    return graph


def cached_sql_sources():
    """Read only bounded cached PP files, verifying their pinned Git blobs."""
    from scripts.peaso_review_catalog import blocks
    cache = Path('/tmp/peasso-aws-review-20261019/steampipe')
    found = {}
    for repo, paths in {'compliance': ['conformance_pack/vpc.pp', 'conformance_pack/ec2.pp', 'conformance_pack/networkfirewall.pp'],
                        'perimeter': ['perimeter/network_access.pp']}.items():
        tree_file, head_file = cache / (repo + '-tree.json'), cache / (repo + '-head.json')
        if not tree_file.exists() or not head_file.exists():
            continue
        tree, head = json.loads(tree_file.read_text()), json.loads(head_file.read_text())
        assert head['commit']['tree']['sha'] == tree['sha']
        entries = {e['path']: e for e in tree['tree']}
        for path in paths:
            candidate = cache / ('steampipe-mod-aws-' + repo) / path
            if not candidate.exists():
                continue
            data = candidate.read_bytes()
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            assert blob == entries[path]['sha']
            for typ, name, body, line in blocks(data.decode()):
                if typ == 'query':
                    found['aws-' + repo + '.control.' + name] = {'repository': 'turbot/steampipe-mod-aws-' + repo,
                        'revision': head['sha'], 'file': path, 'line': line, 'git_blob': blob,
                        'query_body_sha256': hashlib.sha256(body.encode()).hexdigest(),
                        'review': 'pinned-body-located; grouped literal-query semantics reviewed, exhaustive SQL/Python equivalence unproved'}
    return found


def build_review():
    import botocore
    from peaso.collectors import aws
    from peaso.checks.claude_aws_a_common import NOTES as SOURCE_NOTES, ROWS
    models = fields.Models()
    catalog = {r['id']: r for r in json.loads((ROOT / 'peaso/rulepacks/native_catalog.json').read_text())['checks']}
    contracts, producers, rows = {}, {}, []
    cached_sql = cached_sql_sources()
    for kind in sorted(KINDS):
        producer, shape = fields.producer(kind, models)
        producer['projection_source'] = native.source_ref(aws._enrich)
        producer['reviewed_paths'] = {p: fields.shape_at(shape, p).name for p in MANUAL_PATHS[kind] if fields.shape_at(shape, p) is not None}
        producer['projection_statement'] = 'SPECS pages -> _enrich deepcopy with no matching kind mutation -> append/_safe; no FETCHER or extension ENRICHER for this kind.'
        producer['runtime_proof'] = 'test_sdk_network_kind_projection_and_consumer[' + kind + ']; possible SDK responses, not a completeness guarantee'
        producer['sdk_optional_boundary'] = 'Botocore optional members are possible, not guaranteed present; missing typed predicate facts remain UNKNOWN unless a documented omission branch applies.'
        producers[kind] = producer
    for check in cohort():
        target, family, parameters = semantic_target(check)
        assert family in NOTES, (check.id, family)
        graph = review_graph(check)
        refs = [native.source_ref(fn) for fn in graph]
        keys = []
        for ref in refs:
            key = ref['file'] + ':' + ref['qualname'] + ':' + ref['sha256'][:16]
            contracts[key] = ref
            keys.append(key)
        reads, outcomes = fields.fixture_reads(check, cases()[check.id])
        path_rows = []
        for read in reads:
            record = dict(read)
            kind = read['kind']
            if kind in KINDS:
                spec = aws.SPECS[kind]
                shape = fields.shape_at(models.output(spec[0], spec[1]), spec[2])
                record['sdk_member'] = fields.shape_at(shape, read['path']) is not None
                record['proof'] = 'raw-native-projection' if record['sdk_member'] else 'unresolved-path-not-a-proven-gap'
            else:
                record['proof'] = 'engine-metadata' if kind == '@engine' else 'cross-kind-witness-only; producer semantics outside six-kind proof'
            path_rows.append(record)
        static = fields.static_reads([target])
        findings = []
        if family in {'_sg_port_check', 'sg_all_ports', 'sg_any_port', 'sg_any_port_from_ip', 'sg_high_risk'}:
            findings.append('SG-native-protocol-and-range')
        if family == '_nacl_prowler':
            findings.append('NACL-malformed-range-action-protocol')
        if family == 'nacl_remote_admin':
            findings.append('NACL-remote-admin-malformed')
        if family == '_turbot_check' and 'protocols' in parameters.get('kw', {}):
            findings.append('SG-literal-protocol-numeric')
        if family == 'eni_unused':
            findings.append('ENI-status-enum')
        if family == 'rtb_igw':
            findings.append('RTB-optional-target-types-coverage')
        row = {'id': check.id, 'kind': check.kind, 'target': check.target, 'dependencies': list(check.dependencies),
               'status': 'source-and-field-reviewed; bounded-runtime-witnesses', 'callback': native.source_ref(inspect.unwrap(check.evaluate)),
               'predicate': native.source_ref(target), 'source_contracts': keys, 'family': family, 'parameters': closed_json(parameters),
               'meaning': catalog[check.id]['description'], 'source_review': NOTES[family],
               'pinned_local_note': SOURCE_NOTES.get(check.id), 'upstream_rows': ROWS.get(check.id, []),
               'pinned_sql_bodies': [cached_sql[r] for r in ROWS.get(check.id, []) if r in cached_sql],
               'findings': findings,
               'fieldpaths_observed': path_rows, 'direct_source_reads': static, 'witness_outcomes': outcomes,
               'untested': ['Unvisited optional values/branches and all possible joins are not proved by fixture tracing.',
                            'SDK full-shape projection proved by kind; no live account completeness, packet path or listener proof.',
                            'Cross-kind dependency SDK/projection contracts beyond these six kinds are not certified here.'],
               'live_verified': False, 'all_branches_proven': False}
        rows.append(row)
    prowler = json.loads((ROOT / 'docs/aws-review/prowler-parity.json').read_text())
    steampipe = json.loads((ROOT / 'docs/aws-review/steampipe-parity.json').read_text())
    return {'schema_version': 1, 'date': '2026-10-19', 'scope': sorted(KINDS), 'counts': dict(Counter(r['kind'] for r in rows)),
            'botocore_version': botocore.__version__,
            'review_test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'fixture_bundle_sha256': hashlib.sha256((ROOT / 'tests/fixtures/release-test-inputs.json.xz').read_bytes()).hexdigest(),
            'check_count': len(rows), 'checks': rows, 'contracts': contracts, 'producers': producers,
            'kind_source_paths': MANUAL_PATHS,
            'upstream': {'prowler': prowler['upstream'], 'steampipe': steampipe['upstream_sources'],
                         'cached_sql_query_count': len(cached_sql),
                         'review_limit': 'Pinned cached VPC/EC2/NetworkFirewall/perimeter SQL blobs verified against Git trees; grouped declaration/range/direction/join semantics inspected. Prowler network helper Python bodies unavailable locally, so those rows use reviewed local callbacks and pinned metadata associations, not an independently executed upstream model.'},
            'findings': [
                {'id': 'SG-native-protocol-and-range', 'status': 'bounded-fix-implemented', 'detail': 'Prowler helper compared tcp to native numeric 6 and accepted invalid port intervals; normalize documented names/numbers, validate TCP/UDP ranges and independent ICMP type/code, CIDR syntax/family. Root owns metadata materialization.'},
                {'id': 'NACL-malformed-range-action-protocol', 'status': 'bounded-fix-implemented', 'detail': 'Ordered world TCP22 could PASS malformed protocol/action or reversed/out-of-range intervals. Native rule legality now validated before non-match; independent families and ordered semantics preserved.'},
                {'id': 'NACL-remote-admin-malformed', 'status': 'bounded-fix-implemented', 'detail': 'Individual-entry remote-admin callback now validates native entries using the same pure helper; retains intentional lack of rule precedence.'},
                {'id': 'SG-literal-protocol-numeric', 'status': 'bounded-fix-implemented', 'detail': '_turbot protocol-filter variant now normalizes documented numeric6/17; port-only literal variants are intentionally not protocol-filtered.'},
                {'id': 'ENI-status-enum', 'status': 'bounded-fix-implemented', 'detail': 'eni_in_use now requires one of the five documented native Status values before its available/unattached test.'},
                {'id': 'RTB-optional-target-types-coverage', 'status': 'bounded-fix-implemented', 'detail': 'Literal IPv4 route helper now requires RouteTableId and typed optional native fields honoring nested coverage; definite bad rows survive unavailable siblings. Optional native non-IGW targets and IPv4 admitted scope preserved.'},
                {'id': 'SG-optional-range-arrays', 'status': 'conservative-unknown-not-false-pass', 'detail': 'SDK IpPermission range arrays are optional; several helpers require both IpRanges/Ipv6Ranges. Raw collector preserves omission; a valid omitted array can remain UNKNOWN. Live incidence undemonstrated.'},
            ],
            'test_receipt': '/tmp/peasso-aws-review-20261019/native/network-semantic-review.xml',
            'test_execution': receipt_summary(),
            'prior_gate': 'Prior frozen 10,565-pass baseline preserved; no full-suite rerun.', 'live_verified': False}


def closed_json(value):
    return json.loads(json.dumps(value, default=str))


def receipt_summary():
    path = Path('/tmp/peasso-aws-review-20261019/native/network-semantic-review.xml')
    if not path.exists():
        return {'status': 'not-yet-executed'}
    data = path.read_bytes()
    root = ET.fromstring(data)
    suites = list(root.iter('testsuite'))
    return {'status': 'executed', 'sha256': hashlib.sha256(data).hexdigest(),
            **{key: sum(int(s.get(key, 0)) for s in suites) for key in ('tests', 'failures', 'errors', 'skipped')}}


def test_ledger_covers_every_current_active_network_check():
    report = json.loads(LEDGER.read_text())
    assert {r['id'] for r in report['checks']} == {c.id for c in cohort()}
    assert len(report['checks']) == len({r['id'] for r in report['checks']})
    assert not report['live_verified']
    for row in report['checks']:
        assert row['meaning'] and row['source_review'] and row['fieldpaths_observed']
        assert row['source_contracts'] and not row['all_branches_proven']
    # Function-level pins avoid treating unrelated edits elsewhere in a shared
    # collector/check module as reviewed changes to this cohort.
    current = {}
    for check in cohort():
        target, _, _ = semantic_target(check)
        for fn in review_graph(check):
            ref = native.source_ref(fn)
            current[(ref['file'], ref['qualname'])] = ref['sha256']
    for ref in report['contracts'].values():
        assert current[(ref['file'], ref['qualname'])] == ref['sha256']


def test_all_reviewed_kind_paths_are_native_sdk_members():
    from peaso.collectors import aws
    models = fields.Models()
    for kind, paths in MANUAL_PATHS.items():
        service, operation, expression = aws.SPECS[kind]
        shape = fields.shape_at(models.output(service, operation), expression)
        assert kind not in aws.FETCHERS
        if kind == 'vpc':
            from peaso.collectors.aws_network_inventory import vpc_dns_attributes
            assert aws.ENRICHERS[kind] is vpc_dns_attributes
        else:
            assert kind not in aws.ENRICHERS
        assert all(fields.shape_at(shape, path) is not None for path in paths)
    permission = models.session.get_service_model('ec2').shape_for('IpPermission')
    assert 'protocol number' in permission.members['IpProtocol'].documentation
    assert not {'IpRanges', 'Ipv6Ranges'} & set(permission.required_members)


@pytest.mark.parametrize('protocol,low,high', [('icmp', -1, -1), ('1', 8, 0), ('icmpv6', 128, -1), ('58', 128, 0)])
def test_icmp_type_and_code_are_independent_values(protocol, low, high):
    from peaso.checks import claude_aws_a_network as n
    from peaso.checks.claude_aws_a_common import prowler_sg_open
    assert prowler_sg_open(n.world_rule(protocol, low, high), '-1', all_ports=True, any_address=True)
    assert not prowler_sg_open(n.world_rule(protocol, low, high), 'tcp', [22], any_address=True)


@pytest.mark.parametrize('protocol,low,high', [('icmp', -1, 0), ('1', 256, 0), ('icmpv6', 128, -2), ('58', 128, 256)])
def test_malformed_icmp_type_code_never_passes(protocol, low, high):
    from peaso.checks import claude_aws_a_network as n
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.sg_no_world_ssh')
    assert check.evaluate(n.sg_with(n.world_rule(protocol, low, high)), n.idx(**n.IN_USE))[0] == 'UNKNOWN'


@pytest.mark.parametrize('field,value', [('IpRanges', [{'CidrIp': '::/0'}]), ('Ipv6Ranges', [{'CidrIpv6': '0.0.0.0/0'}]), ('IpRanges', [{'CidrIp': 'garbage'}])])
def test_malformed_cidr_and_family_never_passes(field, value):
    from peaso.checks import claude_aws_a_network as n
    row = n.world_rule('6', 443, 443)
    row[field] = value
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.sg_no_world_ssh')
    assert check.evaluate(n.sg_with(row), n.idx(**n.IN_USE))[0] == 'UNKNOWN'


def test_optional_range_array_omission_is_conservative_unknown():
    from peaso.checks import claude_aws_a_network as n
    row = n.world_rule('6', 443, 443)
    del row['Ipv6Ranges']
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.sg_no_world_ssh')
    assert check.evaluate(n.sg_with(row), n.idx(**n.IN_USE))[0] == 'UNKNOWN'


@pytest.mark.parametrize('check', cohort(), ids=lambda c: c.id)
def test_each_predicate_witness_and_unavailable_inputs(check):
    case = cases()[check.id]
    for state, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        if state in case:
            data, index = deepcopy(case[state]), state_index(case, state)
            before = deepcopy((data, index))
            assert check.evaluate(data, index)[0] == expected
            assert (data, index) == before
    for data in [case.get('missing', {}), case.get('malformed'), {'collection_status': 'denied'}]:
        assert check.evaluate(deepcopy(data), state_index(case, 'pass'))[0] == 'UNKNOWN'


@pytest.mark.parametrize('check', cohort(), ids=lambda c: c.id)
@pytest.mark.parametrize('status', ['denied', 'partial', 'not_collected', 'malformed'])
def test_engine_empty_incomplete_subject_never_passes(check, status):
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    snap = make_snapshot('aws', [ACCOUNT + '/' + REGION], [{'type': kind, 'scope': ACCOUNT + '/' + REGION,
                         'service': 'ec2', 'status': status, 'items': []} for kind in {check.kind, *check.dependencies}])
    findings = evaluate_snapshot(snap, checks=[check.id])['findings']
    assert findings and all(f['status'] != 'PASS' for f in findings)


def collect_sdk(sdk, payloads):
    from peaso.collectors import aws
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    ec2 = add('ec2')
    for kind, row in sorted(payloads.items()):
        _, operation, expression = aws.SPECS[kind]
        ec2.add_response(operation, {expression: [row]}, {})
        if kind == 'vpc':
            for attribute, output in [('enableDnsSupport', 'EnableDnsSupport'),
                                      ('enableDnsHostnames', 'EnableDnsHostnames')]:
                ec2.add_response('describe_vpc_attribute',
                                 {'VpcId': row['VpcId'], output: {'Value': True}},
                                 {'VpcId': row['VpcId'], 'Attribute': attribute})
    return aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'options': {'regions': [REGION], 'service_concurrency': 1, 'retry_attempts': 1}}, list(payloads))


@pytest.mark.parametrize('kind', sorted(KINDS))
def test_sdk_network_kind_projection_and_consumer(sdk, kind):
    from peaso.checks import claude_aws_a_network as net
    from peaso.engine import evaluate_snapshot
    examples = {'vpc': (net.VPC, 'aws.claude_a.vpc.vpc_has_subnets'),
                'subnet': (net.SUBNET, 'aws.claude_a.vpc.subnet_no_auto_public_ip'),
                'route_table': (net.RTB_MAIN, 'aws.claude_a.vpc.route_table_no_default_igw_route'),
                'security_group': (net.SG, 'aws.ec2.restrict_internet_ingress'),
                'network_acl': (net.NACL, 'aws.claude_a.vpc.nacl_no_world_tcp_22'),
                'network_interface': (net.ENI, 'aws.claude_a.ec2.eni_source_dest_check')}
    row, cid = examples[kind]
    payload = {kind: deepcopy(row)}
    if kind == 'vpc':
        payload['subnet'] = deepcopy(net.SUBNET)
    snap = collect_sdk(sdk, payload)
    env = next(e for e in snap['collections'] if e['type'] == kind and e['status'] == 'collected')
    item, = env['items']
    assert all(item[key] == value for key, value in row.items())
    if kind == 'vpc':
        assert item['NetworkDnsAttributes'] == [
            {'VpcId': row['VpcId'], 'EnableDnsSupport': {'Value': True}},
            {'VpcId': row['VpcId'], 'EnableDnsHostnames': {'Value': True}},
        ]
        assert all(item['_coverage'][key]['status'] == 'collected'
                   for key in ('enableDnsSupport', 'enableDnsHostnames'))
    expected = 'FAIL' if kind == 'security_group' else 'PASS'  # SG declares world HTTPS.
    assert evaluate_snapshot(snap, checks=[cid])['findings'][0]['status'] == expected


@pytest.mark.parametrize('protocol,low,high,expected', [
    ('tcp', 22, 22, 'FAIL'), ('6', 22, 22, 'FAIL'), ('6', 443, 443, 'PASS'),
    ('udp', 22, 22, 'PASS'), ('17', 22, 22, 'PASS'), ('-1', None, None, 'FAIL'),
    ('6', 0, 65535, 'FAIL'), ('6', 0, 0, 'PASS'), ('6', 65535, 65535, 'PASS'),
    ('6', 23, 22, 'UNKNOWN'), ('6', -1, 22, 'UNKNOWN'), ('6', 65536, 65537, 'UNKNOWN'),
    ('6', None, None, 'UNKNOWN'), ('oops', 22, 22, 'UNKNOWN'), ('256', 22, 22, 'UNKNOWN'),
    ('icmp', -1, -1, 'PASS'), ('1', -1, -1, 'PASS'), ('icmpv6', 128, 0, 'PASS'), ('58', 128, 0, 'PASS'),
])
def test_sdk_numeric_protocol_and_range_to_registered_ssh(sdk, protocol, low, high, expected):
    from peaso.checks import claude_aws_a_network as net
    from peaso.engine import evaluate_snapshot
    payload = {'security_group': net.sg_with(net.world_rule(protocol, low, high)), 'vpc': deepcopy(net.VPC), 'network_interface': deepcopy(net.ENI)}
    snap = collect_sdk(sdk, payload)
    report = evaluate_snapshot(snap, checks=['aws.claude_a.vpc.sg_no_world_ssh'])
    assert report['findings'][0]['status'] == expected


@pytest.mark.parametrize('protocol', ['udp', '17', 'tcp', '6'])
def test_sdk_any_port_customer_interface_named_numeric_equivalence(sdk, protocol):
    from peaso.checks import claude_aws_a_network as net
    from peaso.engine import evaluate_snapshot
    snap = collect_sdk(sdk, {'security_group': net.sg_with(net.world_rule(protocol, 443, 443)), 'vpc': deepcopy(net.VPC), 'network_interface': deepcopy(net.ENI)})
    assert evaluate_snapshot(snap, checks=['aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis'])['findings'][0]['status'] == 'FAIL'


@pytest.mark.parametrize('kind', sorted(KINDS))
def test_sdk_denied_network_collection_cannot_pass(sdk, kind):
    from peaso.collectors import aws
    from peaso.engine import evaluate_snapshot
    _, add, _ = sdk
    add('sts').add_response('get_caller_identity', IDENTITY, {})
    add('ec2').add_client_error(aws.SPECS[kind][1], service_error_code='AccessDenied', http_status_code=403, expected_params={})
    snap = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'options': {'regions': [REGION], 'retry_attempts': 1}}, [kind])
    check = next(c for c in cohort() if c.kind == kind and c.target == 'resource')
    findings = evaluate_snapshot(snap, checks=[check.id])['findings']
    assert findings and all(f['status'] == 'DENIED' for f in findings)


@pytest.mark.parametrize('changes', [{'Protocol': 'oops'}, {'RuleAction': 'oops'}, {'PortRange': {'From': 23, 'To': 22}}, {'PortRange': {'From': 65536, 'To': 65537}}])
@pytest.mark.parametrize('suffix', ['nacl_no_world_tcp_22', 'nacl_no_world_remote_admin'])
def test_nacl_malformed_facts_are_unknown(changes, suffix):
    from peaso.checks import claude_aws_a_network as net
    row = net.nacl_entry('6', 22, 22)
    row.update(changes)
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.' + suffix)
    assert check.evaluate(net.nacl_with(row), deepcopy(net.NACL_INDEX))[0] == 'UNKNOWN'


@pytest.mark.parametrize('mode,expected', [('allow', 'FAIL'), ('earlier_deny', 'PASS'), ('later_deny', 'FAIL'),
    ('v4_deny_v6_allow', 'FAIL'), ('v6_deny_v4_allow', 'FAIL'), ('egress_only', 'PASS'), ('specific_source', 'PASS'),
    ('udp', 'PASS'), ('all_protocols', 'FAIL'), ('missing_ports', 'UNKNOWN'), ('reversed', 'UNKNOWN'), ('overflow', 'UNKNOWN')])
@pytest.mark.parametrize('suffix', ['nacl_no_world_tcp_22', 'nacl_no_world_remote_admin'])
def test_sdk_nacl_order_family_direction_and_intervals(sdk, mode, expected, suffix):
    from peaso.checks import claude_aws_a_network as n
    from peaso.engine import evaluate_snapshot
    row = n.nacl_entry('6', 22, 22)
    entries = [row]
    if mode in ('earlier_deny', 'later_deny'):
        entries.append(n.nacl_entry('6', 22, 22, action='deny', number=1 if mode == 'earlier_deny' else 200))
    if mode == 'v4_deny_v6_allow':
        entries = [n.nacl_entry('6', 22, 22, action='deny', number=1), n.nacl_entry('6', 22, 22, cidr='::/0')]
    if mode == 'v6_deny_v4_allow':
        entries = [n.nacl_entry('6', 22, 22, action='deny', number=1, cidr='::/0'), row]
    if mode == 'egress_only':
        row['Egress'] = True
    if mode == 'specific_source':
        row['CidrBlock'] = '8.8.8.8/32'
    if mode == 'udp':
        row['Protocol'] = '17'
    if mode == 'all_protocols':
        entries = [n.nacl_entry('-1')]
    if mode == 'missing_ports':
        del row['PortRange']
    if mode == 'reversed':
        row['PortRange'] = {'From': 23, 'To': 22}
    if mode == 'overflow':
        row['PortRange'] = {'From': 65536, 'To': 65537}
    item = dict(deepcopy(n.NACL), Entries=entries)
    snap = collect_sdk(sdk, {'network_acl': item})
    if suffix == 'nacl_no_world_remote_admin' and mode in ('earlier_deny', 'udp'):
        expected = 'FAIL'  # Individual-entry declaration question ignores order and includes UDP.
    assert evaluate_snapshot(snap, checks=['aws.claude_a.vpc.' + suffix])['findings'][0]['status'] == expected


def test_remote_admin_reversed_bounds_need_unknown():
    from peaso.checks import claude_aws_a_network as n
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.nacl_no_world_remote_admin')
    assert check.evaluate(n.nacl_with(n.nacl_entry('6', 23, 22)), {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('protocol', ['6', '17'])
def test_literal_protocol_filter_numeric_equivalence(protocol):
    from peaso.checks import claude_aws_a_network as n
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.sg_world_v4_no_tcp_udp')
    assert check.evaluate(n.sg_with(n.world_rule(protocol, 443, 443)), {})[0] == 'FAIL'


@pytest.mark.parametrize('protocol,expected', [('6', 'FAIL'), ('tcp', 'FAIL'), ('17', 'FAIL'), ('udp', 'FAIL'), ('-1', 'FAIL'), ('icmp', 'PASS')])
def test_sdk_literal_protocol_filter_native_names_numbers(sdk, protocol, expected):
    from peaso.checks import claude_aws_a_network as n
    from peaso.engine import evaluate_snapshot
    low, high = (-1, -1) if protocol == 'icmp' else (None, None) if protocol == '-1' else (443, 443)
    snap = collect_sdk(sdk, {'security_group': n.sg_with(n.world_rule(protocol, low, high))})
    assert evaluate_snapshot(snap, checks=['aws.claude_a.vpc.sg_world_v4_no_tcp_udp'])['findings'][0]['status'] == expected


@pytest.mark.parametrize('status,expected', [('available', 'FAIL'), ('associated', 'PASS'), ('attaching', 'PASS'), ('in-use', 'PASS'), ('detaching', 'PASS'), ('garbage', 'UNKNOWN')])
def test_sdk_eni_status_enum_and_optional_managed_attachment(sdk, status, expected):
    from peaso.checks import claude_aws_a_network as n
    from peaso.engine import evaluate_snapshot
    row = dict(deepcopy(n.ENI), Status=status)
    row.pop('Attachment', None)
    snap = collect_sdk(sdk, {'network_interface': row})
    assert evaluate_snapshot(snap, checks=['aws.claude_a.ec2.eni_in_use'])['findings'][0]['status'] == expected


@pytest.mark.parametrize('route,expected', [
    ({'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1'}, 'FAIL'),
    ({'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1', 'State': 'blackhole'}, 'FAIL'),
    ({'DestinationCidrBlock': '0.0.0.0/0', 'NatGatewayId': 'nat-1'}, 'PASS'),
    ({'DestinationCidrBlock': '10.0.0.0/16', 'GatewayId': 'local'}, 'PASS'),
    ({'DestinationIpv6CidrBlock': '::/0', 'GatewayId': 'igw-1'}, 'PASS'),
])
def test_sdk_ipv4_literal_route_scope_and_optional_non_igw_target(sdk, route, expected):
    from peaso.engine import evaluate_snapshot
    snap = collect_sdk(sdk, {'route_table': {'RouteTableId': 'rtb-1', 'Routes': [route]}})
    assert evaluate_snapshot(snap, checks=['aws.claude_a.vpc.route_table_no_default_igw_route'])['findings'][0]['status'] == expected


def test_eni_invalid_status_needs_unknown():
    check = next(c for c in cohort() if c.id == 'aws.claude_a.ec2.eni_in_use')
    assert check.evaluate({'NetworkInterfaceId': 'eni-1', 'Status': 'garbage'}, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('route', [
    {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': {}},
    {'DestinationCidrBlock': {'collection_status': 'denied'}, 'GatewayId': 'igw-1'},
    {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1', '_coverage': {'GatewayId': {'status': 'denied'}}},
])
def test_route_optional_native_fields_respect_types_and_coverage(route):
    check = next(c for c in cohort() if c.id == 'aws.claude_a.vpc.route_table_no_default_igw_route')
    assert check.evaluate({'RouteTableId': 'rtb-1', 'Routes': [route]}, {})[0] == 'UNKNOWN'


def test_intentional_literal_route_port_and_flowlog_distinctions():
    from peaso.checks import claude_aws_a_network as n
    by_id = {c.id: c for c in cohort()}
    def run(suffix, item, index=None):
        return by_id['aws.claude_a.vpc.' + suffix].evaluate(item, deepcopy(index or {}))[0]
    assert run('sg_world_v4_only_80_443', n.sg_with(n.world_rule('udp', 80, 80))) == 'PASS'
    ipv6 = {'RouteTableId': 'rtb-test', 'Routes': [{'DestinationIpv6CidrBlock': '::/0', 'GatewayId': 'igw-1'}]}
    assert run('route_table_no_default_igw_route', ipv6) == 'PASS'
    index = n.idx(network_interface=[n.ENI], flow_log=[dict(n.FLOW, FlowLogStatus='FAILED')])
    assert run('flow_logs_active', n.VPC, index) == 'FAIL'
    assert run('in_use_vpc_has_flow_log', n.VPC, index) == 'PASS'
    # Ordered deny stops the Prowler criterion; the literal individual-entry
    # remote-admin criterion deliberately still reports the allow declaration.
    item = n.nacl_with(n.nacl_entry('6', 22, 22, action='deny', number=1), n.nacl_entry('6', 22, 22, number=2))
    assert run('nacl_no_world_tcp_22', item) == 'PASS'
    assert run('nacl_no_world_remote_admin', item) == 'FAIL'


def write_report():
    report = build_review()
    LEDGER.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    lines = ['# AWS network semantic source review', '',
             f"Reviewed {report['check_count']} currently active AWS IDs across six kinds: " + ', '.join(f'{k}={v}' for k, v in sorted(report['counts'].items())) + '.', '',
             'Every row resolves the registered callback, per-ID closure/dispatch, source hashes, actual field-access witnesses and admitted meaning. Raw EC2 Describe responses retain native members through the actual deepcopy projection; SDK-valid Stubber chains test all six kinds separately from synthetic predicate fixtures. This is a bounded source review, not a proof of all branches or a live network/listener assessment.', '',
             'The Prowler SG helper accepted names but missed native protocol 6 and accepted invalid TCP/UDP ranges. The authorized correction normalizes native names/numbers and rejects malformed bounds/CIDRs while preserving ICMP and all-protocol semantics. Root owns central metadata hashes.', '',
             'Authorized corrections reject malformed NACL action/protocol/range/CIDR facts in both ordered and individual-entry checks, normalize numeric protocols in the literal protocol-filter SG variant, validate the native ENI Status enum, and honor route field types/coverage. These preserve intentional SQL scope, rule order and address families. Root owns central metadata materialization. Optional SDK range-array omissions remain conservative UNKNOWN in helpers requiring both arrays; there is no demonstrated live incidence.', '',
             'Pinned local criteria intentionally differ: literal 80/443 allows UDP; IPv4 route check excludes DestinationIpv6CidrBlock; SQL public/private classification includes NAT while Prowler uses IGW; presence-only flow logs/endpoints/firewalls do not prove ACTIVE state, interface type, routing, or inspection unless that predicate explicitly checks them. These scoped meanings are recorded, not silently broadened.', '',
             'Cached pinned VPC/EC2/NetworkFirewall/perimeter SQL blobs were checked against Git trees and declaration/port/direction/join semantics inspected by family; per-row query hashes are retained where resolved. Prowler network helper Python bodies were unavailable locally; no upstream execution parity is claimed. Cross-kind dependency producer semantics are explicitly outside this six-kind projection proof. Prior 10,565-pass evidence is preserved; only the focused gate is run.', '',
             'Reproduce: `.venv/bin/python -m tests.test_aws_network_semantic_review --write-report` then `.venv/bin/python -m pytest -q tests/test_aws_network_semantic_review.py --junitxml=/tmp/peasso-aws-review-20261019/native/network-semantic-review.xml`.', '',
             'The recorded combined gate also includes `tests/test_aws_ec2_public_reachability_review.py`, `tests/test_peaso_checks_claude_aws_a.py` and `tests/test_peaso_aws_core_ingress_imds_authority.py`. Exact execution receipt summary: `' + json.dumps(report['test_execution'], sort_keys=True) + '`.', '',
             '| Active check | Kind | Predicate source | Family |', '|---|---|---|---|']
    lines.extend(f"| `{r['id']}` | {r['kind']} | `{r['predicate']['file']}:{r['predicate']['line']}` | {r['family']} |" for r in report['checks'])
    (ROOT / 'docs/aws-review/network-semantic-review.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'checks': report['check_count'], 'counts': report['counts'], 'contracts': len(report['contracts']), 'bytes': LEDGER.stat().st_size}))


if __name__ == '__main__':
    if sys.argv[1:] != ['--write-report']:
        raise SystemExit('Use --write-report; pytest runs the execution gate.')
    write_report()
