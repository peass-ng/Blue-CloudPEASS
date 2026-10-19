"""Every registered Kubernetes ID is reviewed against actual evaluator output."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.native_only import exclusions
from peaso.checks.k8s_evidence_explanations import evidence_summary, review_rows, reviewed_explanation
from tests.test_peaso_k8s_observed_configuration import cases_for

K8S = {c.id: c for c in CHECKS if c.provider == 'k8s'}
STATES = ('pass', 'fail', 'unknown', 'malformed', 'missing', 'manual', 'not_applicable')


def _supplemental_index(groups, cluster='fixture'):
    from peaso.checks.facts import MemoIndex
    context = {'provider': 'k8s', 'scope': '*', 'created_at': '2026-10-12T00:00:00Z',
               'metadata': {'cluster_id': cluster, 'compliance_policy': {'status': 'collected', 'cluster_id': cluster,
                 'in_scope_service_names': ['edge'], 'required_external_traffic_policy': 'Local', 'approved_clock_skew': 2}}}
    out = {'context': context, 'collections': {}}
    for kind, values in groups.items():
        for value in values:
            value.setdefault('provenance', {'cluster_id': cluster, 'evidence': 'read-only list'})
        out['collections'][kind] = [{'type': kind, 'scope': '*', 'status': 'collected', 'items': values}]
        out[kind] = [{'type': kind, 'scope': '*', 'data': value} for value in values]
    return MemoIndex(out)


def supplemental_cases(cid):
    """Four catalog IDs have dedicated tests rather than global CASES entries."""
    if cid == 'k8s.network.namespace_policy_inventory':
        item = {'metadata': {'name': 'apps'}}
        policy = {'metadata': {'name': 'p', 'namespace': 'apps'}}
        return {'fail': item, 'fail_index': {'collections': {'networkpolicy': [{'scope': '*', 'status': 'empty', 'items': []}]}},
                'manual': item, 'manual_index': {'collections': {'networkpolicy': [{'scope': '*', 'status': 'collected', 'items': [policy]}]}},
                'unknown': item, 'malformed': None}
    if cid == 'k8s_service_external_traffic_policy_matches_required':
        row = {'metadata': {'name': 'edge', 'namespace': 'apps'}, 'spec': {'type': 'LoadBalancer', 'externalTrafficPolicy': 'Local'}}
        bad = deepcopy(row); bad['spec']['externalTrafficPolicy'] = 'Cluster'
        return {'pass': row, 'pass_index': _supplemental_index({'service': [row]}), 'fail': bad, 'fail_index': _supplemental_index({'service': [bad]}),
                'unknown': row, 'malformed': None}
    if cid == 'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4':
        node = {'metadata': {'name': 'node1'}, 'provenance': {'cluster_id': 'cluster-57', 'evidence': 'read-only list'}}
        clock = {'node_name': 'node1', 'source_operation': 'GET /api/v1/nodes/{name}/proxy/healthz',
                 'date_header': 'Mon, 12 Oct 2026 00:00:00 GMT', 'node_response_verified': True,
                 'trusted_clock_verified': True, 'trusted_utc_at_response': '2026-10-12T00:00:00Z',
                 'provenance': {'cluster_id': 'cluster-57'}}
        good = _supplemental_index({'node': [node], 'node_clock': [clock]}, 'cluster-57')
        bad_clock = deepcopy(clock); bad_clock['date_header'] = 'Mon, 12 Oct 2026 00:00:10 GMT'
        bad = _supplemental_index({'node': [node], 'node_clock': [bad_clock]}, 'cluster-57')
        unknown = _supplemental_index({'node': [node]}, 'cluster-57')
        return {'pass': good['context'], 'pass_index': good, 'fail': bad['context'], 'fail_index': bad,
                'unknown': unknown['context'], 'unknown_index': unknown}
    if cid == 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller':
        row = {'kind': 'Pod', 'metadata': {'name': 'api', 'namespace': 'apps', 'uid': 'api-uid'},
               'spec': {'containers': [{'name': 'api', '_component_config': {'component': 'kube-apiserver', 'flags_complete': True,
                 'flags': {'enable-admission-plugins': 'ImagePolicyWebhook', 'disable-admission-plugins': 'Other',
                           'admission-control-config-file': '/etc/admission.yaml'}}}]}}
        file = {'pod_uid': 'api-uid', 'path': '/etc/admission.yaml', 'verification_status': 'verified',
                'plugins': [{'name': 'ImagePolicyWebhook', 'configuration': {'kubeConfigFile': '/etc/webhook.conf'}}]}
        bad_file = deepcopy(file); bad_file['plugins'] = []
        return {'pass': row, 'pass_index': _supplemental_index({'pod': [row], 'admission_configuration_file': [file]}),
                'fail': row, 'fail_index': _supplemental_index({'pod': [row], 'admission_configuration_file': [bad_file]}),
                'unknown': row, 'unknown_index': _supplemental_index({'pod': [row]}), 'malformed': None}
    return None


def reviewed_cases(cid):
    if cid in exclusions():
        return supplemental_cases(cid) or CASES.get(cid)
    return cases_for(cid, K8S[cid])


def observations_for(cid):
    check, cases = K8S[cid], reviewed_cases(cid)
    assert cases, cid
    for state in STATES:
        if state not in cases:
            continue
        status, evidence = check.evaluate(deepcopy(cases[state]), deepcopy(cases.get(state + '_index', cases.get('index', {}))))
        if cid in ('k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller', 'k8s_cluster_clocks_information_processing_systems_used_by_82e06ff4', 'k8s_service_external_traffic_policy_matches_required') and state in ('pass', 'fail'):
            assert status == state.upper(), (cid, state, status, evidence)
        yield state, {'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence}


def test_all_1005_registered_ids_have_exact_review_records():
    assert len(K8S) == 1005
    assert set(review_rows()) == set(K8S)
    for cid, row in review_rows().items():
        assert row['purpose'].endswith('.') and row['limit'].endswith('.'), cid
        assert len(row['purpose']) < 160 and len(row['limit']) < 150, cid
        assert row['renderer'] in ('native', 'external'), cid


@pytest.mark.parametrize('cid', sorted(K8S))
def test_every_existing_status_witness_has_short_explanatory_output(cid):
    observed = list(observations_for(cid))
    assert observed
    for state, finding in observed:
        before = deepcopy(finding)
        summary = evidence_summary(finding)
        assert isinstance(summary, str) and summary, (cid, state, finding)
        assert '\n' not in summary and len(summary) <= 240, (cid, state, summary)
        assert review_rows()[cid]['purpose'] in summary
        assert summary == reviewed_explanation(cid, summary, finding['status'])
        assert finding == before


@pytest.mark.parametrize('cid', sorted(K8S))
def test_empty_or_wrongly_typed_evidence_never_establishes_configuration(cid):
    for bad in ({}, None, False, 42, [], 'unusable'):
        for status in ('PASS', 'FAIL', 'UNKNOWN', 'MANUAL', 'NOT_APPLICABLE'):
            assert evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': bad}) is None


def test_digest_pull_acceptance_does_not_claim_always_was_declared():
    cid = 'k8s.ports.cronjob.always_pull'
    _, f = next((state, f) for state, f in observations_for(cid) if f['status'] == 'PASS')
    result = evidence_summary(f)
    assert 'accepted SHA256 digest or the Always' in result
    assert 'declare the Always' not in result


def test_grpcs_is_reported_as_observed_without_claiming_https():
    cid = 'k8s_ingress_backend_https'
    cases = reviewed_cases(cid)
    row = deepcopy(cases['pass'])
    row['metadata']['annotations']['nginx.ingress.kubernetes.io/backend-protocol'] = 'GRPCS'
    status, evidence = K8S[cid].evaluate(row, deepcopy(cases.get('pass_index', cases.get('index', {}))))
    assert status == 'PASS'
    text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})
    assert '“GRPCS”' in text
    assert 'declares HTTPS' not in text


def test_wildcard_subresource_pattern_is_not_dropped():
    cid = 'k8s.ports.clusterrole.role_with_wildcards_used'
    status, evidence = K8S[cid].evaluate({'rules': [{'apiGroups': [''], 'resources': ['pods/*'], 'verbs': ['get']}]}, {})
    assert status == 'FAIL'
    assert '“pods/*”' in evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})


def test_explicit_hostport_zero_is_not_reported_as_nonzero():
    cid = 'k8s.ports.cronjob.no_host_ports'
    # This source predicate rejects any declared hostPort, including zero.
    cases = reviewed_cases(cid); row = deepcopy(cases['fail'])
    row['spec']['jobTemplate']['spec']['template']['spec']['containers'][0]['ports'] = [{'containerPort': 8080, 'hostPort': 0}]
    status, evidence = K8S[cid].evaluate(row, {})
    assert status == 'FAIL'
    text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})
    assert 'hostPort field' in text and 'nonzero' not in text


def test_implicit_uid_and_partial_capability_drops_are_not_overstated():
    for cid, item, expected in [
        ('k8s.claude.pod.no_root_user', {'spec': {'containers': [{'name': 'app'}]}}, 'explicitly declares UID zero'),
        ('k8s.claude.pod.capabilities_dropped', {'spec': {'containers': [{'name': 'app', 'securityContext': {'capabilities': {'drop': ['NET_RAW']}}}]}}, 'empty drop list'),
    ]:
        status, evidence = K8S[cid].evaluate(item, {})
        assert status == 'PASS'
        text = evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': status, 'evidence': evidence})
        assert expected in text
        assert 'declare a non-root restriction' not in text
        assert 'drop all' not in text.lower()


def test_review_ledger_accounts_for_each_id_and_replays_every_saved_explanation():
    ledger = json.loads((Path(__file__).parents[1] / 'docs/evidence-reviews/k8s.json').read_text())
    assert set(ledger['checks']) == set(K8S)
    for cid, entry in ledger['checks'].items():
        assert entry['disposition'] == 'rewritten'
        assert entry['missing_fixtures'] == []
        replay = {state: finding for state, finding in observations_for(cid)}
        assert set(replay) == {b['fixture_state'] for b in entry['branches']}
        for branch in entry['branches']:
            finding = replay[branch['fixture_state']]
            assert branch['observed_status'] == finding['status']
            assert branch['explanation'] == evidence_summary(finding)


def test_unhashable_identifiers_and_reason_payloads_do_not_crash():
    for check_id in ([], {}, 5, None):
        assert evidence_summary({'provider': 'k8s', 'check_id': check_id, 'status': 'FAIL', 'evidence': {'reason': 'unavailable'}}) is None
    cid = 'k8s.cis.configure_image_provenance_using_imagepolicywebhook_admission_controller'
    for reason in ([], {}, True, None):
        assert evidence_summary({'provider': 'k8s', 'check_id': cid, 'status': 'FAIL', 'evidence': {'reason': reason}}) is None
