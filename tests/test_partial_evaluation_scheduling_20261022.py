"""Schedule costly partial projections from settled sections, without hiding native evidence."""
from unittest.mock import Mock

import pytest

from peaso import analysis, engine
from peaso.incremental import CheckpointSession
from peaso.snapshot import make_snapshot, resources, seal


SCOPES = ['111111111111/us-east-1', '222222222222/us-east-1']
NETWORK_CHECK = 'aws.ec2.restrict_internet_ingress'


def session_for(monkeypatch, request):
    # Drive deterministic checkpoints explicitly, using the real session state,
    # section dependencies, evaluator and publication filter.
    monkeypatch.setattr(CheckpointSession, '_background', lambda self: None)
    publications = []
    session = CheckpointSession(request, lambda *row: publications.append(row), lambda snapshot: snapshot,
        interval=10**9, collection_stride=10**9, batch_size=10000, batch_interval=10**9,
        clock=lambda: 0)
    return session, publications


def settle(session, kinds, scopes=SCOPES, status='empty'):
    for kind in sorted(kinds):
        for scope in scopes:
            if kind in session.global_types:
                scope = scope.split('/', 1)[0] + '/global'
            key = (kind, scope)
            if key not in session.collections and key not in session.pending:
                session.on_collection({'type': kind, 'scope': scope, 'status': status, 'items': []})
    with session.lock:
        session._flush_pending()


def test_native_results_publish_before_heavy_sections_and_network_completes_independently(monkeypatch):
    request = {'connector': {'provider': 'aws', 'scopes': SCOPES},
        'categories': ['hardening', 'network', 'exposure', 'least_privilege', 'iam_graph', 'privesc'],
        'checks': ['aws.ec2.imdsv2', NETWORK_CHECK, 'privesc'] + [c['id'] for c in analysis.ANALYSIS_CHECKS]}
    session, publications = session_for(monkeypatch, request)
    spies = {}
    for module, name in ((analysis, 'analyze_findings'), (analysis, 'build_network'),
                         (analysis, 'build_iam'), (engine, '_run_privesc')):
        spies[name] = Mock(wraps=getattr(module, name))
        monkeypatch.setattr(module, name, spies[name])
    session.on_collection({'type': 'security_group', 'scope': SCOPES[0], 'status': 'collected',
        'items': [{'GroupId': 'sg-public', 'IpPermissions': [{'IpProtocol': 'tcp', 'FromPort': 22,
            'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]}]})
    session.on_collection({'type': 'instance', 'scope': SCOPES[1], 'status': 'unknown', 'items': []})
    # All kinds have been observed, but the second account's reads are pending.
    settle(session, set().union(*session.section_dependencies.values()), scopes=SCOPES[:1])
    report = session.publish()
    assert report is not None
    assert any(f['check_id'] == NETWORK_CHECK and f['status'] == 'FAIL' for f in report['findings'])
    assert any(f['check_id'] == 'aws.ec2.imdsv2' and f['status'] == 'UNKNOWN' for f in report['findings'])
    assert not any(f['scope'] == SCOPES[1] and f['status'] in {'PASS', 'EMPTY'} for f in report['findings'])
    assert all(spy.call_count == 0 for spy in spies.values())
    assert report['publication']['sections']['network']['status'] == 'running'
    assert any(snapshot and partial is None for snapshot, partial, _ in publications)

    settle(session, session.section_dependencies['network'])
    # Completion bypasses the long cadence even though native network results
    # have already published that category.
    report = session._maybe_publish()
    assert report is not None
    assert report['publication']['sections']['network']['status'] == 'complete'
    assert report['publication']['sections']['least_privilege']['status'] == 'running'
    assert report['publication']['sections']['privesc']['status'] == 'running'
    assert spies['build_network'].call_count == 1
    assert spies['build_iam'].call_count == 0
    assert spies['analyze_findings'].call_count == 0
    assert spies['_run_privesc'].call_count == 0

    # Denied/unknown reads are settled, so they complete their section without
    # claiming successful inventory or turning unknown findings into passes.
    settle(session, session.section_dependencies['exposure'], status='denied')
    report = session._maybe_publish()
    assert report['publication']['sections']['exposure']['status'] == 'complete'
    assert spies['analyze_findings'].call_args.kwargs['categories'] == {'exposure'}
    assert spies['build_iam'].call_count == 0
    settle(session, session.section_dependencies['least_privilege'], status='unknown')
    report = session._maybe_publish()
    assert report['publication']['sections']['least_privilege']['status'] == 'complete'
    assert spies['build_iam'].call_count == 1
    assert 'least_privilege' in spies['analyze_findings'].call_args.kwargs['categories']
    assert spies['_run_privesc'].call_count == 0
    settle(session, session.section_dependencies['privesc'], status='malformed')
    report = session._maybe_publish()
    assert report['publication']['sections']['privesc']['status'] == 'complete'
    assert spies['_run_privesc'].call_count == 1
    assert report['stats']['coverage_complete'] is False
    session.close()


@pytest.mark.parametrize('provider', ['aws', 'gcp', 'azure', 'k8s'])
def test_iam_graph_dependencies_fit_least_privilege_marker(provider):
    assert set(analysis.REQUIRED_TYPES[provider]['iam_graph']) <= set(analysis.REQUIRED_TYPES[provider]['least_privilege'])


def test_graph_only_request_uses_least_privilege_completion_without_running_checks(monkeypatch):
    scopes = ['project-a', 'project-b']
    request = {'connector': {'provider': 'gcp', 'scopes': scopes}, 'categories': ['iam_graph']}
    session, _ = session_for(monkeypatch, request)
    assert session.section_dependencies['least_privilege']
    settle(session, session.section_dependencies['least_privilege'], scopes=scopes[:1])
    assert session.publish() is None
    settle(session, session.section_dependencies['least_privilege'], scopes=scopes)
    report = session.publish()
    assert report['publication']['sections']['least_privilege']['status'] == 'complete'
    assert report['stats']['check_count'] == 0
    assert report['findings'] == []
    assert not [row for row in report['coverage'] if row['level'] == 'check']
    assert report['graphs']['network'] == {'nodes': [], 'edges': []}
    session.close()


def test_named_native_request_without_categories_does_not_schedule_unselected_graphs(monkeypatch):
    request = {'connector': {'provider': 'aws', 'scopes': SCOPES[:1]}, 'checks': ['aws.ec2.imdsv2']}
    session, _ = session_for(monkeypatch, request)
    assert session.graph_categories == set()
    monkeypatch.setattr(analysis, 'build_graphs', Mock(side_effect=AssertionError('unselected graph built')))
    settle(session, {'instance'}, scopes=SCOPES[:1])
    report = session.publish()
    assert report is not None
    assert report['graphs']['network'] == report['graphs']['iam'] == {'nodes': [], 'edges': []}
    session.close()


@pytest.mark.parametrize('category', ['exposure', 'least_privilege'])
def test_selective_analysis_matches_full_projection_and_preserves_unknowns(monkeypatch, category):
    snapshot = make_snapshot('aws', SCOPES, [
        {'type': 'iam_role', 'scope': SCOPES[0], 'status': 'collected', 'items': [
            {'RoleName': 'public', 'AssumeRolePolicyDocument': {'Statement': [
                {'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Principal': '*'}]}}]},
        {'type': 'iam_user', 'scope': SCOPES[1], 'status': 'denied', 'items': []}])
    expected = [f for f in analysis.analyze_findings(snapshot, include_manual_only=False) if f['category'] == category]
    for name in ('internet_findings', 'federated_findings'):
        monkeypatch.setattr(analysis, name, Mock(wraps=getattr(analysis, name)))
    actual = analysis.analyze_findings(snapshot, include_manual_only=False, categories={category})
    assert actual == expected
    if category == 'least_privilege':
        assert any(f['status'] in {'UNKNOWN', 'DENIED'} for f in actual)
        analysis.internet_findings.assert_not_called()
        analysis.federated_findings.assert_not_called()


@pytest.mark.parametrize('graph_kind', ['network', 'iam'])
@pytest.mark.parametrize('malformed', [False, True])
def test_selective_graph_build_does_not_invoke_other_builder(monkeypatch, graph_kind, malformed):
    snapshot = make_snapshot('aws', SCOPES, [])
    if malformed:
        selected_builder = 'build_network' if graph_kind == 'network' else 'build_iam'
        monkeypatch.setattr(analysis, selected_builder, Mock(side_effect=TypeError('malformed native fact')))
    expected = analysis.build_graphs(snapshot, resources(snapshot), max_nodes=None)[graph_kind]
    other = 'build_iam' if graph_kind == 'network' else 'build_network'
    monkeypatch.setattr(analysis, other, Mock(side_effect=AssertionError('unscheduled graph built')))
    assert analysis.build_graphs(snapshot, resources(snapshot), max_nodes=None,
        graph_kinds={graph_kind}) == {graph_kind: expected}


@pytest.mark.parametrize('category', ['exposure', 'least_privilege'])
def test_selective_analysis_keeps_exception_to_unknown_results(monkeypatch, category):
    snapshot = make_snapshot('aws', SCOPES[:1], [
        {'type': 'iam_role', 'scope': SCOPES[0], 'status': 'collected', 'items': [{'RoleName': 'malformed'}]}])
    for name in ('review_findings', 'internet_findings', 'federated_findings'):
        broken = Mock(side_effect=TypeError('malformed native fact'))
        broken.__name__ = name
        monkeypatch.setattr(analysis, name, broken)
    expected = [f for f in analysis.analyze_findings(snapshot, include_manual_only=False) if f['category'] == category]
    actual = analysis.analyze_findings(snapshot, include_manual_only=False, categories={category})
    assert actual == expected
    assert actual and all(f['status'] == 'UNKNOWN' for f in actual)


def test_dynamic_scope_sections_wait_for_collection_closure(monkeypatch):
    request = {'connector': {'provider': 'aws', 'scopes': ['*']},
        'categories': ['least_privilege'], 'checks': ['analysis.coverage']}
    session, _ = session_for(monkeypatch, request)
    settle(session, session.section_dependencies['least_privilege'], scopes=SCOPES[:1])
    assert session.sections()['least_privilege']['status'] == 'running'
    assert session.publish() is None
    session.finish_collection()
    report = session.publish()
    assert report['publication']['sections']['least_privilege']['status'] == 'complete'
    session.close()


def test_final_evaluation_is_independent_of_partial_graph_schedule():
    snapshot = seal(make_snapshot('aws', SCOPES, [
        {'type': 'instance', 'scope': SCOPES[0], 'status': 'collected', 'items': [
            {'InstanceId': 'i-final', 'MetadataOptions': {'HttpTokens': 'optional'}}]}]))
    selection = dict(categories=['hardening', 'network', 'iam_graph', 'least_privilege', 'exposure'],
        checks=['aws.ec2.imdsv2', 'analysis.coverage', 'analysis.internet_exposure'],
        frameworks=['hacktricks'], include_not_applicable=False)
    before = engine.evaluate_snapshot(snapshot, **selection)
    partial = engine.evaluate_snapshot(snapshot, **selection, completed_graph_sections=set())
    assert partial['graphs']['network'] == partial['graphs']['iam'] == {'nodes': [], 'edges': []}
    assert partial['findings'] == before['findings']
    assert partial['coverage'] == before['coverage']
    assert engine.evaluate_snapshot(snapshot, **selection) == before
