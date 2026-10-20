"""GCP content inspection requires explicit opt-in and named native checks."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import collectors, engine
from peaso.snapshot import make_snapshot
from peaso.server.validation import validate_connector
from peaso.collectors import gcp

CID = 'gcp.review.function.literal_environment_secret_indicators'
SCOPE = 'projects/review'
CONTENT_CHECKS = {'function': CID, **{kind:
    'gcp.review.' + kind + '.literal_configuration_secret_indicators'
    for kind in ('instance', 'instance_template', 'project', 'cloudrun_service',
                 'cloudrun_job', 'cloudbuild_trigger', 'cloudbuild_build',
                 'dataflow_job', 'batch_job', 'dataproc_cluster', 'dataproc_job',
                 'composer_environment', 'workbench_instance')}}

CONTENT_CHECKS.update({
    'function_source_archive': 'gcp.review.function.resolved_source_archive_secret_indicators',
    'composer_dag_source': 'gcp.review.composer.dag_source_secret_indicators',
})

@pytest.fixture
def boundary(monkeypatch):
    observations = []
    def collect(connector, requirements):
        observations.append(deepcopy(connector))
        return make_snapshot('gcp', [SCOPE], [])
    monkeypatch.setattr(collectors, 'collect_live', collect)
    return observations

@pytest.mark.parametrize('selection', [{}, {'checks': []}, {'categories': ['hardening']},
                                        {'frameworks': ['hacktricks']},
                                        {'checks': ['gcp.review.workbench.root_access_disabled']}])
def test_broad_or_unrelated_selection_never_enables_content(boundary, selection):
    req = {'connector': {'provider': 'gcp', 'scopes': [SCOPE],
                        'options': {'content_secret_scans': True,
                                    '_content_secret_scan_kinds': ['function']}}, **selection}
    before = deepcopy(req)
    engine.collect_snapshot(req)
    assert boundary[0]['options']['_content_secret_scan_kinds'] == []
    assert req == before


@pytest.mark.parametrize('kind,cid', list(CONTENT_CHECKS.items()))
def test_named_selection_is_carried_without_mutating_request(boundary, kind, cid):
    req = {'connector': {'provider': 'gcp', 'scopes': [SCOPE],
                        'options': {'content_secret_scans': True}}, 'checks': [cid]}
    before = deepcopy(req)
    engine.collect_snapshot(req)
    assert boundary[0]['options']['_content_secret_scan_kinds'] == [kind]
    assert req == before

@pytest.mark.parametrize('options', [{}, {'content_secret_scans': True},
    {'content_secret_scans': True, '_content_secret_scan_kinds': []},
    {'content_secret_scans': False, '_content_secret_scan_kinds': ['function']}])
def test_transport_never_scans_without_both_signals(monkeypatch, options):
    from peaso.collectors import gcp_function_secret_indicators as projection
    monkeypatch.setattr(projection, 'scan_content', lambda *a, **k: pytest.fail('unselected content inspected'))
    class Response:
        status_code = 200
        def json(self):
            return {'functions': [{'name': SCOPE + '/locations/us-central1/functions/worker',
                                   'serviceConfig': {'environmentVariables': {'KEY': 'private-value'}},
                                   'buildConfig': {}}]}
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {}, close=lambda: None),
                              {**options, 'retries': 0})
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=lambda *a, **k: Response()))
    data, _ = transport.request('GET', 'https://cloudfunctions.googleapis.com/v2/' + SCOPE + '/locations/-/functions', scope=SCOPE)
    assert projection.MARKER not in data['functions'][0]
    assert data['functions'][0]['serviceConfig'] == {'environmentVariableNames': ['KEY']}

@pytest.mark.parametrize('value', ['true', 1, [], None])
def test_hosted_option_rejects_non_boolean(value):
    with pytest.raises(HTTPException):
        validate_connector('gcp', {}, {'content_secret_scans': value}, SimpleNamespace())


@pytest.mark.parametrize('enabled', [True, False])
@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_hosted_gcp_boolean_option_is_accepted(enabled, auth_mode):
    validate_connector('gcp', {'method': 'token', 'token': 'synthetic-token'},
                       {'content_secret_scans': enabled}, SimpleNamespace(auth_mode=auth_mode))


def test_hosted_gcp_rejects_caller_internal_kind_override():
    with pytest.raises(HTTPException) as caught:
        validate_connector('gcp', {'method': 'token', 'token': 'synthetic-token'},
            {'content_secret_scans': True, '_content_secret_scan_kinds': ['function']},
            SimpleNamespace(auth_mode='cognito'))
    assert caught.value.status_code == 422

OBJECT_CHECK = 'gcp.review.storage.selected_object_secret_indicators'
OBJECT = {'project_scope': SCOPE, 'bucket': 'selected-review-bucket',
          'object': 'config/settings.env', 'generation': '1234'}


def test_selected_object_engine_admission_and_dependency_plan(boundary):
    request = {'connector': {'provider': 'gcp', 'scopes': [SCOPE],
        'options': {'content_secret_scans': True, 'selected_gcs_objects': [OBJECT]}},
        'checks': [OBJECT_CHECK]}
    snapshot = engine.collect_snapshot(request)
    assert boundary[0]['options']['_content_secret_scan_kinds'] == ['gcs_selected_object']
    assert {'gcs_selected_object', 'bucket', 'project'} <= set(snapshot['metadata']['collection_plan']['requirements'])


@pytest.mark.parametrize('selection', [None, [], [{**OBJECT, 'generation': 'latest'}],
    [{**OBJECT, 'project_scope': 'projects/other'}]])
def test_invalid_object_targets_fail_before_collection(boundary, selection):
    with pytest.raises(ValueError, match='Selected object inspection'):
        engine.collect_snapshot({'connector': {'provider': 'gcp', 'scopes': [SCOPE],
            'options': {'content_secret_scans': True, 'selected_gcs_objects': selection}},
            'checks': [OBJECT_CHECK]})
    assert not boundary


@pytest.mark.parametrize('auth_mode', ['local', 'cognito'])
def test_hosted_exact_object_target_schema(auth_mode):
    settings = SimpleNamespace(auth_mode=auth_mode)
    auth = {'method': 'token', 'token': 'synthetic-token'}
    validate_connector('gcp', auth, {'content_secret_scans': True, 'selected_gcs_objects': [OBJECT]},
                       settings, scopes=[SCOPE])
    with pytest.raises(HTTPException):
        validate_connector('gcp', auth, {'selected_gcs_objects': [{**OBJECT, 'generation': 'latest'}]},
                           settings, scopes=[SCOPE])


@pytest.mark.parametrize('key', ['dataflow_regions', 'batch_regions', 'dataproc_regions'])
def test_hosted_job_regions_are_explicit_bounded_and_gcp_only(key):
    validate_connector('gcp', {}, {key: ['us-central1']}, SimpleNamespace(auth_mode='local'))
    for value in [[], ['global'], ['us-central1'] * 2, ['a','b','c','d','e','f'], True]:
        with pytest.raises(HTTPException):
            validate_connector('gcp', {}, {key: value}, SimpleNamespace(auth_mode='local'))
    with pytest.raises(HTTPException):
        validate_connector('aws', {}, {key: ['us-east-1']}, SimpleNamespace(auth_mode='local'))


def test_explicit_gke_selection_is_checked_before_collection(boundary):
    cid = 'gcp.review.gke_workload.literal_configuration_secret_indicators'
    cluster = SCOPE + '/locations/us-central1/clusters/review'
    request = {'connector': {'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'content_secret_scans': True, 'selected_gke_clusters': [cluster],
        'selected_gke_namespaces': {cluster: ['production']}}}, 'checks': [cid]}
    engine.collect_snapshot(request)
    assert boundary[-1]['options']['_content_secret_scan_kinds'] == ['gke_workload_literal']
    boundary.clear()
    request['connector']['options']['selected_gke_clusters'] = ['projects/other/locations/us-central1/clusters/review']
    with pytest.raises(ValueError, match='GKE content inspection'):
        engine.collect_snapshot(request)
    assert not boundary


def test_selected_artifact_file_admission_and_dependency_plan(boundary):
    cid = 'gcp.review.artifactregistry.selected_file_secret_indicators'
    target = {'project_scope': SCOPE,
              'name': SCOPE + '/locations/us-central1/repositories/packages/files/a%2Fb%2Fc.txt',
              'sha256': 'a' * 64, 'format': 'utf8'}
    req = {'connector': {'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'content_secret_scans': True, 'selected_artifact_files': [target]}}, 'checks': [cid]}
    snapshot = engine.collect_snapshot(req)
    assert boundary[-1]['options']['_content_secret_scan_kinds'] == ['artifact_selected_file']
    assert {'artifact_selected_file', 'project', 'artifact_repository'} <= set(snapshot['metadata']['collection_plan']['requirements'])
    validate_connector('gcp', {}, req['connector']['options'], SimpleNamespace(auth_mode='local'), scopes=[SCOPE])
    boundary.clear()
    target['name'] = target['name'].replace('%2F', '%252F')
    with pytest.raises(ValueError, match='Artifact file inspection'):
        engine.collect_snapshot(req)
    assert not boundary
