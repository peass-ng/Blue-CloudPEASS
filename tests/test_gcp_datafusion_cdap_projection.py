"""Only exact plugin references survive the Data Fusion CDAP projection."""

import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType

import pytest


@pytest.fixture
def projector(monkeypatch):
    root = Path(__file__).resolve().parents[1] / 'peaso/collectors'
    package = ModuleType('isolated_datafusion_projection')
    package.__path__ = [str(root)]
    gcp = ModuleType(package.__name__ + '.gcp')
    gcp.ReadError = type('ReadError', (Exception,), {})
    gcp._validate_iam_policy = lambda policy: policy
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, gcp.__name__, gcp)
    name = package.__name__ + '.gcp_datafusion_privesc'
    spec = importlib.util.spec_from_file_location(name, root / 'gcp_datafusion_privesc.py')
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module, gcp.ReadError


def test_application_projection_keeps_plugin_identity_but_drops_configuration(projector):
    module, _ = projector
    raw = {'name': 'orders', 'configuration': json.dumps({
        'stages': [{'plugin': {'name': 'Writer', 'type': 'batchsink',
                               'artifact': {'name': 'custom-jar', 'version': '2.3.1',
                                            'scope': 'USER'},
                               'properties': {'password': 'do-not-store'}}}],
        'postActions': [], 'properties': {'token': 'do-not-store'}}),
        'programs': [{'type': 'Workflow', 'name': 'DataPipelineWorkflow'}]}
    result = module.project_cdap_response(raw, '/api/v3/namespaces/default/apps/orders')
    assert result == {'name': 'orders', 'pluginArtifacts': [
        {'name': 'custom-jar', 'version': '2.3.1', 'scope': 'USER',
         'pluginName': 'Writer', 'pluginType': 'batchsink'}],
        'pluginReferencesComplete': True, 'hasDataPipelineWorkflow': True}
    assert 'do-not-store' not in json.dumps(result)


def test_missing_artifact_identity_is_incomplete_and_raw_config_is_discarded(projector):
    module, _ = projector
    result = module.project_cdap_response(
        {'name': 'orders', 'configuration': '{"stages":[{"plugin":{"name":"Writer"}}]}'},
        '/api/v3/namespaces/default/apps/orders')
    assert result['pluginArtifacts'] == []
    assert result['pluginReferencesComplete'] is False


def test_list_projection_rejects_malformed_identity(projector):
    module, ReadError = projector
    assert module.project_cdap_response(
        {'items': [{'name': 'jar', 'version': '1.0', 'scope': 'USER'}]},
        '/api/v3/namespaces/default/artifacts') == {
            'items': [{'name': 'jar', 'version': '1.0', 'scope': 'USER'}]}
    with pytest.raises(ReadError):
        module.project_cdap_response({'items': [{'name': 'jar'}]},
                                     '/api/v3/namespaces/default/artifacts')


def test_plugin_inventory_projection_keeps_identity_without_plugin_configuration(projector):
    module, _ = projector
    base = '/api/v3/namespaces/default/artifacts/cdap-data-pipeline/versions/6.3.0/extensions'
    assert module.project_cdap_response({'items': ['action', 'transform']}, base) == {
        'items': [{'type': 'action'}, {'type': 'transform'}]}
    projected = module.project_cdap_response({'items': [{
        'name': 'PySparkProgram', 'type': 'action', 'className': 'example.PySparkProgram',
        'description': 'discard', 'properties': {'password': 'do-not-store'},
        'artifact': {'name': 'pyspark', 'version': '1.0', 'scope': 'USER',
                     'properties': {'token': 'do-not-store'}}}]}, base + '/action')
    assert projected == {'items': [{
        'name': 'PySparkProgram', 'type': 'action', 'className': 'example.PySparkProgram',
        'artifact': {'name': 'pyspark', 'version': '1.0', 'scope': 'USER'}}]}
    assert 'do-not-store' not in json.dumps(projected)


def test_collector_joins_instance_namespace_and_exact_app_artifact(projector):
    module, _ = projector
    scope = 'projects/p1'
    endpoint = ('https://instance-p1-dot-usc1.'
                'datafusion.googleusercontent.com/api')

    class FakeCollector:
        needed = {'datafusion_privesc_instance'}
        scopes = [scope]
        transport = type('Transport', (), {'datafusion_cdap_reads': {}})()

        def pages(self, url, scope_arg, **kwargs):
            assert scope_arg == scope
            if url.endswith('/locations/-/instances'):
                return iter([([{'name': scope + '/locations/us-central1/instances/i1',
                                'state': 'RUNNING', 'apiEndpoint': endpoint,
                                'dataprocServiceAccount': 'runner@p1.iam.gserviceaccount.com',
                                'enableRbac': True}], 'i')])
            if url.endswith(':getIamPolicy'):
                assert kwargs['params'] == {'options.requestedPolicyVersion': 3}
                return iter([([{'version': 3, 'bindings': []}], 'policy')])
            if url.endswith('/v3/namespaces'):
                return iter([([{'name': 'default'}], 'n')])
            if url.endswith('/default/apps'):
                return iter([([{'name': 'orders'}], 'a')])
            if url.endswith('/default/artifacts'):
                return iter([([{'name': 'plugin-jar', 'version': '1.0', 'scope': 'USER'},
                              {'name': 'cdap-data-pipeline', 'version': '6.3.0',
                               'scope': 'SYSTEM'}], 'r')])
            if url.endswith('/default/artifacts/cdap-data-pipeline/versions/6.3.0/extensions'):
                assert kwargs['params'] == {'scope': 'system'}
                return iter([([{'type': 'action'}, {'type': 'batchsink'}], 'extension-types')])
            if url.endswith('/default/artifacts/cdap-data-pipeline/versions/6.3.0/extensions/action'):
                assert kwargs['params'] == {'scope': 'system'}
                return iter([([{'name': 'PySparkProgram', 'type': 'action',
                               'className': 'example.PySparkProgram',
                               'artifact': {'name': 'pyspark', 'version': '1.0',
                                            'scope': 'USER'}}], 'plugins')])
            if url.endswith('/default/profiles'):
                assert kwargs['params'] == {'includeSystem': 'true'}
                return iter([([{'name': 'runner', 'scope': 'USER', 'status': 'ENABLED',
                                'provisioner': 'gcp-dataproc',
                                'runnerServiceAccount': {'value': 'runner@p1.iam.gserviceaccount.com',
                                                         'isEditable': False}}], 'p')])
            if url.endswith('/default/preferences'):
                assert kwargs['params'] == {'resolved': 'true'}
                return iter([([{'profileName': 'user:runner',
                                'runnerServiceAccountOverride': None}], 'namespace-preferences')])
            if url.endswith('/default/apps/orders'):
                assert kwargs['single'] is True
                return iter([([{'name': 'orders', 'pluginArtifacts': [
                    {'name': 'plugin-jar', 'version': '1.0', 'scope': 'USER'}],
                    'pluginReferencesComplete': True,
                    'hasDataPipelineWorkflow': True}], 'd')])
            if url.endswith('/default/apps/orders/workflows/DataPipelineWorkflow/preferences'):
                assert kwargs['params'] == {'resolved': 'true'}
                return iter([([{'profileName': 'user:runner',
                                'runnerServiceAccountOverride': None}], 'w')])
            if url.endswith('/default/apps/orders/schedules'):
                if kwargs['params'] == {'schedule-status': 'SCHEDULED'}:
                    return iter([([{'name': 'daily'}], 'e')])
                return iter([([{'name': 'daily', 'status': 'SCHEDULED',
                                'programName': 'DataPipelineWorkflow',
                                'programType': 'WORKFLOW', 'profileName': None,
                                'runnerServiceAccountOverride': None}], 's')])
            raise AssertionError(url)

    collector = FakeCollector()
    jobs = module.scope_jobs(collector, scope)
    assert len(jobs) == 1
    rows = [item for page, _ in jobs[0][3]() for item in page]
    assert len(rows) == 1
    assert rows[0]['namespaces'][0]['applications'][0]['pluginArtifacts'][0] == {
        'name': 'plugin-jar', 'version': '1.0', 'scope': 'USER'}
    assert len(collector.transport.datafusion_cdap_reads) == 10
    assert rows[0]['namespaces'][0]['pipelinePlugins'][0]['name'] == 'PySparkProgram'
    assert rows[0]['namespaces'][0]['defaultProfile']['profileName'] == 'user:runner'
    assert rows[0]['namespaces'][0]['applications'][0]['schedules'][0]['enabled'] is True
    assert rows[0]['iamPolicy'] == {'version': 3, 'bindings': []}
    assert rows[0]['namespaces'][0]['iamPolicy'] == {'version': 3, 'bindings': []}


def test_profile_projection_drops_key_material_and_keeps_runner_identity(projector):
    module, _ = projector
    raw = {'items': [{'name': 'runner', 'scope': 'USER', 'status': 'ENABLED',
                      'provisioner': {'name': 'gcp-dataproc', 'properties': [
                          {'name': 'accountKey', 'value': 'private-key-material'},
                          {'name': 'serviceAccount', 'value': 'runner@p1.iam.gserviceaccount.com',
                           'isEditable': False},
                          {'name': 'projectId', 'value': 'p1', 'isEditable': False}]}}]}
    result = module.project_cdap_response(raw, '/api/v3/namespaces/default/profiles')
    assert result['items'][0]['runnerServiceAccount'] == {
        'value': 'runner@p1.iam.gserviceaccount.com', 'isEditable': False}
    assert 'private-key-material' not in json.dumps(result)
    preferences = module.project_cdap_response(
        {'system.profile.name': 'user:runner',
         'system.profile.properties.serviceAccount': 'runner@p1.iam.gserviceaccount.com',
         'password': 'hidden'},
        '/api/v3/namespaces/default/apps/orders/workflows/DataPipelineWorkflow/preferences')
    assert preferences == {'profileName': 'user:runner',
                           'runnerServiceAccountOverride': 'runner@p1.iam.gserviceaccount.com'}
    assert 'hidden' not in json.dumps(preferences)


def test_schedule_projection_keeps_run_context_without_other_properties(projector):
    module, _ = projector
    result = module.project_cdap_response(
        {'items': [{'name': 'daily', 'status': 'SCHEDULED',
                    'program': {'programName': 'DataPipelineWorkflow',
                                'programType': 'WORKFLOW'},
                    'properties': {'system.profile.name': 'user:runner',
                                   'system.profile.properties.serviceAccount':
                                   'runner@p1.iam.gserviceaccount.com',
                                   'secret': 'do-not-store'}}]},
        '/api/v3/namespaces/default/apps/orders/schedules')
    assert result == {'items': [{'name': 'daily', 'status': 'SCHEDULED',
                                'programName': 'DataPipelineWorkflow',
                                'programType': 'WORKFLOW', 'profileName': 'user:runner',
                                'runnerServiceAccountOverride':
                                'runner@p1.iam.gserviceaccount.com'}]}
    assert 'do-not-store' not in json.dumps(result)


def test_endpoint_accepts_only_google_owned_datafusion_api(projector):
    module, ReadError = projector
    valid = ('https://instance-p1-dot-usc1.'
             'datafusion.googleusercontent.com/api')
    assert module._endpoint(valid) == valid
    for value in (valid.replace('googleusercontent.com', 'example.com'),
                  valid.replace('/api', '/other'),
                  valid.replace('https:', 'http:'),
                  valid + '?next=https://example.com',
                  'https://u:p@instance-p1-dot-usc1.datafusion.googleusercontent.com/api',
                  'https://instance-p1-dot-usc1.datafusion.googleusercontent.com:bad/api'):
        with pytest.raises(ReadError):
            module._endpoint(value)


def test_instance_accepts_default_compute_service_account(projector):
    module, _ = projector

    class Collector:
        needed = {'datafusion_privesc_instance'}

        def pages(self, url, scope, **kwargs):
            return iter([([{'name': 'projects/p1/locations/us-central1/instances/fusion',
                            'state': 'DISABLED',
                            'dataprocServiceAccount':
                            '123-compute@developer.gserviceaccount.com'}], 'instance')])

    jobs = module.scope_jobs(Collector(), 'projects/p1')
    rows = [item for page, _ in jobs[0][3]() for item in page]
    assert rows[0]['dataprocServiceAccount'] == '123-compute@developer.gserviceaccount.com'
