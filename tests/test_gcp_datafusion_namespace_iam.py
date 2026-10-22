"""Data Fusion namespace bindings apply to the exact namespace resource."""

from peaso.privesc.effective_permissions.gcp import GcpModel
from tests.test_peaso_privesc_schema_ext import snapshot


def test_datafusion_namespace_iam_is_not_granted_on_other_namespace():
    project = 'projects/p1'
    instance = project + '/locations/us-central1/instances/fusion'
    source = 'user:alice@example.com'
    role_name = project + '/roles/fusionPluginWriter'
    role = {'name': role_name, 'includedPermissions': ['datafusion.artifacts.create']}
    model = GcpModel(snapshot('gcp', [
        ('project', project, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', project, [{'name': project, 'bindings': []}]),
        ('iam_role', project, [role]),
        ('service_account', project, []),
        ('iam_deny_policy', project, [], 'empty'),
        ('datafusion_privesc_instance', project, [{
            'name': instance, 'state': 'RUNNING', 'enableRbac': True,
            'iamPolicy': {'bindings': []},
            'namespaces': [
                {'name': 'a', 'iamPolicy': {'bindings': [
                    {'role': role_name, 'members': [source]}]}},
                {'name': 'b', 'iamPolicy': {'bindings': []}},
            ],
        }]),
    ]))
    principal = model.principals[source]
    requirement = {'action': 'datafusion.artifacts.create'}
    assert model.check(principal, requirement, instance + '/namespaces/a') is not None
    assert model.check(principal, requirement, instance + '/namespaces/b') is None
    assert model.check(principal, requirement, instance) is None
