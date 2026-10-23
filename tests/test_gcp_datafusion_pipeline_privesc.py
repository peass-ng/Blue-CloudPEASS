"""Data Fusion pipeline creation reaches only a runnable profile's exact account."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
INSTANCE = PROJECT + '/locations/us-central1/instances/fusion'
SOURCE = 'user:alice@example.com'
RUNNER = 'runner@p1.iam.gserviceaccount.com'
AGENT = 'serviceAccount:service-123@gcp-sa-datafusion.iam.gserviceaccount.com'
ENTRY = next(row for row in privesc.catalog()['entries']
             if row['id'] == 'gcp-datafusion-pipelines-create-execute')


def case(*, plugin=True, code=True, namespace_rights=True, agent_actas=True,
         profile=True, conditional=None, other_account=False, default_profile=None,
         external=False, deny_create=False, missing_inventory=False, entry=ENTRY,
         instance_write=False, namespace_write=False, instance_get=True,
         rbac=True, deny_instance_write=False, writer_condition=None,
         missing_default=False):
    runner = 'runner@p2.iam.gserviceaccount.com' if external else RUNNER
    cluster_project = 'p2' if external else 'p1'
    binding = lambda role, member: {'role': role, 'members': [member]}
    accessor = PROJECT + '/roles/accessor'
    creator = PROJECT + '/roles/creator'
    runtime = PROJECT + '/roles/runtime'
    actas = PROJECT + '/roles/actas'
    writer = PROJECT + '/roles/policyWriter'
    namespace_binding = binding(creator, SOURCE)
    if conditional:
        namespace_binding['condition'] = {'title': 'condition', 'expression': conditional}
    namespace_bindings = [namespace_binding]
    writer_binding = binding(writer, SOURCE)
    if writer_condition:
        writer_binding['condition'] = {'title': 'policy-writer-condition',
                                       'expression': writer_condition}
    if namespace_write:
        namespace_bindings.append(writer_binding)
    namespace = {'name': 'default', 'iamPolicy': {'bindings': namespace_bindings},
                 'defaultProfile': {'profileName': default_profile,
                                    'runnerServiceAccountOverride': None},
                 'profiles': ([{'name': 'batch', 'scope': 'USER', 'status': 'ENABLED',
                               'provisioner': 'gcp-dataproc',
                               'runnerServiceAccount': {'value': runner, 'isEditable': False},
                               'projectId': {'value': cluster_project, 'isEditable': False}}]
                              if profile else []),
                 'pipelinePlugins': ([{'name': 'PySparkProgram' if code else 'BatchSource',
                                      'type': 'action', 'className': 'example.PySparkProgram',
                                      'parentScope': 'SYSTEM', 'parentVersion': '6.3.0',
                                      'artifact': {'name': 'pyspark', 'version': '1.0',
                                                   'scope': 'USER'}}] if plugin else []),
                 'artifacts': [{'name': 'cdap-data-pipeline', 'version': '6.3.0',
                                'scope': 'SYSTEM'}], 'applications': []}
    if missing_inventory:
        del namespace['pipelinePlugins']
    if missing_default:
        del namespace['defaultProfile']
    instance_bindings = [binding(accessor, SOURCE)]
    if instance_write:
        instance_bindings.append(writer_binding)
    fusion = {'name': INSTANCE, 'state': 'RUNNING', 'enableRbac': rbac,
              'dataprocServiceAccount': '123-compute@developer.gserviceaccount.com',
              'iamPolicy': {'bindings': instance_bindings},
              'namespaces': [namespace]}
    roles = [
        {'name': accessor, 'includedPermissions':
         ['datafusion.instances.get'] if instance_get else []},
        {'name': creator, 'includedPermissions':
         (['datafusion.namespaces.get', 'datafusion.pipelines.create',
           'datafusion.pipelines.execute'] if namespace_rights else
          ['datafusion.namespaces.get', 'datafusion.pipelines.create'])},
        {'name': runtime, 'includedPermissions':
         ['datafusion.instances.runtime', 'dataproc.agents.create']},
        {'name': actas, 'includedPermissions': ['iam.serviceAccounts.actAs']},
        {'name': writer, 'includedPermissions':
         (['datafusion.instances.setIamPolicy'] if instance_write else []) +
         (['datafusion.namespaces.setIamPolicy'] if namespace_write else [])},
    ]
    accounts = [{'email': runner, 'projectId': cluster_project,
                 'iamPolicy': {'bindings': [binding(actas, AGENT)] if agent_actas else []}}]
    if other_account:
        accounts.append({'email': 'other@p1.iam.gserviceaccount.com', 'projectId': 'p1',
                         'iamPolicy': {'bindings': []}})
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT,
                                 'bindings': [binding(runtime, 'serviceAccount:' + runner)]}]),
        ('iam_role', PROJECT, roles),
        ('iam_deny_policy', PROJECT, [
            {'name': PROJECT + '/denyPolicies/block-pipeline-create',
             'rules': [{'denyRule': {
                 'deniedPermissions': ['datafusion.googleapis.com/pipelines.create'],
                 'deniedPrincipals': [SOURCE]}}]}
        ] if deny_create else ([
            {'name': PROJECT + '/denyPolicies/block-instance-policy-write',
             'rules': [{'denyRule': {
                 'deniedPermissions': ['datafusion.googleapis.com/instances.setIamPolicy'],
                 'deniedPrincipals': [SOURCE]}}]}
        ] if deny_instance_write else []),
         'collected' if deny_create or deny_instance_write else 'empty'),
        ('datafusion_privesc_instance', PROJECT, [fusion]),
    ]
    if external:
        collections.extend([
            ('project', 'projects/p2', [{'projectId': 'p2', 'name': 'projects/456'}]),
            ('iam_policy', 'projects/p2', [{'name': 'projects/p2',
                                           'bindings': [binding('projects/p2/roles/worker',
                                                                'serviceAccount:' + runner)]}]),
            ('iam_role', 'projects/p2', [{'name': 'projects/p2/roles/worker',
                                         'includedPermissions': ['dataproc.agents.create']}]),
            ('iam_deny_policy', 'projects/p2', [], 'empty'),
            ('datafusion_privesc_instance', 'projects/p2', [], 'empty'),
        ])
    collections.append(('service_account', 'projects/' + cluster_project, accounts))
    snap = snapshot('gcp', collections)
    return [(target_id, grant.confidence)
            for reach in Evaluator(GcpModel(snap), [entry]).run()
            if reach.source.id == SOURCE for target_id, grant in reach.targets.items()]


def test_installed_code_plugin_and_exact_namespace_and_runner_rights():
    assert case() == [('serviceAccount:' + RUNNER, 'conditional')]
    assert case(missing_default=True) == [('serviceAccount:' + RUNNER, 'conditional')]
    assert case(external=True) == [
        ('serviceAccount:runner@p2.iam.gserviceaccount.com', 'conditional')]


def test_missing_plugin_or_exact_namespace_permission_is_not_positive():
    assert case(plugin=False) == []
    assert case(code=False) == []
    assert case(namespace_rights=False) == []
    assert case(profile=False) == []
    assert case(conditional='resource.name.startsWith("projects/p9/")') == []
    assert case(deny_create=True) == []


def test_missing_plugin_inventory_cannot_be_a_confirmed_path():
    result = case(missing_inventory=True)
    assert len(result) == 1 and result[0][1] == 'unknown'


def test_missing_agent_permission_is_unknown_only_for_named_runner():
    result = case(agent_actas=False, other_account=True)
    assert len(result) == 1 and result[0][1] == 'unknown'
