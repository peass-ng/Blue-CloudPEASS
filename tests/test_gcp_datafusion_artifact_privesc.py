"""Only a scheduled pipeline's exact replaceable plugin reaches its runner."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
INSTANCE = PROJECT + '/locations/us-central1/instances/fusion'
SOURCE = 'user:alice@example.com'
RUNNER = 'runner@p1.iam.gserviceaccount.com'
AGENT = 'serviceAccount:service-123@gcp-sa-datafusion.iam.gserviceaccount.com'
ENTRY = next(entry for entry in privesc.catalog()['entries']
             if entry['id'] == 'gcp-datafusion-artifacts-create-plugin-poison')


def case(*, scope='USER', version='1.0-SNAPSHOT', installed=True, delete=True,
         enabled=True, runner=RUNNER, artifact_permission=True, agent_actas=True,
         namespace_condition=None, deny_create=False, installed_version=None,
         external=False, missing_profile=False, malformed_artifacts=False,
         incomplete_refs=False, extra_service_account=False):
    target_email = 'runner@p2.iam.gserviceaccount.com' if external else RUNNER
    runner_email = target_email if external and runner == RUNNER else runner
    cluster_project = 'p2' if external else 'p1'
    caller_role = PROJECT + '/roles/fusionWriter'
    instance_role = PROJECT + '/roles/fusionAccessor'
    runner_role = PROJECT + '/roles/fusionRunner'
    agent_role = PROJECT + '/roles/actAs'
    namespace_permissions = ['datafusion.namespaces.get', 'datafusion.artifacts.create',
                             'datafusion.artifacts.update']
    if delete:
        namespace_permissions.append('datafusion.artifacts.delete')
    roles = [
        {'name': instance_role, 'includedPermissions': ['datafusion.instances.get']},
        {'name': caller_role, 'includedPermissions':
         namespace_permissions if artifact_permission else []},
        {'name': runner_role, 'includedPermissions': ['datafusion.instances.runtime']
         + ([] if external else ['dataproc.agents.create'])},
        {'name': agent_role, 'includedPermissions': ['iam.serviceAccounts.actAs']},
    ]
    binding = lambda role, member: {'role': role, 'members': [member]}
    pipeline = {'name': 'orders', 'hasDataPipelineWorkflow': True,
                'workflowProfile': {'profileName': 'user:profile',
                                    'runnerServiceAccountOverride': None},
                'pluginReferencesComplete': not incomplete_refs,
                'pluginArtifacts': [{'name': 'plugin', 'version': version, 'scope': scope}],
                'schedules': [{'name': 'daily', 'enabled': enabled,
                               'programName': 'DataPipelineWorkflow',
                               'programType': 'WORKFLOW', 'profileName': None,
                               'runnerServiceAccountOverride': None}]}
    profile = {'name': 'profile', 'scope': 'USER', 'status': 'ENABLED',
               'provisioner': 'gcp-dataproc',
               'runnerServiceAccount': {'value': runner_email, 'isEditable': False},
               'projectId': {'value': cluster_project, 'isEditable': False}}
    ns_binding = binding(caller_role, SOURCE)
    if namespace_condition:
        ns_binding['condition'] = {'title': 'namespace-restriction',
                                   'expression': namespace_condition}
    datafusion = {'name': INSTANCE, 'state': 'RUNNING', 'enableRbac': True,
                  'iamPolicy': {'bindings': [binding(instance_role, SOURCE)]},
                  'namespaces': [{'name': 'default',
                                  'iamPolicy': {'bindings': [ns_binding]},
                                  'applications': [pipeline],
                                  'profiles': [] if missing_profile else [profile],
                                  'artifacts': (None if malformed_artifacts else
                                                ([{'name': 'plugin',
                                                   'version': installed_version or version,
                                                   'scope': scope}] if installed else []))}]}
    runner_policy = {'bindings': [binding(agent_role, AGENT)] if agent_actas else []}
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT,
                                 'bindings': [binding(runner_role, 'serviceAccount:' + target_email)]}]),
        ('iam_role', PROJECT, roles),
        ('iam_deny_policy', PROJECT, [
            {'name': PROJECT + '/denyPolicies/block-artifact-create',
             'rules': [{'denyRule': {
                 'deniedPermissions': ['datafusion.googleapis.com/artifacts.create'],
                 'deniedPrincipals': [SOURCE]}}]}
        ] if deny_create else [], 'collected' if deny_create else 'empty'),
        ('datafusion_privesc_instance', PROJECT, [datafusion]),
    ]
    if external:
        other = 'projects/p2'
        worker_role = other + '/roles/worker'
        collections.extend([
            ('project', other, [{'projectId': 'p2', 'name': 'projects/456'}]),
            ('iam_policy', other, [{'name': other,
                                   'bindings': [binding(worker_role, 'serviceAccount:' + target_email)]}]),
            ('iam_role', other, [{'name': worker_role,
                                 'includedPermissions': ['dataproc.agents.create']}]),
            ('iam_deny_policy', other, [], 'empty'),
            ('datafusion_privesc_instance', other, [], 'empty'),
        ])
    accounts = [{'email': target_email, 'projectId': cluster_project,
                 'iamPolicy': runner_policy}]
    if extra_service_account:
        accounts.append({'email': 'unrelated@p1.iam.gserviceaccount.com',
                         'projectId': 'p1', 'iamPolicy': {'bindings': []}})
    collections.append(('service_account', 'projects/' + cluster_project, accounts))
    snap = snapshot('gcp', collections)
    return [(target_id, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for target_id, grant in reach.targets.items()]


def test_exact_snapshot_and_immutable_replacement_paths():
    assert case() == [('serviceAccount:' + RUNNER, 'conditional')]
    assert case(version='1.0.0') == [('serviceAccount:' + RUNNER, 'conditional')]
    assert case(version='1.0.0', installed=False, delete=False) == [
        ('serviceAccount:' + RUNNER, 'conditional')]
    # A different installed version does not block uploading the pinned one.
    assert case(version='1.0.0', installed_version='2.0.0', delete=False) == [
        ('serviceAccount:' + RUNNER, 'conditional')]
    assert case(external=True) == [
        ('serviceAccount:runner@p2.iam.gserviceaccount.com', 'conditional')]


def test_wrong_scope_disabled_schedule_and_missing_permissions_do_not_escalate():
    assert case(scope='SYSTEM') == []
    assert case(enabled=False) == []
    assert case(version='1.0.0', delete=False) == []
    assert case(artifact_permission=False) == []
    assert case(agent_actas=False)[0][1] == 'unknown'
    assert case(runner='other@p1.iam.gserviceaccount.com') == []
    assert case(namespace_condition='resource.name.startsWith("projects/p9/")') == []
    assert case(deny_create=True) == []


def test_unresolved_namespace_condition_stays_unknown():
    result = case(namespace_condition='resource.matchTag("123/env", "prod")')
    assert result and all(confidence == 'unknown' for _, confidence in result)
    assert case(namespace_condition='resource.name.startsWith("projects/p1/")') == []


def test_incomplete_collected_evidence_stays_unknown():
    # A complete profile list with no selected profile has no runnable path.
    assert case(missing_profile=True) == []
    for kwargs in ({'malformed_artifacts': True}, {'incomplete_refs': True}):
        result = case(**kwargs, extra_service_account=True)
        assert len(result) == 1 and result[0][1] == 'unknown'
