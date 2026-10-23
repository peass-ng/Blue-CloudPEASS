"""Profile and schedule overrides select one concrete Data Fusion runner."""

from peaso.privesc.effective_permissions.gcp_datafusion_artifact import resolve_runner


INSTANCE = {'name': 'projects/p1/locations/us-central1/instances/fusion',
            'dataprocServiceAccount': 'instance@p1.iam.gserviceaccount.com'}
PROFILE = {'name': 'runner', 'scope': 'USER', 'status': 'ENABLED',
           'provisioner': 'gcp-dataproc',
           'runnerServiceAccount': {'value': 'profile@p1.iam.gserviceaccount.com',
                                    'isEditable': True},
           'projectId': {'value': 'p1', 'isEditable': False}}
NAMESPACE = {'profiles': [PROFILE]}
APP = {'workflowProfile': {'profileName': 'user:runner',
                           'runnerServiceAccountOverride': None}}
NUMBERS = {'p1': '123', 'other-project': '456'}


def test_schedule_profile_and_editable_runner_override_take_precedence():
    assert resolve_runner(INSTANCE, NAMESPACE, APP, {}, NUMBERS) == (
        'profile@p1.iam.gserviceaccount.com', None)
    schedule = {'runnerServiceAccountOverride': 'scheduled@p1.iam.gserviceaccount.com'}
    assert resolve_runner(INSTANCE, NAMESPACE, APP, schedule, NUMBERS) == (
        'scheduled@p1.iam.gserviceaccount.com', None)


def test_locked_override_does_not_invent_runner():
    namespace = {'profiles': [{**PROFILE, 'runnerServiceAccount': {
        'value': 'profile@p1.iam.gserviceaccount.com', 'isEditable': False}}]}
    schedule = {'runnerServiceAccountOverride': 'scheduled@p1.iam.gserviceaccount.com'}
    assert resolve_runner(INSTANCE, namespace, APP, schedule, NUMBERS) == (
        None, 'datafusion_runner_override_lock_unresolved')


def test_missing_profile_and_cross_project_default_are_handled_exactly():
    assert resolve_runner(INSTANCE, {'profiles': []}, APP, {}, NUMBERS) == (
        None, 'datafusion_profile_not_unique_or_missing')
    namespace = {'profiles': [{**PROFILE, 'runnerServiceAccount': None,
                               'projectId': {'value': 'other-project', 'isEditable': False}}]}
    assert resolve_runner(INSTANCE, namespace, APP, {}, NUMBERS) == (
        '456-compute@developer.gserviceaccount.com', None)
    assert resolve_runner(INSTANCE, namespace, APP, {}, {'p1': '123'}) == (
        None, 'datafusion_profile_project_number_missing')


def test_builtin_profile_uses_instance_runner_only_when_no_profile_is_selected():
    app = {'workflowProfile': {'profileName': None,
                               'runnerServiceAccountOverride': None}}
    assert resolve_runner(INSTANCE, NAMESPACE, app, {}, NUMBERS) == (
        'instance@p1.iam.gserviceaccount.com', None)
