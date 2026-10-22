"""Existing Device Farm test specs need one exact executed run and role effect."""

from peaso import privesc
from tests.test_peaso_privesc_exact_principal_tranche import ENTRIES, case
from tests.test_peaso_privesc_schema_ext import reached


ENTRY = next(e for e in ENTRIES if e['id'] == 'aws-devicefarm-schedulerun-existing-test-spec-passrole')


def _result(snapshot, source):
    return reached(privesc.analyze(snapshot, entries=[ENTRY]), source, ENTRY['id'])


def _parts(snapshot):
    fact = next(c for c in snapshot['collections'] if c['type'] == 'aws_privesc_challenge_evidence')['items'][0]
    upload = next(c for c in snapshot['collections'] if c['type'] == 'devicefarm_upload')
    pool = next(c for c in snapshot['collections'] if c['type'] == 'devicefarm_device_pool')
    actor = next(c for c in snapshot['collections'] if c['type'] == 'iam_user')['items'][0]
    grants = actor['UserPolicyList'][0]['PolicyDocument']['Statement']
    return fact, upload, pool, grants


def test_existing_spec_runs_without_create_upload_and_with_scoped_grants():
    snapshot, source, evidence = case(ENTRY)
    assert all('devicefarm:CreateUpload' not in statement['Action'] for statement in _parts(snapshot)[3])
    assert _result(snapshot, source) == {evidence['items'][0]['TargetId']: 'conditional'}


def test_existing_spec_accepts_project_bound_accountless_pool():
    snapshot, source, evidence = case(ENTRY)
    fact, _, pool, grants = _parts(snapshot)
    old = fact['DevicePoolArn']
    new = old.replace(':111111111111:devicepool:', '::devicepool:')
    fact['DevicePoolArn'] = new
    pool['items'][0]['arn'] = new
    grants[0]['Resource'] = [new if arn == old else arn for arn in grants[0]['Resource']]
    assert _result(snapshot, source) == {evidence['items'][0]['TargetId']: 'conditional'}


def test_existing_spec_rejects_cross_resource_and_unexecuted_claims():
    mutations = [
        lambda fact, upload, pool, grants: fact.update(TestSpecArn=fact['TestPackageArn']),
        lambda fact, upload, pool, grants: fact.update(TestPackageArn=fact['TestSpecArn']),
        lambda fact, upload, pool, grants: upload['items'][0].update(status='FAILED'),
        lambda fact, upload, pool, grants: upload['items'].append(dict(upload['items'][0])),
        lambda fact, upload, pool, grants: pool['items'][0].update(CompatibleWebNodeDevices=0),
        lambda fact, upload, pool, grants: pool['items'][0].update(ProjectArn='arn:aws:devicefarm:us-east-1:111111111111:project:other'),
        lambda fact, upload, pool, grants: grants[0].update(Resource=[fact['ProjectArn'], fact['DevicePoolArn'], fact['TestPackageArn']]),
        lambda fact, upload, pool, grants: grants[1]['Condition']['StringEquals'].update({'iam:PassedToService': 'lambda.amazonaws.com'}),
        lambda fact, upload, pool, grants: fact.update(RunExecutedTestSpec=False),
        lambda fact, upload, pool, grants: fact.update(TestSpecControlledBySource=False),
        lambda fact, upload, pool, grants: fact.update(RoleActionSucceeded=False),
    ]
    for mutate in mutations:
        snapshot, source, _ = case(ENTRY)
        mutate(*_parts(snapshot))
        assert 'conditional' not in _result(snapshot, source).values()
