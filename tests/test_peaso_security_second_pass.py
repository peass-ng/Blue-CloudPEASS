"""Adversarial regressions; all identities/cloud calls are synthetic."""
from types import SimpleNamespace

import boto3
import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from peaso.auth.aws_trust import require_external_id_boundary, UnsafeRoleTrust
from peaso.storage import SQLiteStore, StoreError
from peaso.storage.dynamodb import DynamoStore


def denied():
    return ClientError({'Error': {'Code': 'AccessDenied'}}, 'AssumeRole')


@pytest.mark.parametrize('policy', ['no_condition', 'wildcard', 'exact', 'timeout'])
def test_shared_collector_requires_verified_exact_external_id(policy):
    calls = []
    def assume(external):
        calls.append(external)
        if policy == 'timeout':
            raise TimeoutError()
        if policy == 'exact' or policy == 'wildcard' and external is None:
            raise denied()
        return {'Credentials': {'SessionToken': 'discard-this-probe'}}
    if policy == 'exact':
        require_external_id_boundary(assume, 'hacktricks-cspm-ws-customer')
        assert len(calls) == 2
    else:
        with pytest.raises(UnsafeRoleTrust):
            require_external_id_boundary(assume, 'hacktricks-cspm-ws-customer')
    assert calls[0] is None
    if len(calls) == 2:
        assert calls[1].startswith('hacktricks-cspm-ws-') and calls[1] != 'hacktricks-cspm-ws-customer'


@pytest.mark.parametrize('policy', ['no_condition', 'wildcard', 'exact', 'timeout'])
@pytest.mark.parametrize('entrypoint', ['access_check', 'logs'])
def test_aws_reads_never_use_unbound_shared_collector(monkeypatch, policy, entrypoint):
    from peaso.server import access_check, attack_logs
    role = 'arn:aws:iam::123456789012:role/Audit'
    external = 'hacktricks-cspm-ws-customer'
    exchanges, reads = [], []
    class Session:
        def __init__(self, phase): self.phase = phase
        def client(self, service, **kwargs):
            if service != 'sts': reads.append(service)
            return Client(self.phase)
    class Client:
        def __init__(self, phase): self.phase = phase
        def assume_role(self, **params):
            exchanges.append((self.phase, params))
            if self.phase == 'source':
                phase = 'broker'
            else:
                value = params.get('ExternalId')
                if policy == 'timeout': raise TimeoutError()
                if policy == 'exact' and value != external or policy == 'wildcard' and value is None:
                    raise denied()
                phase = 'customer'
            return {'Credentials': {'AccessKeyId': phase, 'SecretAccessKey': 'inert', 'SessionToken': 'inert'}}
        def get_caller_identity(self):
            reads.append('identity')
            return {'Account': '123456789012', 'Arn': role}
        def __getattr__(self, name):
            def read(**kwargs):
                reads.append(name)
                return {}
            return read
    factory = lambda *a, **kw: (Session('source'), 'fixture')
    monkeypatch.setattr('peaso.collectors.aws._session', factory)
    monkeypatch.setattr(attack_logs, '_session', factory)
    monkeypatch.setattr(boto3, 'Session', lambda **kw: Session(kw['aws_access_key_id']))
    auth = {'method': 'assume_role', 'external_id': external, 'role_arn': role}
    if entrypoint == 'access_check':
        issues, principals = [], []
        access_check._aws(auth, [], {}, issues, principals)
        assert bool(principals) is (policy == 'exact')
    else:
        source = SimpleNamespace(kind='aws_event_history', role_arn=role, region='us-east-1')
        if policy == 'exact':
            assert attack_logs.check_aws_source(auth, {}, source)['source_status'] == 'accessible'
        else:
            with pytest.raises(attack_logs.LogAccessError, match='external_id_trust_unverified'):
                attack_logs.check_aws_source(auth, {}, source)
    assert bool(reads) is (policy == 'exact')
    # Every probe must use the actual exchange's parameters; session-name or
    # duration-specific trust must not let a misleading probe authorize reads.
    target_calls = [params for phase, params in exchanges if phase == 'broker']
    assert len({(p['RoleSessionName'], p.get('DurationSeconds')) for p in target_calls}) == 1


@pytest.fixture(params=['sqlite', 'dynamodb'])
def store(request, tmp_path):
    if request.param == 'sqlite':
        yield SQLiteStore(tmp_path / 'db')
        return
    from moto import mock_aws
    with mock_aws():
        client = boto3.client('dynamodb', region_name='us-east-1', aws_access_key_id='inert', aws_secret_access_key='inert')
        client.create_table(TableName='security', KeySchema=[{'AttributeName': k, 'KeyType': t} for k, t in [('PK', 'HASH'), ('SK', 'RANGE')]],
            AttributeDefinitions=[{'AttributeName': k, 'AttributeType': 'S'} for k in ['PK', 'SK']], BillingMode='PAY_PER_REQUEST')
        yield DynamoStore('security', client)


@pytest.mark.parametrize('action', ['invite', 'grant', 'remove', 'revoke'])
@pytest.mark.parametrize('new_role', [None, 'read', 'write'])
def test_revoked_admin_cannot_finish_inflight_membership_write(store, action, new_role):
    wid = store.create_workspace('owner', 'Team', 'team', 'owner@example.com')['id']
    for user, role in [('attacker', 'admin'), ('reader', 'read')]:
        store.invite_workspace(wid, user, user + '@example.com', role, 'owner')
        store.respond_workspace_invitation(wid, user, True)
    store.invite_workspace(wid, 'pending', 'pending@example.com', 'read', 'owner')
    # This is the permission result obtained by an already in-flight request.
    assert store.workspace_role(wid, 'attacker') == 'admin'
    if new_role is None:
        store.remove_workspace_member(wid, 'attacker', actor='owner')
    else:
        store.set_workspace_role(wid, 'attacker', new_role, actor='owner')
    operations = {
        'invite': lambda: store.invite_workspace(wid, 'backdoor', 'backdoor@example.com', 'admin', 'attacker'),
        'grant': lambda: store.set_workspace_role(wid, 'reader', 'admin', actor='attacker'),
        'remove': lambda: store.remove_workspace_member(wid, 'reader', actor='attacker'),
        'revoke': lambda: store.revoke_workspace_invitation(wid, 'pending', actor='attacker'),
    }
    with pytest.raises(StoreError) as exc:
        operations[action]()
    assert exc.value.status == 403
    assert store.workspace_role(wid, 'reader') == 'read'
    assert store.workspace_invitations('backdoor') == []
    assert len(store.workspace_invitations('pending')) == 1


def test_admin_can_demote_self_atomically(store):
    wid = store.create_workspace('owner', 'Team', 'team', 'owner@example.com')['id']
    store.invite_workspace(wid, 'admin', 'admin@example.com', 'admin', 'owner')
    store.respond_workspace_invitation(wid, 'admin', True)
    store.set_workspace_role(wid, 'admin', 'read', actor='admin')
    assert store.workspace_role(wid, 'admin') == 'read'


def test_admin_can_remove_self_atomically(store):
    wid = store.create_workspace('owner', 'Team', 'team', 'owner@example.com')['id']
    store.invite_workspace(wid, 'admin', 'admin@example.com', 'admin', 'owner')
    store.respond_workspace_invitation(wid, 'admin', True)
    store.remove_workspace_member(wid, 'admin', actor='admin')
    assert store.workspace_role(wid, 'admin') is None
    assert store.workspaces('admin') == []


def test_api_directory_lookup_cannot_finish_invite_after_admin_revocation(store, tmp_path):
    from peaso.auth import Identity
    from peaso.server import create_app
    from peaso.server.config import Settings
    wid = store.create_workspace('owner', 'Team', 'team', 'owner@example.com')['id']
    store.invite_workspace(wid, 'attacker', 'attacker@example.com', 'admin', 'owner')
    store.respond_workspace_invitation(wid, 'attacker', True)
    class Auth:
        def authenticate(self, authorization): return Identity('attacker', True)
        def find_user_by_email(self, email):
            # Owner revokes access while the directory lookup is in progress.
            store.remove_workspace_member(wid, 'attacker', actor='owner')
            return {'user_id': 'backdoor', 'email': email}
    settings = Settings(auth_mode='cognito', state_dir=tmp_path/'state', identity_dir=tmp_path/'identity')
    with TestClient(create_app(settings, store=store, authenticator=Auth()), base_url='http://localhost:8000') as client:
        response = client.post(f'/api/workspaces/{wid}/invitations', headers={'Authorization': 'Bearer inert'},
            json={'email': 'backdoor@example.com', 'role': 'admin'})
    assert response.status_code == 403
    assert store.workspace_invitations('backdoor') == []
