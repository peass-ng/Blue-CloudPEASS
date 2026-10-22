"""An unusable AWS session must stop before any inventory is scheduled."""
from types import SimpleNamespace
import pytest
from botocore.exceptions import ClientError
from peaso.worker import _verify_aws_credentials


def test_expired_session_fails_with_sanitized_error(monkeypatch):
    from peaso.collectors import aws
    calls = []
    def denied():
        calls.append('identity')
        raise ClientError({'Error': {'Code': 'ExpiredToken', 'Message': 'PRIVATE_PROVIDER_DETAIL'}}, 'GetCallerIdentity')
    monkeypatch.setattr(aws, '_session', lambda auth, region: (SimpleNamespace(client=lambda *a, **kw: SimpleNamespace(get_caller_identity=denied)), 'selected'))
    with pytest.raises(PermissionError, match='authentication failed before collection') as error:
        _verify_aws_credentials({'provider': 'aws', 'auth': {'method': 'access_keys'}})
    assert calls == ['identity']
    assert 'PRIVATE_PROVIDER_DETAIL' not in str(error.value)
    assert error.value.__suppress_context__ is True


def test_valid_selected_session_has_one_bounded_identity_probe(monkeypatch):
    from peaso.collectors import aws
    calls = []
    def session(auth, region):
        assert auth == {'method': 'profile', 'profile': 'selected'}
        assert region == 'eu-west-1'
        def client(service, config):
            assert service == 'sts' and config.connect_timeout == 5 and config.read_timeout == 10
            return SimpleNamespace(get_caller_identity=lambda: calls.append('identity'))
        return SimpleNamespace(client=client), 'selected'
    monkeypatch.setattr(aws, '_session', session)
    _verify_aws_credentials({'provider': 'aws', 'auth': {'method': 'profile', 'profile': 'selected'}, 'options': {'regions': ['eu-west-1']}})
    assert calls == ['identity']


def test_other_providers_do_not_probe_aws():
    _verify_aws_credentials({'provider': 'gcp'})


def test_offline_aws_snapshot_does_not_require_live_credentials(monkeypatch):
    from peaso.collectors import aws
    def must_not_authenticate(*args, **kwargs):
        raise AssertionError('Offline snapshot evaluation must not contact AWS')
    monkeypatch.setattr(aws, '_session', must_not_authenticate)
    _verify_aws_credentials({'provider': 'aws', 'input_mode': 'offline_snapshot'})
    _verify_aws_credentials({'provider': 'aws', 'input_mode': 'demo'})
