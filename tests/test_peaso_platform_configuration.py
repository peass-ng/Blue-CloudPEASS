"""Runtime token configuration has no implicit operator infrastructure dependency."""
import json
from types import SimpleNamespace

import pytest

from peaso.ai import auth
from tests.test_peaso_ai_review import token


@pytest.fixture
def no_default_access(monkeypatch):
    monkeypatch.delenv('CODEX_ACCESS_TOKEN', raising=False)
    monkeypatch.delenv('CODEX_TOKEN_SECRET_ARN', raising=False)
    monkeypatch.setenv('PEASO_AUTH_MODE', 'cognito')


def test_hosted_mode_does_not_discover_a_token_source(no_default_access, monkeypatch):
    import boto3
    monkeypatch.setattr(boto3, 'client', lambda *a, **kw: pytest.fail('Unconfigured AWS lookup'))
    monkeypatch.setattr(boto3, 'resource', lambda *a, **kw: pytest.fail('Legacy table lookup'))
    with pytest.raises(RuntimeError, match='^codex_auth_unavailable$'):
        auth.default_token()


@pytest.mark.parametrize('encoded', [False, True])
def test_configured_secret_is_read_at_runtime_and_picks_its_region(no_default_access, monkeypatch, encoded):
    import boto3
    access = token()
    arn = 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:example-token-abcdef'
    monkeypatch.setenv('CODEX_TOKEN_SECRET_ARN', arn)
    def read(**kwargs):
        assert kwargs == {'SecretId': arn}
        return {'SecretString': json.dumps({'access_token': access}) if encoded else access}
    def client(service, **kwargs):
        assert service == 'secretsmanager' and kwargs == {'region_name': 'eu-west-1'}
        return SimpleNamespace(get_secret_value=read)
    monkeypatch.setattr(boto3, 'client', client)
    assert auth.default_token() == access


def test_explicit_token_precedes_secret_lookup(no_default_access, monkeypatch):
    import boto3
    access = token()
    monkeypatch.setenv('CODEX_ACCESS_TOKEN', access)
    monkeypatch.setenv('CODEX_TOKEN_SECRET_ARN', 'configured-secret')
    monkeypatch.setattr(boto3, 'client', lambda *a, **kw: pytest.fail('Unnecessary API read'))
    assert auth.default_token() == access


@pytest.mark.parametrize('raw', ['expired', '{"access_token":42}', '{"other":"value"}', '[]'])
def test_unusable_secret_fails_without_disclosing_contents(no_default_access, monkeypatch, raw):
    import boto3
    monkeypatch.setenv('CODEX_TOKEN_SECRET_ARN', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:private-name')
    monkeypatch.setattr(boto3, 'client', lambda *a, **kw: SimpleNamespace(get_secret_value=lambda **kw: {'SecretString': raw}))
    with pytest.raises(RuntimeError, match='^codex_auth_unavailable$'):
        auth.default_token()


def test_aws_error_does_not_disclose_secret_identifier(no_default_access, monkeypatch):
    import boto3
    arn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:private-name'
    monkeypatch.setenv('CODEX_TOKEN_SECRET_ARN', arn)
    def read(**kwargs):
        raise RuntimeError('AccessDenied for ' + arn)
    monkeypatch.setattr(boto3, 'client', lambda *a, **kw: SimpleNamespace(get_secret_value=read))
    with pytest.raises(RuntimeError) as caught:
        auth.default_token()
    assert str(caught.value) == 'codex_auth_unavailable'
    assert caught.value.__suppress_context__
