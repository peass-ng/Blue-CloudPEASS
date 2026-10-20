"""Codex discovery may omit usable manual IDs; inference still must succeed."""
import base64
import json
import time

import pytest
from peaso.ai import auth, providers


def token():
    claims = {'exp': time.time() + 3600, 'https://api.openai.com/auth': {'chatgpt_account_id': 'synthetic-account'}}
    return 'e30.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.synthetic'


def http(monkeypatch, terminal, models):
    calls = []
    class Response:
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def iter_content(self, size): yield json.dumps({'models': models}).encode()
        def iter_lines(self, **kwargs): yield b'data: ' + json.dumps(terminal).encode()
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs)); return Response()
        def post(self, url, **kwargs):
            calls.append(('POST', url, kwargs)); return Response()
    monkeypatch.setattr('requests.Session', Session)
    monkeypatch.setattr(auth, 'default_token', lambda: pytest.fail('Never substitute platform credentials'))
    return calls


@pytest.mark.parametrize('model,effort', [('gpt-6-sol', 'high'), ('custom-account-alias', 'medium')])
def test_unlisted_valid_alias_runs_exact_real_probe_adapter(monkeypatch, model, effort):
    access = providers.check_selection('codex', model, effort, token())
    calls = http(monkeypatch, {'type': 'response.completed', 'response': {'id': 'synthetic-confirmed', 'status': 'completed'}},
                 [{'slug': 'other-listed-model', 'supported_reasoning_levels': [{'effort': 'low'}]}])
    # Exercise provider_json + codex_probe through stubbed HTTP, not mocked
    # validation helpers. The old catalog gate fails before the POST here.
    assert providers.validate_before_launch(access) is access
    assert [call[0] for call in calls] == ['GET', 'POST']
    _, url, kwargs = calls[1]
    body, headers = kwargs['json'], kwargs['headers']
    assert url == 'https://chatgpt.com/backend-api/codex/responses'
    assert headers['Authorization'] == 'Bearer ' + access.credential
    assert headers['ChatGPT-Account-ID'] == 'synthetic-account'
    assert body['model'] == model
    assert body['reasoning'] == {'effort': effort}
    assert body['stream'] is True and body['store'] is False
    assert 'max_output_tokens' not in body
    assert body['tools'][0]['name'] == 'configuration_probe'
    assert kwargs['stream'] is True and kwargs['allow_redirects'] is False


def test_unlisted_invalid_alias_probe_rejection_blocks_without_fallback(monkeypatch):
    access = providers.check_selection('codex', 'unavailable-manual-id', 'high', token())
    calls = http(monkeypatch, {'type': 'response.failed', 'response': {'id': 'rejected', 'error': {'message': 'PRIVATE provider failure'}}}, [])
    with pytest.raises(providers.ConfigurationError, match='inference validation failed') as failure:
        providers.validate_before_launch(access)
    assert 'PRIVATE' not in str(failure.value)
    assert [call[0] for call in calls] == ['GET', 'POST']
    assert calls[1][2]['json']['model'] == 'unavailable-manual-id'
    assert calls[1][2]['json']['reasoning'] == {'effort': 'high'}


def test_listed_model_advertised_unsupported_effort_still_rejected_before_probe(monkeypatch):
    access = providers.check_selection('codex', 'listed-model', 'high', token())
    calls = http(monkeypatch, {'type': 'response.completed', 'response': {'id': 'must-not-be-called'}},
                 [{'slug': 'listed-model', 'supported_reasoning_levels': [{'effort': 'low'}]}])
    with pytest.raises(providers.ConfigurationError, match='unavailable for this Codex account'):
        providers.validate_before_launch(access)
    assert [call[0] for call in calls] == ['GET']
