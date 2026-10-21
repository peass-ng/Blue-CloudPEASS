from datetime import datetime, timezone
import io
import json
from types import SimpleNamespace

import pytest
from peaso.collectors import azure
from runtime_native import collect
from test_runtime_reader import SITE, payloads

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)


class Credential:
    def __init__(self): self.scopes = []
    def get_token(self, scope):
        self.scopes.append(scope)
        return SimpleNamespace(token='synthetic-token-never-exported', expires_on=4102444800)


class Response(io.BytesIO):
    status = 200


class Opener:
    def __init__(self, bodies):
        self.bodies, self.calls = list(bodies), []
    def open(self, request, timeout):
        assert request.get_method() == 'GET'
        assert request.data is None
        assert request.get_header('Authorization') == 'Bearer synthetic-token-never-exported'
        self.calls.append(request.full_url)
        return Response(json.dumps(self.bodies.pop(0)).encode())


@pytest.mark.parametrize('cap,expected,count', [(3, 'PASS', 3), (2, 'UNKNOWN', 2)])
def test_existing_credentials_scheduler_and_native_http_contract(monkeypatch, cap, expected, count):
    credential, opener = Credential(), Opener(payloads())
    monkeypatch.setattr(azure, 'build_opener', lambda *args: opener)
    reader = azure._Reader({'retries': 0, 'max_calls': cap})
    transport = azure.AzureTransport({'method': 'auto'}, credential=credential)
    result = collect(reader, transport.request, site_id=SITE, scope=SCOPE, selected=True, as_of=NOW)
    assert result['status'] == expected
    assert len(opener.calls) == reader.budget.calls == count
    assert credential.scopes == ['https://management.azure.com/.default']
    assert 'synthetic-token-never-exported' not in json.dumps(result)
    assert all(url.startswith('https://management.azure.com/') for url in opener.calls)
