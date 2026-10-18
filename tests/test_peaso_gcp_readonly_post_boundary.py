"""GCP transport only authorizes service-bound stateless POST reads."""
from types import SimpleNamespace

import pytest
from peaso.collectors import gcp


class SpyCredentials:
    def __init__(self):
        self.calls = 0

    def headers(self):
        self.calls += 1
        return {'Authorization': 'Bearer inert-local-test'}


@pytest.fixture
def transport(monkeypatch):
    credentials = SpyCredentials()
    sent = []
    def request(method, url, **kwargs):
        sent.append((method, url))
        return SimpleNamespace(status_code=200, json=lambda: {}, headers={})
    result = gcp.Transport(credentials, {'retries': 0}, sleep=lambda _: None)
    monkeypatch.setattr(result, '_session', lambda: SimpleNamespace(request=request, close=lambda: None))
    return result, credentials, sent


@pytest.mark.parametrize('url', [
    'https://cloudresourcemanager.googleapis.com/v3/projects/demo:getIamPolicy',
    'https://cloudresourcemanager.googleapis.com/v3/folders/123:getIamPolicy',
    'https://cloudresourcemanager.googleapis.com/v3/organizations/123:getIamPolicy',
    'https://cloudresourcemanager.googleapis.com/v1/projects/demo:getAncestry',
    'https://bigtableadmin.googleapis.com/v2/projects/demo/instances/one:getIamPolicy',
    'https://iam.googleapis.com/v1/projects/-/serviceAccounts/a@demo.iam.gserviceaccount.com:getIamPolicy',
    'https://logging.googleapis.com/v2/entries:list',
    'https://policytroubleshooter.googleapis.com/v3beta/iam:troubleshoot',
])
def test_documented_stateless_post_reads_reach_transport(transport, url):
    client, credentials, sent = transport
    client.request('POST', url, scope='projects/demo', body={})
    assert credentials.calls == 1
    assert sent == [('POST', url)]


@pytest.mark.parametrize('method,url', [
    ('POST', 'https://cloudkms.googleapis.com/v2/entries:list'),
    ('POST', 'https://logging.googleapis.com/v1/projects/demo:getAncestry'),
    ('POST', 'https://cloudkms.googleapis.com/v1/projects/demo/locations/global/keyRings/r/cryptoKeys/k:getIamPolicy'),
    ('POST', 'https://logging.googleapis.com/v2/projects/demo:getIamPolicy'),
    ('POST', 'https://cloudresourcemanager.googleapis.com/v3/projects/demo:delete:getIamPolicy'),
    ('POST', 'https://logging.googleapis.com/v2/entries:write'),
    ('PATCH', 'https://cloudresourcemanager.googleapis.com/v3/projects/demo:getIamPolicy'),
    ('DELETE', 'https://cloudresourcemanager.googleapis.com/v3/projects/demo'),
])
def test_foreign_or_mutating_action_rejected_before_credentials(transport, method, url):
    client, credentials, sent = transport
    with pytest.raises(gcp.ReadError, match='cloud_mutation_prohibited'):
        client.request(method, url, scope='projects/demo', body={})
    assert credentials.calls == 0
    assert sent == []
    assert client.calls == 0
