"""Collect only the exact linked repository state needed for the proxy path."""

import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType

import pytest

_PATH = Path(__file__).resolve().parents[1] / 'peaso/collectors/gcp_developerconnect_links.py'
_SPEC = spec_from_file_location('peaso.collectors.gcp_developerconnect_links', _PATH)
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
collection_pages = _MODULE.collection_pages


LINK = 'projects/p1/locations/us-central1/connections/c/gitRepositoryLinks/r'


class ReadError(Exception):
    def __init__(self, status, error):
        self.status = status
        self.error = error


class Collector:
    options = {'cloudbuild_locations': ['us-central1']}
    allowed = None

    def __init__(self, response):
        self.response = response
        self.reads = []

    def pages(self, url, scope, **kwargs):
        assert scope == 'projects/p1'
        assert kwargs['key'] == 'triggers'
        if '/locations/us-central1/' in url:
            yield [{'developerConnectEventConfig': {'gitRepositoryLink': LINK}},
                   {'developerConnectEventConfig': {'gitRepositoryLink': LINK}}], 'triggers-request'
        else:
            yield [], 'global-request'

    def read(self, url, scope):
        self.reads.append((url, scope))
        return self.response, 'link-request'


@pytest.fixture(autouse=True)
def stub_collector_error(monkeypatch):
    package = ModuleType('peaso.collectors')
    package.__path__ = []
    module = ModuleType('peaso.collectors.gcp')
    module.ReadError = ReadError
    history = ModuleType('peaso.collectors.gcp_history')
    history.cloudbuild_locations = lambda collector, scope: iter([(['global', 'us-central1'], None)])
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setitem(sys.modules, history.__name__, history)


def test_link_projection_reads_once_and_drops_unneeded_provider_fields():
    collector = Collector({'name': LINK,
                           'gitProxyUri': 'https://proxy.developerconnect.dev/r',
                           'reconciling': False,
                           'token': 'discard-me'})
    result = list(collection_pages(collector, 'projects/p1'))
    rows = [row for batch, _ in result for row in batch]
    assert rows == [{'name': LINK,
                     'gitProxyUri': 'https://proxy.developerconnect.dev/r',
                     'reconciling': False, '_representation': 'partial'}]
    assert collector.reads == [('https://developerconnect.googleapis.com/v1/' + LINK,
                                'projects/p1')]
    assert 'discard-me' not in repr(result)


def test_link_identity_mismatch_is_rejected():
    with pytest.raises(ReadError) as caught:
        list(collection_pages(Collector({'name': LINK + '-other'}), 'projects/p1'))
    assert caught.value.status == 'malformed'
