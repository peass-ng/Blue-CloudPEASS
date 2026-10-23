"""Deployment eligibility reads only exact deployment names and fingerprints."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest


_PATH = Path(__file__).resolve().parents[1] / 'peaso/collectors/gcp_deploymentmanager_deployments.py'
_SPEC = spec_from_file_location('deployment_manager_projection', _PATH)
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def test_deployment_projection_keeps_only_eligibility_and_update_fields():
    assert _MODULE.project({'name': 'prior-deployment', 'fingerprint': 'abc',
                            'target': {'password': 'discard-me'}}) == {
        'name': 'prior-deployment', 'fingerprint': 'abc'}


def test_malformed_names_and_fingerprints_are_rejected():
    for row in ({'name': 'Invalid'}, {'name': 'trailing-'},
                {'name': 'okay', 'fingerprint': 3}, {'name': 'okay', 'fingerprint': ''}):
        with pytest.raises(ValueError):
            _MODULE.project(row)


def test_collection_hydrates_policy_for_the_exact_listed_deployment():
    class Collector:
        def pages(self, url, scope, **kwargs):
            assert url == 'https://www.googleapis.com/deploymentmanager/v2/projects/p1/global/deployments'
            assert scope == 'projects/p1'
            assert kwargs['params'] == {'fields': 'deployments(name,fingerprint),nextPageToken'}
            yield [kwargs['transform']({'name': 'existing', 'fingerprint': 'current',
                                        'target': {'password': 'discard-me'}})], 'list-request'

        def hydrate(self, row, field, url, scope):
            assert field == 'iamPolicy'
            assert url.endswith('/projects/p1/global/deployments/existing/getIamPolicy')
            assert scope == 'projects/p1'
            return {**row, field: {'etag': 'etag123', 'bindings': []},
                    '_coverage': {field: {'status': 'collected'}}}

        def parallel(self, function, rows):
            return [function(row) for row in rows]

    pages = list(_MODULE.collection_pages(Collector(), 'projects/p1'))
    assert pages[0][0][0]['iamPolicy']['etag'] == 'etag123'
    assert 'discard-me' not in repr(pages)
