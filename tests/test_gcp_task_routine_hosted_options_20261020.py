"""Hosted optional content selectors are validated before authentication."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from peaso.server.validation import OPTIONS, validate_connector

SCOPE = 'projects/review-project'
TARGETS = [
    ('selected_cloudtasks_tasks', SCOPE + '/locations/us-central1/queues/queue/tasks/task'),
    ('selected_bigquery_routines', SCOPE + '/datasets/dataset/routines/routine'),
]


def validate(provider, option, selection, scopes=None):
    validate_connector(provider, {}, {option: selection}, SimpleNamespace(auth_mode='local'), scopes=scopes or [SCOPE])


@pytest.mark.parametrize('option,target', TARGETS)
def test_exact_same_project_selector_is_available_without_credential_reads(option, target):
    assert option in OPTIONS
    validate('gcp', option, [target])
    validate('gcp', option, [target + str(i) for i in range(8)])


@pytest.mark.parametrize('option,target', TARGETS)
@pytest.mark.parametrize('fault', ['empty', 'none', 'not_list', 'duplicate', 'foreign', 'url', 'query', 'many', 'many_scopes', 'wrong_provider'])
def test_invalid_content_scope_never_reaches_authentication(option, target, fault):
    selection, scopes, provider = [target], [SCOPE], 'gcp'
    if fault == 'empty': selection = []
    elif fault == 'none': selection = None
    elif fault == 'not_list': selection = target
    elif fault == 'duplicate': selection *= 2
    elif fault == 'foreign': selection = [target.replace('review-project', 'foreign-project')]
    elif fault == 'url': selection = ['https://example.com/' + target]
    elif fault == 'query': selection = [target + '?view=FULL']
    elif fault == 'many': selection = [target + str(i) for i in range(9)]
    elif fault == 'many_scopes': scopes += ['projects/another-project']
    elif fault == 'wrong_provider': provider = 'aws'
    with pytest.raises(HTTPException) as error:
        validate(provider, option, selection, scopes)
    assert error.value.status_code == 422
