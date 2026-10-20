"""Ordinary native response edge cases for each unregistered Workbench proposal."""
import pytest

from tests.test_gcp_workbench_head3_proposal_20261020 import ordinary_capture, SCOPE, NAME
from peaso.checks.gcp_workbench_head3_proposal_20261020 import EVALUATORS


@pytest.mark.parametrize('cid', tuple(EVALUATORS))
@pytest.mark.parametrize('case,expected', [
    ('omitted', 'FAIL'), ('deleted', 'NOT_APPLICABLE'), ('foreign', 'UNKNOWN'),
    ('unrecognized_state', 'UNKNOWN'), ('malformed_metadata', 'UNKNOWN'),
    ('redacted', 'UNKNOWN'),
])
def test_ordinary_native_edges_per_control(cid, case, expected):
    metadata = {'notebook-disable-terminal': 'true', 'notebook-disable-downloads': 'true',
                'notebook-upgrade-schedule': '00 19 * * MON'}
    kwargs = {}
    if case == 'omitted':
        metadata = {}
    elif case == 'deleted':
        kwargs['state'] = 'DELETED'
    elif case == 'foreign':
        kwargs['name'] = NAME.replace('/review/', '/other/')
    elif case == 'unrecognized_state':
        kwargs['state'] = 'FUTURE_STATE'
    elif case == 'malformed_metadata':
        metadata = None
    elif case == 'redacted':
        metadata = {key: None for key in metadata}
    item, index, snapshot = ordinary_capture(metadata, **kwargs)
    actual, evidence = EVALUATORS[cid](item, index)
    assert actual == expected, (cid, case, actual, evidence)
    assert snapshot['provider'] == 'gcp' and index['context']['scope'] == SCOPE
