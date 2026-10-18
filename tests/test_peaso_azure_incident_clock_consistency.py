# Historical fixture contracts; current native admission is tested separately.
"""A claimed triage event after the capture cutoff is not proof of compliance."""
from copy import deepcopy
import pytest
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_incident_triage_requirements import incident_snapshot, review, SCOPE, CID


@pytest.mark.parametrize('mode,expected', [('future_timely', 'UNKNOWN'), ('future_late', 'UNKNOWN'),
    ('mixed_future', 'UNKNOWN'), ('future_creation', 'NOT_APPLICABLE'),
    ('past_outside_window', 'NOT_APPLICABLE'), ('valid', 'PASS')])
def test_incident_and_triage_times_must_not_exceed_capture_cutoff(mode, expected):
    initial = incident_snapshot(review(), history=True)
    row = deepcopy(initial['collections'][0]['items'][0])
    if mode == 'future_timely':
        row['properties']['createdTimeUtc'] = '2026-10-12T11:00:00Z'
        row['triageHistory'][0]['at'] = '2026-10-12T12:30:00Z'
    elif mode == 'future_late': row['triageHistory'][0]['at'] = '2026-10-12T13:00:00Z'
    elif mode == 'mixed_future': row['triageHistory'].append({'type': 'triage', 'at': '2026-10-12T13:00:00Z'})
    elif mode == 'future_creation': row['properties']['createdTimeUtc'] = '2026-10-12T13:00:00Z'
    elif mode == 'past_outside_window': row['properties']['createdTimeUtc'] = '2026-10-09T10:00:00Z'
    snapshot = make_snapshot('azure', [SCOPE], [{'type': 'defender_incident', 'scope': SCOPE,
        'status': 'collected', 'items': [row]}], created_at='2026-10-12T12:00:00Z',
        metadata={'compliance_policy': {'sw27': review()}})
    findings = evaluate_snapshot(snapshot, checks=[CID])['findings']
    assert findings and {finding['status'] for finding in findings} == {expected}
