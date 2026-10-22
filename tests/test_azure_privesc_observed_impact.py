"""Reviewed Azure privilege paths keep evidence and explain possible impact."""

import json
from pathlib import Path

from peaso.privesc.azure_observed_impact import _IMPACT, format_path
from peaso.privesc.finding_explanation import REVIEWED
from peaso.privesc import catalog


ROOT = Path(__file__).resolve().parents[1]


def test_reviewed_azure_paths_have_three_lines_without_check_limits():
    active = {entry['id'] for entry in catalog()['entries'] if entry['provider'] == 'azure'}
    assert len(active) == 162
    assert set(_IMPACT) == active
    for check_id, lines in _IMPACT.items():
        assert len(lines) == 2
        purpose = REVIEWED[check_id]['purpose']
        summary = f'alice has a recorded grant on the named resource. {purpose} Execution was not tested.'
        for status in ('FAIL', 'MANUAL'):
            result = format_path(check_id, status, summary, 'alice')
            assert len(result.splitlines()) == 3
            assert result.splitlines()[1:] == lines
            assert 'alice' in result.splitlines()[0]
            assert 'not tested' not in result
    for check_id, row in REVIEWED.items():
        if not check_id.startswith('azure-'):
            continue
        summary = f'The named resource or grant for alice is unresolved. {row["purpose"]} No operation was attempted.'
        result = format_path(check_id, 'UNKNOWN', summary, 'alice')
        assert len(result.splitlines()) == 3
        assert 'No operation was attempted' not in result


def test_browser_fixture_keeps_exact_azure_reviewed_paths():
    rows = json.loads((ROOT / 'tests/fixtures/shared_evidence_review.json').read_text())
    for row in rows:
        if row['provider'] == 'azure' and (row['id'] in _IMPACT or row['id'] == 'admin-equivalent'):
            assert len(row['summary'].splitlines()) == 3, (row['id'], row['status'])
