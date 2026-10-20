"""Preserved custom/history contracts are never silently selected for automation."""
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.native_only import exclusions,automated_checks
from peaso.engine import _selection
GCP={c.id for c in CHECKS if c.provider=='gcp'}
ARCHIVED=GCP&exclusions().keys()
@pytest.mark.parametrize('cid',sorted(ARCHIVED))
def test_each_archived_contract_remains_explicit_and_unselectable(cid):
    entry=exclusions()[cid]
    assert entry['reason'].strip()
    assert Path(__file__).resolve().parents[1].joinpath(entry['source'].split('::')[0].split(':')[0]).is_file()
    for alternative in entry.get('native_alternatives',[]):
        assert alternative in GCP and alternative not in ARCHIVED
    with pytest.raises(ValueError,match='not available for automated scans'):_selection('gcp',None,[cid],None)
def test_default_automated_roster_excludes_exact_archived_ids():
    selected={c.id for c in automated_checks(CHECKS)if c.provider=='gcp'}
    assert selected==GCP-ARCHIVED
    assert selected.isdisjoint(ARCHIVED)
