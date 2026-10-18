"""Retired owner-policy scenarios cannot re-enter automatic read-only scans."""
import json

import pytest

from peaso.checks import CHECKS
from peaso.checks.native_only import exclusions
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


DEFINITIONS = {check.id: check for check in CHECKS}
ARCHIVED = frozenset(exclusions())
ACTIVE = {
    provider: next(check.id for check in CHECKS
                   if check.provider == provider and check.id not in ARCHIVED)
    for provider in ("aws", "gcp", "azure", "k8s")
}


@pytest.mark.parametrize("check_id", sorted(ARCHIVED))
def test_archived_control_is_rejected_alone_and_in_mixed_selection(check_id):
    provider = DEFINITIONS[check_id].provider
    snapshot = make_snapshot(provider, [], [])
    before = json.dumps(snapshot, sort_keys=True)
    for selection in ([check_id], [ACTIVE[provider], check_id]):
        with pytest.raises(ValueError, match="requires external policy or manual evidence") as failure:
            evaluate_snapshot(snapshot, checks=selection)
        assert check_id in str(failure.value)
        assert json.dumps(snapshot, sort_keys=True) == before
