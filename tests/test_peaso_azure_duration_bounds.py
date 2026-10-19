"""Malformed durations must not turn retention/rotation checks green."""
import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_azure_common import cid
from peaso.checks.claude_azure_network import _flow, _watcher


def evaluate(suffix, item):
    check = next(c for c in CHECKS if c.id == cid(suffix))
    return check.evaluate(item, {})[0]


@pytest.mark.parametrize("days, expected", [(-90, "UNKNOWN"), (-1, "UNKNOWN"),
                                           (0, "PASS"), (1, "FAIL"), (89, "FAIL"),
                                           (90, "PASS"), (365, "PASS"),
                                           ("90", "UNKNOWN"), (None, "UNKNOWN")])
def test_retention_boundaries_and_indefinite_zero(days, expected):
    assert evaluate("network_watcher_flow_logs_retention_90",
                    _watcher(flow_logs=[_flow(days=days)])) == expected


@pytest.mark.parametrize("days, expected", [(-90, "UNKNOWN"), (-1, "UNKNOWN"),
                                           (0, "FAIL"), (1, "PASS"), (90, "PASS"),
                                           (91, "FAIL"), ("60", "UNKNOWN"),
                                           (None, "UNKNOWN")])
def test_key_rotation_boundaries(days, expected):
    item = {"properties": {"keyPolicy": {"keyExpirationPeriodInDays": days}}}
    assert evaluate("storage_key_expiration_policy_max_90", item) == expected


def test_short_retention_or_disabled_flow_cannot_hide_behind_indefinite_peer():
    assert evaluate("network_watcher_flow_logs_retention_90", _watcher(flow_logs=[
        _flow(days=0), _flow(days=30),
    ])) == "FAIL"
    assert evaluate("network_watcher_flow_logs_retention_90", _watcher(flow_logs=[
        _flow(days=0, enabled=False),
    ])) == "FAIL"
