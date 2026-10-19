"""Per-port prose must preserve the firewall rule's actual scope and verdicts."""
from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.catalog import _base_description_for, description_for
from peaso.checks.claude_gcp_k8s_common import CASES
from peaso.checks.claude_gcp_k8s_compute import FIREWALL_PORTS, FIREWALL_PORT_IDS
from peaso.checks.gcp_firewall_clarity_reviewed import ROWS, description, remediation
from peaso.remediation import rules


@pytest.mark.parametrize("suffix", FIREWALL_PORTS)
def test_port_guidance_preserves_real_predicate_and_contract(suffix):
    cid = FIREWALL_PORT_IDS[suffix]
    check = next(c for c in CHECKS if c.id == cid)
    base = _base_description_for(cid)
    before = deepcopy(base)
    current = description_for(cid)
    assert base == before
    assert {k: v for k, v in current.items() if k != "description"} == {
        k: v for k, v in base.items() if k != "description"
    }
    for port in FIREWALL_PORTS[suffix][0]:
        assert str(port) in current["description"]
    assert "endpoint reachability are not evaluated" in current["description"]
    for case, expected in (("pass", "PASS"), ("fail", "FAIL"),
                           ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"),
                           ("not_applicable", "NOT_APPLICABLE")):
        assert check.evaluate(CASES[cid][case], {})[0] == expected
    assert len(rules()[cid]["steps"]) == 1


def test_reviewed_family_is_exact_and_stale_content_fails_closed():
    assert set(ROWS) == set(FIREWALL_PORT_IDS.values())
    cid = next(iter(ROWS))
    with pytest.raises(ValueError, match="base changed"):
        description(cid, {"description": "new upstream condition"})
    with pytest.raises(ValueError, match="base changed"):
        remediation(cid, {"steps": ["new upstream action"]})
    original = {"description": "Other check"}
    assert description("unrelated.check", original) == original
    assert description("unrelated.check", original) is not original
