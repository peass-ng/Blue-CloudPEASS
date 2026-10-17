"""Directed original-contract proof for Azure VM protection checks."""
from tests.compliance_draft_isolation import staged_registry

with staged_registry(("compliance_new_sw17",)):
    from test_peaso_compliance_new_sw17 import case, native, run


def test_adaptive_network_healthy_without_required_rule_details_is_unknown():
    suffix = "adaptive_network_hardening_recommendation_applied"
    machine, index = case(suffix)
    evidence = native(index, "adaptive_network_hardening")
    evidence["requiredRules"] = []
    assert evidence["rulesComplete"] is True
    assert run(suffix, machine, index)[0] == "UNKNOWN"


def test_adaptive_network_bound_effective_rule_still_passes():
    suffix = "adaptive_network_hardening_recommendation_applied"
    machine, index = case(suffix)
    assert run(suffix, machine, index)[0] == "PASS"


def test_adaptive_network_unhealthy_assessment_precedes_empty_rule_uncertainty():
    suffix = "adaptive_network_hardening_recommendation_applied"
    machine, index = case(suffix)
    native(index, "adaptive_network_hardening")["requiredRules"] = []
    native(index, "security_assessment")["properties"]["status"]["code"] = "Unhealthy"
    assert run(suffix, machine, index)[0] == "FAIL"
