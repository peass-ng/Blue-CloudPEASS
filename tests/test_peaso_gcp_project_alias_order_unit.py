"""IAM Policy set order is irrelevant only after native authority validation."""
from copy import deepcopy

import pytest

from peaso.gcp_project_alias import AliasUnavailable, prove_project_alias
from tests.test_peaso_gcp_project_alias import SCOPE, fixture


def policy_sets():
    bindings = [
        {"role": "roles/viewer", "members": ["user:b@example.invalid", "user:a@example.invalid"]},
        {"role": "roles/viewer", "members": ["user:c@example.invalid"],
         "condition": {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')", "title": "limit"}},
        {"role": "roles/browser", "members": ["group:readers@example.invalid"]},
    ]
    audit = [
        {"service": "spanner.googleapis.com", "auditLogConfigs": [
            {"logType": "DATA_WRITE", "exemptedMembers": ["user:z@example.invalid", "user:a@example.invalid"]},
            {"logType": "DATA_READ", "exemptedMembers": ["user:y@example.invalid", "user:b@example.invalid"]},
            {"logType": "DATA_READ", "exemptedMembers": ["user:other@example.invalid"]}]},
        {"service": "spanner.googleapis.com", "auditLogConfigs": [
            {"logType": "ADMIN_READ", "exemptedMembers": []}]},
        {"service": "storage.googleapis.com", "auditLogConfigs": [
            {"logType": "ADMIN_READ", "exemptedMembers": []}]},
    ]
    return bindings, audit


def ordered_case():
    projects, policies, ledger = fixture()
    bindings, audit = policy_sets()
    direct, alias = policies["items"]
    direct.update(bindings=deepcopy(bindings), auditConfigs=deepcopy(audit), version=3, etag="opaque-etag")
    alias.update(bindings=deepcopy(list(reversed(bindings))),
                 auditConfigs=deepcopy(list(reversed(audit))), version=3, etag="opaque-etag")
    alias["bindings"][-1]["members"].reverse()
    alias["auditConfigs"][-1]["auditLogConfigs"].reverse()
    for config in alias["auditConfigs"]:
        for log in config["auditLogConfigs"]:
            log["exemptedMembers"].reverse()
    return projects, policies, ledger


def prove(case):
    projects, policies, ledger = case
    return prove_project_alias(SCOPE, projects, policies, ledger)


def test_only_named_set_orders_are_canonicalized_without_mutating_evidence():
    case = ordered_case()
    before = deepcopy(case)
    binding = prove(case)
    assert binding.project_number == "123456789"
    assert (binding.direct_position, binding.alias_position) == (0, 1)
    assert case == before
    assert case[1]["items"][0]["bindings"] != case[1]["items"][1]["bindings"]
    assert case[1]["items"][0]["auditConfigs"] != case[1]["items"][1]["auditConfigs"]
    assert sum(config["service"] == "spanner.googleapis.com" for config in
               case[1]["items"][0]["auditConfigs"]) == 2


@pytest.mark.parametrize("change", [
    lambda direct, alias: alias["bindings"][0].update(role="roles/editor"),
    lambda direct, alias: alias["bindings"][1]["condition"].update(expression="true"),
    lambda direct, alias: alias.update(etag="different-etag"),
    lambda direct, alias: alias.update(version=1),
    lambda direct, alias: alias["auditConfigs"][0]["auditLogConfigs"][0].update(logType="DATA_WRITE"),
    lambda direct, alias: alias["auditConfigs"][0]["auditLogConfigs"][0]["exemptedMembers"].append("user:new@example.invalid"),
])
def test_scalar_or_membership_changes_remain_unknown(change):
    case = ordered_case()
    direct, alias = case[1]["items"]
    change(direct, alias)
    with pytest.raises(AliasUnavailable):
        prove(case)


def test_split_bindings_are_never_merged_into_one_binding():
    case = ordered_case()
    direct, alias = case[1]["items"]
    direct["bindings"] = [{"role": "roles/viewer", "members": ["user:a@example.invalid"]},
                          {"role": "roles/viewer", "members": ["user:b@example.invalid"]}]
    alias["bindings"] = [{"role": "roles/viewer", "members": ["user:a@example.invalid", "user:b@example.invalid"]}]
    with pytest.raises(AliasUnavailable):
        prove(case)


@pytest.mark.parametrize("duplicate", [
    "member", "binding", "audit_service", "audit_log_type", "exempted_member",
])
def test_ambiguous_set_duplicates_are_rejected_even_when_both_views_agree(duplicate):
    case = ordered_case()
    direct, alias = case[1]["items"]
    for policy in (direct, alias):
        if duplicate == "member":
            policy["bindings"][0]["members"].append(policy["bindings"][0]["members"][0])
        elif duplicate == "binding":
            policy["bindings"].append(deepcopy(policy["bindings"][0]))
        elif duplicate == "audit_service":
            policy["auditConfigs"].append(deepcopy(policy["auditConfigs"][0]))
        elif duplicate == "audit_log_type":
            policy["auditConfigs"][0]["auditLogConfigs"].append(
                deepcopy(policy["auditConfigs"][0]["auditLogConfigs"][0]))
        else:
            exempt = next(log["exemptedMembers"] for config in policy["auditConfigs"]
                          for log in config["auditLogConfigs"] if log["exemptedMembers"])
            exempt.append(exempt[0])
    with pytest.raises(AliasUnavailable):
        prove(case)


def test_nested_denied_coverage_cannot_be_hidden_by_ordering():
    case = ordered_case()
    alias = case[1]["items"][1]
    alias["bindings"][0]["_coverage"] = {"members": {"status": "denied"}}
    with pytest.raises(AliasUnavailable):
        prove(case)


def test_explicit_empty_projection_conflicts_but_omitted_projection_is_no_assertion():
    case = ordered_case()
    case[1]["items"][1]["bindings"] = []
    with pytest.raises(AliasUnavailable):
        prove(case)
    case = ordered_case()
    case[1]["items"][1].pop("bindings")
    case[1]["items"][1].pop("auditConfigs")
    assert prove(case).project_number == "123456789"
