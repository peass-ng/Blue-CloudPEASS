"""An exact exchange policy write can add a permission the source lacks."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
EXCHANGE = PROJECT + "/locations/us/dataExchanges/private"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-analyticshub-dataexchanges-setiampolicy-data-exchange-self-grant"


def snapshot(*, mutate=True, already=False, policy_status="collected", resource=EXCHANGE):
    def row(kind, value, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": value, "error": None}
    editor = PROJECT + "/roles/exchangePolicyEditor"
    role_permissions = ["analyticshub.dataExchanges.setIamPolicy"] if mutate else []
    if already:
        role_permissions.append("analyticshub.dataExchanges.subscribe")
    exchange = {"name": resource, "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": policy_status}}}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "created_at": "2026-10-21T10:05:00Z", "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": editor, "includedPermissions": role_permissions}]),
                row("iam_policy", [{"name": PROJECT,
                    "bindings": [{"role": editor, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("analyticshub_data_exchange", [exchange]),
            ]}


def targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:possible-exchange-self-grant:")}


def reviewed_targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:self-grant:")}


def review():
    return {"TechniqueId": TECHNIQUE, "SourceId": SOURCE, "TargetScope": PROJECT,
            "TargetResource": EXCHANGE, "GrantedResource": EXCHANGE,
            "AccessPermission": "analyticshub.dataExchanges.setIamPolicy",
            "GrantedPrincipalId": SOURCE,
            "GrantedPermissions": ["analyticshub.dataExchanges.subscribe"],
            "PriorTestedPermission": "analyticshub.dataExchanges.subscribe",
            "AfterTestedPermission": "analyticshub.dataExchanges.subscribe",
            "PriorTestedResource": EXCHANGE, "AfterTestedResource": EXCHANGE,
            "AcceptedBindingMember": SOURCE, "AcceptedBindingRole": "roles/analyticshub.subscriber",
            "BindingPresentAtSnapshot": True,
            "PriorAccessCheckedAt": "2026-10-21T10:00:00Z",
            "PolicyMutationObservedAt": "2026-10-21T10:01:00Z",
            "AfterAccessCheckedAt": "2026-10-21T10:02:00Z",
            "BindingCheckedAt": "2026-10-21T10:03:00Z",
            "EvidenceObservedAt": "2026-10-21T10:04:00Z",
            "PriorPermissionAbsent": True, "PolicyMutationAuthorized": True,
            "PolicyMutationAccepted": True, "AfterPermissionAllowed": True,
            "Status": "verified", "EvidenceRef": "reviewed-exchange-policy-1"}


def with_review(record=None):
    snap = snapshot()
    exchange = next(c for c in snap["collections"] if c["type"] == "analyticshub_data_exchange")["items"][0]
    exchange["iamPolicy"]["bindings"] = [{"role": "roles/analyticshub.subscriber", "members": [SOURCE]}]
    snap["collections"].append({"type": "gcp_resource_self_grant_evidence",
        "scope": PROJECT, "service": "reviewed", "status": "collected",
        "items": [review() if record is None else record], "error": None})
    return snap


def test_complete_exchange_policy_and_new_permission_make_conditional_path():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-exchange-self-grant:" + EXCHANGE: "conditional"}


def test_no_policy_write_or_existing_subscription_is_not_new_gain():
    assert not targets(snapshot(mutate=False))
    assert not targets(snapshot(already=True))


def test_wrong_resource_or_unavailable_policy_cannot_claim_conditional_gain():
    assert not targets(snapshot(resource=EXCHANGE + "/listings/child"))
    assert "conditional" not in targets(snapshot(policy_status="denied")).values()


def test_exchange_policy_existing_subscription_binding_is_not_new_gain():
    snap = snapshot()
    exchange = next(c for c in snap["collections"] if c["type"] == "analyticshub_data_exchange")["items"][0]
    exchange["iamPolicy"]["bindings"] = [{"role": "roles/analyticshub.subscriber", "members": [SOURCE]}]
    roles = next(c for c in snap["collections"] if c["type"] == "iam_role")
    roles["items"].append({"name": "roles/analyticshub.subscriber",
                           "includedPermissions": ["analyticshub.dataExchanges.subscribe"]})
    assert not targets(snap)


def test_reviewed_exchange_mutation_binds_exact_tested_permission_and_resource():
    assert len(reviewed_targets(with_review())) == 1
    for field, value in (
            ("TargetResource", PROJECT + "/secrets/s1"),
            ("GrantedResource", EXCHANGE + "/listings/child"),
            ("PriorTestedPermission", "analyticshub.listings.subscribe"),
            ("AfterTestedResource", EXCHANGE + "/listings/child"),
            ("AcceptedBindingMember", "user:other@example.com"),
            ("BindingPresentAtSnapshot", False),
            ("AfterAccessCheckedAt", "2026-10-21T09:59:00Z")):
        record = deepcopy(review())
        record[field] = value
        assert not reviewed_targets(with_review(record)), field
