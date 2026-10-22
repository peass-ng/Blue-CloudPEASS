"""A listing self-grant must add a permission absent at the listing and exchange."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
EXCHANGE = PROJECT + "/locations/us/dataExchanges/private"
LISTING = EXCHANGE + "/listings/data"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-analyticshub-listings-setiampolicy-listing-self-grant"


def snapshot(*, write=True, prior=False, listing_policy="collected", exchange_policy="collected"):
    def row(kind, data, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": data, "error": None}
    editor = PROJECT + "/roles/listingEditor"
    permissions = ["analyticshub.listings.setIamPolicy"] if write else []
    if prior:
        permissions.append("analyticshub.listings.subscribe")
    resource = lambda name, status: {"name": name, "iamPolicy": {"bindings": []},
                                      "_coverage": {"iamPolicy": {"status": status}}}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "created_at": "2026-10-21T10:05:00Z", "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": editor, "includedPermissions": permissions}]),
                row("iam_policy", [{"name": PROJECT,
                    "bindings": [{"role": editor, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("analyticshub_data_exchange", [resource(EXCHANGE, exchange_policy)]),
                row("analyticshub_listing", [resource(LISTING, listing_policy)]),
            ]}


def targets(snap, prefix="possible-listing-self-grant"):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:" + prefix + ":")}


def test_new_listing_permission_is_conditional_on_exact_policies():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-listing-self-grant:" + LISTING: "conditional"}


def test_missing_write_existing_permission_and_wrong_resource_do_not_claim_gain():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(prior=True))
    snap = snapshot()
    next(c for c in snap["collections"] if c["type"] == "analyticshub_listing")["items"][0]["name"] = EXCHANGE
    assert not targets(snap)


def test_existing_exchange_grant_or_incomplete_parent_policy_is_not_new_access():
    snap = snapshot()
    exchange = next(c for c in snap["collections"] if c["type"] == "analyticshub_data_exchange")
    exchange["items"][0]["iamPolicy"]["bindings"] = [
        {"role": "roles/analyticshub.subscriber", "members": [SOURCE]}]
    next(c for c in snap["collections"] if c["type"] == "iam_role")["items"].append(
        {"name": "roles/analyticshub.subscriber",
         "includedPermissions": ["analyticshub.listings.subscribe"]})
    assert not targets(snap)
    assert "conditional" not in targets(snapshot(exchange_policy="denied")).values()
    assert "conditional" not in targets(snapshot(listing_policy="malformed")).values()


def review():
    return {"TechniqueId": TECHNIQUE, "SourceId": SOURCE, "TargetScope": PROJECT,
            "TargetResource": LISTING, "GrantedResource": LISTING,
            "AccessPermission": "analyticshub.listings.setIamPolicy",
            "GrantedPrincipalId": SOURCE, "GrantedPermissions": ["analyticshub.listings.subscribe"],
            "PriorTestedPermission": "analyticshub.listings.subscribe",
            "AfterTestedPermission": "analyticshub.listings.subscribe",
            "PriorTestedResource": LISTING, "AfterTestedResource": LISTING,
            "AcceptedBindingMember": SOURCE, "AcceptedBindingRole": "roles/analyticshub.subscriber",
            "BindingPresentAtSnapshot": True,
            "PriorAccessCheckedAt": "2026-10-21T10:00:00Z",
            "PolicyMutationObservedAt": "2026-10-21T10:01:00Z",
            "AfterAccessCheckedAt": "2026-10-21T10:02:00Z",
            "BindingCheckedAt": "2026-10-21T10:03:00Z",
            "EvidenceObservedAt": "2026-10-21T10:04:00Z",
            "PriorPermissionAbsent": True, "PolicyMutationAuthorized": True,
            "PolicyMutationAccepted": True, "AfterPermissionAllowed": True,
            "Status": "verified", "EvidenceRef": "reviewed-listing-policy-1"}


def reviewed_targets(record, *, binding=True):
    snap = snapshot()
    listing = next(c for c in snap["collections"] if c["type"] == "analyticshub_listing")["items"][0]
    if binding:
        listing["iamPolicy"]["bindings"] = [{"role": "roles/analyticshub.subscriber", "members": [SOURCE]}]
    snap["collections"].append({"type": "gcp_resource_self_grant_evidence",
        "scope": PROJECT, "service": "reviewed", "status": "collected",
        "items": [record], "error": None})
    return targets(snap, prefix="self-grant")


def test_reviewed_mutation_must_bind_same_listing_permission_and_current_binding():
    assert len(reviewed_targets(review())) == 1
    assert not reviewed_targets(review(), binding=False)
    for field, value in (("TargetResource", EXCHANGE),
                         ("GrantedResource", LISTING + "/child"),
                         ("PriorTestedPermission", "analyticshub.dataExchanges.subscribe"),
                         ("AfterTestedResource", EXCHANGE),
                         ("AcceptedBindingMember", "user:other@example.com"),
                         ("BindingPresentAtSnapshot", False)):
        record = deepcopy(review())
        record[field] = value
        assert not reviewed_targets(record), field
