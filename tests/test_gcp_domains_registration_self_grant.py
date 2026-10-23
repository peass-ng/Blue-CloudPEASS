"""Registration policy control must confer new DNS permission on one active domain."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.effective_permissions.gcp_resource_self_grant import _valid
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@example.net"
REGISTRATION = PROJECT + "/locations/global/registrations/example.com"
ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-domains-registrations-setiampolicy-self-grant")


def case(*, writer=True, prior=False, policy=True, editor=True,
         state="ACTIVE", domain="example.com", name=REGISTRATION):
    role = PROJECT + "/roles/registrationWriter"
    permissions = (["domains.registrations.setIamPolicy"] if writer else []) + (
        ["domains.registrations.configureDns"] if prior else [])
    registration = {"name": name, "domainName": domain, "state": state,
                    "iamPolicy": {"bindings": []} if policy else {"collection_status": "denied"},
                    "_coverage": {"iamPolicy": {"status": "collected" if policy else "denied"}}}
    collections = [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT,
                                  "bindings": [{"role": role, "members": [SOURCE]}] if permissions else []}]),
        ("iam_role", PROJECT, [{"name": role, "includedPermissions": permissions}]),
        ("iam_role_builtin", PROJECT,
         [{"name": "roles/domains.editor", "includedPermissions": ["domains.registrations.configureDns"]}]
         if editor else [], "collected" if editor else "empty"),
        ("service_account", PROJECT, [], "empty"),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("org_policy_effective", PROJECT, [], "empty"),
        ("group", PROJECT, [], "empty"),
        ("group_membership", PROJECT, [], "empty"),
        ("domains_registration", PROJECT, [registration]),
    ]
    model = GcpModel(snapshot("gcp", collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_active_registration_policy_writer_can_grant_new_dns_permission():
    got = case()
    assert set(got.values()) == {"conditional"}
    assert next(iter(got)).startswith("gcp_verified_authority:possible-domain-registration-self-grant:")


def test_no_path_without_writer_or_new_permission_or_active_registration():
    assert case(writer=False) == {}
    assert case(prior=True) == {}
    assert case(state="EXPORTED") == {}
    assert case(domain="other.com") == {}
    assert case(name=PROJECT + "/locations/global/registrations/other.com") == {}


def test_incomplete_policy_or_unverified_grantable_role_is_not_positive():
    assert "conditional" not in case(policy=False).values()
    assert "conditional" not in case(editor=False).values()


def test_reviewed_mutation_requires_current_exact_binding_and_ordered_evidence():
    record = {
        "TechniqueId": ENTRY["id"], "SourceId": SOURCE, "TargetScope": PROJECT,
        "TargetResource": REGISTRATION, "GrantedResource": REGISTRATION,
        "GrantedPrincipalId": SOURCE, "AccessPermission": "domains.registrations.setIamPolicy",
        "GrantedPermissions": ["domains.registrations.configureDns"],
        "PriorTestedPermission": "domains.registrations.configureDns",
        "AfterTestedPermission": "domains.registrations.configureDns",
        "PriorTestedResource": REGISTRATION, "AfterTestedResource": REGISTRATION,
        "AcceptedBindingMember": SOURCE, "AcceptedBindingRole": "roles/domains.editor",
        "BindingPresentAtSnapshot": True,
        "PriorPermissionAbsent": True, "PolicyMutationAuthorized": True,
        "PolicyMutationAccepted": True, "AfterPermissionAllowed": True,
        "Status": "verified", "EvidenceRef": "reviewed-change",
        "PriorAccessCheckedAt": "2026-10-22T10:00:00Z",
        "PolicyMutationObservedAt": "2026-10-22T10:01:00Z",
        "AfterAccessCheckedAt": "2026-10-22T10:02:00Z",
        "BindingCheckedAt": "2026-10-22T10:03:00Z",
        "EvidenceObservedAt": "2026-10-22T10:04:00Z",
    }
    registration = {"name": REGISTRATION, "domainName": "example.com", "state": "ACTIVE",
                    "iamPolicy": {"bindings": [{"role": "roles/domains.editor", "members": [SOURCE]}]},
                    "_coverage": {"iamPolicy": {"status": "collected"}}}
    snap = snapshot("gcp", [("domains_registration", PROJECT, [registration])])
    snap["created_at"] = "2026-10-22T10:05:00Z"
    assert _valid(record, PROJECT, snap)
    stale = deepcopy(record)
    stale["BindingCheckedAt"] = "2026-10-22T09:40:00Z"
    assert not _valid(stale, PROJECT, snap)
    wrong = deepcopy(record)
    wrong["GrantedResource"] += "/other"
    assert not _valid(wrong, PROJECT, snap)
    registration["iamPolicy"]["bindings"] = []
    assert not _valid(record, PROJECT, snap)
    registration["iamPolicy"]["bindings"] = [{"role": "roles/domains.editor", "members": [SOURCE]}]
    registration["domainName"] = "another.com"
    assert not _valid(record, PROJECT, snap)
