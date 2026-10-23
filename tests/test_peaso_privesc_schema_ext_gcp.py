"""GCP schema extensions: open-group self-join, Cloud Domains registration -> Workspace super admin, image-family
consumers (ledger NS-1..NS-3)."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import entry, errors_of, reached, snapshot

ALICE = "user:alice@corp.com"
OUTSIDER = "user:eve@evil.com"
ROLE = {"name": "projects/p1/roles/imager", "includedPermissions": ["compute.images.create", "domains.registrations.configuredns"]}


def gsnap(bindings, extra=(), sas=()):
    return snapshot("gcp", [
        ("project", "projects/p1", [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", "projects/p1", [{"name": "projects/p1", "bindings": bindings}]),
        ("iam_role", "projects/p1", [ROLE]),
        ("service_account", "projects/p1", [{"email": e, "projectId": "p1", "name": f"projects/p1/serviceAccounts/{e}"}
                                            for e in sas]),
        ("iam_deny_policy", "projects/p1", [], "empty"),
        *extra])


GROUP_ENTRY = entry("gcp-t-group-join", "gcp", {}, {"kind": "gcp_group", "selector": {"gcp_group_join_open_to_source": True},
                                                 "scope": "any"}, source_kind="gcp_user")


def test_group_self_join_validates_and_uses_group_settings():
    assert errors_of(GROUP_ENTRY) == []
    bad = entry("gcp-t-bad", "gcp", {}, {"kind": "gcp_user", "selector": {"gcp_group_join_open_to_source": True}, "scope": "any"},
                source_kind="gcp_user")
    assert any("needs target kind gcp_group" in e for e in errors_of(bad))
    bindings = [{"role": "roles/viewer", "members": [ALICE, OUTSIDER]},
                {"role": "roles/owner", "members": ["group:open@corp.com"]},
                {"role": "roles/editor", "members": ["group:domain@corp.com"]},
                {"role": "roles/editor", "members": ["group:invite@corp.com"]},
                {"role": "roles/editor", "members": ["group:nosettings@corp.com"]}]
    groups = [{"groupKey": {"id": "open@corp.com"}, "groupSettings": {"whoCanJoin": "ANYONE_CAN_JOIN", "allowExternalMembers": "false"}},
              {"groupKey": {"id": "domain@corp.com"}, "groupSettings": {"whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN"}},
              {"groupKey": {"id": "invite@corp.com"}, "groupSettings": {"whoCanJoin": "INVITED_CAN_JOIN"}}]
    result = privesc.analyze(gsnap(bindings, [("group", "organizations/1", groups)]), entries=[GROUP_ENTRY])
    got = reached(result, ALICE, "gcp-t-group-join")
    assert got.get("group:open@corp.com") == "derived"
    assert got.get("group:domain@corp.com") == "conditional"
    assert "group:invite@corp.com" not in got
    assert "group:nosettings@corp.com" not in got  # missing settings: unresolved placeholder, never a member
    # External source: open group without allowExternalMembers is not joinable.
    assert "group:open@corp.com" not in reached(result, OUTSIDER, "gcp-t-group-join")


def test_group_self_join_without_settings_is_coverage_only():
    bindings = [{"role": "roles/viewer", "members": [ALICE]}, {"role": "roles/owner", "members": ["group:open@corp.com"]}]
    result = privesc.analyze(gsnap(bindings), entries=[GROUP_ENTRY])
    assert reached(result, ALICE, "gcp-t-group-join") == {}
    assert "gcp_group_join_open_to_source not evaluated" in repr(result)


DOMAINS_ENTRY = entry("gcp-t-domains", "gcp",
                      {"all_of": [{"action": "domains.registrations.configureDns", "resource": "{target.domain_registration}"}]},
                      {"kind": "gcp_workspace_user", "selector": {"gcp_workspace_super_admin_with_registered_domain": True},
                       "scope": "any"})


def test_domains_registration_reaches_super_admin_of_that_domain():
    assert errors_of(DOMAINS_ENTRY) == []
    reg = "projects/p1/locations/global/registrations/corp.com"
    extra = [("domains_registration", "projects/p1", [{"name": reg, "domainName": "corp.com", "state": "ACTIVE"}]),
             ("workspace_customer", "customers/C1", [{"id": "C1", "customerDomain": "corp.com"},
                                                     {"id": "C2", "customerDomain": "other.com"}]),
             ("workspace_user", "customers/C1", [{"primaryEmail": "boss@corp.com", "id": "1", "customerId": "C1", "isAdmin": True},
                                                 {"primaryEmail": "boss@other.com", "id": "2", "customerId": "C2", "isAdmin": True},
                                                 {"primaryEmail": "intern@corp.com", "id": "3", "customerId": "C1", "isAdmin": False}])]
    bindings = [{"role": "projects/p1/roles/imager", "members": [ALICE]}]
    got = reached(privesc.analyze(gsnap(bindings, extra), entries=[DOMAINS_ENTRY]), ALICE, "gcp-t-domains")
    assert set(k for k in got if not k.startswith("unresolved:")) == {"user:boss@corp.com"}
    # Not collected: no members, only unresolved placeholders.
    got = reached(privesc.analyze(gsnap(bindings, extra[1:]), entries=[DOMAINS_ENTRY]), ALICE, "gcp-t-domains")
    assert "user:boss@corp.com" not in got
    inactive = [("domains_registration", "projects/p1", [{"name": reg, "domainName": "corp.com", "state": "SUSPENDED"}]), *extra[1:]]
    got = reached(privesc.analyze(gsnap(bindings, inactive), entries=[DOMAINS_ENTRY]), ALICE, "gcp-t-domains")
    assert "user:boss@corp.com" not in got


@pytest.mark.parametrize("technique,action", [
    ("gcp-domains-configuredns-workspace-admin-recovery", "domains.registrations.configureDns"),
    ("gcp-domains-configuremanagement-transfer-workspace-admin-recovery", "domains.registrations.configureManagement"),
])
def test_catalog_domain_recovery_requires_exact_active_registration_and_admin(technique, action):
    catalog_entry = next(item for item in privesc.catalog()["entries"] if item["id"] == technique)

    def targets(*, permission=None, state="ACTIVE", domain="corp.com", admin=True, project="p1"):
        registration = f"projects/{project}/locations/global/registrations/corp.com"
        extra = [
            ("domains_registration", f"projects/{project}",
             [{"name": registration, "domainName": "corp.com", "state": state}]),
            ("workspace_customer", "customers/C1", [{"id": "C1", "customerDomain": domain}]),
            ("workspace_user", "customers/C1", [{"primaryEmail": "boss@corp.com", "id": "1",
                                                   "customerId": "C1", "isAdmin": admin}]),
        ]
        snap = gsnap([{"role": "projects/p1/roles/imager", "members": [ALICE]}], extra)
        role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
        role["includedPermissions"] = [permission or action]
        return reached(privesc.analyze(snap, entries=[catalog_entry]), ALICE, technique)

    assert targets() == {"user:boss@corp.com": "conditional"}
    assert "user:boss@corp.com" not in targets(permission="domains.registrations.get")
    assert "user:boss@corp.com" not in targets(state="SUSPENDED")
    assert "user:boss@corp.com" not in targets(domain="other.com")
    assert "user:boss@corp.com" not in targets(admin=False)
    assert "user:boss@corp.com" not in targets(project="p2")


def test_image_family_poison_is_manual_only():
    technique = "gcp-compute-images-create-family-poison"
    assert technique not in {item["id"] for item in privesc.catalog()["entries"]}
    excluded_path = Path(__file__).parents[1] / "peaso/privesc/catalog/gcp/_excluded.yaml"
    excluded = yaml.safe_load(excluded_path.read_text())
    record = next(item for item in excluded if item.get("id") == technique)
    assert record["reason"].startswith("Manual-only:")
