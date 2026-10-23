"""GCP schema extensions: open-group self-join, Cloud Domains registration -> Workspace super admin, image-family
consumers (ledger NS-1..NS-3)."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import entry, errors_of, reached, snapshot

ALICE = "user:alice@corp.com"
OUTSIDER = "user:eve@evil.com"
SA1 = "sa1@p1.iam.gserviceaccount.com"
SA2 = "sa2@p1.iam.gserviceaccount.com"
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


IMAGE_ENTRY = entry("gcp-t-image", "gcp",
                    {"all_of": [{"action": "compute.images.create", "resource": "{target.image_family_project}"}]},
                    {"kind": "gcp_service_account", "selector": {"gcp_image_family_consumer": True}, "scope": "any"})


def test_image_family_consumer_targets_template_sas_only():
    assert errors_of(IMAGE_ENTRY) == []
    template = {"name": "t1", "properties": {
        "disks": [{"boot": True, "initializeParams": {"sourceImage": "projects/p1/global/images/family/golden"}}],
        "serviceAccounts": [{"email": SA1}]}}
    pinned = {"name": "t2", "properties": {
        "disks": [{"initializeParams": {"sourceImage": "https://www.googleapis.com/compute/v1/projects/p1/global/images/img-1"}}],
        "serviceAccounts": [{"email": SA2}]}}
    extra = [("instance_template", "projects/p1", [template, pinned])]
    bindings = [{"role": "projects/p1/roles/imager", "members": [ALICE]}]
    got = reached(privesc.analyze(gsnap(bindings, extra, sas=(SA1, SA2)), entries=[IMAGE_ENTRY]), ALICE, "gcp-t-image")
    assert got == {f"serviceAccount:{SA1}": "derived"}
    # The family lives in another project the source cannot write: no edge.
    template["properties"]["disks"][0]["initializeParams"]["sourceImage"] = "projects/debian-cloud/global/images/family/debian-12"
    got = reached(privesc.analyze(gsnap(bindings, extra, sas=(SA1, SA2)), entries=[IMAGE_ENTRY]), ALICE, "gcp-t-image")
    assert f"serviceAccount:{SA1}" not in got
