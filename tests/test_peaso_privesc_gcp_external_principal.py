"""External-plane credentials create an edge only with exact reviewed gain."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp_external_principal import FIREBASE_CUSTOM_TOKEN_AUDIENCE
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached, snapshot

SOURCE = "user:alice@corp.com"
SCOPE = "projects/p1"
RESOURCE = "projects/p1/locations/us-central1-a/privateClouds/pc1"
PERMISSION = "vmwareengine.privateClouds.showVcenterCredentials"
TECHNIQUE = "gcp-test-vmware-vcenter-credential"
ENTRY = {
    "id": TECHNIQUE, "provider": "gcp", "service": "vmwareengine",
    "title": "Reach the exact vCenter CloudOwner principal",
    "source": "src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-vmwareengine-gcve-privesc.md#vmwareengineprivatecloudsshowvcentercredentials--shownsxcredentials--cross-into-the-vmware-management-plane",
    "summary": "An exact usable generated credential reaches its named vCenter principal.",
    "requires": {"all_of": [{"action": PERMISSION, "resource": "{target.resource}"}]},
    "target": {"kind": "gcp_external_principal", "selector": {
        "gcp_external_principal_evidence": True, "gcp_external_plane": "vmware_vcenter"},
        "scope": "same_project", "outcome": "credentials"},
    "conditions": [], "blockers": [], "confidence": "conditional", "severity": "high",
    "mitigation": "Restrict VMware Engine credential reads.",
}


def proof():
    return {"TechniqueId": TECHNIQUE, "SourceId": SOURCE, "TargetScope": SCOPE,
            "ActionResource": RESOURCE, "AccessPermission": PERMISSION,
            "TargetPlane": "vmware_vcenter", "TargetServiceResource": RESOURCE + "/vcenter",
            "TargetPrincipalId": "CloudOwner@gve.local", "ObservedPrincipalId": "CloudOwner@gve.local",
            "CredentialRef": "reviewed-vcenter-password-1", "GainedPermission": "vcenter.VirtualMachine.Config.EditDevice",
            "PriorTestedPermission": "vcenter.VirtualMachine.Config.EditDevice",
            "AfterTestedPermission": "vcenter.VirtualMachine.Config.EditDevice",
            "PriorTestedResource": RESOURCE + "/vcenter",
            "AfterTestedResource": RESOURCE + "/vcenter",
            "ActionSucceeded": True, "PriorSourceAccessDenied": True, "CredentialUsable": True,
            "CredentialFreshnessVerified": True,
            "AfterAuthenticationSucceeded": True, "AfterTargetPermissionAllowed": True,
            "EvidenceObservedAt": "2026-10-16T11:04:00Z",
            "PriorAccessCheckedAt": "2026-10-16T11:01:00Z",
            "ActionObservedAt": "2026-10-16T11:02:00Z",
            "AfterAccessCheckedAt": "2026-10-16T11:03:00Z",
            "CredentialExpiresAt": "2026-10-16T12:00:00Z",
            "Status": "verified", "EvidenceRef": "reviewed-login-and-authorization-1"}


def case(records=None, *, status="collected", permission=True):
    role = {"name": "projects/p1/roles/vmwareReader", "includedPermissions": [PERMISSION] if permission else []}
    snap = snapshot("gcp", [
        ("project", SCOPE, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", SCOPE, [{"name": SCOPE, "bindings": [{"role": role["name"], "members": [SOURCE]}]}]),
        ("iam_role", SCOPE, [role]), ("service_account", SCOPE, []),
        ("iam_deny_policy", SCOPE, [], "empty"),
        ("gcp_external_principal_evidence", SCOPE, [proof()] if records is None else records, status),
    ])
    snap["created_at"] = "2026-10-16T11:05:00Z"
    return snap


def paths(snap, entry=ENTRY):
    result = privesc.analyze(snap, entries=[entry])
    return {target: confidence for target, confidence in reached(result, SOURCE, entry["id"]).items()
            if not target.startswith(("unknown:", "unresolved:"))}


def firebase_fact(entry):
    signer = "signer@p1.iam.gserviceaccount.com"
    account = SCOPE + "/accounts/uid-7"
    return {**proof(), "TechniqueId": entry["id"],
            "ActionResource": SCOPE + "/serviceAccounts/" + signer,
            "AccessPermission": entry["requires"]["all_of"][0]["action"],
            "TargetPlane": "firebase_auth", "TargetServiceResource": account,
            "TargetPrincipalId": "uid-7", "ObservedPrincipalId": "uid-7",
            "PriorTestedResource": account, "AfterTestedResource": account,
            "GainedPermission": "app.admin", "PriorTestedPermission": "app.admin",
            "AfterTestedPermission": "app.admin", "SignedTokenAlgorithm": "RS256",
            "SignedTokenIssuer": signer, "SignedTokenSubject": signer,
            "SignedTokenAudience": FIREBASE_CUSTOM_TOKEN_AUDIENCE,
            "SignedTokenUid": "uid-7", "ExchangeProjectId": "p1",
            "ExchangeUid": "uid-7", "ExchangeAccepted": True}


def test_exact_reviewed_login_and_new_permission_reach_only_named_principal():
    assert validate_entry(ENTRY)[0] == []
    got = paths(case())
    assert len(got) == 1
    assert next(iter(got)).startswith("gcp_external_principal:vmware_vcenter:")
    assert set(got.values()) == {"conditional"}


def test_missing_partial_duplicate_stale_or_unusable_evidence_fails_closed():
    for snap in (case([]), case(status="partial"), case(status="unknown"),
                 case([proof(), proof()]), case(permission=False)):
        assert paths(snap) == {}
    incomplete_sibling = {"TechniqueId": TECHNIQUE, "SourceId": SOURCE,
                          "ActionResource": RESOURCE, "AccessPermission": PERMISSION}
    assert paths(case([proof(), incomplete_sibling])) == {}
    for field, value in (("TargetScope", "projects/p2"), ("TargetPrincipalId", "Other@gve.local"),
                         ("ObservedPrincipalId", "Other@gve.local"), ("TargetPlane", "vmware_nsx"),
                         ("ActionResource", "projects/p2/locations/x/privateClouds/pc1"),
                         ("CredentialUsable", False), ("PriorSourceAccessDenied", False),
                         ("CredentialFreshnessVerified", False),
                         ("PriorTestedPermission", "vcenter.Datastore.Delete"),
                         ("AfterTestedResource", RESOURCE + "/nsx"),
                         ("AfterAuthenticationSucceeded", False), ("AfterTargetPermissionAllowed", False),
                         ("Status", "stale"), ("EvidenceRef", ""), ("CredentialRef", "")):
        altered = copy.deepcopy(proof())
        altered[field] = value
        assert paths(case([altered])) == {}, (field, value)
    old = copy.deepcopy(proof())
    old["EvidenceObservedAt"] = "2026-10-16T10:00:00Z"
    assert paths(case([old])) == {}
    expired = copy.deepcopy(proof())
    expired["CredentialExpiresAt"] = "2026-10-16T11:04:00Z"
    assert paths(case([expired])) == {}
    reversed_checks = copy.deepcopy(proof())
    reversed_checks["PriorAccessCheckedAt"] = "2026-10-16T11:04:00Z"
    assert paths(case([reversed_checks])) == {}


def test_wrong_action_and_ambiguous_subject_do_not_join():
    altered = copy.deepcopy(proof())
    altered["AccessPermission"] = "vmwareengine.privateClouds.get"
    assert paths(case([altered])) == {}
    second = copy.deepcopy(proof())
    second["TargetPrincipalId"] = "other@gve.local"
    second["ObservedPrincipalId"] = "other@gve.local"
    # One action claiming two different management subjects is ambiguous.
    assert paths(case([proof(), second])) == {}


def test_firebase_exact_signer_and_accepted_exchange_bind_one_user():
    import yaml
    from pathlib import Path

    entry = yaml.safe_load((Path(__file__).resolve().parents[1]
                            / "peaso/privesc/catalog/gcp/firebase_external.yaml").read_text())[0]
    assert validate_entry(entry)[0] == []
    action = entry["requires"]["all_of"][0]["action"]
    fact = firebase_fact(entry)
    assert len(paths(case([fact], permission=False), entry)) == 0
    snap = snapshot("gcp", [
        ("project", SCOPE, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", SCOPE, [{"name": SCOPE, "bindings": [{"role": "projects/p1/roles/firebaseUpdater", "members": [SOURCE]}]}]),
        ("iam_role", SCOPE, [{"name": "projects/p1/roles/firebaseUpdater", "includedPermissions": [action]}]),
        ("service_account", SCOPE, []), ("iam_deny_policy", SCOPE, [], "empty"),
        ("gcp_external_principal_evidence", SCOPE, [fact], "collected"),
    ])
    snap["created_at"] = "2026-10-16T11:05:00Z"
    assert len(paths(snap, entry)) == 1
    for field, value in (("ActionResource", SCOPE),
                         ("SignedTokenIssuer", "other@p1.iam.gserviceaccount.com"),
                         ("SignedTokenAudience", "https://other.example.test"),
                         ("SignedTokenUid", "uid-8"),
                         ("ExchangeProjectId", "p2"),
                         ("ExchangeAccepted", False)):
        altered = copy.deepcopy(fact)
        altered[field] = value
        next(c for c in snap["collections"] if c["type"] == "gcp_external_principal_evidence")["items"] = [altered]
        assert paths(snap, entry) == {}, (field, value)


def test_active_external_principal_rows_require_exact_plane_and_permission():
    import yaml
    from pathlib import Path

    catalog = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/gcp"
    entries = yaml.safe_load((catalog / "vmware_external.yaml").read_text())
    entries += yaml.safe_load((catalog / "agentregistry_external.yaml").read_text())
    entries += yaml.safe_load((catalog / "firebase_external.yaml").read_text())[1:]
    for entry in entries:
        assert validate_entry(entry)[0] == []
        action = entry["requires"]["all_of"][0]["action"]
        plane = entry["target"]["selector"]["gcp_external_plane"]
        fact = {**proof(), "TechniqueId": entry["id"], "AccessPermission": action,
                "TargetPlane": plane}
        if plane == "vmware_nsx":
            fact.update(TargetServiceResource=RESOURCE + "/nsx", TargetPrincipalId="admin",
                        ObservedPrincipalId="admin", PriorTestedResource=RESOURCE + "/nsx",
                        AfterTestedResource=RESOURCE + "/nsx", GainedPermission="nsx.policy.write",
                        PriorTestedPermission="nsx.policy.write", AfterTestedPermission="nsx.policy.write")
        if plane == "cloudsql_database":
            fact.update(ActionResource=SCOPE + "/locations/us-central1/secrets/db-admin",
                        TargetServiceResource=SCOPE + "/instances/sql1/users/dbadmin",
                        TargetPrincipalId="dbadmin", ObservedPrincipalId="dbadmin",
                        PriorTestedResource=SCOPE + "/instances/sql1/users/dbadmin",
                        AfterTestedResource=SCOPE + "/instances/sql1/users/dbadmin",
                        GainedPermission="sql.table.read", PriorTestedPermission="sql.table.read",
                        AfterTestedPermission="sql.table.read")
        if plane == "bms_os":
            fact.update(ActionResource=SCOPE + "/secrets/bms1/versions/1",
                        TargetServiceResource=SCOPE + "/locations/us-central1/instances/bms1/users/customeradmin",
                        TargetPrincipalId="customeradmin", ObservedPrincipalId="customeradmin",
                        PriorTestedResource=SCOPE + "/locations/us-central1/instances/bms1/users/customeradmin",
                        AfterTestedResource=SCOPE + "/locations/us-central1/instances/bms1/users/customeradmin",
                        GainedPermission="os.shell.login", PriorTestedPermission="os.shell.login",
                        AfterTestedPermission="os.shell.login")
        if plane == "agent_registry_provider":
            fact.update(ActionResource=SCOPE + "/locations/us-central1/services/mcp1",
                        TargetServiceResource="https://api.example.test/accounts/victim-7",
                        TargetPrincipalId="victim-7", ObservedPrincipalId="victim-7",
                        PriorTestedResource="https://api.example.test/accounts/victim-7",
                        AfterTestedResource="https://api.example.test/accounts/victim-7",
                        GainedPermission="account.read", PriorTestedPermission="account.read",
                        AfterTestedPermission="account.read",
                        QuotaProject=SCOPE, ServiceProjectedUrnBefore="urn:mcp:provider1",
                        ServiceProjectedUrnAfter="urn:mcp:provider1",
                        BindingResource=SCOPE + "/locations/us-central1/bindings/b1",
                        BindingTargetUrn="urn:mcp:provider1",
                        BindingAuthProvider=SCOPE + "/locations/us-central1/authProviders/ap1",
                        ServiceUrlBefore="https://provider.example.test/mcp",
                        ServiceUrlAfter="https://capture.example.test/mcp",
                        CaptureEndpointUrl="https://capture.example.test/mcp",
                        VictimPrincipalId="victim-7", CredentialKind="api_key",
                        CredentialHeaderName="Authorization",
                        VictimInvocationObservedAt="2026-10-16T11:02:20Z",
                        CredentialCapturedAt="2026-10-16T11:02:30Z",
                        BindingPresentBefore=True, BindingPresentAfter=True,
                        ServiceUpdatedOnlyInterfaces=True,
                        VictimRuntimeAuthorizedToRetrieve=True,
                        VictimUsedBindingAwareRuntime=True,
                        CredentialCapturedAtControlledEndpoint=True)
        if plane == "firebase_auth":
            fact.update(firebase_fact(entry))
        if plane == "firebase_idp":
            fact.update(ActionResource=SCOPE,
                        TargetServiceResource="https://idp.example.test/accounts/user-8",
                        TargetPrincipalId="user-8", ObservedPrincipalId="user-8",
                        PriorTestedResource="https://idp.example.test/accounts/user-8",
                        AfterTestedResource="https://idp.example.test/accounts/user-8",
                        GainedPermission="profile.read", PriorTestedPermission="profile.read",
                        AfterTestedPermission="profile.read")
        role = {"name": "projects/p1/roles/externalReader", "includedPermissions":
                [req["action"] for req in entry["requires"]["all_of"]]}
        snap = snapshot("gcp", [
            ("project", SCOPE, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
            ("iam_policy", SCOPE, [{"name": SCOPE, "bindings": [{"role": role["name"], "members": [SOURCE]}]}]),
            ("iam_role", SCOPE, [role]), ("service_account", SCOPE, []),
            ("iam_deny_policy", SCOPE, [], "empty"),
            ("gcp_external_principal_evidence", SCOPE, [fact], "collected"),
        ])
        snap["created_at"] = "2026-10-16T11:05:00Z"
        assert len(paths(snap, entry)) == 1, entry["id"]
