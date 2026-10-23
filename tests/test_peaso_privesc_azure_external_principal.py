"""Exact adjacent-plane principal evidence must fail closed."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.effective_permissions.azure_external_principal import CONTRACT
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az

AVS = f"{RG}/providers/Microsoft.AVS/privateClouds/pc1"
CATALOG = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/azure/avs.yaml"
AVS_ENTRIES = {e["id"]: e for e in yaml.safe_load(CATALOG.read_text())}
ENTRIES = {**AVS_ENTRIES, **{e["id"]: e for e in yaml.safe_load(
    CATALOG.with_name("adjacent_principals.yaml").read_text())}}


def proof(technique="azure-avs-list-vcenter-cloudadmin-external-principal"):
    permission = ENTRIES[technique]["requires"]["all_of"][0]["action"]
    nsx = "nsxt" in technique
    run_command = "run-command" in technique
    plane = "vmware_nsx" if nsx else "vmware_vcenter"
    resource = "https://nsx.pc1.example.local/api" if nsx else "https://vcenter.pc1.example.local/sdk"
    subject = "admin" if nsx else "cloudadmin@vsphere.local"
    fact = {
        "TechniqueId": technique, "SourceId": "u-alice", "TargetScope": SUB,
        "ActionResource": AVS, "AccessPermission": permission, "TargetPlane": plane,
        "TargetServiceResource": resource, "TargetPrincipalId": subject,
        "ObservedPrincipalId": subject, "AccessArtifactKind": "identity_grant" if run_command else "credential",
        "AccessArtifactRef": "reviewed-grant-1" if run_command else "reviewed-password-1",
        "GainedPermission": "VirtualMachine.Config.EditDevice",
        "PriorTestedPermission": "VirtualMachine.Config.EditDevice",
        "AfterTestedPermission": "VirtualMachine.Config.EditDevice",
        "PriorTestedResource": resource, "AfterTestedResource": resource,
        "ActionSucceeded": True, "PriorSourceAccessDenied": True,
        "AccessArtifactUsable": True, "AfterAuthenticationSucceeded": True,
        "AfterTargetPermissionAllowed": True,
        "TargetServiceBindingVerified": True, "TargetSubjectBindingVerified": True,
        "TargetServiceBindingEvidenceRef": "private-cloud-to-vcenter-1",
        "TargetSubjectBindingEvidenceRef": "response-to-login-subject-1",
        "PriorAccessCheckedAt": "2026-10-16T11:01:00Z",
        "ActionObservedAt": "2026-10-16T11:02:00Z",
        "AfterAccessCheckedAt": "2026-10-16T11:03:00Z",
        "EvidenceObservedAt": "2026-10-16T11:04:00Z",
        "EvidenceExpiresAt": "2026-10-16T12:00:00Z",
        "Status": "verified", "EvidenceRef": "reviewed-login-and-authorization-1",
    }
    if run_command:
        package = f"{AVS}/scriptPackages/Microsoft.AVS.Identity@1.0"
        fact.update(ExecutedPackageId=package,
                    ExecutedCmdletId=f"{package}/scriptCmdlets/Add-GroupToCloudAdmins",
                    ScriptExecutionResourceId=f"{AVS}/scriptExecutions/run-1",
                    GrantedGroupName="CloudAdmins", ExecutedGroupName="CloudAdmins",
                    GroupMembershipEvidenceRef="cloudadmins-member-1",
                    SourceLoginEvidenceRef="cloudadmin-login-1",
                    AuthenticatedPrincipalId=subject, SourceControlsTargetLogin=True,
                    TargetInGrantedGroupVerified=True,
                    GrantOperationEvidenceRef="cmdlet-execution-1", GrantOperationSucceeded=True)
    elif nsx:
        action = "GET /api/v1/policy/api/v1/infra/domains/default"
        fact.update(GainedPermission=action, PriorTestedPermission=action,
                    AfterTestedPermission=action, NsxtGainedAction=action,
                    ReturnedNsxtUsername=subject, NsxtPasswordReturnedVerified=True,
                    NsxtActionAuthorizedVerified=True,
                    CredentialResponseEvidenceRef="nsx-credential-response-1",
                    NsxtActionEvidenceRef="nsx-action-1")
    else:
        fact.update(VcenterGainedAction="VirtualMachine.Config.EditDevice",
                    ReturnedVcenterUsername=subject, VcenterPasswordReturnedVerified=True,
                    VcenterActionAuthorizedVerified=True,
                    CredentialResponseEvidenceRef="vcenter-credential-response-1",
                    VcenterActionEvidenceRef="vcenter-action-1")
    return fact


def case(technique, records=None, *, status="collected", allowed=True):
    entry = ENTRIES[technique]
    actions = [r["action"] for r in entry["requires"]["all_of"]] if allowed else ["Microsoft.AVS/privateClouds/read"]
    snap = az(assignments=[("u-alice", "User", AVS, ROLE_ID)], roles={ROLE_ID: (actions, [])},
              extra=[("azure_external_principal_evidence", SUB,
                      [proof(technique)] if records is None else records, status)])
    snap["created_at"] = "2026-10-16T11:05:00Z"
    return snap


def paths(technique, snap):
    result = privesc.analyze(snap, entries=[ENTRIES[technique]])
    return {target: confidence for target, confidence in reached(result, "u-alice", technique).items()
            if not target.startswith(("unknown:", "unresolved:"))}


def test_exact_vcenter_nsx_and_run_command_identity_paths():
    for technique, entry in AVS_ENTRIES.items():
        assert validate_entry(entry)[0] == []
        got = paths(technique, case(technique))
        assert len(got) == 1, technique
        assert next(iter(got)).startswith("azure_external_principal:")
        assert set(got.values()) == {"conditional"}


def test_missing_partial_duplicate_stale_and_wrong_authority_fail_closed():
    technique = "azure-avs-list-vcenter-cloudadmin-external-principal"
    for snap in (case(technique, []), case(technique, status="partial"),
                 case(technique, [proof(technique), proof(technique)]),
                 case(technique, allowed=False)):
        assert paths(technique, snap) == {}
    for field, value in (
        ("TargetPrincipalId", "other@vsphere.local"), ("ObservedPrincipalId", "other@vsphere.local"),
        ("ActionResource", f"{RG}/providers/Microsoft.AVS/privateClouds/other"),
        ("TargetScope", "/subscriptions/other"), ("TargetPlane", "vmware_nsx"),
        ("AccessArtifactKind", "identity_grant"), ("AccessArtifactUsable", False),
        ("PriorSourceAccessDenied", False), ("AfterAuthenticationSucceeded", False),
        ("AfterTargetPermissionAllowed", False), ("PriorTestedPermission", "Datastore.Delete"),
        ("TargetServiceBindingVerified", False), ("TargetSubjectBindingEvidenceRef", ""),
        ("AfterTestedResource", "https://other.example.local/sdk"),
        ("EvidenceRef", ""), ("AccessArtifactRef", ""),
        ("EvidenceExpiresAt", "2026-10-16T11:04:00Z"),
    ):
        altered = copy.deepcopy(proof(technique))
        altered[field] = value
        assert paths(technique, case(technique, [altered])) == {}, (field, value)


def test_conflicting_incomplete_sibling_poison_exact_source_scope():
    technique = "azure-avs-list-vcenter-cloudadmin-external-principal"
    sibling = {"TechniqueId": technique, "SourceId": "u-alice", "ActionResource": AVS,
               "AccessPermission": proof(technique)["AccessPermission"]}
    assert paths(technique, case(technique, [proof(technique), sibling])) == {}


def test_named_portal_github_and_mqtt_paths_need_exact_new_authority():
    cases = (
        ("azure-apim-developer-portal-sso-external-principal",
         f"{RG}/providers/Microsoft.ApiManagement/service/api1/users/bob",
         "apim_developer_portal", "https://api1.portal.example.com/users/bob", "bob", "credential"),
        ("azure-datafactory-github-oauth-external-principal",
         f"{RG}/providers/Microsoft.DataFactory/factories/finance",
         "github_repository", "https://github.com/example/factory", "github-user-7", "credential"),
        ("azure-eventgrid-mqtt-client-grant-external-principal",
         f"{RG}/providers/Microsoft.EventGrid/namespaces/ns1",
         "eventgrid_mqtt", f"{RG}/providers/Microsoft.EventGrid/namespaces/ns1/topicSpaces/ops",
         "mqtt-client-7", "identity_grant"),
    )
    for technique, resource, plane, service, subject, artifact in cases:
        entry = ENTRIES[technique]
        assert validate_entry(entry)[0] == []
        fact = {**proof(), "TechniqueId": technique, "ActionResource": resource,
                "AccessPermission": next(req["action"] for req in entry["requires"]["all_of"]
                                         if req["action"].casefold() == CONTRACT[technique][0]),
                "TargetPlane": plane, "TargetServiceResource": service,
                "TargetPrincipalId": subject, "ObservedPrincipalId": subject,
                "AccessArtifactKind": artifact, "PriorTestedResource": service,
                "AfterTestedResource": service}
        if plane == "eventgrid_mqtt":
            fact.update(GainedPermission="publisher", PriorTestedPermission="publisher",
                        AfterTestedPermission="publisher")
            fact.update(MqttClientId=subject, MqttClientGroupId="ops-clients",
                        PermissionBindingId="ops-publish", OwnedCredentialEvidenceRef="mqtt-cert-1",
                        GrantOperationEvidenceRef="binding-1", ClientCreated=True,
                        ClientGroupBound=True, PermissionBindingCreated=True,
                        CredentialOwnedBySource=True, GrantOperationSucceeded=True,
                        MqttClientResourceId=f"{resource}/clients/{subject}",
                        PermissionBindingResourceId=f"{resource}/permissionBindings/ops-publish",
                        PermissionBindingClientGroupName="ops-clients",
                        PermissionBindingTopicSpaceName="ops",
                        PermissionBindingPermission="publisher",
                        ClientGroupQueryEvidenceRef="client-group-match-1",
                        ClientGroupQueryMatchedClient=True)
        elif plane == "github_repository":
            fact.update(GitHubHost="github.com", GitHubRepositoryOwner="example",
                        GitHubRepositoryName="factory",
                        GitHubAuthorizationCodeEvidenceRef="github-code-1",
                        GitHubTokenResponseEvidenceRef="github-token-1",
                        GitHubAuthenticatedSubjectEvidenceRef="github-login-1",
                        GitHubRepositoryActionEvidenceRef="github-repository-read-1",
                        GitHubAuthorizationCodeSupplied=True,
                        GitHubTokenFromActionResponseVerified=True,
                        GitHubTokenUsedForAuthenticationVerified=True,
                        GitHubRepositoryActionAuthorizedVerified=True)
        actions = [r["action"] for r in entry["requires"]["all_of"]]
        snap = az(assignments=[("u-alice", "User", resource, ROLE_ID)],
                  roles={ROLE_ID: (actions, [])},
                  extra=[("azure_external_principal_evidence", SUB, [fact], "collected")])
        snap["created_at"] = "2026-10-16T11:05:00Z"
        assert len(paths(technique, snap)) == 1, technique
        bad = copy.deepcopy(snap)
        next(c for c in bad["collections"] if c["type"] == "azure_external_principal_evidence")["items"][0]["AfterTargetPermissionAllowed"] = False
        assert paths(technique, bad) == {}, technique


@pytest.mark.parametrize("technique,operation", [
    ("azure-apim-developer-portal-sso-external-principal", "generateSsoUrl"),
    ("azure-apim-developer-portal-shared-token-external-principal", "token"),
])
def test_apim_portal_token_requires_the_named_user_resource(technique, operation):
    user_resource = f"{RG}/providers/Microsoft.ApiManagement/service/api1/users/bob"
    portal = "https://api1.portal.example.com/users/bob"
    permission = ENTRIES[technique]["requires"]["all_of"][0]["action"]

    def targets(action_resource, principal="bob"):
        record = {**proof(), "TechniqueId": technique, "ActionResource": action_resource,
                  "AccessPermission": permission, "TargetPlane": "apim_developer_portal",
                  "TargetServiceResource": portal, "TargetPrincipalId": principal,
                  "ObservedPrincipalId": principal, "AccessArtifactKind": "credential",
                  "AccessArtifactRef": "reviewed-portal-token-1",
                  "GainedPermission": "portal:read-subscription",
                  "PriorTestedPermission": "portal:read-subscription",
                  "AfterTestedPermission": "portal:read-subscription",
                  "PriorTestedResource": portal, "AfterTestedResource": portal}
        snap = az(assignments=[("u-alice", "User", action_resource, ROLE_ID)],
                  roles={ROLE_ID: ([permission], [])},
                  extra=[("azure_external_principal_evidence", SUB, [record], "collected")])
        snap["created_at"] = "2026-10-16T11:05:00Z"
        return paths(technique, snap)

    assert len(targets(user_resource)) == 1
    assert len(targets(f"{user_resource}/{operation}")) == 1
    assert targets(f"{RG}/providers/Microsoft.Storage/storageAccounts/api1") == {}
    assert targets(user_resource, principal="other") == {}
    assert targets(f"{user_resource}/otherAction") == {}
