"""A Registry redirect needs one complete, timed, source-bound credential capture."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
QUOTA = "projects/p2"
SERVICE = PROJECT + "/locations/us-central1/services/mcp1"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-agentregistry-service-redirect-exact-external-principal"


def proof(*, quota=PROJECT):
    external = "https://api.example.test/accounts/victim-7"
    urn = "urn:mcp:publisher:namespace:mcp1"
    return {
        "TechniqueId": TECHNIQUE, "SourceId": SOURCE, "TargetScope": PROJECT,
        "ActionResource": SERVICE, "AccessPermission": "agentregistry.services.update",
        "QuotaProject": quota, "TargetPlane": "agent_registry_provider",
        "TargetServiceResource": external, "TargetPrincipalId": "victim-7",
        "ObservedPrincipalId": "victim-7", "CredentialRef": "reviewed-capture-1",
        "GainedPermission": "account.read", "EvidenceRef": "reviewed-target-api-test-1",
        "PriorTestedPermission": "account.read", "AfterTestedPermission": "account.read",
        "PriorTestedResource": external, "AfterTestedResource": external,
        "ActionSucceeded": True, "PriorSourceAccessDenied": True,
        "CredentialUsable": True, "CredentialFreshnessVerified": True,
        "AfterAuthenticationSucceeded": True, "AfterTargetPermissionAllowed": True,
        "EvidenceObservedAt": "2026-10-16T11:04:00Z",
        "PriorAccessCheckedAt": "2026-10-16T11:01:00Z",
        "ActionObservedAt": "2026-10-16T11:02:00Z",
        "VictimInvocationObservedAt": "2026-10-16T11:02:20Z",
        "CredentialCapturedAt": "2026-10-16T11:02:30Z",
        "AfterAccessCheckedAt": "2026-10-16T11:03:00Z",
        "CredentialExpiresAt": "2026-10-16T12:00:00Z",
        "Status": "verified", "ServiceProjectedUrnBefore": urn,
        "ServiceProjectedUrnAfter": urn, "BindingTargetUrn": urn,
        "BindingResource": PROJECT + "/locations/us-central1/bindings/b1",
        "BindingAuthProvider": PROJECT + "/locations/us-central1/authProviders/oauth",
        "ServiceUrlBefore": "https://old.example.test/mcp",
        "ServiceUrlAfter": "https://capture.example.test/mcp",
        "CaptureEndpointUrl": "https://capture.example.test/mcp",
        "VictimPrincipalId": "serviceAccount:victim@p1.iam.gserviceaccount.com",
        "CredentialKind": "oauth_access_token", "CredentialHeaderName": "Authorization",
        "BindingPresentBefore": True, "BindingPresentAfter": True,
        "ServiceUpdatedOnlyInterfaces": True,
        "VictimRuntimeAuthorizedToRetrieve": True,
        "VictimUsedBindingAwareRuntime": True,
        "CredentialCapturedAtControlledEndpoint": True,
    }


def snapshot(record=None, *, quota_grant=True, status="collected"):
    def row(kind, scope, value, state="collected"):
        return {"type": kind, "scope": scope, "service": kind,
                "status": state, "items": value, "error": None}
    registry_role = PROJECT + "/roles/registryEditor"
    quota_role = QUOTA + "/roles/quotaUser"
    record = proof() if record is None else record
    collections = [
        row("project", PROJECT, [{"projectId": "p1", "name": "projects/111"}]),
        row("project", QUOTA, [{"projectId": "p2", "name": "projects/222"}]),
        row("iam_role", PROJECT, [{"name": registry_role,
            "includedPermissions": ["agentregistry.services.update", "serviceusage.services.use"]}]),
        row("iam_role", QUOTA, [{"name": quota_role,
            "includedPermissions": ["serviceusage.services.use"] if quota_grant else []}]),
        row("iam_policy", PROJECT, [{"name": PROJECT,
            "bindings": [{"role": registry_role, "members": [SOURCE]}]}]),
        row("iam_policy", QUOTA, [{"name": QUOTA,
            "bindings": [{"role": quota_role, "members": [SOURCE]}]}]),
        row("service_account", PROJECT, [], "empty"),
        row("iam_deny_policy", PROJECT, [], "empty"),
        row("iam_deny_policy", QUOTA, [], "empty"),
        row("gcp_external_principal_evidence", PROJECT, [record], status),
    ]
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT, QUOTA],
            "metadata": {}, "created_at": "2026-10-16T11:05:00Z", "collections": collections}


def targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_external_principal:")}


def test_complete_same_project_capture_reaches_exact_external_subject():
    result = targets(snapshot())
    assert len(result) == 1
    assert next(iter(result)).startswith("gcp_external_principal:agent_registry_provider:")
    assert set(result.values()) == {"conditional"}


def test_quota_project_can_differ_but_must_be_authorized():
    record = proof(quota=QUOTA)
    assert len(targets(snapshot(record))) == 1
    assert not targets(snapshot(record, quota_grant=False))


def test_missing_or_mismatched_binding_and_capture_facts_fail_closed():
    for field, value in (
            ("BindingResource", ""), ("BindingTargetUrn", "urn:mcp:other"),
            ("ServiceProjectedUrnAfter", "urn:mcp:other"),
            ("BindingPresentAfter", False), ("ServiceUpdatedOnlyInterfaces", False),
            ("ServiceUrlAfter", "https://different.example.test/mcp"),
            ("VictimRuntimeAuthorizedToRetrieve", False),
            ("VictimUsedBindingAwareRuntime", False),
            ("CredentialCapturedAtControlledEndpoint", False),
            ("VictimPrincipalId", SOURCE), ("CredentialKind", "refresh_token"),
            ("CredentialCapturedAt", "2026-10-16T11:01:30Z"),
            ("VictimInvocationObservedAt", "2026-10-16T11:03:30Z")):
        record = deepcopy(proof())
        record[field] = value
        assert not targets(snapshot(record)), field


def test_partial_or_duplicate_reviewed_records_fail_closed():
    assert not targets(snapshot(status="partial"))
    snap = snapshot()
    next(row for row in snap["collections"] if row["type"] == "gcp_external_principal_evidence")["items"] *= 2
    assert not targets(snap)
