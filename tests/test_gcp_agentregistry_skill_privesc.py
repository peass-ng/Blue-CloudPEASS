"""Agent Registry Skill escalation needs exact consumer and bounded action proof."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


TECHNIQUE = "gcp-agentregistry-skill-default-revision-replace"
PROJECT = "projects/p1"
QUOTA = "projects/p2"
SOURCE = "user:editor@example.com"
SKILL = PROJECT + "/locations/global/skills/private-review"
REVISION = SKILL + "/revisions/r2"


def proof(*, mode="create_auto_active", quota=PROJECT):
    return {
        "TechniqueId": TECHNIQUE, "SourceId": SOURCE, "TargetScope": PROJECT,
        "SkillResource": SKILL, "QuotaProject": quota,
        "ConsumerResource": "projects/p1/locations/global/agents/consumer",
        "ConsumerRuntimePrincipal": "serviceAccount:consumer@p1.iam.gserviceaccount.com",
        "ConsumerSkillSource": SKILL, "ConsumerRegistry": "agent_registry",
        "ConsumerMountMode": "logical_skill",
        "DefaultRevisionBefore": SKILL + "/revisions/r1",
        "DefaultRevisionAfter": REVISION, "ReplacementRevision": REVISION,
        "ConsumerResolvedRevision": REVISION,
        "DownstreamPermission": "secretmanager.versions.access",
        "DownstreamResource": PROJECT + "/secrets/private/versions/latest",
        "PriorTestedPermission": "secretmanager.versions.access",
        "PriorTestedResource": PROJECT + "/secrets/private/versions/latest",
        "ObservedRuntimePrincipal": "serviceAccount:consumer@p1.iam.gserviceaccount.com",
        "ObservedPermission": "secretmanager.versions.access",
        "ObservedResource": PROJECT + "/secrets/private/versions/latest",
        "EvidenceRef": "reviewed-execution-1", "MutationMode": mode,
        "Status": "verified", "ExistingCustomSkill": True,
        "RevisionCreated": True, "RevisionPayloadValidated": True,
        "ReplacementRevisionActive": True, "ConsumerResolvedDefaultRevision": True,
        "ConsumerPayloadLoaded": True, "PayloadActionSucceeded": True,
        "PriorSourceAccessDenied": True, "DefaultPointerUpdated": mode == "explicit_update",
        "PriorAccessCheckedAt": "2026-10-21T10:00:00Z",
        "RevisionCreatedAt": "2026-10-21T10:01:00Z",
        "DefaultPointerUpdatedAt": "2026-10-21T10:01:10Z",
        "ConsumerResolvedAt": "2026-10-21T10:01:20Z",
        "DownstreamActionObservedAt": "2026-10-21T10:01:30Z",
        "EvidenceObservedAt": "2026-10-21T10:02:00Z",
    }


def snapshot(record=None, *, update=False, create_grant=True, quota_grant=True, status="collected"):
    def row(kind, scope, value, state="collected"):
        return {"type": kind, "scope": scope, "service": kind,
                "status": state, "items": value, "error": None}
    registry_role = PROJECT + "/roles/registryPublisher"
    quota_role = QUOTA + "/roles/quotaUser"
    record = proof() if record is None else record
    permissions = ["serviceusage.services.use"]
    if create_grant:
        permissions.append("agentregistry.skillRevisions.create")
    if update:
        permissions.append("agentregistry.skills.update")
    collections = [
        row("project", PROJECT, [{"projectId": "p1", "name": "projects/111"}]),
        row("project", QUOTA, [{"projectId": "p2", "name": "projects/222"}]),
        row("iam_role", PROJECT, [{"name": registry_role, "includedPermissions": permissions}]),
        row("iam_role", QUOTA, [{"name": quota_role,
            "includedPermissions": ["serviceusage.services.use"] if quota_grant else []}]),
        row("iam_policy", PROJECT, [{"name": PROJECT,
            "bindings": [{"role": registry_role, "members": [SOURCE]}]}]),
        row("iam_policy", QUOTA, [{"name": QUOTA,
            "bindings": [{"role": quota_role, "members": [SOURCE]}]}]),
        row("service_account", PROJECT, [], "empty"),
        row("iam_deny_policy", PROJECT, [], "empty"),
        row("iam_deny_policy", QUOTA, [], "empty"),
        row("gcp_agentregistry_skill_evidence", PROJECT, [record], status),
    ]
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT, QUOTA],
            "metadata": {}, "created_at": "2026-10-21T10:03:00Z", "collections": collections}


def targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:agentregistry_skill:")}


def test_create_only_with_exact_consumer_and_new_bounded_action():
    assert len(targets(snapshot())) == 1
    assert set(targets(snapshot()).values()) == {"conditional"}
    assert not targets(snapshot(create_grant=False))


def test_explicit_pointer_update_needs_update_right_and_exact_quota_right():
    record = proof(mode="explicit_update", quota=QUOTA)
    assert not targets(snapshot(record))
    assert not targets(snapshot(record, update=True, quota_grant=False))
    assert len(targets(snapshot(record, update=True))) == 1


def test_unrelated_registry_pinned_or_unexecuted_payload_does_not_escalate():
    for field, value in (
            ("ConsumerRegistry", "skill_registry"),
            ("ConsumerMountMode", "pinned_revision"),
            ("ConsumerSkillSource", SKILL + "/revisions/r1"),
            ("ConsumerResolvedDefaultRevision", False),
            ("ConsumerPayloadLoaded", False),
            ("PayloadActionSucceeded", False),
            ("PriorSourceAccessDenied", False),
            ("ObservedRuntimePrincipal", "serviceAccount:other@p1.iam.gserviceaccount.com"),
            ("ObservedPermission", "storage.objects.get"),
            ("DefaultRevisionAfter", SKILL + "/revisions/other"),
            ("ConsumerResolvedRevision", SKILL + "/revisions/r1"),
            ("PriorTestedResource", PROJECT + "/secrets/other/versions/latest"),
            ("DefaultPointerUpdated", True),
            ("ConsumerResolvedAt", "2026-10-21T09:59:00Z")):
        record = deepcopy(proof())
        record[field] = value
        assert not targets(snapshot(record)), field


def test_partial_and_duplicate_records_do_not_claim_gain():
    assert not targets(snapshot(status="partial"))
    snap = snapshot()
    next(row for row in snap["collections"] if row["type"] == "gcp_agentregistry_skill_evidence")["items"] *= 2
    assert not targets(snap)
