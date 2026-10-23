"""Repository IAM self-grant reaches only an exact writable repository."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
REPO = PROJECT + "/locations/us-central1/repositories/app"
OTHER = PROJECT + "/locations/us-central1/repositories/other"
ACCOUNT = "user:source@example.com"
TECHNIQUE = "gcp-artifactregistry-repositories-setiampolicy-repository-self-grant"


def snapshot(*, mode="STANDARD_REPOSITORY", policy=True, prior=False,
             repo_policy="collected", org_restricted=False, project_binding=False):
    def row(kind, value, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": value, "error": None}
    writer = PROJECT + "/roles/policyWriter"
    grant = {"role": writer, "members": [ACCOUNT]}
    repository = lambda name, bindings: {
        "name": name, "format": "DOCKER", "mode": mode,
        "iamPolicy": {"bindings": bindings},
        "_coverage": {"iamPolicy": {"status": repo_policy}},
    }
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": writer, "includedPermissions":
                    ["artifactregistry.repositories.setIamPolicy"] if policy else []},
                    {"name": "roles/artifactregistry.writer", "includedPermissions":
                    ["artifactregistry.repositories.uploadArtifacts"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": [grant] if project_binding else []}]),
                row("artifact_repository", [repository(REPO, ([] if project_binding else [grant]) +
                    ([{"role": "roles/artifactregistry.writer", "members": [ACCOUNT]}]
                     if prior else [])), repository(OTHER, [])]),
                row("org_policy_effective", [{"constraint": "iam.allowedPolicyMemberDomains"}]
                    if org_restricted else [], "collected" if org_restricted else "empty"),
                row("iam_deny_policy", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
            ]}


def result(snap):
    entry, = [e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == ACCOUNT
            for target, grant in reach.targets.items()}


def test_exact_repository_policy_grant_is_conditional():
    targets = result(snapshot())
    assert targets["gcp_verified_authority:possible-artifact-upload-self-grant:" + REPO] == "conditional"
    assert "gcp_verified_authority:possible-artifact-upload-self-grant:" + OTHER not in targets


def test_no_new_upload_access_when_missing_authority_or_already_granted():
    assert not result(snapshot(policy=False))
    assert not any("possible-artifact-upload-self-grant:" in target
                   for target in result(snapshot(prior=True)))


def test_remote_repository_has_no_upload_path():
    assert not any("possible-artifact-upload-self-grant:" in target
                   for target in result(snapshot(mode="REMOTE_REPOSITORY")))


def test_incomplete_policy_or_member_constraint_is_unresolved():
    assert any(target.startswith("unresolved:") for target in result(
        snapshot(repo_policy="denied", project_binding=True)))
    assert any(target.startswith("unresolved:") for target in result(snapshot(org_restricted=True)))
