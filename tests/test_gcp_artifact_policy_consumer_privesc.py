"""Repository policy write must reach the same tagged image consumer."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
CONSUMER = "projects/p2"
TARGET = "runtime@p2.iam.gserviceaccount.com"
REPO = PROJECT + "/locations/us-central1/repositories/app"
TECHNIQUE = "gcp-artifactregistry-repositories-setiampolicy"


def snapshot(*, image="us-central1-docker.pkg.dev/p1/app/web:latest", repo=REPO,
             mode="STANDARD_REPOSITORY", immutable=False, policy=True,
             repo_binding=False, domain_constraint=False, org_status="empty"):
    def row(kind, scope, items, status="collected"):
        return {"type": kind, "scope": scope, "service": kind, "status": status,
                "items": items, "error": None}
    role = PROJECT + "/roles/policy-writer"
    source_binding = {"role": role, "members": ["user:source@example.com"]}
    repository = {"name": repo, "format": "DOCKER", "mode": mode,
                  "dockerConfig": {"immutableTags": immutable},
                  "iamPolicy": {"bindings": [source_binding] if repo_binding else []},
                  "_coverage": {"iamPolicy": {"status": "collected"}}}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT, CONSUMER],
            "metadata": {}, "collections": [
                row("project", PROJECT, [{"projectId": "p1", "name": "projects/111"}]),
                row("project", CONSUMER, [{"projectId": "p2", "name": "projects/222"}]),
                row("iam_role", PROJECT, [{"name": role, "includedPermissions":
                    ["artifactregistry.repositories.setIamPolicy"] if policy else []}]),
                row("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [] if repo_binding else [source_binding]}]),
                row("service_account", CONSUMER, [{"email": TARGET, "projectId": "p2",
                                                   "iamPolicy": {"bindings": []}}]),
                row("artifact_repository", PROJECT, [repository]),
                row("cloudrun_service", CONSUMER, [{"name": CONSUMER + "/locations/us-central1/services/web",
                    "template": {"serviceAccount": TARGET,
                                 "containers": [{"image": image}]}}]),
                row("org_policy_effective", PROJECT,
                    [{"constraint": "iam.allowedPolicyMemberDomains", "spec": {"rules": []}}]
                    if domain_constraint else [], org_status),
                row("iam_deny_policy", PROJECT, [], "empty"),
            ]}


def outcome(snap):
    model = GcpModel(snap)
    source = model.principals["user:source@example.com"]
    target = model.sas["serviceAccount:" + TARGET]
    direct = model.selector("gcp_artifact_policy_consumer_path", True,
                            {target.id: target}, source)
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = [reach for reach in Evaluator(model, [entry]).run()
               if reach.source.id == source.id]
    return direct.get(target.id), reaches


def test_project_policy_write_and_exact_consumer_is_conditional():
    verdict, reaches = outcome(snapshot())
    assert verdict[0] == "conditional"
    assert reaches


def test_repository_level_policy_write_is_not_missed():
    verdict, reaches = outcome(snapshot(repo_binding=True))
    assert verdict[0] == "conditional"
    assert reaches


def test_permission_or_exact_repository_missing_has_no_edge():
    assert outcome(snapshot(policy=False))[1] == []
    assert outcome(snapshot(image="us-central1-docker.pkg.dev/p1/other/web:latest"))[1] == []


def test_digest_pinned_and_remote_repository_have_no_upload_path():
    assert outcome(snapshot(image="us-central1-docker.pkg.dev/p1/app/web@sha256:" + "a" * 64))[1] == []
    assert outcome(snapshot(mode="REMOTE_REPOSITORY"))[1] == []


def test_immutable_tags_or_member_constraint_remain_unknown():
    assert outcome(snapshot(immutable=True))[0][0] == "unknown"
    assert outcome(snapshot(domain_constraint=True, org_status="collected"))[0][0] == "unknown"
    assert outcome(snapshot(org_status="denied"))[0][0] == "unknown"


def test_legacy_contract_remains_held():
    from peaso.privesc.versioned_catalog import _verified_prior
    prior, _ = _verified_prior()
    model = GcpModel(snapshot())
    assert Evaluator(model, [prior[TECHNIQUE]]).run() == []
    assert any(TECHNIQUE in row["reason"] for row in model.coverage)
