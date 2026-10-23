"""Safety checks for plans dispatched through operator-owned release Actions."""
from __future__ import annotations

import pytest

from scripts import peaso_gha_release as release


VERSION = "a" * 64
IMAGE = release.WORKER_REPOSITORY + "@sha256:" + "b" * 64


@pytest.fixture(autouse=True)
def private_integration(monkeypatch):
    monkeypatch.setenv("PEASO_DEPLOY_GCP_PLATFORM_SA_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-gcp-platform-sa-ABC123")


def test_review_rejects_a_different_operator_secret():
    candidate = plan()
    candidate["variables"]["gcp_platform_sa_secret_arn"]["value"] += "-different"
    with pytest.raises(ValueError, match="private configuration"):
        release.review_plan(candidate, {"source_version": VERSION})


def plan():
    return {
        "variables": {
            "source_version": {"value": VERSION},
            "region": {"value": release.REGION},
            "enable_public_customer_role_template": {"value": True},
            "gcp_platform_sa_secret_arn": {"value": "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-gcp-platform-sa-ABC123"},
            "worker_image": {"value": IMAGE},
            "api_zip": {"value": str(release.deploy.BUILD / "api.zip")},
        },
        "resource_changes": [
            {"mode": "managed", "address": address, "change": {"actions": ["update"]}}
            for address in sorted(release.REQUIRED_RUNTIME - {'aws_ecs_task_definition.tasks'})
        ] + [
            {"mode": "managed", "address": f'aws_ecs_task_definition.tasks["{stage}"]',
             "change": {"actions": ["delete", "create"]}}
            for stage in ('collector', 'analyzer')
        ],
        "resource_drift": [],
    }


def test_review_accepts_only_dedicated_runtime_updates():
    summary = release.review_plan(plan(), {"source_version": VERSION})
    assert summary["source_version"] == VERSION
    assert len(summary["changes"]) == 4


def test_review_accepts_dedicated_role_free_ai_runtime_resources():
    candidate = plan()
    dedicated = {'aws_ecs_cluster.ai', 'aws_cloudwatch_log_group.ai_tasks',
                 'aws_iam_role.ai_execution', 'aws_iam_role_policy.ai_execution'}
    candidate['resource_changes'] += [
        {'mode': 'managed', 'address': address, 'change': {'actions': ['create']}}
        for address in sorted(dedicated)
    ]
    summary = release.review_plan(candidate, {'source_version': VERSION})
    assert dedicated <= {row['address'] for row in summary['changes']}
    candidate['resource_changes'].append({
        'mode': 'managed', 'address': 'aws_iam_role.other_execution',
        'change': {'actions': ['create']}})
    with pytest.raises(ValueError, match='Unowned Terraform change'):
        release.review_plan(candidate, {'source_version': VERSION})


@pytest.mark.parametrize("address,actions", [
    ("aws_lambda_function.wiki_backend", ["update"]),
    ("aws_lambda_function.api", ["delete"]),
    ("module.other.aws_lambda_function.api", ["update"]),
])
def test_review_rejects_unowned_or_destructive_change(address, actions):
    candidate = plan()
    candidate["resource_changes"].append(
        {"mode": "managed", "address": address, "change": {"actions": actions}}
    )
    with pytest.raises(ValueError):
        release.review_plan(candidate, {"source_version": VERSION})


def test_review_requires_complete_runtime_and_frozen_image():
    candidate = plan()
    candidate["resource_changes"].pop()
    with pytest.raises(ValueError, match="both collector and analyzer"):
        release.review_plan(candidate, {"source_version": VERSION})
    candidate = plan()
    candidate["resource_changes"].pop(0)
    with pytest.raises(ValueError, match="all CSPM API and worker runtimes"):
        release.review_plan(candidate, {"source_version": VERSION})
    candidate = plan()
    candidate["variables"]["worker_image"]["value"] = IMAGE.replace("@sha256:", ":latest-")
    with pytest.raises(ValueError, match="immutable"):
        release.review_plan(candidate, {"source_version": VERSION})


@pytest.mark.parametrize("member_count,accepted", [(2504, True), (release.deploy.CURRENT_SOURCE_MEMBER_LIMIT, True), (release.deploy.CURRENT_SOURCE_MEMBER_LIMIT + 1, False)])
def test_current_source_member_growth_keeps_an_explicit_upper_bound(tmp_path, monkeypatch, member_count, accepted):
    import json
    import zipfile

    manifest = {"source_version": VERSION, "files": {}}
    archive = tmp_path / f"peaso-source-{VERSION}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        for index in range(member_count - 1):
            target.writestr(f"source/{index:04d}.txt", b"x")
        target.writestr("release.json", json.dumps(manifest, indent=2).encode())
    monkeypatch.setattr(release.deploy, "BUILD", tmp_path)
    if accepted:
        assert release.verify_source_archive(manifest) == archive
    else:
        with pytest.raises(ValueError, match="member count"):
            release.verify_source_archive(manifest)


def test_current_source_reviewer_accepts_exact_byte_budget_and_rejects_one_byte_over(tmp_path, monkeypatch):
    import json
    import zipfile

    manifest = {"source_version": VERSION, "files": {}}
    archive = tmp_path / f"peaso-source-{VERSION}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        target.writestr("release.json", json.dumps(manifest, indent=2).encode())
    monkeypatch.setattr(release.deploy, "BUILD", tmp_path)
    measured = archive.stat().st_size
    monkeypatch.setattr(release.deploy, "CURRENT_SOURCE_ARCHIVE_LIMIT", measured)
    assert release.verify_source_archive(manifest) == archive
    monkeypatch.setattr(release.deploy, "CURRENT_SOURCE_ARCHIVE_LIMIT", measured - 1)
    with pytest.raises(ValueError, match="reviewed size"):
        release.verify_source_archive(manifest)


def _sized_api_archive(path, expanded_bytes):
    import zipfile
    # A real compressed stream keeps disk/RAM use bounded while exercising
    # actual ZIP sizes, not a mocked central directory or relaxed test budget.
    block=b'0'*(1024*1024)
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as target:
        with target.open('payload.bin','w') as member:
            while expanded_bytes:
                chunk=block[:min(len(block),expanded_bytes)]
                member.write(chunk)
                expanded_bytes-=len(chunk)


@pytest.mark.parametrize('over_budget',[0,1])
def test_current_api_expanded_budget_accepts_exact_limit_and_rejects_one_byte_over(tmp_path,monkeypatch,over_budget):
    limit=release.deploy.CURRENT_API_UNCOMPRESSED_LIMIT
    assert limit==260_000_000 and limit<250*1024*1024
    _sized_api_archive(tmp_path/'api.zip',limit+over_budget)
    monkeypatch.setattr(release.deploy,'BUILD',tmp_path)
    if over_budget:
        with pytest.raises(ValueError,match='expands beyond reviewed size'):
            release.verify_api_archive()
    else:
        release.verify_api_archive()


def test_api_producer_enforces_shared_expanded_budget_before_zip_write(tmp_path,monkeypatch):
    deploy=release.deploy
    source=tmp_path/'source';source.mkdir()
    for name in ('peaso','risk_rules','bluepeass','scripts'):(source/name).mkdir()
    for name in ('bluepeass/__init__.py','bluepeass/k8s.py','bluepeass/k8s_risks.py','scripts/cloud_permission_risks.py'):
        (source/name).write_text('public source\n')
    build=tmp_path/'build'
    monkeypatch.setattr(deploy,'BUILD',build)
    monkeypatch.setattr(deploy,'source_root',lambda:source)
    # Isolate only dependency installation: this test exercises package_api's
    # real copy, permissions, member stat and pre-ZIP byte guard.
    monkeypatch.setattr(deploy,'run',lambda *args,**kwargs:None)
    monkeypatch.setattr(deploy,'CURRENT_API_UNCOMPRESSED_LIMIT',1)
    with pytest.raises(RuntimeError,match='API uncompressed byte limit exceeded'):
        deploy.package_api()
    assert not (build/'api.zip').exists()


def test_api_archive_upload_budget_accepts_exact_limit_and_rejects_one_byte_over(tmp_path, monkeypatch):
    import zipfile
    path = tmp_path / "api.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("runtime.py", b"# runtime\n")
    monkeypatch.setattr(release.deploy, "BUILD", tmp_path)
    measured = path.stat().st_size
    monkeypatch.setattr(release.deploy, "CURRENT_API_ARCHIVE_LIMIT", measured)
    release.verify_api_archive()
    monkeypatch.setattr(release.deploy, "CURRENT_API_ARCHIVE_LIMIT", measured - 1)
    with pytest.raises(ValueError, match="exceeds reviewed size"):
        release.verify_api_archive()
