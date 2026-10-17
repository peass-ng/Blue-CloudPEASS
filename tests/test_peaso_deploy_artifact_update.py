"""Offline artifact update route tests using exact private QA inputs."""
from __future__ import annotations
from tests.release_successor_history import historical_release as read_historical_release

from copy import deepcopy
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent if HERE.name == "tests" else HERE.parents[3]
sys.path.insert(0, str(ROOT))
if HERE.name == "tests":
    from scripts import peaso_deploy_artifact_update as artifact
    from scripts import peaso_deploy as deploy
else:
    sys.path.insert(0, str(HERE))
    import peaso_deploy_artifact_update as artifact
    deploy_spec = importlib.util.spec_from_file_location("proposed_peaso_deploy", HERE / "peaso_deploy.py")
    deploy = importlib.util.module_from_spec(deploy_spec)
    deploy_spec.loader.exec_module(deploy)
guard = artifact
fixture = SimpleNamespace(guard=artifact)
QA_ENV = "PEASO_ARTIFACT_UPDATE_QA_DIR"
QA_INPUTS = {
    "state.json": artifact.BASELINE_RAW_SHA,
    "old-plan.json": "a7d9ed2cd0cd8bc5fafdb986fe21dbbd169566aed7d01d94ade068b1aa5afdc0",
    "source.zip": artifact.SOURCE_ZIP_SHA,
    "api.zip": artifact.SOURCE_API_SHA,
    "frontend-build.json": artifact.SOURCE_FRONTEND_SHA,
    "release.json": artifact.SOURCE_RELEASE_SHA,
}

def candidate_frontend_files():
    """Retain every pinned asset name, with deterministic offline fixture bytes."""
    names = json.loads(OLD_FRONT.read_bytes())["files"]
    assert len(names) == 14 and "index.html" in names
    assert all(name and not Path(name).is_absolute() and ".." not in Path(name).parts for name in names)
    return {name: b"Offline artifact update fixture: " + name.encode() + b"\n"
            for name in sorted(names)}


def stage_candidate_frontend(destination: Path):
    """Materialize the candidate's own immutable build, independent of shared build output."""
    for name, body in candidate_frontend_files().items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

def private_inputs():
    value = os.environ.get(QA_ENV)
    if not value:
        raise unittest.SkipTest(f"{QA_ENV} exact private QA directory was not supplied")
    folder = Path(value)
    if not folder.is_absolute() or not folder.is_dir() or folder.is_symlink() or folder.stat().st_mode & 0o777 != 0o700:
        raise AssertionError("Artifact update QA input directory must be absolute, real, mode 0700")
    result = {}
    for name, expected in QA_INPUTS.items():
        path = folder / name
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o777 != 0o600:
            raise AssertionError("Artifact update QA input must be a real mode-0600 file: " + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise AssertionError("Artifact update QA input differs from pinned SHA256: " + name)
        result[name] = path
    return result

def synthetic_candidate_release(extra_files=None, api_extra=(), api_drop=(), drop_files=()):
    """One harmless README byte change, while retaining all 1,299 real members."""
    with zipfile.ZipFile(OLD_ZIP) as old:
        files = {name: old.read(name) for name in old.namelist() if name != "release.json"}
    assert len(files) == 1299 and "README.md" in files
    files["README.md"] += b"\nOffline artifact-update fixture only.\n"
    files.update(extra_files or {})
    for name in drop_files:
        del files[name]
    api_added = {name: files[name] for name in api_extra}
    manifest = {name: guard.sha(value) for name, value in files.items()}
    version = guard.sha(guard.canonical(manifest))
    release = {"source_version": version,
               "source_url": f"https://cspm.hacktricks.wiki/source/peaso-source-{version}.zip",
               "license": "AGPL-3.0", "files": manifest}
    release_raw = (json.dumps(release, indent=2) + "\n").encode()
    source_output = io.BytesIO()
    with zipfile.ZipFile(source_output, "w", compression=zipfile.ZIP_DEFLATED) as out:
        for name, value in sorted(files.items()):
            out.writestr(name, value)
        out.writestr("release.json", release_raw)
    source_zip = source_output.getvalue()
    del files
    api_output = io.BytesIO()
    with zipfile.ZipFile(OLD_API) as old, zipfile.ZipFile(api_output, "w") as out:
        for member in old.infolist():
            if member.filename in api_drop:
                continue
            body = release_raw if member.filename == "peaso_release.json" else old.read(member)
            out.writestr(member, body)
        for name, body in sorted(api_added.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(info, body)
    api_zip = api_output.getvalue()
    frontend = {"source_version": version,
                "files": {name: guard.sha(body) for name, body in candidate_frontend_files().items()}}
    frontend_raw = (json.dumps(frontend, indent=2) + "\n").encode()
    image = ("202533532952.dkr.ecr.us-east-1.amazonaws.com/hacktricks-cspm-worker"
             "@sha256:" + "1" * 64)
    candidate = {"source_version": version, "release_json_sha256": guard.sha(release_raw),
                 "source_zip_sha256": guard.sha(source_zip), "api_zip_sha256": guard.sha(api_zip),
                 "frontend_manifest_sha256": guard.sha(frontend_raw), "worker_image": image}
    return candidate, release_raw, source_zip, api_zip, frontend_raw


def complete_positive_fixture(state, release=None):
    """Build a complete offline plan from actual 75 state rows and seven data inputs."""
    candidate, release_raw, source_zip, api_zip, frontend_raw = release or synthetic_candidate_release()
    old = json.loads(OLD_PLAN.read_bytes())
    raw_resources = guard.managed(state)
    state_data = {}
    for block in state["resources"]:
        if block.get("mode") == "data":
            state_data[f'data.{block["type"]}.{block["name"]}'] = block["instances"][0]["attributes"]
    assert len(state_data) == 7
    drift = []
    resources = deepcopy(raw_resources)
    for address in ('aws_ecs_task_definition.tasks["collector"]',
                    'aws_ecs_task_definition.tasks["analyzer"]'):
        before = raw_resources[address]
        assert before.get("tags") is None
        after = deepcopy(before)
        after["tags"] = {}
        drift.append({"address": address, "mode": "managed", "change": {
            "actions": ["update"], "before": before, "after": after, "after_unknown": {}}})
        resources[address] = after
    prior = deepcopy(old["prior_state"]["values"]["root_module"]["resources"])
    assert len(prior) == 82
    for row in prior:
        address = row["address"]
        row["values"] = deepcopy(resources[address] if row["mode"] == "managed" else state_data[address])
    prior_map = {row["address"]: row for row in prior}
    old_changes = {row["address"]: row for row in old["resource_changes"]}
    assert len(old_changes) == 75
    rows = []
    for address, before in resources.items():
        old_row = old_changes[address]
        row = {key: deepcopy(old_row[key]) for key in ("address", "mode", "type", "name", "provider_name")}
        if "index" in old_row:
            row["index"] = deepcopy(old_row["index"])
        row["change"] = {"actions": ["no-op"], "before": deepcopy(before),
                         "after": deepcopy(before), "after_unknown": {}}
        rows.append(row)
    changes = {row["address"]: row["change"] for row in rows}
    version = candidate["source_version"]
    source_url = f"https://cspm.hacktricks.wiki/source/peaso-source-{version}.zip"
    api_hash = base64.b64encode(bytes.fromhex(candidate["api_zip_sha256"])).decode()
    for address in ("aws_lambda_function.api", "aws_lambda_function.scheduler"):
        before = changes[address]["before"]
        after = deepcopy(before)
        after["source_code_hash"] = api_hash
        after["environment"][0]["variables"]["PEASO_SOURCE_VERSION"] = version
        after["environment"][0]["variables"]["PEASO_SOURCE_URL"] = source_url
        changes[address].update({"actions": ["update"], "after": after})
    for address in ('aws_ecs_task_definition.tasks["collector"]',
                    'aws_ecs_task_definition.tasks["analyzer"]'):
        before = changes[address]["before"]
        after = deepcopy(before)
        container = json.loads(after["container_definitions"])
        container[0]["image"] = candidate["worker_image"]
        for item in container[0]["environment"]:
            if item["name"] == "PEASO_SOURCE_VERSION":
                item["value"] = version
        after["container_definitions"] = json.dumps(container, separators=(",", ":"))
        for key in ("arn", "arn_without_revision", "id", "revision", "enable_fault_injection", "ipc_mode", "pid_mode", "tags"):
            after[key] = None
        after["volume"] = [dict(after["volume"][0])]
        after["volume"][0].pop("configure_at_launch")
        markers = {key: True for key in ("arn", "arn_without_revision", "id", "revision", "enable_fault_injection")}
        markers["volume"] = [{"configure_at_launch": True, "docker_volume_configuration": [],
                              "efs_volume_configuration": [], "fsx_windows_file_server_volume_configuration": [],
                              "s3files_volume_configuration": []}]
        changes[address].update({"actions": ["delete", "create"], "after": after,
                                 "after_unknown": markers})
    for address, field in (("aws_sfn_state_machine.scan", "definition"),
                           ("aws_iam_role_policy.workflow", "policy")):
        before = changes[address]["before"]
        after = deepcopy(before)
        after[field] = re.sub(r'(task-definition/hacktricks-cspm-(?:collector|analyzer)):7', r'\1:8', before[field])
        assert after[field] != before[field]
        changes[address].update({"actions": ["update"], "after": after})
    data = {"errored": False, "applyable": True, "complete": True,
            "terraform_version": "1.14.3", "resource_drift": drift,
            "prior_state": {"values": {"root_module": {"resources": prior}}},
            "resource_changes": rows}
    refresh = {"errored": False, "terraform_version": "1.14.3", "resource_drift": deepcopy(drift)}
    refresh_raw = guard.canonical(refresh)
    plan_raw = guard.canonical(data)
    plan_binary = b"offline synthetic Terraform plan; never apply\n"
    approved_drift = {row["address"]: {
        "before_sha256": guard.sha(guard.canonical(row["change"]["before"])),
        "after_sha256": guard.sha(guard.canonical(row["change"]["after"])),
        "change_sha256": guard.sha(guard.canonical(row["change"]))} for row in drift}
    approved_changes = {address: {"actions": changes[address]["actions"],
                                  "changed_fields": guard.current.changed_fields(changes[address]),
                                  "change_sha256": guard.sha(guard.canonical(changes[address]))}
                        for address in guard.SIX_ACTIONS}
    baseline_release = {"source_version": guard.SOURCE_VERSION,
                        "release_json_sha256": guard.SOURCE_RELEASE_SHA,
                        "source_zip_sha256": guard.SOURCE_ZIP_SHA,
                        "api_zip_sha256": guard.SOURCE_API_SHA,
                        "frontend_manifest_sha256": guard.SOURCE_FRONTEND_SHA,
                        "worker_image": guard.SOURCE_IMAGE}
    contract = {"schema": "peaso-artifact-update-epoch29-v1", "account": guard.ACCOUNT,
                "backend": guard.BACKEND,
                "state": {"sha256": guard.BASELINE_RAW_SHA,
                          "canonical_sha256": guard.BASELINE_CANONICAL_SHA,
                          "lineage": guard.LINEAGE, "serial": guard.SERIAL,
                          "managed_address_sha256": guard.ADDRESS_SHA, "managed_count": guard.COUNT},
                "baseline_release": baseline_release, "candidate_release": candidate,
                "plan": {"sha256": guard.sha(plan_binary), "json_sha256": guard.sha(plan_raw)},
                "refresh": {"json_sha256": guard.sha(refresh_raw)},
                "approved_drift": approved_drift, "approved_changes": approved_changes}
    blobs = {"contract_raw": guard.canonical(contract), "state_raw": BASELINE.read_bytes(),
             "baseline_release_raw": OLD_RELEASE.read_bytes(),
             "refresh_raw": refresh_raw, "plan_raw": plan_raw, "plan_binary": plan_binary,
             "candidate_release_raw": release_raw, "candidate_source_zip": source_zip,
             "candidate_api_zip": api_zip, "candidate_frontend_manifest": frontend_raw}
    return contract, data, refresh, blobs


def private_file(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
    return path


class Client:
    def __init__(self, kind, *, active=False, account=artifact.ACCOUNT):
        self.kind, self.active, self.account = kind, active, account

    def get_caller_identity(self):
        return {"Account": self.account}

    def list_executions(self, **kwargs):
        return {"executions": [{"executionArn": "active"}] if self.active else []}

    def list_tasks(self, **kwargs):
        return {"taskArns": ["active"] if self.active else []}

    def get_item(self, **kwargs):
        return {}

    def scan(self, **kwargs):
        return {"Count": 0}

    def create_invalidation(self, **kwargs):
        return {"Invalidation": {"Id": "offline-only"}}


class Session:
    def __init__(self, *, active=False, account=artifact.ACCOUNT):
        self.active, self.account = active, account

    def client(self, kind):
        return Client(kind, active=self.active, account=self.account)


class ResolvedSession(Session):
    def __init__(self, resources, plan_rows, *, corrupt_object=False):
        super().__init__()
        self.resources, self.plan_rows = resources, plan_rows
        self.corrupt_object = corrupt_object

    def client(self, kind):
        if kind == "iam":
            return self
        if kind == "s3":
            return self
        return super().client(kind)

    def get_role_policy(self, **kwargs):
        workflow = self.resources["aws_iam_role_policy.workflow"]
        api = self.resources["aws_iam_role_policy.api"]
        if kwargs["RoleName"] == workflow["role"] and kwargs["PolicyName"] == workflow["name"]:
            text = self.plan_rows["aws_iam_role_policy.workflow"]["change"]["after"]["policy"]
        elif kwargs["RoleName"] == api["role"] and kwargs["PolicyName"] == api["name"]:
            text = api["policy"]
        else:
            raise AssertionError(kwargs)
        return {"PolicyDocument": json.loads(text)}

    def get_bucket_policy(self, **kwargs):
        assert kwargs["Bucket"] == self.resources["aws_s3_bucket.templates[0]"]["id"]
        return {"Policy": self.resources["aws_s3_bucket_policy.templates[0]"]["policy"]}

    def get_object(self, **kwargs):
        key = kwargs["Key"]
        digest = key.rsplit("customer-role-", 1)[-1].removesuffix(".json") if "customer-role-" in key else fixture.guard.current.TEMPLATE_HASHES[-1]
        path = ROOT / "infra/aws" / f"customer-role-{digest}.json"
        body = path.read_bytes()
        if self.corrupt_object:
            body += b"changed"
        template = key.startswith("customer-role-")
        result = {"ContentLength": len(body), "Body": io.BytesIO(body),
                  "ContentType": "application/json",
                  "ContentDisposition": 'attachment; filename="customer-role.json"'}
        if template:
            result.update({"Metadata": {"sha256": digest},
                           "CacheControl": "public,max-age=31536000,immutable"})
        if kwargs.get("ChecksumMode") == "ENABLED":
            result.update({"ServerSideEncryption": "AES256", "ChecksumType": "FULL_OBJECT",
                           "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode()})
        return result

    def get_object_acl(self, **kwargs):
        return {"Owner": {"ID": "owner"}, "Grants": [
            {"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}]}


class ArtifactOuterRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inputs = private_inputs()
        global BASELINE, OLD_PLAN, OLD_ZIP, OLD_API, OLD_FRONT, OLD_RELEASE
        BASELINE = inputs["state.json"]
        OLD_PLAN = inputs["old-plan.json"]
        OLD_ZIP = inputs["source.zip"]
        OLD_API = inputs["api.zip"]
        OLD_FRONT = inputs["frontend-build.json"]
        OLD_RELEASE = inputs["release.json"]
        fixture.BASELINE = BASELINE
        fixture.complete_positive_fixture = complete_positive_fixture
        cls.temporary = tempfile.TemporaryDirectory(prefix="epoch29-private-route-")
        cls.root = Path(cls.temporary.name)
        cls.infra = cls.root / "infra/aws"
        cls.build = cls.infra / "build"
        cls.build.mkdir(parents=True)
        state = json.loads(fixture.BASELINE.read_bytes())
        cls.review, cls.plan_data, cls.refresh, cls.blobs = fixture.complete_positive_fixture(state)
        # A real refresh-only JSON includes the same complete prior inventory.
        cls.refresh["prior_state"] = {"values": {"root_module": {
            "resources": deepcopy(cls.plan_data["prior_state"]["values"]["root_module"]["resources"])}}}
        cls.blobs["refresh_raw"] = artifact.canonical(cls.refresh)
        cls.review["refresh"]["json_sha256"] = artifact.sha(cls.blobs["refresh_raw"])
        with zipfile.ZipFile(io.BytesIO(cls.blobs["candidate_source_zip"])) as archive:
            for name in archive.namelist():
                body = archive.read(name)
                if name == "release.json":
                    path = cls.build / "source-snapshot/release.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
                    continue
                for base in (cls.root, cls.build / "source-snapshot"):
                    path = base / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
        target_dist = cls.build / "source-snapshot/frontend/dist"
        stage_candidate_frontend(target_dist)
        cls.release = json.loads(cls.blobs["candidate_release_raw"])
        (cls.build / "release.json").write_bytes(cls.blobs["candidate_release_raw"])
        (cls.build / f'peaso-source-{cls.release["source_version"]}.zip').write_bytes(cls.blobs["candidate_source_zip"])
        (cls.build / "api.zip").write_bytes(cls.blobs["candidate_api_zip"])
        (cls.build / "frontend-build.json").write_bytes(cls.blobs["candidate_frontend_manifest"])
        (cls.infra / "deployment.auto.tfvars.json").write_text(json.dumps({
            "source_version": cls.release["source_version"],
            "worker_image": cls.review["candidate_release"]["worker_image"],
            "api_zip": str((cls.build / "api.zip").resolve())}))
        backend = cls.infra / ".terraform/terraform.tfstate"
        backend.parent.mkdir(parents=True)
        backend.write_text(json.dumps({"backend": {"type": "s3", "config": artifact.BACKEND}}))
        cls.plan = private_file(cls.root / "saved-plan.tfplan", cls.blobs["plan_binary"])
        paths = {"state_path": private_file(cls.root / "state.private.json", cls.blobs["state_raw"]),
                 "refresh_path": private_file(cls.root / "refresh.private.json", cls.blobs["refresh_raw"]),
                 "plan_json_path": private_file(cls.root / "plan.private.json", cls.blobs["plan_raw"]),
                 "baseline_release_path": private_file(cls.root / "baseline-release.private.json",
                                                       cls.blobs["baseline_release_raw"])}
        outer = {"schema": "peaso-artifact-update-evidence-v1", "review": cls.review,
                 "evidence": {key: str(value.resolve()) for key, value in paths.items()}}
        cls.contract_raw = artifact.canonical(outer)
        cls.contract = private_file(cls.root / "contract.private.json", cls.contract_raw)
        cls.contract_sha = artifact.sha(cls.contract_raw)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def real_context(self):
        return artifact.load_context(self.plan, self.blobs["plan_raw"], self.plan_data,
                                     self.contract, self.contract_sha, self.infra, self.build)

    def test_real_private_loader_reviews_complete_fixture_and_frozen_root(self):
        result = self.real_context()
        self.assertEqual(len(result["resources"]), 75)
        self.assertEqual(len(result["approved_changes"]), 6)
        self.assertEqual(result["release"]["source_version"], self.release["source_version"])

    def test_loader_rejects_changed_private_contract_or_root_member(self):
        with self.assertRaises(RuntimeError):
            artifact.load_context(self.plan, self.blobs["plan_raw"], self.plan_data,
                                  self.contract, "0" * 64, self.infra, self.build)
        member = self.root / "README.md"
        before = member.read_bytes()
        try:
            member.write_bytes(before + b"changed")
            with self.assertRaises(RuntimeError):
                self.real_context()
        finally:
            member.write_bytes(before)

    def test_original_preapply_accepts_real_outer_envelope_and_rejects_changed_live_facts(self):
        state_text = [self.blobs["state_raw"].decode()]
        refresh_text = [self.blobs["refresh_raw"].decode()]
        def terraform_stub(*args, capture=False):
            if args[:2] == ("show", "-json") and Path(args[2]) == self.plan:
                return SimpleNamespace(stdout=self.blobs["plan_raw"].decode())
            if args[:2] == ("state", "pull"):
                return SimpleNamespace(stdout=state_text[0])
            if args[:2] == ("plan", "-refresh-only"):
                return SimpleNamespace(stdout="")
            if args[:2] == ("show", "-json"):
                return SimpleNamespace(stdout=refresh_text[0])
            raise AssertionError(args)
        with patch.object(deploy, "INFRA", self.infra), patch.object(deploy, "BUILD", self.build), \
             patch.object(deploy, "terraform", side_effect=terraform_stub):
            self.assertIsNone(deploy.verify_current_update_live(
                self.plan, self.contract, self.contract_sha, Session(), artifact=True))
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_live(self.plan, self.contract, self.contract_sha,
                                                  Session(active=True), artifact=True)
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_live(self.plan, self.contract, self.contract_sha,
                                                  Session(account="000000000000"), artifact=True)
            altered_state = json.loads(state_text[0])
            altered_state["serial"] = 30
            state_text[0] = json.dumps(altered_state)
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_live(self.plan, self.contract, self.contract_sha,
                                                  Session(), artifact=True)
            state_text[0] = self.blobs["state_raw"].decode()
            altered_refresh = deepcopy(self.refresh)
            altered_refresh["resource_drift"] = []
            refresh_text[0] = json.dumps(altered_refresh)
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_live(self.plan, self.contract, self.contract_sha,
                                                  Session(), artifact=True)

    def test_cli_paired_artifact_review_routes_to_real_loader(self):
        def real_review(plan, **kwargs):
            self.assertEqual(Path(plan).resolve(), self.plan.resolve())
            self.assertEqual(kwargs["artifact_update_contract"], self.contract)
            self.assertEqual(kwargs["artifact_update_sha256"], self.contract_sha)
            self.real_context()
            return artifact.sha(self.blobs["plan_binary"])
        argv = ["peaso_deploy.py", "review-artifact-plan", "--plan", str(self.plan),
                "--artifact-update-contract", str(self.contract),
                "--artifact-update-sha256", self.contract_sha]
        with patch.object(sys, "argv", argv), patch.object(deploy, "verify_backend"), \
             patch.object(deploy, "plan_summary", side_effect=real_review):
            deploy.main()
        with patch.object(sys, "argv", argv[:-2]):
            with self.assertRaises(SystemExit):
                deploy.main()

    def test_original_resolved_route_uses_real_loader_and_complete_object_readback(self):
        context = self.real_context()
        rows = {row["address"]: row for row in self.plan_data["resource_changes"]}
        revisions = {stage: f"arn:aws:ecs:us-east-1:{artifact.ACCOUNT}:task-definition/hacktricks-cspm-{stage}:8"
                     for stage in ("collector", "analyzer")}
        definition = json.loads(rows["aws_sfn_state_machine.scan"]["change"]["after"]["definition"])
        def show(*args, capture=False):
            self.assertEqual(args[:2], ("show", "-json"))
            return SimpleNamespace(stdout=self.blobs["plan_raw"].decode())
        with patch.object(deploy, "INFRA", self.infra), patch.object(deploy, "BUILD", self.build), \
             patch.object(deploy, "terraform", side_effect=show):
            deploy.verify_current_update_resolved(ResolvedSession(context["resources"], rows),
                                                  self.plan, self.contract, self.contract_sha,
                                                  definition, revisions, artifact=True)
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_resolved(
                    ResolvedSession(context["resources"], rows, corrupt_object=True),
                    self.plan, self.contract, self.contract_sha, definition, revisions, artifact=True)

    def test_resolved_reference_and_publication_target_binding(self):
        context = self.real_context()
        resources = context["resources"]
        rows = {row["address"]: row for row in self.plan_data["resource_changes"]}
        revisions = {stage: f"arn:aws:ecs:us-east-1:{artifact.ACCOUNT}:task-definition/hacktricks-cspm-{stage}:8"
                     for stage in ("collector", "analyzer")}
        workflow = json.loads(rows["aws_sfn_state_machine.scan"]["change"]["after"]["definition"])
        workflow_policy = json.loads(rows["aws_iam_role_policy.workflow"]["change"]["after"]["policy"])
        api_policy = json.loads(resources["aws_iam_role_policy.api"]["policy"])
        template_policy = json.loads(resources["aws_s3_bucket_policy.templates[0]"]["policy"])
        artifact.check_resolved_documents(resources, rows, workflow, workflow_policy,
                                          api_policy, template_policy, revisions)
        artifact.check_publish_target({"frontend_bucket": {"value": "hacktricks-cspm-frontend-202533532952"},
                                       "cloudfront_distribution_id": {"value": "E24KDR2EDPKSBS"}})
        with self.assertRaises(RuntimeError):
            artifact.check_publish_target({"frontend_bucket": {"value": "wiki-tools"},
                                           "cloudfront_distribution_id": {"value": "E24KDR2EDPKSBS"}})

    def test_candidate_frontend_survives_an_unrelated_later_build(self):
        manifest = json.loads(self.blobs["candidate_frontend_manifest"])
        self.assertEqual(len(manifest["files"]), 14)
        target = self.build / "source-snapshot/frontend/dist"
        actual = {str(path.relative_to(target)): artifact.sha(path.read_bytes())
                  for path in target.rglob("*") if path.is_file()}
        self.assertEqual(actual, manifest["files"])
        with tempfile.TemporaryDirectory(prefix="foreign-build-") as temporary:
            foreign = Path(temporary) / "frontend/dist"
            foreign.mkdir(parents=True)
            (foreign / "index.html").write_bytes(b"A different release was built later.\n")
            independent = Path(temporary) / "candidate/dist"
            stage_candidate_frontend(independent)
            staged = {str(path.relative_to(independent)): artifact.sha(path.read_bytes())
                      for path in independent.rglob("*") if path.is_file()}
            self.assertEqual(staged, manifest["files"])
            self.assertNotEqual(artifact.sha((foreign / "index.html").read_bytes()),
                                manifest["files"]["index.html"])

    def test_publish_cli_checks_original_resolved_gate_and_exact_output_target(self):
        argv = ["peaso_deploy.py", "publish-frontend", "--plan", str(self.plan),
                "--reviewed-sha256", artifact.sha(self.blobs["plan_binary"]),
                "--artifact-update-contract", str(self.contract),
                "--artifact-update-sha256", self.contract_sha]
        output = {"frontend_bucket": {"value": "hacktricks-cspm-frontend-202533532952"},
                  "cloudfront_distribution_id": {"value": "E24KDR2EDPKSBS"}}
        def terraform_output(*args, capture=False):
            self.assertEqual(args, ("output", "-json"))
            return SimpleNamespace(stdout=json.dumps(output))
        with patch.object(sys, "argv", argv), patch.object(deploy, "BUILD", self.build), \
             patch.object(deploy, "source_root", return_value=self.build / "source-snapshot"), \
             patch.object(deploy, "aws_identity", return_value=Session()), \
             patch.object(deploy, "verify_resolved_deployment") as resolved, \
             patch.object(deploy, "terraform", side_effect=terraform_output), \
             patch.object(deploy, "run") as run:
            deploy.main()
            resolved.assert_called_once()
            self.assertEqual(run.call_count, 4)
            self.assertIn("s3://hacktricks-cspm-frontend-202533532952/", run.call_args_list[0].args[0])
            run.reset_mock()
            output["frontend_bucket"]["value"] = "wiki-tools"
            with self.assertRaises(RuntimeError):
                deploy.main()
            run.assert_not_called()

    def test_publish_cli_rejects_changed_candidate_frontend(self):
        argv = ["peaso_deploy.py", "publish-frontend", "--plan", str(self.plan),
                "--reviewed-sha256", artifact.sha(self.blobs["plan_binary"]),
                "--artifact-update-contract", str(self.contract),
                "--artifact-update-sha256", self.contract_sha]
        index = self.build / "source-snapshot/frontend/dist/index.html"
        original = index.read_bytes()
        try:
            index.write_bytes(original + b"changed after candidate build\n")
            with patch.object(sys, "argv", argv), patch.object(deploy, "BUILD", self.build), \
                 patch.object(deploy, "source_root", return_value=self.build / "source-snapshot"), \
                 patch.object(deploy, "aws_identity", return_value=Session()), \
                 patch.object(deploy, "verify_resolved_deployment") as resolved, \
                 patch.object(deploy, "terraform") as terraform, patch.object(deploy, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "Built frontend changed"):
                    deploy.main()
                resolved.assert_called_once()
                terraform.assert_not_called()
                run.assert_not_called()
        finally:
            index.write_bytes(original)


class ArtifactSourceInventoryBounds(unittest.TestCase):
    """Public reproduction inputs grow the source ZIP; bounds and runtime set stay exact."""
    CONFIG = "peaso/checks/aws_config_recording.py"
    UNEXPECTED = "peaso/checks/zz_offline_runtime_fixture.py"
    LEDGER = "docs/compliance-ledgers/offline-fixture.json"
    SUCCESSOR_ADDITIONS = {
        "peaso/checks/aws_backup_plan_frequency.py": "0f40ddcace19dded128369f32efad6d72e36a8a95590073beb8cada2d4cff08d",
        "peaso/checks/central_native_fixtures.py": "2b9665b5b12e164a76b0982bc055857be82cd72d09eafcb8588bc96ead0503f4",
        "peaso/checks/gcp_data_access.py": "ce997648d524475e848aff41353b99f3add7075eca451146a89a7998da9f51c5",
        "peaso/checks/k8s_namespace_policy_presence.py": "47f64b995e1f5ca9b6db72ff62a7a4594521448f2a1fbba174d453251698a2b2",
        "peaso/collectors/aws_policy.py": "a3003f6c3930bd5f23523cc6128192ee6a22891a47035df922e34498ada0429d",
        "peaso/gcp_data_access_policy.py": "03167a5cf56583a9ae4efb08aba2beb24fa0e62fcafded1b6f7f47181cb5d4c7",
    }

    @classmethod
    def setUpClass(cls):
        inputs = private_inputs()
        global BASELINE, OLD_PLAN, OLD_ZIP, OLD_API, OLD_FRONT, OLD_RELEASE
        BASELINE, OLD_PLAN, OLD_ZIP = inputs["state.json"], inputs["old-plan.json"], inputs["source.zip"]
        OLD_API, OLD_FRONT, OLD_RELEASE = inputs["api.zip"], inputs["frontend-build.json"], inputs["release.json"]
        cls.state = json.loads(BASELINE.read_bytes())
        cls.config = (ROOT / cls.CONFIG).read_bytes()
        assert guard.sha(cls.config) == guard.APPROVED_RUNTIME_ADDITIONS[cls.CONFIG]
        cls.extra = {cls.CONFIG: cls.config, cls.LEDGER: b'{"offline": true}\n'}
        cls.blobs = cls.fixture(extra_files=cls.extra, api_extra=(cls.CONFIG,))

    @classmethod
    def fixture(cls, **release):
        return complete_positive_fixture(cls.state, synthetic_candidate_release(**release))[3]

    def test_reviewed_bounds_cover_measured_reproduction_source(self):
        self.assertEqual((guard.MAX_SOURCE_MEMBERS, guard.MAX_SOURCE_MEMBER_BYTES,
                          guard.MAX_SOURCE_UNCOMPRESSED_BYTES, guard.MAX_SOURCE_ARCHIVE_BYTES,
                          guard.BASELINE_RUNTIME_MEMBERS),
                         (1866, 40_000_000, 250_000_000, 32_000_000, 751))
        self.assertEqual(guard.APPROVED_RUNTIME_ADDITIONS, {
            self.CONFIG: "50800c1a5c30aa407d0791d4416cc473ea19c3d03f584a2a4a2cfa694d2eabec"})
        # Prospective full-source freeze with public ledgers (members incl.
        # release.json, largest member, expanded bytes, archive bytes); this
        # file's own edits move the last two by a few kilobytes at most.
        measured = (1450, 35_167_907, 228_642_059, 27_220_715)
        self.assertLessEqual(measured[0], guard.MAX_SOURCE_MEMBERS + 1)
        self.assertLessEqual(measured[1], guard.MAX_SOURCE_MEMBER_BYTES)
        self.assertLessEqual(measured[2], guard.MAX_SOURCE_UNCOMPRESSED_BYTES)
        self.assertLessEqual(measured[3], guard.MAX_SOURCE_ARCHIVE_BYTES)

    def test_legacy_baseline_runtime_set_is_reviewed(self):
        blobs = self.fixture(extra_files={self.LEDGER: self.extra[self.LEDGER]})
        self.assertEqual(len(guard.review_bytes(**blobs)["approved_changes"]), 6)

    def test_approved_config_runtime_and_ledger_members_are_reviewed(self):
        result = guard.review_bytes(**self.blobs)
        self.assertEqual(len(result["approved_changes"]), 6)
        release = json.loads(self.blobs["candidate_release_raw"])
        self.assertEqual(len(release["files"]), 1301)
        self.assertEqual(release["files"][self.CONFIG], guard.APPROVED_RUNTIME_ADDITIONS[self.CONFIG])

    def successor_files(self):
        approved = {self.CONFIG: guard.APPROVED_RUNTIME_ADDITIONS[self.CONFIG], **self.SUCCESSOR_ADDITIONS}
        self.assertEqual(guard.APPROVED_SUCCESSOR_RUNTIME_ADDITIONS, approved)
        files = {name: (ROOT / name).read_bytes() for name in approved}
        self.assertEqual({name: guard.sha(body) for name, body in files.items()}, approved)
        return files

    def test_exact_successor_runtime_and_ledger_members_are_reviewed(self):
        files = self.successor_files()
        blobs = self.fixture(extra_files={**files, self.LEDGER: self.extra[self.LEDGER]},
                             api_extra=tuple(files))
        self.assertEqual(len(guard.review_bytes(**blobs)["approved_changes"]), 6)
        release = json.loads(blobs["candidate_release_raw"])
        self.assertEqual(len(release["files"]), 1307)
        self.assertEqual({name: release["files"][name] for name in files},
                         guard.APPROVED_SUCCESSOR_RUNTIME_ADDITIONS)

    def test_incomplete_successor_runtime_set_rejected(self):
        files = self.successor_files()
        files.pop("peaso/checks/central_native_fixtures.py")
        blobs = self.fixture(extra_files=files, api_extra=tuple(files))
        with self.assertRaisesRegex(RuntimeError, "required runtime inventory differs"):
            guard.review_bytes(**blobs)

    def test_successor_runtime_wrong_bytes_rejected(self):
        files = self.successor_files()
        files["peaso/gcp_data_access_policy.py"] += b"\n"
        blobs = self.fixture(extra_files=files, api_extra=tuple(files))
        with self.assertRaisesRegex(RuntimeError, "required runtime inventory differs"):
            guard.review_bytes(**blobs)

    def test_successor_runtime_extra_member_rejected(self):
        files = self.successor_files()
        files[self.UNEXPECTED] = b"VALUE = 1\n"
        blobs = self.fixture(extra_files=files, api_extra=tuple(files))
        with self.assertRaisesRegex(RuntimeError, "required runtime inventory differs"):
            guard.review_bytes(**blobs)

    def test_unexpected_runtime_member_rejected(self):
        for extra in ({self.UNEXPECTED: b"VALUE = 1\n"},
                      {self.CONFIG: self.config, self.UNEXPECTED: b"VALUE = 1\n"},
                      {"risk_rules/zz_offline.yaml": b"rules: []\n"}):
            with self.subTest(sorted(extra)):
                blobs = self.fixture(extra_files=extra, api_extra=tuple(extra))
                with self.assertRaisesRegex(RuntimeError, "required runtime inventory differs"):
                    guard.review_bytes(**blobs)

    def test_approved_runtime_member_wrong_bytes_rejected(self):
        blobs = self.fixture(extra_files={self.CONFIG: self.config + b"\n"}, api_extra=(self.CONFIG,))
        with self.assertRaisesRegex(RuntimeError, "required runtime inventory differs"):
            guard.review_bytes(**blobs)

    def test_source_archive_budget_rejects_one_byte_over(self):
        size = len(self.blobs["candidate_source_zip"])
        with patch.object(guard, "MAX_SOURCE_ARCHIVE_BYTES", size - 1):
            with self.assertRaisesRegex(RuntimeError, "source ZIP exceeds measured archive budget"):
                guard.review_bytes(**self.blobs)
        with patch.object(guard, "MAX_SOURCE_ARCHIVE_BYTES", size):
            guard.review_bytes(**self.blobs)

    def test_source_expanded_and_member_budgets_reject_one_over(self):
        with zipfile.ZipFile(io.BytesIO(self.blobs["candidate_source_zip"])) as archive:
            members = archive.infolist()
        expanded = sum(member.file_size for member in members)
        largest = max(member.file_size for member in members)
        for name, value in (("MAX_SOURCE_UNCOMPRESSED_BYTES", expanded - 1),
                            ("MAX_SOURCE_MEMBERS", len(members) - 2),
                            ("MAX_SOURCE_MEMBER_BYTES", largest - 1)):
            with self.subTest(name), patch.object(guard, name, value):
                with self.assertRaisesRegex(RuntimeError, "source ZIP inventory differs"):
                    guard.review_bytes(**self.blobs)

    def test_api_must_carry_approved_runtime_member(self):
        blobs = self.fixture(extra_files=self.extra)
        with self.assertRaisesRegex(RuntimeError, "API ZIP inventory or metadata differs"):
            guard.review_bytes(**blobs)

    def test_api_must_keep_every_baseline_runtime_member(self):
        blobs = self.fixture(extra_files=self.extra, api_extra=(self.CONFIG,), api_drop=("peaso/engine.py",))
        with self.assertRaisesRegex(RuntimeError, "API ZIP inventory or metadata differs"):
            guard.review_bytes(**blobs)

    def test_candidate_cannot_drop_baseline_runtime_member(self):
        # The ledger keeps the candidate at 1,299 members so the drop itself is judged.
        blobs = self.fixture(extra_files={self.LEDGER: self.extra[self.LEDGER]},
                             drop_files=("peaso/engine.py",), api_drop=("peaso/engine.py",))
        with self.assertRaisesRegex(RuntimeError, "omitted a baseline source member"):
            guard.review_bytes(**blobs)


if __name__ == "__main__":
    unittest.main()


def test_exact_next_batch_runtime_roster_rejects_partial_altered_and_extra_members():
    historical = guard.APPROVED_BATCH_RUNTIME_ADDITIONS
    assert historical and len(historical) == 35
    accepted = guard.APPROVED_POST_DFAF_RUNTIME_ADDITIONS
    assert set(accepted) - set(historical) == {"peaso/checks/post_dfaf_aws.py", "peaso/checks/post_dfaf_aws_specs.py", "peaso/checks/post_dfaf_azure.py"}
    assert {n for n in historical if historical[n] != accepted[n]} == {"peaso/checks/central_batch_fixtures.json", "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json", "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json"}
    assert len(accepted) == 38
    accepted_release = read_historical_release(ROOT / 'infra/aws/build/peaso-source-649803fb5d475bee5dfcfc33ab91dbef803ba117b5d9949f08e273debae5b646.zip')
    assert read_historical_release(ROOT / 'infra/aws/build/peaso-source-bb12ea10f8c3b32e7902108232bb92c982cffbfddfe6130ab94d9cbf8bc202f9.zip')['source_version']=='bb12ea10f8c3b32e7902108232bb92c982cffbfddfe6130ab94d9cbf8bc202f9'
    assert accepted_release["source_version"] == "649803fb5d475bee5dfcfc33ab91dbef803ba117b5d9949f08e273debae5b646"
    assert len(accepted_release["files"]) == 1554
    next20_changed = {"peaso/checks/central_batch_fixtures.json",
                      "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json"}
    assert {name: accepted_release["files"][name] for name in accepted if name not in next20_changed} == \
           {name: digest for name, digest in accepted.items() if name not in next20_changed}
    approved = guard.APPROVED_NEXT20_RUNTIME_ADDITIONS
    assert {name: accepted_release["files"][name] for name in approved} == approved
    assert set(approved) - set(accepted) == {"peaso/checks/next20_aws.py"}
    assert {name for name in accepted if accepted[name] != approved[name]} == {
        "peaso/checks/central_batch_fixtures.json",
        "peaso/rulepacks/remediation_compliance_batch_remaining_aws.json"}
    assert len(approved) == 39
    old_runtime = {name for name in accepted_release["files"]
                   if name.startswith(("peaso/", "risk_rules/"))} | guard.RUNTIME_EXTRAS
    assert len(old_runtime) == 790
    assert len(old_runtime | {"peaso/checks/next20_aws.py"}) == 790
    assert guard.approved_runtime_additions(historical)
    assert guard.approved_runtime_additions(accepted)
    current = guard.APPROVED_APIM_GCP_RUNTIME_ADDITIONS
    evolved = {"peaso/checks/central_batch_fixtures.json",
               "peaso/rulepacks/remediation_compliance_batch_remaining_azure.json",
               "peaso/rulepacks/remediation_compliance_batch_remaining_gcp.json"}
    # Historical exact branches are verified against their immutable release.
    assert {name: accepted_release["files"][name] for name in approved} == approved
    bb12_release = read_historical_release(ROOT / 'infra/aws/build/peaso-source-bb12ea10f8c3b32e7902108232bb92c982cffbfddfe6130ab94d9cbf8bc202f9.zip')
    assert {name: bb12_release["files"][name] for name in current} == current
    # Current candidate runtime bytes have a separate exact admission branch.
    from tests.release_successor_history import ancestor_sha
    assert {name: ancestor_sha(ROOT / name) for name in guard.APPROVED_TWO_HOUR_NATIVE_RUNTIME_ADDITIONS} == guard.APPROVED_TWO_HOUR_NATIVE_RUNTIME_ADDITIONS
    assert guard.approved_runtime_additions(approved)
    for exact in (accepted, approved):
        first = next(iter(exact))
        assert not guard.approved_runtime_additions({k: v for k, v in exact.items() if k != first})
        assert not guard.approved_runtime_additions({**exact, first: "0" * 64})
        assert not guard.approved_runtime_additions({**exact, "peaso/checks/zz_unreviewed.py": "0" * 64})
    assert guard.approved_runtime_additions({})
    assert guard.approved_runtime_additions(guard.APPROVED_RUNTIME_ADDITIONS)
    assert guard.approved_runtime_additions(guard.APPROVED_SUCCESSOR_RUNTIME_ADDITIONS)


def test_exact_next_group_runtime_admission_rejects_missing_tampered_extra():
    current = guard.APPROVED_NEXT_GROUP_RUNTIME_ADDITIONS
    assert guard.approved_runtime_additions(current)
    preimages = {
        "peaso/collectors/gcp.py": "9325aad599a5929050c2add8f743882638741912811a5b54a3d41d703f76cb41",
        "peaso/collectors/azure.py": "f98a2f8f9181ddcf1a07592a525e8df8abaeab428d2115a07346b466b9bfbc5d",
    }
    published = read_historical_release(ROOT / 'infra/aws/build/peaso-source-7d60a2384e5d1ec0b18213af2dae8f078ef095553e9a938c324ae4af45a4530e.zip')
    for name, digest in current.items():
        if name in preimages:
            assert digest == preimages[name]
        else:
            assert published['files'][name] == digest
    first = next(iter(current))
    assert not guard.approved_runtime_additions({name:value for name,value in current.items() if name!=first})
    assert not guard.approved_runtime_additions({**current,first:'0'*64})


def test_live_validation_successor_is_exact_and_preserves_historical_branches():
    historical = guard.APPROVED_NEXT_GROUP_RUNTIME_ADDITIONS
    current = guard.APPROVED_LIVE_VALIDATION_RUNTIME_ADDITIONS
    assert set(current) - set(historical) == {
        "peaso/engine.py", "peaso/analysis/network.py", "peaso/analysis/internet_exposure.py"}
    assert {name for name in historical if current[name] != historical[name]} == {
        "peaso/collectors/gcp.py", "peaso/collectors/azure.py"}
    assert guard.approved_runtime_additions(current)
    published = read_historical_release(ROOT / 'infra/aws/build/peaso-source-7d60a2384e5d1ec0b18213af2dae8f078ef095553e9a938c324ae4af45a4530e.zip')
    for name, digest in current.items():
        assert published['files'][name] == digest
        assert not guard.approved_runtime_additions({key: value for key, value in current.items() if key != name})
        assert not guard.approved_runtime_additions({**current, name: "0" * 64})
    assert not guard.approved_runtime_additions({**current, "peaso/unreviewed.py": "0" * 64})
    assert not guard.approved_runtime_additions({**current,'peaso/checks/extra_unreviewed.py':'0'*64})


def test_gcp_history_successor_preserves_old_release_and_rejects_any_unreviewed_change():
    historical = guard.APPROVED_LIVE_VALIDATION_RUNTIME_ADDITIONS
    current = guard.APPROVED_GCP_HISTORY_RUNTIME_ADDITIONS
    assert set(current) - set(historical) == {'peaso/collectors/gcp_history.py',
        'peaso/collectors/gcp_compliance_wave.py'}
    assert {n for n in historical if historical[n] != current[n]} == {'peaso/collectors/gcp.py', 'peaso/server/validation.py'}
    assert guard.approved_runtime_additions(current)
    published = read_historical_release(ROOT / 'infra/aws/build/peaso-source-e022caf8ffd81b18571939a12313dfd9afa60c8f2095239cf3ad25e3002a31b7.zip')
    for name, digest in current.items():
        assert published['files'][name] == digest
        assert not guard.approved_runtime_additions({k: v for k, v in current.items() if k != name})
        assert not guard.approved_runtime_additions({**current, name: '0' * 64})
    assert not guard.approved_runtime_additions({**current, 'peaso/unreviewed.py': '0' * 64})


def test_psc_runtime_delta_is_exact_signed_and_preserves_every_other_registered_id():
    from tests.release_successor_history import ancestor_sha, ancestor_json
    changes = json.loads((ROOT / 'tests/fixtures/post_dfaf_integration/psc_native_source_changes.json').read_text())['changes']
    historical = guard.APPROVED_PSC_RUNTIME_ADDITIONS
    current = guard.APPROVED_TWO_HOUR_NATIVE_RUNTIME_ADDITIONS
    cohort = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/two_hour_native_cohort.json").read_text())
    assert guard.approved_runtime_additions(current)
    assert {n: ancestor_sha(ROOT / n) for n in current} == current
    for name in current:
        assert not guard.approved_runtime_additions({k: v for k, v in current.items() if k != name})
        assert not guard.approved_runtime_additions({**current, name: '0' * 64})
    assert not guard.approved_runtime_additions({**current, 'peaso/unreviewed.py': '0' * 64})
    for name, entry in changes.items():
        assert ancestor_sha(ROOT / name) == cohort['source_changes'].get(name,entry)['sha256']
    from tests.release_successor_history import historical_catalog_ids
    baseline_ids = historical_catalog_ids(ROOT / 'infra/aws/build/peaso-source-e022caf8ffd81b18571939a12313dfd9afa60c8f2095239cf3ad25e3002a31b7.zip')
    latest = ancestor_json(ROOT / 'peaso/rulepacks/native_catalog.json')
    assert {c['id'] for c in latest['checks']} - baseline_ids == {'gcp.network.private_service_connect_google_apis'} | set(cohort['ids'])
    assert baseline_ids <= {c['id'] for c in latest['checks']}


def test_v20_exact_runtime_additions_match_reviewed_current_bytes():
    current = guard.APPROVED_V20_RUNTIME_ADDITIONS
    assert len(current) == 159
    assert guard.BASELINE_RUNTIME_MEMBERS == 751
    assert guard.APPROVED_V20_RUNTIME_MEMBERS == 909
    assert {name: _v20_current_source_files_without_export()[name] for name in current} == current
    assert guard.approved_runtime_additions(current)


def test_v20_runtime_additions_reject_every_missing_or_tampered_member():
    current = guard.APPROVED_V20_RUNTIME_ADDITIONS
    for name in current:
        assert not guard.approved_runtime_additions({k: v for k, v in current.items() if k != name})
        assert not guard.approved_runtime_additions({**current, name: '0' * 64})


def test_v20_runtime_additions_reject_extra_and_unreviewed_successor():
    current = guard.APPROVED_V20_RUNTIME_ADDITIONS
    assert not guard.approved_runtime_additions({**current, 'peaso/unreviewed_v20.py': '0' * 64})
    assert not guard.approved_runtime_additions({**current, 'peaso/rulepacks/upstream_manifest.json.gz': '0' * 64})


@__import__('functools').lru_cache(maxsize=1)
def _v20_current_source_files_without_export():
    """Retain the authenticated V20 source roster as newer releases evolve."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-fed2b285bc9a88e78c519eaf8e1cfe7ee9614657c60b2981247ccba1b82300ae.zip')['files']


def test_v20_complete_exporter_inventory_and_only_canonical_gzip_omission_admitted():
    files = _v20_current_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(files) == 1807 and len(runtime) == 909
    assert guard.approved_v20_runtime(runtime)
    assert guard.approved_v20_baseline_omission(files, baseline)
    assert set(baseline) - set(files) == {'peaso/rulepacks/upstream_manifest.json.gz'}
    assert {name: digest for name, digest in runtime.items() if name not in baseline} == guard.APPROVED_V20_RUNTIME_ADDITIONS


def test_v20_complete_runtime_rejects_every_missing_tampered_and_extra_member():
    files = _v20_current_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    for name in runtime:
        assert not guard.approved_v20_runtime({key: value for key, value in runtime.items() if key != name})
        assert not guard.approved_v20_runtime({**runtime, name: '0' * 64})
    assert not guard.approved_v20_runtime({**runtime, 'peaso/unreviewed_v20.py': '0' * 64})


def test_v20_gzip_exception_rejects_other_omissions_and_modified_canonical_json():
    files = _v20_current_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    for name in ('README.md', 'peaso/engine.py'):
        omitted = {key: value for key, value in files.items() if key != name}
        assert not guard.approved_v20_baseline_omission(omitted, baseline)
        assert not guard.approved_v20_baseline_omission({**omitted, 'docs/unreviewed_v20.txt': '0' * 64}, baseline)
    plain = 'peaso/rulepacks/upstream_manifest.json'
    assert not guard.approved_v20_baseline_omission({**files, plain: '0' * 64}, baseline)
    assert not guard.approved_v20_baseline_omission(files, {**baseline, plain: '0' * 64})
    duplicate = plain + '.gz'
    assert not guard.approved_v20_baseline_omission(files, {**baseline, duplicate: '0' * 64})
    assert not guard.approved_v20_baseline_omission({**files, duplicate: baseline[duplicate]}, baseline)




@__import__('functools').lru_cache(maxsize=1)
def _v21_candidate_source_files_without_export():
    """Read the approved immutable44b6 roster as subsequent source evolves."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-44b6c987a289a94221730fd48f0b67cbac7f0877a4f2d114cbc4b145537810d6.zip')['files']


def test_v21_complete_runtime_and_source_inventory_are_exact():
    files = _v21_candidate_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(files) == guard.APPROVED_V21_SOURCE_MEMBERS <= guard.MAX_SOURCE_MEMBERS
    assert len(runtime) == guard.APPROVED_V21_RUNTIME_MEMBERS
    assert guard.BASELINE_RUNTIME_MEMBERS == 751
    assert len(runtime) == 751 - 1 + len(guard.APPROVED_V21_RUNTIME_ADDITIONS)
    assert guard.approved_v21_runtime(runtime)
    assert guard.approved_v21_baseline_omission(files, baseline)
    assert set(baseline) - set(files) == {'peaso/rulepacks/upstream_manifest.json.gz'}
    additions = {name: digest for name, digest in runtime.items() if name not in baseline}
    assert additions == guard.APPROVED_V21_RUNTIME_ADDITIONS
    assert guard.approved_runtime_additions(additions)


def test_v21_complete_runtime_rejects_missing_tampered_and_extra_members():
    files = _v21_candidate_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    for name in runtime:
        assert not guard.approved_v21_runtime({key: value for key, value in runtime.items() if key != name})
        assert not guard.approved_v21_runtime({**runtime, name: '0' * 64})
    assert not guard.approved_v21_runtime({**runtime, 'peaso/unreviewed_v21.py': '0' * 64})
    additions = guard.APPROVED_V21_RUNTIME_ADDITIONS
    for name in additions:
        assert not guard.approved_runtime_additions({key: value for key, value in additions.items() if key != name})
        assert not guard.approved_runtime_additions({**additions, name: '0' * 64})
    assert not guard.approved_runtime_additions({**additions, 'peaso/unreviewed_v21.py': '0' * 64})


def test_v21_gzip_exception_cannot_omit_other_source_or_change_canonical_bytes():
    files = _v21_candidate_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    for name in ('README.md', 'peaso/engine.py'):
        omitted = {key: value for key, value in files.items() if key != name}
        assert not guard.approved_v21_baseline_omission(omitted, baseline)
        assert not guard.approved_v21_baseline_omission({**omitted, 'docs/unreviewed_v21.txt': '0' * 64}, baseline)
    plain = 'peaso/rulepacks/upstream_manifest.json'
    duplicate = plain + '.gz'
    assert not guard.approved_v21_baseline_omission({**files, plain: '0' * 64}, baseline)
    assert not guard.approved_v21_baseline_omission(files, {**baseline, plain: '0' * 64})
    assert not guard.approved_v21_baseline_omission(files, {**baseline, duplicate: '0' * 64})
    assert not guard.approved_v21_baseline_omission({**files, duplicate: baseline[duplicate]}, baseline)


def test_v21_preserves_exact_v20_admission_and_rejects_cross_version_runtime():
    old_files = _v20_current_source_files_without_export()
    old_runtime = {name: digest for name, digest in old_files.items()
                   if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(old_files) == 1807 and len(old_runtime) == 909
    assert guard.APPROVED_V20_RUNTIME_SHA256 == '1c98ed3c1c09c1a2cf4d2bc3d724f12e07378972b22e51965193441ec5477af8'
    assert guard.approved_v20_runtime(old_runtime)
    assert not guard.approved_v21_runtime(old_runtime)
    files = _v21_candidate_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert not guard.approved_v20_runtime(runtime)


@__import__('functools').lru_cache(maxsize=1)
def _v23_software_source_files_without_export():
    """Read the exact public f296 roster as subsequent source evolves."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-f296d6ef15f7a1d35c4efc2de520d82ca0c23704043fcc973bd4c6456af9624d.zip')['files']


def test_v23_software_complete_inventory_and_old_versions_are_independent():
    files = _v23_software_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(files) == guard.APPROVED_V23_SOURCE_MEMBERS == 1818 <= guard.MAX_SOURCE_MEMBERS
    assert len(runtime) == guard.APPROVED_V23_RUNTIME_MEMBERS == 914
    assert guard.BASELINE_RUNTIME_MEMBERS == 751
    assert len(runtime) == 751 - 1 + len(guard.APPROVED_V23_RUNTIME_ADDITIONS)
    assert guard.approved_v23_runtime(runtime)
    assert not guard.approved_v21_runtime(runtime)
    assert not guard.approved_v20_runtime(runtime)
    historic = _v21_candidate_source_files_without_export()
    old_runtime = {name: digest for name, digest in historic.items()
                   if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(historic) == 1814 and len(old_runtime) == 912
    assert guard.approved_v21_runtime(old_runtime)
    assert not guard.approved_v23_runtime(old_runtime)


def test_v23_software_runtime_rejects_every_missing_tampered_or_extra_member():
    files = _v23_software_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    for name in runtime:
        assert not guard.approved_v23_runtime({key: value for key, value in runtime.items() if key != name})
        assert not guard.approved_v23_runtime({**runtime, name: '0' * 64})
    assert not guard.approved_v23_runtime({**runtime, 'peaso/unreviewed_v23.py': '0' * 64})
    additions = guard.APPROVED_V23_RUNTIME_ADDITIONS
    assert guard.approved_runtime_additions(additions)
    for name in additions:
        assert not guard.approved_runtime_additions({key: value for key, value in additions.items() if key != name})
        assert not guard.approved_runtime_additions({**additions, name: '0' * 64})
    assert not guard.approved_runtime_additions({**additions, 'peaso/unreviewed_v23.py': '0' * 64})


def test_v23_software_only_verified_canonical_gzip_omission_is_admitted():
    files = _v23_software_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    assert guard.approved_v23_baseline_omission(files, baseline)
    assert set(baseline) - set(files) == {'peaso/rulepacks/upstream_manifest.json.gz'}
    additions = {name: digest for name, digest in files.items()
                 if name not in baseline and (name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS)}
    assert additions == guard.APPROVED_V23_RUNTIME_ADDITIONS


def test_v23_software_other_omissions_extra_source_or_changed_canonical_bytes_rejected():
    files = _v23_software_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    for name in ('README.md', 'peaso/engine.py'):
        omitted = {key: value for key, value in files.items() if key != name}
        assert not guard.approved_v23_baseline_omission(omitted, baseline)
        assert not guard.approved_v23_baseline_omission({**omitted, 'docs/unreviewed_v23.txt': '0' * 64}, baseline)
    plain = 'peaso/rulepacks/upstream_manifest.json'
    duplicate = plain + '.gz'
    assert not guard.approved_v23_baseline_omission({**files, plain: '0' * 64}, baseline)
    assert not guard.approved_v23_baseline_omission(files, {**baseline, plain: '0' * 64})
    assert not guard.approved_v23_baseline_omission(files, {**baseline, duplicate: '0' * 64})
    assert not guard.approved_v23_baseline_omission({**files, duplicate: baseline[duplicate]}, baseline)


@__import__('functools').lru_cache(maxsize=1)
def _v24_aks_source_files_without_export():
    """Read the exact public ddf roster as subsequent source evolves."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-ddf6933fd4bb85daed677b3d0ad7ebbb073c810b56c1d5dccc3bfae34db8020b.zip')['files']

def test_v24_aks_complete_inventory_and_old_versions_are_independent():
    files = _v24_aks_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(files) == guard.APPROVED_V24_SOURCE_MEMBERS == 1819 <= guard.MAX_SOURCE_MEMBERS
    assert len(runtime) == guard.APPROVED_V24_RUNTIME_MEMBERS == 914
    assert guard.BASELINE_RUNTIME_MEMBERS == 751
    assert len(runtime) == 751 - 1 + len(guard.APPROVED_V24_RUNTIME_ADDITIONS)
    assert guard.approved_v24_runtime(runtime)
    assert not guard.approved_v21_runtime(runtime)
    assert not guard.approved_v20_runtime(runtime)
    v23 = _v23_software_source_files_without_export()
    v23_runtime = {n: h for n,h in v23.items() if n.startswith(('peaso/','risk_rules/')) or n in guard.RUNTIME_EXTRAS}
    assert guard.approved_v23_runtime(v23_runtime) and not guard.approved_v24_runtime(v23_runtime)
    assert not guard.approved_v23_runtime(runtime)
    historic = _v21_candidate_source_files_without_export()
    old_runtime = {name: digest for name, digest in historic.items()
                   if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(historic) == 1814 and len(old_runtime) == 912
    assert guard.approved_v21_runtime(old_runtime)
    assert not guard.approved_v24_runtime(old_runtime)


def test_v24_aks_runtime_rejects_every_missing_tampered_or_extra_member():
    files = _v24_aks_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    for name in runtime:
        assert not guard.approved_v24_runtime({key: value for key, value in runtime.items() if key != name})
        assert not guard.approved_v24_runtime({**runtime, name: '0' * 64})
    assert not guard.approved_v24_runtime({**runtime, 'peaso/unreviewed_v23.py': '0' * 64})
    additions = guard.APPROVED_V24_RUNTIME_ADDITIONS
    assert guard.approved_runtime_additions(additions)
    for name in additions:
        assert not guard.approved_runtime_additions({key: value for key, value in additions.items() if key != name})
        assert not guard.approved_runtime_additions({**additions, name: '0' * 64})
    assert not guard.approved_runtime_additions({**additions, 'peaso/unreviewed_v23.py': '0' * 64})


def test_v24_aks_only_verified_canonical_gzip_omission_is_admitted():
    files = _v24_aks_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    assert guard.approved_v24_baseline_omission(files, baseline)
    assert set(baseline) - set(files) == {'peaso/rulepacks/upstream_manifest.json.gz'}
    additions = {name: digest for name, digest in files.items()
                 if name not in baseline and (name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS)}
    assert additions == guard.APPROVED_V24_RUNTIME_ADDITIONS


def test_v24_aks_other_omissions_extra_source_or_changed_canonical_bytes_rejected():
    files = _v24_aks_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    for name in ('README.md', 'peaso/engine.py'):
        omitted = {key: value for key, value in files.items() if key != name}
        assert not guard.approved_v24_baseline_omission(omitted, baseline)
        assert not guard.approved_v24_baseline_omission({**omitted, 'docs/unreviewed_v23.txt': '0' * 64}, baseline)
    plain = 'peaso/rulepacks/upstream_manifest.json'
    duplicate = plain + '.gz'
    assert not guard.approved_v24_baseline_omission({**files, plain: '0' * 64}, baseline)
    assert not guard.approved_v24_baseline_omission(files, {**baseline, plain: '0' * 64})
    assert not guard.approved_v24_baseline_omission(files, {**baseline, duplicate: '0' * 64})
    assert not guard.approved_v24_baseline_omission({**files, duplicate: baseline[duplicate]}, baseline)


@__import__('functools').lru_cache(maxsize=1)
def _v25_compat_source_files_without_export():
    """Keep exact V25 source372 as new candidate evolves."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-37271822fc123bd465c5edbf177535f1771e44d4f4f1e5ada23796c35b90cd0c.zip')['files']

def test_v25_compat_complete_inventory_and_old_versions_are_independent():
    files = _v25_compat_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(files) == guard.APPROVED_V25_SOURCE_MEMBERS == 1821 <= guard.MAX_SOURCE_MEMBERS
    assert len(runtime) == guard.APPROVED_V25_RUNTIME_MEMBERS == 914
    assert guard.BASELINE_RUNTIME_MEMBERS == 751
    assert len(runtime) == 751 - 1 + len(guard.APPROVED_V25_RUNTIME_ADDITIONS)
    assert guard.approved_v25_runtime(runtime)
    assert not guard.approved_v21_runtime(runtime)
    assert not guard.approved_v20_runtime(runtime)
    v23 = _v23_software_source_files_without_export()
    v23_runtime = {n: h for n,h in v23.items() if n.startswith(('peaso/','risk_rules/')) or n in guard.RUNTIME_EXTRAS}
    assert guard.approved_v23_runtime(v23_runtime) and not guard.approved_v25_runtime(v23_runtime)
    assert not guard.approved_v23_runtime(runtime)
    v24 = _v24_aks_source_files_without_export()
    v24_runtime = {n: h for n,h in v24.items() if n.startswith(('peaso/','risk_rules/')) or n in guard.RUNTIME_EXTRAS}
    assert guard.approved_v24_runtime(v24_runtime) and not guard.approved_v25_runtime(v24_runtime)
    assert not guard.approved_v24_runtime(runtime)
    historic = _v21_candidate_source_files_without_export()
    old_runtime = {name: digest for name, digest in historic.items()
                   if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(historic) == 1814 and len(old_runtime) == 912
    assert guard.approved_v21_runtime(old_runtime)
    assert not guard.approved_v25_runtime(old_runtime)


def test_v25_compat_runtime_rejects_every_missing_tampered_or_extra_member():
    files = _v25_compat_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    for name in runtime:
        assert not guard.approved_v25_runtime({key: value for key, value in runtime.items() if key != name})
        assert not guard.approved_v25_runtime({**runtime, name: '0' * 64})
    assert not guard.approved_v25_runtime({**runtime, 'peaso/unreviewed_v23.py': '0' * 64})
    additions = guard.APPROVED_V25_RUNTIME_ADDITIONS
    assert guard.approved_runtime_additions(additions)
    for name in additions:
        assert not guard.approved_runtime_additions({key: value for key, value in additions.items() if key != name})
        assert not guard.approved_runtime_additions({**additions, name: '0' * 64})
    assert not guard.approved_runtime_additions({**additions, 'peaso/unreviewed_v23.py': '0' * 64})


def test_v25_compat_only_verified_canonical_gzip_omission_is_admitted():
    files = _v25_compat_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    assert guard.approved_v25_baseline_omission(files, baseline)
    assert set(baseline) - set(files) == {'peaso/rulepacks/upstream_manifest.json.gz'}
    additions = {name: digest for name, digest in files.items()
                 if name not in baseline and (name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS)}
    assert additions == guard.APPROVED_V25_RUNTIME_ADDITIONS


def test_v25_compat_other_omissions_extra_source_or_changed_canonical_bytes_rejected():
    files = _v25_compat_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    for name in ('README.md', 'peaso/engine.py'):
        omitted = {key: value for key, value in files.items() if key != name}
        assert not guard.approved_v25_baseline_omission(omitted, baseline)
        assert not guard.approved_v25_baseline_omission({**omitted, 'docs/unreviewed_v23.txt': '0' * 64}, baseline)
    plain = 'peaso/rulepacks/upstream_manifest.json'
    duplicate = plain + '.gz'
    assert not guard.approved_v25_baseline_omission({**files, plain: '0' * 64}, baseline)
    assert not guard.approved_v25_baseline_omission(files, {**baseline, plain: '0' * 64})
    assert not guard.approved_v25_baseline_omission(files, {**baseline, duplicate: '0' * 64})
    assert not guard.approved_v25_baseline_omission({**files, duplicate: baseline[duplicate]}, baseline)


@__import__('functools').lru_cache(maxsize=1)
def _v26_apim_source_files_without_export():
    """Keep exact V26 source915e as the reviewed successor evolves."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-915e37aed843a02c49dd3c00f79adeacf1dcc99285ce557cebd2af61fe39919b.zip')['files']

def test_v26_apim_complete_inventory_and_old_versions_are_independent():
    files = _v26_apim_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(files) == guard.APPROVED_V26_SOURCE_MEMBERS == 1823 <= guard.MAX_SOURCE_MEMBERS
    assert len(runtime) == guard.APPROVED_V26_RUNTIME_MEMBERS == 915
    assert guard.BASELINE_RUNTIME_MEMBERS == 751
    assert len(runtime) == 751 - 1 + len(guard.APPROVED_V26_RUNTIME_ADDITIONS)
    assert guard.approved_v26_runtime(runtime)
    assert not guard.approved_v21_runtime(runtime)
    assert not guard.approved_v20_runtime(runtime)
    v25 = _v25_compat_source_files_without_export()
    old25 = {n:h for n,h in v25.items() if n.startswith(('peaso/','risk_rules/')) or n in guard.RUNTIME_EXTRAS}
    assert guard.approved_v25_runtime(old25) and not guard.approved_v26_runtime(old25)
    assert not guard.approved_v25_runtime(runtime)
    v23 = _v23_software_source_files_without_export()
    v23_runtime = {n: h for n,h in v23.items() if n.startswith(('peaso/','risk_rules/')) or n in guard.RUNTIME_EXTRAS}
    assert guard.approved_v23_runtime(v23_runtime) and not guard.approved_v26_runtime(v23_runtime)
    assert not guard.approved_v23_runtime(runtime)
    v24 = _v24_aks_source_files_without_export()
    v24_runtime = {n: h for n,h in v24.items() if n.startswith(('peaso/','risk_rules/')) or n in guard.RUNTIME_EXTRAS}
    assert guard.approved_v24_runtime(v24_runtime) and not guard.approved_v26_runtime(v24_runtime)
    assert not guard.approved_v24_runtime(runtime)
    historic = _v21_candidate_source_files_without_export()
    old_runtime = {name: digest for name, digest in historic.items()
                   if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    assert len(historic) == 1814 and len(old_runtime) == 912
    assert guard.approved_v21_runtime(old_runtime)
    assert not guard.approved_v26_runtime(old_runtime)


def test_v26_apim_runtime_rejects_every_missing_tampered_or_extra_member():
    files = _v26_apim_source_files_without_export()
    runtime = {name: digest for name, digest in files.items()
               if name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS}
    for name in runtime:
        assert not guard.approved_v26_runtime({key: value for key, value in runtime.items() if key != name})
        assert not guard.approved_v26_runtime({**runtime, name: '0' * 64})
    assert not guard.approved_v26_runtime({**runtime, 'peaso/unreviewed_v23.py': '0' * 64})
    additions = guard.APPROVED_V26_RUNTIME_ADDITIONS
    assert guard.approved_runtime_additions(additions)
    for name in additions:
        assert not guard.approved_runtime_additions({key: value for key, value in additions.items() if key != name})
        assert not guard.approved_runtime_additions({**additions, name: '0' * 64})
    assert not guard.approved_runtime_additions({**additions, 'peaso/unreviewed_v23.py': '0' * 64})


def test_v26_apim_only_verified_canonical_gzip_omission_is_admitted():
    files = _v26_apim_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    assert guard.approved_v26_baseline_omission(files, baseline)
    assert set(baseline) - set(files) == {'peaso/rulepacks/upstream_manifest.json.gz'}
    additions = {name: digest for name, digest in files.items()
                 if name not in baseline and (name.startswith(('peaso/', 'risk_rules/')) or name in guard.RUNTIME_EXTRAS)}
    assert additions == guard.APPROVED_V26_RUNTIME_ADDITIONS


def test_v26_apim_other_omissions_extra_source_or_changed_canonical_bytes_rejected():
    files = _v26_apim_source_files_without_export()
    baseline = json.loads(private_inputs()['release.json'].read_bytes())['files']
    for name in ('README.md', 'peaso/engine.py'):
        omitted = {key: value for key, value in files.items() if key != name}
        assert not guard.approved_v26_baseline_omission(omitted, baseline)
        assert not guard.approved_v26_baseline_omission({**omitted, 'docs/unreviewed_v23.txt': '0' * 64}, baseline)
    plain = 'peaso/rulepacks/upstream_manifest.json'
    duplicate = plain + '.gz'
    assert not guard.approved_v26_baseline_omission({**files, plain: '0' * 64}, baseline)
    assert not guard.approved_v26_baseline_omission(files, {**baseline, plain: '0' * 64})
    assert not guard.approved_v26_baseline_omission(files, {**baseline, duplicate: '0' * 64})
    assert not guard.approved_v26_baseline_omission({**files, duplicate: baseline[duplicate]}, baseline)


@__import__('functools').lru_cache(maxsize=1)
def _v27_native_source_files_without_export():
    """Keep authentic V27 c90 as current source evolves."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-c90dc9d4bdb0a1bd5c6696c8f085b660d10ae88af643a36d46a64df0d94da993.zip')['files']


def test_v27_exact_native_runtime_and_historical_v26_independent():
    files=_v27_native_source_files_without_export()
    runtime={n:h for n,h in files.items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    assert len(files)==guard.APPROVED_V27_SOURCE_MEMBERS==1836
    assert len(runtime)==guard.APPROVED_V27_RUNTIME_MEMBERS==918
    assert guard.BASELINE_RUNTIME_MEMBERS==751
    assert guard.approved_v27_runtime(runtime)
    old=_v26_apim_source_files_without_export()
    prior={n:h for n,h in old.items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    assert guard.approved_v26_runtime(prior)and not guard.approved_v27_runtime(prior)
    assert not guard.approved_v26_runtime(runtime)
    assert guard.approved_runtime_additions(guard.APPROVED_V27_RUNTIME_ADDITIONS)
    for name in ('peaso/collectors/azure.py','peaso/collectors/aws.py','peaso/collectors/azure_devops_pipeline_native.py','peaso/collectors/aws_region_data_native.py','peaso/collectors/azure_vault_key_versions_native.py','peaso/checks/compliance_new_sw14.py','peaso/server/validation.py'):
        assert not guard.approved_v27_runtime({k:v for k,v in runtime.items()if k!=name})
        assert not guard.approved_v27_runtime({**runtime,name:'0'*64})
    assert not guard.approved_v27_runtime({**runtime,'peaso/unreviewed_v27.py':'0'*64})


def test_v27_only_exact_source_and_canonical_gzip_omission_allowed():
    files=_v27_native_source_files_without_export()
    baseline={**files,'peaso/rulepacks/upstream_manifest.json.gz':'b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627'}
    assert guard.approved_v27_baseline_omission(files,baseline)
    for name in ('README.md','peaso/engine.py'):
        changed={k:v for k,v in files.items()if k!=name}
        assert not guard.approved_v27_baseline_omission(changed,baseline)
        assert not guard.approved_v27_baseline_omission({**changed,'docs/unreviewed_v27.txt':'0'*64},baseline)
    plain='peaso/rulepacks/upstream_manifest.json'
    assert not guard.approved_v27_baseline_omission({**files,plain:'0'*64},baseline)
    assert not guard.approved_v27_baseline_omission(files,{**baseline,plain:'0'*64})
    duplicate=plain+'.gz'
    assert not guard.approved_v27_baseline_omission(files,{**baseline,duplicate:'0'*64})


@__import__('functools').lru_cache(maxsize=1)
def _v28_group_names_source_files_without_export():
    """Keep authentic V28 9e506 as current source evolves."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-9e50647f72df9127cdf25dcb80c13e217edc458e45de53db3c570b03e47375d6.zip')['files']


def test_v28_group_names_exact_runtime_and_authentic_v27_remain_independent():
    files=_v28_group_names_source_files_without_export()
    runtime={n:h for n,h in files.items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    old=_v27_native_source_files_without_export()
    prior={n:h for n,h in old.items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    assert len(files)==guard.APPROVED_V28_SOURCE_MEMBERS==1836
    assert len(runtime)==guard.APPROVED_V28_RUNTIME_MEMBERS==918
    assert guard.BASELINE_RUNTIME_MEMBERS==751
    assert guard.approved_v28_runtime(runtime) and not guard.approved_v27_runtime(runtime)
    assert guard.approved_v27_runtime(prior) and not guard.approved_v28_runtime(prior)
    assert {n for n in runtime if runtime[n]!=prior[n]}=={'peaso/collectors/azure_devops_pipeline_native.py'}
    assert guard.approved_runtime_additions(guard.APPROVED_V28_RUNTIME_ADDITIONS)
    assert guard.approved_runtime_additions(guard.APPROVED_V27_RUNTIME_ADDITIONS)
    for name in runtime:
        assert not guard.approved_v28_runtime({k:v for k,v in runtime.items()if k!=name})
        assert not guard.approved_v28_runtime({**runtime,name:'0'*64})
    assert not guard.approved_v28_runtime({**runtime,'peaso/unreviewed_v28.py':'0'*64})
    additions=guard.APPROVED_V28_RUNTIME_ADDITIONS
    for name in additions:
        assert not guard.approved_runtime_additions({k:v for k,v in additions.items()if k!=name})
        assert not guard.approved_runtime_additions({**additions,name:'0'*64})
    assert not guard.approved_runtime_additions({**additions,'peaso/unreviewed_v28.py':'0'*64})


def test_v28_group_names_only_canonical_gzip_omission_and_exact_source_admitted():
    files=_v28_group_names_source_files_without_export()
    baseline={**files,'peaso/rulepacks/upstream_manifest.json.gz':'b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627'}
    assert guard.approved_v28_baseline_omission(files,baseline)
    for name in ('README.md','peaso/engine.py'):
        changed={k:v for k,v in files.items()if k!=name}
        assert not guard.approved_v28_baseline_omission(changed,baseline)
        assert not guard.approved_v28_baseline_omission({**changed,'docs/unreviewed_v28.txt':'0'*64},baseline)
    assert not guard.approved_v28_baseline_omission({**files,'docs/unreviewed_v28.txt':'0'*64},baseline)
    plain='peaso/rulepacks/upstream_manifest.json';duplicate=plain+'.gz'
    assert not guard.approved_v28_baseline_omission({**files,plain:'0'*64},baseline)
    assert not guard.approved_v28_baseline_omission(files,{**baseline,plain:'0'*64})
    assert not guard.approved_v28_baseline_omission(files,{**baseline,duplicate:'0'*64})
    assert not guard.approved_v28_baseline_omission({**files,duplicate:baseline[duplicate]},baseline)


@__import__('functools').lru_cache(maxsize=1)
def _v29_sw20_source_files_without_export():
    """Keep authentic V29 ace448 as current source evolves."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-ace448e1bbe7c73cfb727008dc6d0a116c55eb07804e3d6d4c46bd57a4df5db6.zip')['files']


def test_v29_tls_exact_runtime_and_all_historical_v28_bytes_independent():
    files=_v29_sw20_source_files_without_export()
    runtime={n:h for n,h in files.items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    prior={n:h for n,h in _v28_group_names_source_files_without_export().items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    assert len(files)==guard.APPROVED_V29_SOURCE_MEMBERS<=guard.MAX_SOURCE_MEMBERS
    assert len(runtime)==guard.APPROVED_V29_RUNTIME_MEMBERS
    assert guard.BASELINE_RUNTIME_MEMBERS==751
    assert (guard.MAX_SOURCE_MEMBER_BYTES,guard.MAX_SOURCE_UNCOMPRESSED_BYTES,guard.MAX_SOURCE_ARCHIVE_BYTES)==(40_000_000,250_000_000,32_000_000)
    assert guard.approved_v29_runtime(runtime)and not guard.approved_v28_runtime(runtime)
    assert guard.approved_v28_runtime(prior)and not guard.approved_v29_runtime(prior)
    assert guard.approved_runtime_additions(guard.APPROVED_V29_RUNTIME_ADDITIONS)
    for n in runtime:
        assert not guard.approved_v29_runtime({k:v for k,v in runtime.items()if k!=n})
        assert not guard.approved_v29_runtime({**runtime,n:'0'*64})
    assert not guard.approved_v29_runtime({**runtime,'peaso/unreviewed_v29.py':'0'*64})
    additions=guard.APPROVED_V29_RUNTIME_ADDITIONS
    for n in additions:
        assert not guard.approved_runtime_additions({k:v for k,v in additions.items()if k!=n})
        assert not guard.approved_runtime_additions({**additions,n:'0'*64})
    assert not guard.approved_runtime_additions({**additions,'peaso/unreviewed_v29.py':'0'*64})


def test_v29_tls_only_exact_source_and_canonical_gzip_omission_admitted():
    files=_v29_sw20_source_files_without_export()
    plain='peaso/rulepacks/upstream_manifest.json';duplicate=plain+'.gz'
    baseline={**files,duplicate:'b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627'}
    assert guard.approved_v29_baseline_omission(files,baseline)
    for n in ('README.md','peaso/engine.py'):
        changed={k:v for k,v in files.items()if k!=n}
        assert not guard.approved_v29_baseline_omission(changed,baseline)
        assert not guard.approved_v29_baseline_omission({**changed,'docs/unreviewed_v29.txt':'0'*64},baseline)
    assert not guard.approved_v29_baseline_omission({**files,'docs/unreviewed_v29.txt':'0'*64},baseline)
    assert not guard.approved_v29_baseline_omission({**files,plain:'0'*64},baseline)
    assert not guard.approved_v29_baseline_omission(files,{**baseline,plain:'0'*64})
    assert not guard.approved_v29_baseline_omission(files,{**baseline,duplicate:'0'*64})
    assert not guard.approved_v29_baseline_omission({**files,duplicate:baseline[duplicate]},baseline)


@__import__('functools').lru_cache(maxsize=1)
def _v30_readonly_source_files_without_export():
    """Retain the exact published V30 source map as current source advances."""
    return read_historical_release(ROOT / 'infra/aws/build/peaso-source-475e4f00e15d9cb05549ea184120209db0e893617583ac8ba4bbaf13b53020a1.zip')['files']






def test_v30_readonly_exact_runtime_and_all_historical_v29_bytes_independent():
    files=_v30_readonly_source_files_without_export()
    runtime={n:h for n,h in files.items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    prior={n:h for n,h in _v29_sw20_source_files_without_export().items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    assert len(files)==guard.APPROVED_V30_SOURCE_MEMBERS<=guard.MAX_SOURCE_MEMBERS
    assert len(runtime)==guard.APPROVED_V30_RUNTIME_MEMBERS
    assert guard.BASELINE_RUNTIME_MEMBERS==751
    assert (guard.MAX_SOURCE_MEMBER_BYTES,guard.MAX_SOURCE_UNCOMPRESSED_BYTES,guard.MAX_SOURCE_ARCHIVE_BYTES)==(40_000_000,250_000_000,32_000_000)
    assert guard.approved_v30_runtime(runtime)and not guard.approved_v29_runtime(runtime)
    assert guard.approved_v29_runtime(prior)and not guard.approved_v30_runtime(prior)
    assert guard.approved_runtime_additions(guard.APPROVED_V30_RUNTIME_ADDITIONS)
    for n in runtime:
        assert not guard.approved_v30_runtime({k:v for k,v in runtime.items()if k!=n})
        assert not guard.approved_v30_runtime({**runtime,n:'0'*64})
    assert not guard.approved_v30_runtime({**runtime,'peaso/unreviewed_v30.py':'0'*64})
    additions=guard.APPROVED_V30_RUNTIME_ADDITIONS
    for n in additions:
        assert not guard.approved_runtime_additions({k:v for k,v in additions.items()if k!=n})
        assert not guard.approved_runtime_additions({**additions,n:'0'*64})
    assert not guard.approved_runtime_additions({**additions,'peaso/unreviewed_v30.py':'0'*64})


def test_v30_readonly_only_exact_source_and_canonical_gzip_omission_admitted():
    files=_v30_readonly_source_files_without_export()
    plain='peaso/rulepacks/upstream_manifest.json';duplicate=plain+'.gz'
    baseline={**files,duplicate:'b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627'}
    assert guard.approved_v30_baseline_omission(files,baseline)
    for n in ('README.md','peaso/engine.py'):
        changed={k:v for k,v in files.items()if k!=n}
        assert not guard.approved_v30_baseline_omission(changed,baseline)
        assert not guard.approved_v30_baseline_omission({**changed,'docs/unreviewed_v30.txt':'0'*64},baseline)
    assert not guard.approved_v30_baseline_omission({**files,'docs/unreviewed_v30.txt':'0'*64},baseline)
    assert not guard.approved_v30_baseline_omission({**files,plain:'0'*64},baseline)
    assert not guard.approved_v30_baseline_omission(files,{**baseline,plain:'0'*64})
    assert not guard.approved_v30_baseline_omission(files,{**baseline,duplicate:'0'*64})
    assert not guard.approved_v30_baseline_omission({**files,duplicate:baseline[duplicate]},baseline)


@__import__('functools').lru_cache(maxsize=1)
def _v31_publicedge_source_files_without_export():
    """Exercise the exact published v31 inventory, not today's larger source."""
    path = ROOT / 'infra/aws/build/peaso-source-414e037b411d4e5abd0a214fc67b4b8bd96aede52dc843cf23748054f4dfbe6d.zip'
    return read_historical_release(path)['files']



def test_v31_publicedge_exact_runtime_and_all_historical_v30_bytes_independent():
    files=_v31_publicedge_source_files_without_export()
    runtime={n:h for n,h in files.items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    prior={n:h for n,h in _v30_readonly_source_files_without_export().items()if n.startswith(('peaso/','risk_rules/'))or n in guard.RUNTIME_EXTRAS}
    assert len(files)==guard.APPROVED_V31_SOURCE_MEMBERS==guard.MAX_SOURCE_MEMBERS
    assert len(runtime)==guard.APPROVED_V31_RUNTIME_MEMBERS
    assert guard.BASELINE_RUNTIME_MEMBERS==751
    assert (guard.MAX_SOURCE_MEMBER_BYTES,guard.MAX_SOURCE_UNCOMPRESSED_BYTES,guard.MAX_SOURCE_ARCHIVE_BYTES)==(40_000_000,250_000_000,32_000_000)
    assert guard.approved_v31_runtime(runtime)and not guard.approved_v30_runtime(runtime)
    assert guard.approved_v30_runtime(prior)and not guard.approved_v31_runtime(prior)
    assert guard.approved_runtime_additions(guard.APPROVED_V31_RUNTIME_ADDITIONS)
    for n in runtime:
        assert not guard.approved_v31_runtime({k:v for k,v in runtime.items()if k!=n})
        assert not guard.approved_v31_runtime({**runtime,n:'0'*64})
    assert not guard.approved_v31_runtime({**runtime,'peaso/unreviewed_v31.py':'0'*64})
    additions=guard.APPROVED_V31_RUNTIME_ADDITIONS
    for n in additions:
        assert not guard.approved_runtime_additions({k:v for k,v in additions.items()if k!=n})
        assert not guard.approved_runtime_additions({**additions,n:'0'*64})
    assert not guard.approved_runtime_additions({**additions,'peaso/unreviewed_v31.py':'0'*64})


def test_v31_publicedge_only_exact_source_and_canonical_gzip_omission_admitted():
    files=_v31_publicedge_source_files_without_export()
    plain='peaso/rulepacks/upstream_manifest.json';duplicate=plain+'.gz'
    baseline={**files,duplicate:'b4e2c0c4c8e5bdff53b68dc210dc677f4d79de1a77d6ad002990a2f53f34e627'}
    assert guard.approved_v31_baseline_omission(files,baseline)
    for n in ('README.md','peaso/engine.py'):
        changed={k:v for k,v in files.items()if k!=n}
        assert not guard.approved_v31_baseline_omission(changed,baseline)
        assert not guard.approved_v31_baseline_omission({**changed,'docs/unreviewed_v31.txt':'0'*64},baseline)
    assert not guard.approved_v31_baseline_omission({**files,'docs/unreviewed_v31.txt':'0'*64},baseline)
    assert not guard.approved_v31_baseline_omission({**files,plain:'0'*64},baseline)
    assert not guard.approved_v31_baseline_omission(files,{**baseline,plain:'0'*64})
    assert not guard.approved_v31_baseline_omission(files,{**baseline,duplicate:'0'*64})
    assert not guard.approved_v31_baseline_omission({**files,duplicate:baseline[duplicate]},baseline)
