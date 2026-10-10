#!/usr/bin/env python3
"""Build CSPM artifacts and apply only a coordinator-reviewed, dedicated plan."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra" / "aws"
BUILD = INFRA / "build"
TF = os.environ.get("PEASO_TERRAFORM", "terraform")
ACCOUNT = "202533532952"
REPOSITORY = f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/hacktricks-cspm-worker"
ZERO_IMAGE = REPOSITORY + "@sha256:" + "0" * 64
ALLOWED_RESOURCES = set("""
aws_cloudwatch_log_group.api aws_cloudwatch_log_group.scheduler aws_apigatewayv2_stage.api
aws_budgets_budget.cspm aws_route53_record.cspm aws_ecs_task_definition.tasks
aws_cloudfront_distribution.cspm aws_iam_role_policy.analyzer aws_iam_role.workflow
aws_cloudfront_function.spa aws_vpc_endpoint.dynamodb aws_apigatewayv2_api.cspm
aws_cloudwatch_event_target.schedules aws_s3_bucket_policy.frontend
aws_cloudfront_origin_access_control.frontend aws_s3_bucket_public_access_block.private
aws_route_table.tasks aws_s3_bucket.artifacts aws_internet_gateway.cspm
aws_kms_alias.connectors aws_lambda_function.scheduler aws_cloudfront_response_headers_policy.security
aws_ecs_cluster.cspm aws_s3_bucket_policy.tls aws_iam_role.execution
aws_cloudwatch_metric_alarm.api_errors aws_vpc.cspm aws_sfn_state_machine.scan
aws_s3_bucket.frontend aws_lambda_permission.api aws_s3_bucket_lifecycle_configuration.artifacts
aws_s3_bucket_ownership_controls.private aws_apigatewayv2_integration.api aws_iam_role_policy.api
aws_secretsmanager_secret.credentials aws_security_group.tasks aws_iam_role.collector
aws_lambda_function.api aws_kms_key.connectors aws_iam_role_policy.workflow
aws_iam_role.analyzer aws_iam_role_policy.execution aws_dynamodb_table.metadata
aws_cloudwatch_event_rule.schedules aws_s3_bucket_server_side_encryption_configuration.private
aws_s3_bucket_cors_configuration.artifacts
random_bytes.credential_key aws_cloudwatch_log_group.tasks aws_subnet.tasks
aws_secretsmanager_secret_version.credentials aws_vpc_endpoint.s3 aws_ecr_repository.worker
aws_route_table_association.tasks aws_apigatewayv2_route.api aws_lambda_permission.schedules
aws_iam_role_policy.collector aws_ecr_lifecycle_policy.worker aws_iam_role.api
""".split())


def source_root():
    return BUILD / "source-snapshot" if (BUILD / "source-snapshot" / "release.json").is_file() else ROOT


def freeze_release(release_source=None):
    """Freeze exact corresponding source without Git, credentials, or caches."""
    import shutil
    release_root = Path(release_source).resolve() if release_source else ROOT
    files = set()
    for folder in ["peaso", "risk_rules", "frontend/src", "frontend/public", "frontend/tests", "frontend/e2e"]:
        files.update(p for p in (release_root / folder).rglob("*") if p.is_file())
    for pattern in ["infra/aws/*.tf", "infra/aws/Dockerfile.worker", "infra/aws/customer-role.json",
                    "infra/aws/.terraform.lock.hcl", "scripts/peaso*.py", "scripts/peaso_test_resources/*.py",
                    "docs/peaso*.md", "tests/test_peaso*.py", "frontend/package*.json", "frontend/*config*",
                    "frontend/index.html"]:
        files.update(release_root.glob(pattern))
    files.update(release_root / name for name in ["bluepeass/__init__.py", "bluepeass/k8s.py", "bluepeass/k8s_risks.py", "scripts/cloud_permission_risks.py"])
    files.update(release_root / f for f in ["LICENSE", "README.md", "pyproject.toml"])
    paths = {str(path.relative_to(release_root)): path for path in files}
    for pattern in ["infra/aws/*.tf", "infra/aws/Dockerfile.worker", "infra/aws/customer-role.json",
                    "infra/aws/.terraform.lock.hcl", "scripts/peaso_deploy*.py", "docs/peaso-aws.md"]:
        for path in ROOT.glob(pattern):
            paths[str(path.relative_to(ROOT))] = path
    source = {}
    for relative_name, path in sorted(paths.items()):
        relative = Path(relative_name)
        if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".pyc", ".tsbuildinfo", ".db", ".sqlite", ".sqlite3", ".key", ".pem", ".log"}:
            continue
        if any(part.startswith(".") and part != ".terraform.lock.hcl" for part in relative.parts):
            continue
        if str(relative).startswith(("tests/", "frontend/tests/", "frontend/e2e/")) and path.suffix not in {".py", ".ts", ".tsx", ".js", ".mjs"}:
            continue
        if path.is_symlink() or not any(path.resolve().is_relative_to(base.resolve()) for base in (ROOT, release_root)):
            raise RuntimeError("Source archive cannot include symlinks or external files")
        content = path.read_bytes()
        if path.suffix == ".json":
            try:
                json.loads(content)
            except (ValueError, UnicodeDecodeError) as error:
                raise RuntimeError(f"Source JSON changing or invalid: {relative}; retry after its owner finishes") from error
        if path.suffix == ".py":
            try:
                compile(content, str(relative), "exec")
            except SyntaxError as error:
                raise RuntimeError(f"Source Python changing or invalid: {relative}; retry after its owner finishes") from error
        source[str(relative)] = content
    manifest = {name: hashlib.sha256(value).hexdigest() for name, value in source.items()}
    version = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    release = {"source_version": version, "source_url": f"https://cspm.hacktricks.wiki/source/peaso-source-{version}.zip",
               "license": "AGPL-3.0", "files": manifest}
    snapshot = BUILD / "source-snapshot"
    if snapshot.exists():
        shutil.rmtree(snapshot)
    for name, value in source.items():
        destination = snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value)
    (snapshot / "release.json").write_text(json.dumps(release, indent=2) + "\n")
    (BUILD / "release.json").write_text(json.dumps(release, indent=2) + "\n")
    archive_path = BUILD / f"peaso-source-{version}.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in sorted(source.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, value)
        info = zipfile.ZipInfo("release.json", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, json.dumps(release, indent=2))
    print(f"Frozen source {version}: {len(source)} files; {archive_path}")
    return release


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def terraform(*args, capture=False):
    return run([TF, f"-chdir={INFRA}", *args], capture_output=capture, text=True)


def aws_identity():
    import boto3
    session = boto3.Session(region_name="us-east-1")
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != ACCOUNT:
        raise RuntimeError("Deployment requires the existing wiki account 202533532952")
    print(f"Verified wiki account {identity['Account']}; caller {identity['Arn']}")
    return session


def package_api():
    import shutil
    BUILD.mkdir(parents=True, exist_ok=True)
    target = BUILD / "api-package"
    if target.exists():
        shutil.rmtree(target)
    target.mkdir()
    run([sys.executable, "-m", "pip", "install", "--target", target,
         "--platform", "manylinux2014_x86_64", "--implementation", "cp",
         "--python-version", "3.12", "--abi", "cp312", "--only-binary=:all:",
         "fastapi>=0.115", "uvicorn>=0.30", "cryptography>=43", "PyYAML>=6",
         "PyJWT[crypto]>=2.10", "mangum>=0.19", "boto3>=1.34", "requests>=2"])
    shutil.copytree(source_root() / "peaso", target / "peaso", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(source_root() / "risk_rules", target / "risk_rules", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ["bluepeass/__init__.py", "bluepeass/k8s.py", "bluepeass/k8s_risks.py", "scripts/cloud_permission_risks.py"]:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root() / name, destination)
    if (BUILD / "release.json").is_file():
        shutil.copyfile(BUILD / "release.json", target / "peaso_release.json")
    package = BUILD / "api.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(target.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(target))
    print(f"API package: {package}; {package.stat().st_size} bytes")
    return package


def build_worker(tag):
    context = source_root()
    if context == ROOT:
        raise RuntimeError("Freeze the reviewed release sources before building the worker")
    run(["docker", "build", "--platform", "linux/amd64", "-f", context / "infra/aws/Dockerfile.worker",
         "-t", f"peaso-worker:{tag}", context])


def write_vars(image, api_zip):
    if not api_zip.is_file():
        raise RuntimeError("Build the API ZIP before planning")
    variables = {"api_zip": str(api_zip.resolve()), "worker_image": image}
    if (BUILD / "release.json").is_file():
        variables["source_version"] = json.loads((BUILD / "release.json").read_text())["source_version"]
    # Preserve the explicitly reviewed onboarded role allow-list between builds.
    existing = INFRA / "deployment.auto.tfvars.json"
    if existing.exists():
        variables.update({k: v for k, v in json.loads(existing.read_text()).items()
                          if k in {"customer_role_arns", "budget_email", "monthly_budget_usd"}})
    existing.write_text(json.dumps(variables, indent=2) + "\n")
    existing.chmod(0o600)


def plan_summary(plan, bootstrap=False):
    data = json.loads(terraform("show", "-json", plan, capture=True).stdout)
    changes = []
    bootstrap_allowed = {"aws_ecr_repository.worker", "aws_ecr_lifecycle_policy.worker"}
    for resource in data.get("resource_changes", []):
        if resource.get("mode") != "managed":
            continue
        actions = resource["change"]["actions"]
        if actions == ["no-op"]:
            continue
        if "delete" in actions:
            raise RuntimeError(f"Destructive plan refused: {resource['address']}")
        if resource.get("module_address"):
            raise RuntimeError("Unexpected child module in the dedicated CSPM root")
        if resource["type"] + "." + resource["name"] not in ALLOWED_RESOURCES:
            raise RuntimeError(f"Resource outside the dedicated CSPM inventory: {resource['address']}")
        if actions not in (["create"], ["update"]):
            raise RuntimeError(f"Unsupported apply action refused: {resource['address']}")
        if bootstrap and resource["address"] not in bootstrap_allowed:
            raise RuntimeError("Bootstrap plan contains a resource outside dedicated ECR")
        # Every managed before/after must belong to CSPM. IAM policies, route
        # associations, and secret versions inherit that scope through references.
        values = resource["change"].get("after") or {}
        for name in ("name", "bucket", "function_name", "family", "alarm_name", "repository"):
            value = values.get(name)
            if resource["type"] == "aws_apigatewayv2_stage" and name == "name" and value == "$default":
                continue
            if value and not (str(value).startswith("hacktricks-cspm") or
                              str(value).startswith("/ecs/hacktricks-cspm") or
                              str(value).startswith("/aws/lambda/hacktricks-cspm") or
                              str(value).startswith("alias/hacktricks-cspm") or
                              str(value) == "cspm.hacktricks.wiki"):
                # S3 bucket policies contain generated bucket IDs, not wiki IDs.
                raise RuntimeError(f"Unrelated named resource refused: {resource['address']}")
        if resource["type"] == "aws_route53_record" and values.get("name") != "cspm.hacktricks.wiki":
            raise RuntimeError("DNS plan must address only cspm.hacktricks.wiki")
        if resource["type"] == "aws_ecs_task_definition":
            for container in json.loads(values.get("container_definitions") or "[]"):
                if container.get("image") == ZERO_IMAGE:
                    raise RuntimeError("Placeholder worker image cannot be reviewed/applied")
        if resource["type"] == "aws_lambda_function" and values.get("filename"):
            import base64
            package = Path(values["filename"])
            current_hash = base64.b64encode(hashlib.sha256(package.read_bytes()).digest()).decode()
            if current_hash != values.get("source_code_hash"):
                raise RuntimeError("API ZIP changed after planning; recreate the plan and obtain review")
        changes.append({"address": resource["address"], "actions": actions})
    if bootstrap and any(c["actions"] != ["create"] for c in changes):
        raise RuntimeError("ECR bootstrap must be create-only")
    digest = hashlib.sha256(plan.read_bytes()).hexdigest()
    summary = {"plan": str(plan), "sha256": digest, "resources": changes,
               "counts": {action: sum(action in c["actions"] for c in changes)
                          for action in ["create", "update", "delete"]}}
    report = plan.with_suffix(".review.json")
    report.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("package-api")
    sub.add_parser("verify-package")
    sub.add_parser("validate-workflow")
    freeze = sub.add_parser("freeze-release")
    freeze.add_argument("--source-root", type=Path,
                        help="Coordinator-provided defensive source export; no primary workspace mutations")
    build = sub.add_parser("build-worker")
    build.add_argument("--tag", default=f"release-{int(time.time())}")
    push = sub.add_parser("push-worker")
    push.add_argument("--tag", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--image")
    plan.add_argument("--bootstrap-ecr", action="store_true")
    plan.add_argument("--output", type=Path, default=BUILD / "cspm.tfplan")
    apply = sub.add_parser("apply")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--reviewed-sha256", required=True,
                       help="Exact plan digest approved by the coordinator")
    apply.add_argument("--bootstrap-ecr", action="store_true")
    sub.add_parser("publish-frontend")
    verify = sub.add_parser("verify-host")
    verify.add_argument("--url", default="https://cspm.hacktricks.wiki")
    args = parser.parse_args()
    if args.command == "package-api":
        package_api()
        return
    if args.command == "freeze-release":
        freeze_release(args.source_root)
        return
    if args.command == "verify-package":
        code = """
import json
import importlib.util
from bluepeass.k8s import KubernetesApi
from bluepeass.k8s_risks import PermissionKey
from scripts.cloud_permission_risks import classify_permission
from peaso.engine import get_catalog
from peaso.server.lambda_handler import handler
assert importlib.util.find_spec('peaso.privesc') is not None
from peaso.privesc import analyze
print('Native catalog checks:',len(get_catalog()['checks']))
for path, expected in [('/api/health',200),('/api/me',401),('/api/connectors',401)]:
    event={'version':'2.0','routeKey':'$default','rawPath':path,'rawQueryString':'',
           'headers':{'host':'localhost'},'requestContext':{'stage':'$default',
           'domainName':'localhost','http':{'method':'GET','path':path,
           'sourceIp':'127.0.0.1','protocol':'HTTP/1.1'}},'isBase64Encoded':False}
    result=handler(event,None)
    assert result['statusCode']==expected,(path,result['statusCode'])
    print(path,result['statusCode'])
"""
        run(["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "-v", f"{BUILD / 'api-package'}:/opt:ro", "-e", "PYTHONPATH=/opt",
             "-e", "PEASO_STATE_DIR=/tmp/state", "-e", "PEASO_IDENTITY_DIR=/tmp/identity",
             "python:3.12-slim", "python", "-c", code])
        return
    if args.command == "build-worker":
        build_worker(args.tag)
        return
    if args.command == "verify-host":
        import urllib.request
        import urllib.error
        results = []
        for path, expected in [("/", 200), ("/api/health", 200), ("/api/me", 401),
                               ("/api/connectors", 401), ("/api/scans", 401), ("/api/schedules", 401)]:
            request = urllib.request.Request(args.url.rstrip("/") + path)
            try:
                response = urllib.request.urlopen(request, timeout=30)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                actual = response.status
                body = response.read()
                if actual != expected:
                    raise RuntimeError(f"Hosted check {path}: expected HTTP {expected}, got {actual}")
                if path == "/api/health":
                    payload = json.loads(body)
                    if not isinstance(payload, dict):
                        raise RuntimeError("Hosted health must be a JSON object")
                results.append({"path": path, "status": actual})
        print(json.dumps({"url": args.url, "https_checks": results}, indent=2))
        return
    session = aws_identity()
    if args.command == "validate-workflow":
        from peaso_deploy_validate_workflow import validate
        validate(ROOT, TF, session)
    elif args.command == "push-worker":
        ecr = session.client("ecr")
        auth = ecr.get_authorization_token()["authorizationData"][0]
        import base64
        username, password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
        run(["docker", "login", "--username", username, "--password-stdin", auth["proxyEndpoint"]],
            input=password, text=True)
        run(["docker", "tag", f"peaso-worker:{args.tag}", f"{REPOSITORY}:{args.tag}"])
        run(["docker", "push", f"{REPOSITORY}:{args.tag}"])
        digest = ecr.describe_images(repositoryName="hacktricks-cspm-worker",
                                     imageIds=[{"imageTag": args.tag}])["imageDetails"][0]["imageDigest"]
        image = f"{REPOSITORY}@{digest}"
        write_vars(image, BUILD / "api.zip")
        print(f"Published immutable image: {image}")
    elif args.command == "plan":
        BUILD.mkdir(parents=True, exist_ok=True)
        if args.bootstrap_ecr:
            write_vars(ZERO_IMAGE, BUILD / "api.zip")
        elif args.image:
            write_vars(args.image, BUILD / "api.zip")
        elif not (INFRA / "deployment.auto.tfvars.json").exists():
            raise RuntimeError("Publish an image or provide its digest before the full plan")
        if not args.bootstrap_ecr and json.loads((INFRA / "deployment.auto.tfvars.json").read_text())["worker_image"] == ZERO_IMAGE:
            raise RuntimeError("Publish the built native worker before the full plan")
        command = ["plan", "-input=false", f"-out={args.output.resolve()}"]
        if args.bootstrap_ecr:
            command += ["-target=aws_ecr_repository.worker", "-target=aws_ecr_lifecycle_policy.worker"]
        terraform(*command)
        args.output.chmod(0o600)
        plan_summary(args.output.resolve(), args.bootstrap_ecr)
    elif args.command == "apply":
        actual = hashlib.sha256(args.plan.read_bytes()).hexdigest()
        if actual != args.reviewed_sha256:
            raise RuntimeError("Plan changed after coordinator review; apply refused")
        plan_summary(args.plan.resolve(), args.bootstrap_ecr)
        terraform("apply", "-input=false", args.plan.resolve())
    elif args.command == "publish-frontend":
        frontend = source_root() / "frontend"
        run(["npm", "ci"], cwd=frontend)
        run(["npm", "run", "build"], cwd=frontend)
        output = json.loads(terraform("output", "-json", capture=True).stdout)
        bucket = output["frontend_bucket"]["value"]
        run(["aws", "s3", "sync", frontend / "dist", f"s3://{bucket}/", "--delete", "--exclude", "source/*",
             "--cache-control", "public,max-age=300"])
        run(["aws", "s3", "cp", frontend / "dist" / "index.html", f"s3://{bucket}/index.html",
             "--cache-control", "no-cache", "--content-type", "text/html"])
        release = json.loads((BUILD / "release.json").read_text())
        filename = f"peaso-source-{release['source_version']}.zip"
        run(["aws", "s3", "cp", BUILD / filename, f"s3://{bucket}/source/{filename}",
             "--cache-control", "public,max-age=31536000,immutable", "--content-type", "application/zip"])
        run(["aws", "s3", "cp", BUILD / "release.json", f"s3://{bucket}/source/release.json",
             "--cache-control", "no-cache", "--content-type", "application/json"])
        session.client("cloudfront").create_invalidation(
            DistributionId=output["cloudfront_distribution_id"]["value"],
            InvalidationBatch={"Paths": {"Quantity": 1, "Items": ["/*"]}, "CallerReference": str(time.time_ns())})


if __name__ == "__main__":
    main()
