"""Optional, read-only cloud configuration audits through Powerpipe/Steampipe.

Only the credentials already selected by a scanner cross the container boundary.
Preflight reads are evidence that an audit can start, never proof that every
service is readable. Query failures remain part of the coverage report.
"""

from __future__ import annotations

import base64
import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid


DEFAULT_IMAGE = "blue-cloudpeass-hardening:local"
PLUGIN_VERSIONS = {"aws": "1.34.0", "azure": "1.15.0", "azuread": "1.9.0", "gcp": "1.13.1", "kubernetes": "1.7.0"}


def add_hardening_arguments(parser):
    group = parser.add_argument_group("Infrastructure hardening")
    group.add_argument("--hardening", choices=["auto", "on", "off"], default="auto", help="Run all compliance/perimeter checks after a successful configuration read (default: auto); on bypasses preflight, off keeps only the IAM/RBAC audit.")
    group.add_argument("--hardening-image", default=DEFAULT_IMAGE, help="Prebuilt Docker hardening image (never built or pulled automatically).")
    group.add_argument("--hardening-timeout", type=int, default=1800, help="Total hardening time limit per target in seconds (default: 1800).")
    group.add_argument("--hardening-out-dir", help="Keep native benchmark exports and the normalized hardening report in this directory.")
    group.add_argument("--hardening-show-passed", action="store_true", help="Also print PASS and SKIP hardening results; all results are always retained in JSON.")


def validate_hardening_arguments(parser, args):
    if args.hardening_timeout < 1:
        parser.error("--hardening-timeout must be positive")


def _write_private(path: Path, data: Any):
    """Atomic credentials updates; the mount is a directory, not a single inode."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as stream:
        json.dump(data, stream)
    if os.getuid() == 0 and path.exists():
        previous = path.stat()
        os.chown(temporary, previous.st_uid, previous.st_gid)
    os.replace(temporary, path)


def _write_config(path: Path, text: str):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as stream:
        stream.write(text)
    if os.getuid() == 0 and path.exists():
        previous = path.stat()
        os.chown(temporary, previous.st_uid, previous.st_gid)
    os.replace(temporary, path)


def _hcl(value):
    # HCL quoted strings interpret ${...} and %{...}; JSON escaping alone is
    # insufficient for user-controlled connection values.
    return json.dumps(value).replace("${", "$${").replace("%{", "%%{")


def _connection(name, plugin, **settings):
    # Versioned installations do not create an @latest alias. Connections must
    # select the exact baked-in plugin rather than silently missing its schema.
    selected = plugin + "@" + PLUGIN_VERSIONS[plugin]
    return f'connection "{name}" {{\n  plugin = "{selected}"\n' + "".join(f"  {key} = {_hcl(value)}\n" for key, value in settings.items()) + "}\n"


def _http(url, token, *, body=None, quota_project=None):
    headers = {"Authorization": "Bearer " + token}
    if quota_project:
        headers["X-Goog-User-Project"] = quota_project
    payload = json.dumps(body).encode() if body is not None else None
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, headers=headers, data=payload)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


class AwsCredentials:
    provider = "aws"

    def __init__(self, session):
        self.session = session

    def probe(self):
        from botocore.config import Config
        config = Config(connect_timeout=10, read_timeout=15, retries={"max_attempts": 1})
        evidence = []
        for service, operation in [("ec2", "describe_vpcs"), ("s3", "list_buckets")]:
            try:
                getattr(self.session.client(service, region_name=self.session.region_name or "us-east-1", config=config), operation)()
                evidence.append({"read": service + ":" + operation, "allowed": True})
            except Exception as exc:
                evidence.append({"read": service + ":" + operation, "allowed": False, "error": _safe_error(exc)})
        return evidence

    def write(self, root):
        credentials = self.session.get_credentials()
        if credentials is None:
            raise ValueError("The selected AWS session has no credentials.")
        frozen = credentials.get_frozen_credentials()
        document = {"Version": 1, "AccessKeyId": frozen.access_key, "SecretAccessKey": frozen.secret_key}
        if frozen.token:
            document["SessionToken"] = frozen.token
        expiry = getattr(credentials, "_expiry_time", None)
        if expiry:
            document["Expiration"] = expiry.isoformat()
        _write_private(root / "aws-credentials.json", document)
        _write_config(root / "aws-config", '[profile bluepeass]\ncredential_process = python /opt/bluepeass/credential_helper.py aws\nregion = ' + (self.session.region_name or "us-east-1") + "\n")
        _write_config(root / "aws.spc", _connection("aws", "aws", profile="bluepeass", regions=["*"], default_region=self.session.region_name or "us-east-1"))


class GcpCredentials:
    provider = "gcp"

    def __init__(self, token, project, quota_project=None, token_supplier=None):
        self.token, self.project, self.quota_project = token, project, quota_project
        self.token_supplier = token_supplier

    def probe(self):
        permissions = ["compute.instances.list", "storage.buckets.list", "container.clusters.list"]
        try:
            if self.token_supplier:
                self.token = self.token_supplier()
            response = _http(f"https://cloudresourcemanager.googleapis.com/v1/projects/{urllib.parse.quote(self.project, safe='')}:testIamPermissions", self.token, body={"permissions": permissions}, quota_project=self.quota_project)
            return [{"read": permission, "allowed": permission in response.get("permissions", [])} for permission in permissions]
        except Exception as exc:
            return [{"read": "projects.testIamPermissions", "allowed": False, "error": _safe_error(exc)}]

    def write(self, root):
        if self.token_supplier:
            self.token = self.token_supplier()
        settings = {"project": self.project, "impersonate_access_token": self.token}
        if self.quota_project:
            settings["quota_project"] = self.quota_project
        _write_config(root / "gcp.spc", _connection("gcp", "gcp", **settings))


class AzureCredentials:
    provider = "azure"

    def __init__(self, credential, subscription, tenant=None):
        self.credential, self.subscription, self.tenant = credential, subscription, tenant

    def probe(self):
        try:
            token = self.credential.get_token("https://management.azure.com/.default").token
            _http(f"https://management.azure.com/subscriptions/{self.subscription}/resourcegroups?api-version=2021-04-01&%24top=1", token)
            return [{"read": "Microsoft.Resources/subscriptions/resourceGroups/read", "allowed": True}]
        except Exception as exc:
            return [{"read": "Microsoft.Resources/subscriptions/resourceGroups/read", "allowed": False, "error": _safe_error(exc)}]

    def write(self, root):
        tokens = {}
        for audience in ["https://management.azure.com", "https://graph.microsoft.com"]:
            try:
                value = self.credential.get_token(audience + "/.default")
                tokens[audience] = {"token": value.token, "expires_on": value.expires_on}
            except Exception:
                if audience == "https://management.azure.com":
                    raise
                # Graph controls still run and report missing Graph coverage.
        tenant = self.tenant
        if not tenant:
            try:
                payload = tokens["https://management.azure.com"]["token"].split(".")[1]
                tenant = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["tid"]
            except (KeyError, IndexError, ValueError):
                raise ValueError("Unable to identify the Azure tenant from the selected credentials.") from None
        # ARM SDKs use both of these equivalent resource identifiers.
        tokens["https://management.core.windows.net"] = tokens["https://management.azure.com"]
        _write_private(root / "azure-tokens.json", {"tokens": tokens, "subscription": self.subscription, "tenant": tenant})
        # Setting tenant_id without a client secret makes the upstream Entra
        # plugin select incomplete service-principal auth. Its CLI auth obtains
        # the selected tenant from our private credential adapter instead.
        _write_config(root / "azure.spc", _connection("azure", "azure", subscription_id=self.subscription) + _connection("azuread", "azuread"))


class KubernetesCredentials:
    provider = "kubernetes"

    def __init__(self, api):
        self.api = api

    def probe(self):
        evidence = []
        for kind in ["pods", "services"]:
            try:
                self.api.get_json("/api/v1/" + kind, {"limit": 1})
                evidence.append({"read": "list " + kind, "allowed": True})
            except Exception as exc:
                evidence.append({"read": "list " + kind, "allowed": False, "error": _safe_error(exc)})
        return evidence

    def write(self, root):
        config = self.api.api_client.configuration
        try:
            version = self.api.get_json("/version")
        except Exception:
            version = {}
        _write_private(root / "kubernetes-version.json", version)
        host = config.host
        parsed = urllib.parse.urlsplit(host)
        cluster = {"server": host, "insecure-skip-tls-verify": not config.verify_ssl}
        if parsed.hostname in ["localhost", "127.0.0.1", "::1"]:
            port = ":" + str(parsed.port) if parsed.port else ""
            cluster["server"] = urllib.parse.urlunsplit((parsed.scheme, "host.docker.internal" + port, parsed.path, parsed.query, parsed.fragment))
            cluster["tls-server-name"] = parsed.hostname
        if config.tls_server_name:
            cluster["tls-server-name"] = config.tls_server_name
        if config.ssl_ca_cert and config.verify_ssl:
            cluster["certificate-authority-data"] = base64.b64encode(Path(config.ssl_ca_cert).read_bytes()).decode()
        if config.proxy:
            cluster["proxy-url"] = config.proxy
        user = {}
        token = config.get_api_key_with_prefix("authorization")
        if token:
            user["token"] = token.removeprefix("Bearer ")
        for field, name in [("cert_file", "client-certificate-data"), ("key_file", "client-key-data")]:
            filename = getattr(config, field, None)
            if filename:
                user[name] = base64.b64encode(Path(filename).read_bytes()).decode()
        if config.username:
            user.update(username=config.username, password=config.password)
        _write_private(root / "kubeconfig", {"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "selected", "cluster": cluster}], "users": [{"name": "selected", "user": user}], "contexts": [{"name": "selected", "context": {"cluster": "selected", "user": "selected"}}], "current-context": "selected"})
        _write_config(root / "kubernetes.spc", _connection("kubernetes", "kubernetes", config_path="/input/kubeconfig", source_types=["deployed"], custom_resource_tables=[]))


def _safe_error(exc):
    # SDK messages may contain request headers or supplied credential material.
    # Record a useful status/code without copying arbitrary exception strings.
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    response = getattr(exc, "response", {})
    if isinstance(response, dict) and response.get("Error", {}).get("Code"):
        return str(response["Error"]["Code"])
    return type(exc).__name__


def _empty(status, reason):
    errors = [{"error": reason}] if status in {"error", "unavailable"} else []
    return {"engine": "steampipe-powerpipe", "status": status, "reason": reason, "findings": [], "controls": [], "errors": errors, "coverage": {"complete": False}, "summary": {}}


def normalize_results(payload, provider, target):
    """Flatten benchmark trees, preserving control errors and every row."""
    findings, controls, errors = {}, {}, list(payload.get("errors", []))
    statuses = {"alarm": "FAIL", "ok": "PASS", "info": "MANUAL", "skip": "SKIP", "error": "ERROR"}

    def visit(node, suite, control=None):
        if isinstance(node, list):
            for value in node:
                visit(value, suite, control)
            return
        if not isinstance(node, dict):
            return
        identifier = node.get("control_id") or node.get("name")
        if identifier and (".control." in str(identifier) or "results" in node):
            identifier = str(identifier)
            if identifier.startswith("control."):
                identifier = suite.replace("-", "_") + "." + identifier
            control = {"control_id": identifier, "title": node.get("title", identifier), "description": node.get("description", ""), "severity": node.get("severity") or "unknown", "tags": node.get("tags", {})}
            key = suite + ":" + control["control_id"]
            controls.setdefault(key, {**control, "suite": suite, "rows": 0})
            if node.get("error") or node.get("run_error"):
                errors.append({"suite": suite, "control_id": control["control_id"], "error": node.get("run_error") or node["error"]})
        if "status" in node and "resource" in node:
            control = control or {"control_id": str(node.get("control_id", "unknown")), "title": node.get("title", "Unknown control"), "tags": {}}
            status = statuses.get(str(node["status"]).lower(), str(node["status"]).upper())
            key = (control["control_id"], str(node["resource"]), status, str(node.get("reason", "")), json.dumps(node.get("dimensions", {}), sort_keys=True))
            native_dimensions = node.get("dimensions") or {}
            dimensions = {d["key"]: d.get("value") for d in native_dimensions if isinstance(d, dict) and "key" in d} if isinstance(native_dimensions, list) else dict(native_dimensions)
            dimensions.update({k: v for k, v in node.items() if k not in {"resource", "status", "reason", "dimensions"}})
            reference = "https://hub.powerpipe.io/mods/turbot/steampipe-mod-" + suite + "/benchmarks/control." + control["control_id"].split(".")[-1]
            finding = findings.setdefault(key, {**control, "provider": provider, "target_id": target, "resource": node["resource"], "status": status, "reason": node.get("reason", ""), "dimensions": dimensions, "reference_url": reference, "suites": []})
            if suite not in finding["suites"]:
                finding["suites"].append(suite)
            if status == "ERROR":
                errors.append({"suite": suite, "control_id": control["control_id"], "error": node.get("reason", "Query error")})
            if suite + ":" + control["control_id"] in controls:
                controls[suite + ":" + control["control_id"]]["rows"] += 1
            return
        for key, value in node.items():
            if key not in {"tags", "summary", "dimensions", "error"} and isinstance(value, (dict, list)):
                visit(value, suite, control)

    runs = payload.get("runs", [])
    for run in runs:
        if run.get("document") is not None:
            visit(run["document"], run["mod"])
        if run.get("exit_code", 0) and not run.get("document"):
            errors.append({"suite": run["mod"], "error": "Benchmark execution failed."})
    values = list(findings.values())
    count = dict(collections.Counter(f["status"] for f in values))
    excluded = payload.get("excluded_controls", [])
    if not controls:
        errors.append({"error": "No control results were exported; hardening coverage is unavailable."})
    complete = bool(controls) and not errors and not excluded and not count.get("MANUAL") and not count.get("ERROR")
    return {"engine": "steampipe-powerpipe", "status": "completed" if complete else "partial", "findings": values, "controls": list(controls.values()), "errors": errors,
            "coverage": {"complete": complete, "excluded_controls": excluded, "zero_result_controls": [c["control_id"] for c in controls.values() if not c["rows"]]},
            "summary": {"findings": len(values), "controls": len(controls), "execution_errors": len(errors), "by_status": count},
            "versions": {r["mod"]: r["version"] for r in runs}}


def run_hardening(args, adapter, target):
    if args is None or args.hardening == "off":
        return _empty("disabled", "Hardening disabled.")
    evidence = adapter.probe() if args.hardening == "auto" else []
    if args.hardening == "auto" and not any(item.get("allowed") for item in evidence):
        result = _empty("skipped", "No successful configuration read; request the documented audit read permissions.")
        result["coverage"]["preflight"] = evidence
        return result
    if not shutil.which("docker"):
        result = _empty("unavailable", "Docker is required for hardening. Build Dockerfile.hardening or use --hardening off.")
        result["coverage"]["preflight"] = evidence
        return result
    name = "bluepeass-hardening-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="bluepeass-hardening-") as work:
        root = Path(work)
        auth, output = root / "auth", root / "output"
        auth.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        try:
            adapter.write(auth)
            for path in auth.iterdir():
                path.chmod(0o600)
            uid, gid = os.getuid(), os.getgid()
            if uid == 0:
                uid = gid = 9193
                for path in [root, auth, output, *auth.iterdir()]:
                    os.chown(path, uid, gid)
            command = ["docker", "run", "--rm", "--pull=never", "--name", name, "--user", f"{uid}:{gid}", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--add-host=host.docker.internal:host-gateway",
                       "--mount", f"type=bind,src={auth},dst=/input,readonly", "--mount", f"type=bind,src={output},dst=/output",
                       "--env", "AWS_CONFIG_FILE=/input/aws-config", "--env", "AWS_PROFILE=bluepeass", "--env", "AWS_EC2_METADATA_DISABLED=true",
                       args.hardening_image, "--provider", adapter.provider, "--timeout", str(args.hardening_timeout)]
            print(f"[*] Hardening {adapter.provider} {target}: running all compliance/perimeter checks.", flush=True)
            stop = threading.Event()
            refresh_errors = []

            def refresh():
                while not stop.wait(120):
                    try:
                        adapter.write(auth)
                    except Exception as exc:
                        refresh_errors.append({"error": "Credential refresh failed: " + _safe_error(exc)})

            refresher = threading.Thread(target=refresh, daemon=True)
            refresher.start()
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=args.hardening_timeout + 180)
            finally:
                stop.set()
                refresher.join(timeout=30)
            result_path = output / "result.json"
            if not result_path.exists():
                result = _empty("error", "Hardening container produced no report. Check Docker and the prebuilt image.")
                result["errors"].append({"error": completed.stderr[-2000:]})
            else:
                result = normalize_results(json.loads(result_path.read_text()), adapter.provider, str(target))
            if refresh_errors:
                result["errors"].extend(refresh_errors)
                result["status"] = "partial"
                result["coverage"]["complete"] = False
            result["coverage"]["preflight"] = evidence
            if args.hardening_out_dir:
                identifier = hashlib.sha256(str(target).encode()).hexdigest()[:12]
                destination = Path(args.hardening_out_dir) / f"{adapter.provider}-{identifier}-{uuid.uuid4().hex[:8]}"
                destination.mkdir(parents=True, mode=0o700)
                for path in output.glob("*.json"):
                    shutil.copyfile(path, destination / path.name)
                    (destination / path.name).chmod(0o600)
                _write_private(destination / "hardening.json", result)
                result["exports_directory"] = str(destination)
            return result
        except subprocess.TimeoutExpired:
            return _empty("error", "Hardening exceeded its time limit; the container was stopped.")
        except Exception as exc:
            return _empty("error", "Hardening setup failed: " + _safe_error(exc))
        finally:
            try:
                subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                pass


def print_hardening(result, *, target, show_passed=False):
    if not result:
        return
    print(f"\nInfrastructure hardening — {target}: {result['status']}")
    if result.get("reason"):
        print("  " + result["reason"])
    counts = result.get("summary", {}).get("by_status", {})
    if counts:
        print("  " + ", ".join(f"{status}={count}" for status, count in sorted(counts.items())))
    for finding in result.get("findings", []):
        if not show_passed and finding["status"] in {"PASS", "SKIP"}:
            continue
        print(f"  [{finding['status']}] {finding['title']}\n    Resource: {finding['resource']}\n    {finding['reason']}\n    Control: {finding['control_id']}")
        if finding.get("dimensions"):
            print("    Scope: " + ", ".join(f"{key}={value}" for key, value in finding["dimensions"].items()))
        if finding.get("severity") not in {None, "unknown"}:
            print("    Severity: " + finding["severity"])
        print("    Reference: " + finding["reference_url"])
    for error in result.get("errors", []):
        print(f"  [ERROR] {error.get('control_id', error.get('suite', error.get('mod', 'runner')))}: {error.get('error')}")
    for control in result.get("coverage", {}).get("excluded_controls", []):
        print(f"  [SKIP] {control['control_id']}: {control['reason']}")
    if result.get("exports_directory"):
        print("  Native exports: " + result["exports_directory"])


def attach_hardening(data, result):
    """Additive extension of the shared report format, leaving IAM catalogs intact."""
    if result is not None:
        data["hardening"] = result
    return data
