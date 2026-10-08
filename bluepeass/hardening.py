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
import signal
import subprocess
import tempfile
import threading
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid
import sys
from bluepeass.hardening_report import group_hardening_targets, render_hardening_markdown
from bluepeass.finding_filters import filter_hardening_audit


DEFAULT_IMAGE = "blue-cloudpeass-hardening:local"
PLUGIN_VERSIONS = {"aws": "1.34.0", "azure": "1.15.0", "azuread": "1.9.0", "gcp": "1.13.1", "kubernetes": "1.7.0"}
_NATIVE_LOCK = threading.Lock()


def add_hardening_arguments(parser):
    group = parser.add_argument_group("Infrastructure hardening")
    group.add_argument("--hardening", choices=["auto", "on", "off"], default="auto", help="Run all compliance/perimeter checks after a successful configuration read (default: auto); on bypasses preflight, off keeps only the IAM/RBAC audit.")
    group.add_argument("--hardening-image", default=DEFAULT_IMAGE, help="Prebuilt Docker hardening image (never built or pulled automatically).")
    group.add_argument("--hardening-timeout", type=int, default=1800, help="Total hardening time limit per target in seconds (default: 1800).")
    group.add_argument("--hardening-out-dir", help="Keep native benchmark exports and the normalized hardening report in this directory.")
    group.add_argument("--hardening-show-passed", action="store_true", help="Also print PASS and SKIP hardening results; all results are always retained in JSON.")
    group.add_argument("--hardening-out-markdown", help="Write the grouped hardening Markdown report (.md or .txt), combining all targets.")
    group.add_argument("--hardening-runtime", choices=["docker", "native"], default="docker", help="Use Docker (default) or preinstalled native tools in a managed worker image.")


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


def _run_native_worker(command, *, env, timeout):
    # PostgreSQL and plugin processes must also stop if a managed worker times
    # out. A new session lets us terminate the entire audit process group.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=env, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        except ProcessLookupError:
            process.communicate()
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def run_hardening(args, adapter, target):
    if args is None or args.hardening == "off" or getattr(args, "hardening_runtime", "docker") != "native":
        return _run_hardening(args, adapter, target)
    # Native workers share a process namespace; keep their databases/CPU budgets
    # separate by completing one account at a time. Docker workers are isolated.
    with _NATIVE_LOCK:
        return _run_hardening(args, adapter, target)


def _run_hardening(args, adapter, target):
    if args is None or args.hardening == "off":
        return _empty("disabled", "Hardening disabled.")
    deadline = os.environ.get("BLUEPEASS_HARDENING_DEADLINE")
    if deadline and float(deadline) <= time.monotonic():
        # Queued native targets must finish promptly after the earlier audit
        # consumes the execution budget, rather than making more API probes.
        return _empty("error", "Execution budget exhausted before this target's hardening audit.")
    evidence = adapter.probe() if args.hardening == "auto" else []
    if args.hardening == "auto" and not any(item.get("allowed") for item in evidence):
        result = _empty("skipped", "No successful configuration read; request the documented audit read permissions.")
        result["coverage"]["preflight"] = evidence
        return result
    native = getattr(args, "hardening_runtime", "docker") == "native"
    timeout = args.hardening_timeout
    if deadline:
        timeout = min(timeout, max(0, int(float(deadline) - time.monotonic())))
    if timeout < 1:
        return _empty("error", "Execution budget exhausted before this target's hardening audit.")
    if native and not all(shutil.which(tool) for tool in ["steampipe", "powerpipe"]):
        return _empty("unavailable", "Native hardening requires preinstalled Steampipe and Powerpipe.")
    if not native and not shutil.which("docker"):
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
            def write_auth():
                adapter.write(auth)
                if native:
                    for path in auth.glob("*.spc"):
                        _write_config(path, path.read_text().replace("/input/", str(auth) + "/"))
                for path in auth.iterdir():
                    path.chmod(0o600)
            write_auth()
            uid, gid = os.getuid(), os.getgid()
            if uid == 0 and not native:
                uid = gid = 9193
                for path in [root, auth, output, *auth.iterdir()]:
                    os.chown(path, uid, gid)
            command = ["docker", "run", "--rm", "--pull=never", "--name", name, "--user", f"{uid}:{gid}", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--add-host=host.docker.internal:host-gateway",
                       "--mount", f"type=bind,src={auth},dst=/input,readonly", "--mount", f"type=bind,src={output},dst=/output",
                       "--env", "AWS_CONFIG_FILE=/input/aws-config", "--env", "AWS_PROFILE=bluepeass", "--env", "AWS_EC2_METADATA_DISABLED=true",
                       args.hardening_image, "--provider", adapter.provider, "--timeout", str(timeout)]
            process_env = None
            if native:
                worker = Path(__file__).resolve().parent.parent / "docker" / "hardening_worker.py"
                command = [sys.executable, str(worker), "--provider", adapter.provider, "--timeout", str(timeout), "--input-dir", str(auth), "--output-dir", str(output), "--work-dir", str(root / "runtime")]
                process_env = dict(os.environ)
                for key in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS"]:
                    process_env.pop(key, None)
                _write_config(auth / "aws-shared-credentials", "")
                process_env.update(AWS_CONFIG_FILE=str(auth / "aws-config"), AWS_SHARED_CREDENTIALS_FILE=str(auth / "aws-shared-credentials"), AWS_PROFILE="bluepeass", AWS_EC2_METADATA_DISABLED="true", BLUEPEASS_AUTH_DIR=str(auth))
            print(f"[*] Hardening {adapter.provider} {target}: running all compliance/perimeter checks.", flush=True)
            stop = threading.Event()
            refresh_errors = []

            def refresh():
                while not stop.wait(120):
                    try:
                        write_auth()
                    except Exception as exc:
                        refresh_errors.append({"error": "Credential refresh failed: " + _safe_error(exc)})

            refresher = threading.Thread(target=refresh, daemon=True)
            refresher.start()
            try:
                if native:
                    completed = _run_native_worker(command, env=process_env, timeout=timeout + 15)
                else:
                    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 180)
            finally:
                stop.set()
                refresher.join(timeout=30)
            result_path = output / "result.json"
            if not result_path.exists():
                result = _empty("error", "Hardening worker produced no report. Check the selected runtime and preinstalled tools.")
                result["errors"].append({"error": completed.stderr[-2000:]})
            else:
                result = filter_hardening_audit(normalize_results(json.loads(result_path.read_text()), adapter.provider, str(target)), adapter.provider)
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
                grouped = group_hardening_targets([{"target_id": str(target), "data": {"hardening": result}}], adapter.provider)
                _write_private(destination / "hardening.json", grouped)
                _write_config(destination / "hardening.md", render_hardening_markdown(grouped, show_passed=args.hardening_show_passed))
                result["exports_directory"] = str(destination)
            return result
        except subprocess.TimeoutExpired:
            partial_path = output / "result.json"
            if partial_path.exists():
                try:
                    result = filter_hardening_audit(normalize_results(json.loads(partial_path.read_text()), adapter.provider, str(target)), adapter.provider)
                    result["status"] = "partial"
                    result["coverage"].update(complete=False, preflight=evidence)
                    result["errors"].append({"error": "Hardening exceeded its time limit; completed suite results are retained."})
                    return result
                except (OSError, ValueError):
                    pass
            return _empty("error", "Hardening exceeded its time limit; the worker was stopped.")
        except Exception as exc:
            return _empty("error", "Hardening setup failed: " + _safe_error(exc))
        finally:
            try:
                if not native:
                    subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                pass


def print_hardening(result, *, target, show_passed=False):
    if not result:
        return
    provider = next((row.get("provider") for row in result.get("findings", []) if row.get("provider")), "unknown")
    grouped = result if "services" in result else group_hardening_targets([{"target_id": str(target), "data": {"hardening": result}}], provider)
    print("\n" + render_hardening_markdown(grouped, show_passed=show_passed), end="")


def attach_hardening(data, result):
    """Additive extension of the shared report format, leaving IAM catalogs intact."""
    if result is not None:
        data["hardening"] = result
    return data
