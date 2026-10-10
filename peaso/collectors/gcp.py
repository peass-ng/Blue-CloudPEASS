"""Native, bounded GCP metadata collection. No cloud mutation or secret access.

The injectable transport is intentionally below the collector so fixtures exercise
the same pagination, provenance, scope filtering and hydration as real API reads.
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import threading
import time
from itertools import count
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlsplit

OAUTH_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
HOSTS = frozenset(f"{s}.googleapis.com" for s in (
    "cloudasset", "cloudresourcemanager", "compute", "storage", "iam", "logging",
    "sqladmin", "container", "cloudkms", "secretmanager", "recommender", "bigquery", "artifactregistry",
    "run", "cloudfunctions", "cloudidentity", "appengine"))
SAFE_REASONS = frozenset(("SERVICE_DISABLED", "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "IAM_PERMISSION_DENIED",
    "PERMISSION_DENIED", "UNAUTHENTICATED", "NOT_FOUND", "RESOURCE_EXHAUSTED", "INVALID_ARGUMENT",
    "BILLING_DISABLED", "USER_PROJECT_DENIED", "QUOTA_EXCEEDED", "RATE_LIMIT_EXCEEDED", "UNAVAILABLE"))
SENSITIVE_KEYS = frozenset(("privatekey", "privatekeydata", "publickeydata", "accesstoken", "refreshtoken",
    "idtoken", "clientsecret", "password", "certificate", "clientcertificate", "clientkey", "token",
    "authorization", "secretvalue", "payload", "startupscript", "sshkeys", "userdata", "connectionstring",
    "cert", "servercacert", "sharedsecret", "sharedsecrethash", "environmentvariables",
    "secretenvironmentvariables", "args", "command", "subjecttoken", "apikey", "keystring",
    "authtoken", "oauthtoken", "secretaccesskey", "sessiontoken", "credentials", "authcredentials"))


def sanitize(value):
    """Keep configuration evidence while dropping credentials, scripts and values."""
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in SENSITIVE_KEYS or normalized.endswith(("password", "token", "privatekey", "clientsecret", "secretvalue")):
                continue
            if key == "env" and isinstance(item, list):
                output[key] = [{"name": entry.get("name"), **({"valueFrom": sanitize(entry["valueFrom"])}
                    if "valueFrom" in entry else {})} for entry in item if isinstance(entry, dict)]
                continue
            if key in ("metadata", "commonInstanceMetadata") and isinstance(item, dict) and isinstance(item.get("items"), list):
                output[key] = {**sanitize({k: v for k, v in item.items() if k != "items"}),
                    "items": [{"key": x.get("key"), **({"value": x.get("value")} if x.get("key") in
                        ("enable-oslogin", "enable-oslogin-2fa", "block-project-ssh-keys", "serial-port-enable", "disable-legacy-endpoints") else {})}
                        for x in item["items"] if isinstance(x, dict)]}
            else:
                output[key] = sanitize(item)
        return output
    if isinstance(value, list):
        return [sanitize(x) for x in value]
    if isinstance(value, str) and ("-----BEGIN " in value or re.search(r"(?i)\b(?:bearer|ya29\.)\s*\S+", value)):
        return "[redacted]"
    return value


class ReadError(Exception):
    def __init__(self, status="unavailable", code="read_failed", *, http_status=None, reason=None):
        super().__init__(code)
        self.status = status
        self.error = {"code": code}
        if http_status is not None:
            self.error["http_status"] = http_status
        if reason in SAFE_REASONS:
            self.error["reason"] = reason


def http_error(status, payload):
    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    reason = next((x.get("reason") for x in error.get("details", []) if isinstance(x, dict)
        and x.get("reason") in SAFE_REASONS), None) if isinstance(error, dict) else None
    state = "denied" if status in (401, 403) else "unavailable"
    if reason in ("SERVICE_DISABLED", "BILLING_DISABLED"):
        state = "unavailable"
    if status in (405, 501):
        state = "unsupported"
    return ReadError(state, "api_error", http_status=status, reason=reason)


def bound(options, name, default, low, high):
    value = options.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer between {low} and {high}")
    return value


def optional_bound(options, name, low, high):
    return None if options.get(name) is None else bound(options, name, None, low, high)


def _gcloud(command, env):
    try:
        result = subprocess.run(["gcloud", *command], env=env, capture_output=True, text=True,
                                check=True, timeout=30)
    except Exception:
        raise ReadError("denied", "gcloud_auth_failed") from None
    value = result.stdout.strip()
    if not value or value == "(unset)":
        raise ReadError("denied", "gcloud_identity_missing")
    return value


def validate_external_config(info, *, inline=False):
    """Validate credential destinations before handing config to google-auth."""
    if not isinstance(info, dict) or info.get("type") != "external_account":
        raise ReadError("denied", "external_account_config_required")
    if info.get("token_url") != "https://sts.googleapis.com/v1/token":
        raise ReadError("denied", "unsafe_external_token_endpoint")
    if info.get("token_info_url") not in (None, "https://sts.googleapis.com/v1/introspect"):
        raise ReadError("denied", "unsafe_external_token_endpoint")
    impersonation_url = info.get("service_account_impersonation_url")
    if impersonation_url is not None and (not isinstance(impersonation_url, str) or not re.fullmatch(
        r"https://iamcredentials\.googleapis\.com/v1/projects/-/serviceAccounts/[A-Za-z0-9@._%+-]+:generateAccessToken",
        impersonation_url)):
        raise ReadError("denied", "unsafe_external_impersonation_endpoint")
    source = info.get("credential_source", {})
    if not isinstance(source, dict) or "executable" in source:
        raise ReadError("unsupported", "external_executable_source_prohibited")
    if inline:
        # The inline supplier replaces the config's source, so it cannot execute
        # a plugin, read a server file, or make source-directed network requests.
        return
    if source.get("environment_id") == "aws1":
        expected = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
            "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            "imdsv2_session_token_url": "http://169.254.169.254/latest/api/token"}
        for key, value in expected.items():
            if key in source and (not isinstance(source[key], str) or source[key].rstrip("/") != value):
                raise ReadError("denied", "unsafe_external_credential_source")
        verification = source.get("regional_cred_verification_url", "")
        if not isinstance(verification, str) or not re.fullmatch(r"https://sts\.\{region\}\.amazonaws\.com(?:\.cn)?/\?Action=GetCallerIdentity&Version=2011-06-15", verification):
            raise ReadError("denied", "unsafe_external_credential_source")
    elif source.get("url") or not isinstance(source.get("file"), str):
        raise ReadError("unsupported", "external_source_requires_local_file_or_inline_token")


class GcloudCredentials:
    """Pin account AND impersonation before the first token is requested."""
    def __init__(self, auth):
        self.env = dict(os.environ)
        self.account = auth.get("account") or _gcloud(["config", "get-value", "account"], self.env)
        target = auth.get("target_principal") or auth.get("impersonate_service_account")
        if target is None:
            try:
                target = _gcloud(["config", "get-value", "auth/impersonate_service_account"], self.env)
            except ReadError as exc:
                if exc.error["code"] != "gcloud_identity_missing":
                    raise
                target = ""
        delegates = auth.get("delegates", [])
        if delegates:
            raise ReadError("unsupported", "gcloud_delegates_require_impersonation_method")
        self.env["CLOUDSDK_CORE_ACCOUNT"] = self.account
        self.env["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"] = target or ""
        self.command = ["auth", "print-access-token", "--account", self.account, "--quiet"]
        if target:
            self.command += ["--impersonate-service-account", target]
        self.token = None
        self.expires = 0.0

    def headers(self):
        if time.monotonic() >= self.expires:
            self.token = _gcloud(self.command, self.env)
            self.expires = time.monotonic() + 240
        return {"Authorization": "Bearer " + self.token}


def selected_auth_method(auth):
    if "token" in auth:
        return "token"
    if "method" in auth:
        method = auth["method"]
    elif any(key in auth for key in ("service_account_file", "sa_json")):
        method = "service-account"
    elif any(key in auth for key in ("external_account_file", "credential_file", "external_account_json")):
        method = "external-account"
    else:
        method = "adc"
    if not isinstance(method, str):
        return "unsupported"
    method = {"auto": "adc", "gcloud-cli": "gcloud", "service_account": "service-account",
              "external_account": "external-account", "wif": "external-account", "impersonate": "impersonation"}.get(method, method)
    return method if method in ("adc", "gcloud", "service-account", "external-account", "metadata", "impersonation") else "unsupported"


class Credentials:
    def __init__(self, auth, *, timeout=20):
        self.lock = threading.Lock()
        self.failure = None
        self.timeout = timeout
        self.method = selected_auth_method(auth)
        self.direct_token = auth.get("token")
        self.credential = None
        self.gcloud = None
        self.session = None
        try:
            if "token" in auth:
                if not isinstance(self.direct_token, str) or not self.direct_token.strip():
                    raise ReadError("denied", "explicit_token_required")
                return
            if self.method == "gcloud":
                self.gcloud = GcloudCredentials(auth)
                return
            import google.auth
            import requests
            from google.auth.transport.requests import Request
            self.session = requests.Session()
            self.request = Request(session=self.session)
            if self.method == "adc":
                self.credential, _ = google.auth.default(scopes=OAUTH_SCOPES, quota_project_id=auth.get("quota_project"))
            elif self.method == "service-account":
                from google.oauth2.service_account import Credentials as SACredentials
                if isinstance(auth.get("sa_json"), dict):
                    self.credential = SACredentials.from_service_account_info(auth["sa_json"], scopes=OAUTH_SCOPES)
                elif auth.get("sa_json", "").lstrip().startswith("{"):
                    self.credential = SACredentials.from_service_account_info(json.loads(auth["sa_json"]), scopes=OAUTH_SCOPES)
                else:
                    self.credential = SACredentials.from_service_account_file(auth.get("service_account_file")
                        or auth.get("sa_json"), scopes=OAUTH_SCOPES)
            elif self.method == "external-account":
                inline = auth.get("external_account_json")
                if inline is not None:
                    from google.auth import identity_pool
                    info = json.loads(inline) if isinstance(inline, str) else copy.deepcopy(inline)
                    validate_external_config(info, inline=True)
                    subject_token = auth.get("subject_token")
                    if not isinstance(subject_token, str) or not subject_token:
                        raise ReadError("denied", "inline_subject_token_required")
                    class Supplier(identity_pool.SubjectTokenSupplier):
                        def get_subject_token(self, context, request):
                            return subject_token
                    info.pop("credential_source", None)
                    self.credential = identity_pool.Credentials.from_info(info, scopes=OAUTH_SCOPES,
                        subject_token_supplier=Supplier(), quota_project_id=auth.get("quota_project"))
                else:
                    path = auth.get("external_account_file") or auth.get("credential_file")
                    with open(path, encoding="utf-8") as stream:
                        info = json.load(stream)
                    validate_external_config(info)
                    # Load the already-validated document to avoid a file-change
                    # race replacing safe config with an executable/url source.
                    self.credential, _ = google.auth.load_credentials_from_dict(info, scopes=OAUTH_SCOPES,
                        quota_project_id=auth.get("quota_project"))
            elif self.method == "metadata":
                from google.auth.compute_engine import Credentials as MetadataCredentials
                self.credential = MetadataCredentials(scopes=OAUTH_SCOPES,
                    service_account_email=auth.get("service_account_email", "default"))
            elif self.method == "impersonation":
                from google.auth import impersonated_credentials
                source = auth.get("source_auth")
                if not isinstance(source, dict) or source.get("method") in ("impersonation", "impersonate"):
                    raise ReadError("denied", "explicit_impersonation_source_required")
                source_credentials = Credentials(source, timeout=timeout)
                if source_credentials.gcloud is not None:
                    from google.oauth2.credentials import Credentials as UserCredentials
                    def refresh_handler(request, scopes=None):
                        headers = source_credentials.headers()
                        return headers["Authorization"].removeprefix("Bearer "), (
                            datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=240))
                    source_credentials.credential = UserCredentials(token=None, scopes=OAUTH_SCOPES,
                        refresh_handler=refresh_handler)
                if source_credentials.credential is None:
                    source_credentials.close()
                    raise ReadError("unsupported", "impersonation_source_must_use_google_auth")
                self.source = source_credentials
                target = auth.get("target_principal") or auth.get("impersonate_service_account")
                if not target:
                    raise ReadError("denied", "impersonation_target_required")
                self.credential = impersonated_credentials.Credentials(source_credentials=source_credentials.credential,
                    target_principal=target, target_scopes=OAUTH_SCOPES, delegates=auth.get("delegates", []),
                    lifetime=bound(auth, "lifetime", 900, 300, 3600), quota_project_id=auth.get("quota_project"))
            else:
                raise ReadError("unsupported", "unsupported_auth_method")
        except ReadError:
            self.close()
            raise
        except Exception:
            self.close()
            raise ReadError("denied", "credential_initialization_failed") from None

    def headers(self):
        with self.lock:
            if self.failure is not None:
                raise self.failure
            try:
                if self.direct_token:
                    return {"Authorization": "Bearer " + self.direct_token}
                if self.gcloud:
                    return self.gcloud.headers()
                headers = {}
                def request(*args, **kwargs):
                    kwargs["timeout"] = min(kwargs.get("timeout", self.timeout), self.timeout)
                    return self.request(*args, **kwargs)
                self.credential.before_request(request, "GET", "https://cloudasset.googleapis.com/", headers)
                return headers
            except ReadError as exc:
                self.failure = exc
                raise
            except Exception:
                self.failure = ReadError("denied", "credential_refresh_failed")
                raise self.failure from None

    def close(self):
        if self.session:
            self.session.close()
        if getattr(self, "source", None):
            self.source.close()


class Transport:
    def __init__(self, credentials, options, *, sleep=time.sleep):
        self.credentials, self.options, self.sleep = credentials, options, sleep
        self.max_calls = optional_bound(options, "max_calls", 1, 100000)
        self.retries = bound(options, "retries", 2, 0, 5)
        self.timeout = bound(options, "timeout", 20, 1, 120)
        self.calls = 0
        self.lock = threading.Lock()
        self.local = threading.local()
        self.sessions = []
        self.evidence = []
        self.cache = {}
        self.started = time.monotonic()
        self.deadline_seconds = optional_bound(options, "deadline_seconds", 1, 86400)
        if self.deadline_seconds is None:
            self.deadline_seconds = optional_bound(options, "collection_deadline_seconds", 1, 86400)
        self.deadline = options.get("deadline")
        if self.deadline is not None and (isinstance(self.deadline, bool) or not isinstance(self.deadline, (int, float))):
            raise ValueError("deadline must be an absolute epoch timestamp")

    def check_cancelled(self):
        event = self.options.get("cancel_event")
        if event is not None and event.is_set():
            raise ReadError("unavailable", "cancelled")
        callback = self.options.get("_cancel_check")
        if callable(callback) and callback():
            raise ReadError("unavailable", "cancelled")
        if self.deadline is not None and time.time() >= self.deadline:
            raise ReadError("unavailable", "execution_deadline")
        if self.deadline_seconds is not None and time.monotonic() - self.started >= self.deadline_seconds:
            raise ReadError("unavailable", "execution_deadline")

    def _session(self):
        if not getattr(self.local, "session", None):
            import requests
            self.local.session = requests.Session()
            with self.lock:
                self.sessions.append(self.local.session)
        return self.local.session

    def request(self, method, url, *, params=None, body=None, scope=None, operation=None):
        self.check_cancelled()
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in HOSTS or parsed.port not in (None, 443) or parsed.username or parsed.query:
            raise ReadError("unsupported", "unsafe_api_endpoint")
        if method not in ("GET", "POST") or (method == "POST" and not
            (parsed.path.endswith(":getIamPolicy") or parsed.path.endswith(":getAncestry") or parsed.path == "/v2/entries:list")):
            raise ReadError("unsupported", "cloud_mutation_prohibited")
        if re.search(r"/versions/[^/]+(?::access|$)|/oauthClients/|/keys/[^/]+$", parsed.path):
            raise ReadError("unsupported", "sensitive_value_read_prohibited")
        cache_key = json.dumps([method, url, params, body], sort_keys=True)
        # Coalesce identical requests, including simultaneous hydration calls.
        with self.lock:
            cached = self.cache.get(cache_key)
            if cached is None:
                cached = {"event": threading.Event()}
                self.cache[cache_key] = cached
                owner = True
            else:
                owner = False
        if not owner:
            cached["event"].wait()
            if "error" in cached:
                raise cached["error"]
            return copy.deepcopy(cached["data"]), cached["id"]
        safe_params = {k: v for k, v in (params or {}).items() if k != "pageToken"}
        evidence = {"id": None, "scope": scope, "method": method, "url": url,
            "operation": operation or parsed.path, "query": sanitize(safe_params), "attempts": 0,
            "http_attempts": 0, "started_at": datetime.now(timezone.utc).isoformat()}
        if body:
            evidence["request"] = sanitize({k: v for k, v in body.items() if k != "pageToken"})
        try:
            for attempt in range(self.retries + 1):
                self.check_cancelled()
                with self.lock:
                    if self.max_calls is not None and self.calls >= self.max_calls:
                        raise ReadError("unavailable", "call_limit")
                    self.calls += 1
                evidence["attempts"] += 1
                headers = self.credentials.headers()
                if self.options.get("quota_project"):
                    headers["X-Goog-User-Project"] = self.options["quota_project"]
                try:
                    evidence["http_attempts"] += 1
                    response = self._session().request(method, url, params=params, json=body, headers=headers,
                        timeout=self.timeout, allow_redirects=False)
                except Exception:
                    error = ReadError("unavailable", "network_error")
                    if attempt < self.retries:
                        self.sleep(min(4, 0.25 * 2 ** attempt))
                        continue
                    raise error from None
                evidence["http_status"] = response.status_code
                try:
                    data = response.json()
                except Exception:
                    data = None
                if response.status_code >= 400 or 300 <= response.status_code < 400:
                    error = http_error(response.status_code, data)
                    if response.status_code in (429, 500, 502, 503, 504) and attempt < self.retries:
                        self.sleep(min(4, 0.25 * 2 ** attempt))
                        continue
                    raise error
                if not isinstance(data, dict):
                    raise ReadError("malformed", "malformed_response")
                evidence["status"] = "collected"
                cached["data"] = data
                break
        except ReadError as exc:
            evidence["status"], evidence["error"] = exc.status, exc.error
            # Credential failure is memoized across requests; provenance belongs
            # to this request, so do not mutate that shared exception instance.
            cached["error"] = ReadError(exc.status, exc.error["code"], http_status=exc.error.get("http_status"),
                                        reason=exc.error.get("reason"))
        except Exception:
            error = ReadError("unavailable", "read_failed")
            evidence["status"], evidence["error"], cached["error"] = error.status, error.error, error
        finally:
            with self.lock:
                evidence["id"] = f"request-{len(self.evidence) + 1}"
                self.evidence.append(evidence)
            cached["id"] = evidence["id"]
            cached["event"].set()
        if "error" in cached:
            cached["error"].request_id = cached["id"]
            raise cached["error"]
        return copy.deepcopy(cached["data"]), cached["id"]

    def close(self):
        for session in self.sessions:
            session.close()
        self.credentials.close()


# (kind, Compute endpoint, list field, aggregated). Full native configuration is
# returned by these list calls; IAM and fields absent from list APIs are hydrated.
COMPUTE = (
    ("network", "global/networks", "items", False),
    ("subnetwork", "aggregated/subnetworks", "subnetworks", True),
    ("firewall", "global/firewalls", "items", False),
    ("firewall_policy", "aggregated/firewallPolicies", "firewallPolicies", True),
    ("instance", "aggregated/instances", "instances", True),
    ("route", "global/routes", "items", False),
    ("router", "aggregated/routers", "routers", True),
    ("vpn_gateway", "aggregated/vpnGateways", "vpnGateways", True),
    ("vpn_gateway", "aggregated/targetVpnGateways", "targetVpnGateways", True),
    ("vpn_tunnel", "aggregated/vpnTunnels", "vpnTunnels", True),
    ("forwarding_rule", "aggregated/forwardingRules", "forwardingRules", True),
    ("backend_service", "aggregated/backendServices", "backendServices", True),
    ("backend_bucket", "global/backendBuckets", "items", False),
    ("url_map", "aggregated/urlMaps", "urlMaps", True),
    ("health_check", "aggregated/healthChecks", "healthChecks", True),
    ("instance_group", "aggregated/instanceGroups", "instanceGroups", True),
    ("address", "aggregated/addresses", "addresses", True),
    *(("target_proxy", f"aggregated/{name}", name, True) for name in
      ("targetHttpProxies", "targetHttpsProxies", "targetTcpProxies")),
    *(("target_proxy", f"global/{name}", "items", False) for name in ("targetSslProxies", "targetGrpcProxies")),
)
SUPPORTED_TYPES = frozenset({x[0] for x in COMPUTE} | {
    "asset", "iam_policy", "iam_role", "iam_deny_policy", "project", "organization", "folder",
    "service_account", "service_account_key", "activity", "recommendation", "insight", "shared_vpc",
    "bucket", "sql_instance", "gke_cluster", "kms_key_ring", "kms_key", "secret", "log_sink",
    "workload_identity_pool", "workload_identity_provider", "workforce_pool", "workforce_provider",
    "bigquery_dataset", "artifact_repository", "cloudrun_service", "function", "group", "group_membership",
    "principal_access_boundary_policy", "policy_binding", "app_engine_application"})
DEPENDENCIES = {"service_account_key": {"service_account"}, "workload_identity_provider": {"workload_identity_pool"},
                "workforce_provider": {"workforce_pool"}, "kms_key": {"kms_key_ring"},
                "group": {"iam_policy", "organization"}, "group_membership": {"group", "iam_policy", "organization"}}


def normalize_scope(value):
    if not isinstance(value, str):
        raise ValueError("GCP scopes must be project, organization or folder names")
    if value == "*":
        return value
    scope = value if "/" in value else "projects/" + value
    if not re.fullmatch(r"(?:projects|organizations|folders)/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", scope):
        raise ValueError("invalid GCP scope")
    return scope


def wire_status(status):
    return "unknown" if status in ("unavailable", "unsupported") else status


def item_identity(kind, scope, item):
    for field in ("selfLink", "resource", "name"):
        name = item.get(field)
        if kind == "iam_policy" and name == scope:
            return "//cloudresourcemanager.googleapis.com/" + scope
        if isinstance(name, str) and (name.startswith(("https://", "//", "projects/", "organizations/", "folders/", "locations/", "groups/", "roles/", "policies/"))):
            return name
    name = str(item.get("name") or item.get("id") or item.get("email") or "")
    location = item.get("zone") or item.get("region") or item.get("location") or item.get("_aggregated_scope") or "global"
    return f"//gcp/{scope}/{location}/{kind}/{name}" if name else None


def relationships(item):
    """Only explicitly declared references; no inferred effective reachability."""
    edges = []
    fields = {"network": "uses_network", "subnetwork": "uses_subnetwork", "peerNetwork": "peers_with",
        "vpnGateway": "uses_vpn_gateway", "targetVpnGateway": "uses_vpn_gateway", "router": "uses_router",
        "target": "forwards_to", "backendService": "uses_backend", "urlMap": "uses_url_map",
        "defaultService": "uses_backend", "service": "uses_backend", "group": "uses_instance_group",
        "healthChecks": "uses_health_check", "kmsKeyName": "encrypted_with", "defaultKmsKeyName": "encrypted_with",
        "destination": "logs_to", "keyRing": "belongs_to_key_ring", "group": "member_of_group", "member": "member_reference"}
    def visit(value, path=""):
        if isinstance(value, dict):
            for field, child in value.items():
                if field.startswith("_"):
                    continue
                if field in fields:
                    for ref in child if isinstance(child, list) else [child]:
                        if isinstance(ref, str) and ref:
                            edges.append({"type": fields[field], "target": ref, "field": path + field})
                visit(child, path + field + ".")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + str(index) + ".")
    visit(item)
    return sorted({(e["type"], e["target"], e["field"]): e for e in edges}.values(),
                  key=lambda e: (e["type"], e["target"], e["field"]))


class GCPCollector:
    def __init__(self, connector, requirements=None, *, transport=None):
        self.options = dict(connector.get("options") or {})
        self.auth = connector.get("auth", {})
        if self.auth is None:
            self.auth = {}
        if not isinstance(self.auth, dict):
            raise ValueError("GCP auth must be an object")
        if self.auth.get("quota_project"):
            self.options["quota_project"] = self.auth["quota_project"]
        requested = self.options.get("inventories", sorted(SUPPORTED_TYPES))
        if not isinstance(requested, list) or any(x not in SUPPORTED_TYPES for x in requested):
            raise ValueError("inventories must contain supported GCP resource types")
        if requirements is not None and (not isinstance(requirements, (list, tuple, set)) or
                                        any(x not in SUPPORTED_TYPES for x in requirements)):
            raise ValueError("requirements must contain supported GCP resource types")
        self.wanted = set(requested) & (set(requirements) if requirements is not None else SUPPORTED_TYPES)
        self.needed = set(self.wanted)
        for kind in self.wanted:
            self.needed.update(DEPENDENCIES.get(kind, set()))
        self.scopes = list(dict.fromkeys(normalize_scope(s) for s in connector.get("scopes", [])))
        self.requested_scopes = self.scopes[:]
        self.auto_scopes = not self.scopes
        if self.auto_scopes:
            self.scopes = ["*"]
            self.options["all_projects"] = True
            self.options["all_hierarchy"] = True
        self.allowed = self.options.get("project_restrictions", self.options.get("allowed_projects"))
        if self.allowed is not None:
            if not isinstance(self.allowed, list) or any(not isinstance(x, str) for x in self.allowed):
                raise ValueError("project_restrictions must be a project string list")
            self.allowed = set(normalize_scope(x) for x in self.allowed)
            if any(not x.startswith("projects/") for x in self.allowed):
                raise ValueError("project_restrictions must contain only projects")
            if any(s.startswith("projects/") and s not in self.allowed for s in self.scopes):
                raise ValueError("explicit project is outside project_restrictions")
        if not self.scopes or ("*" in self.scopes and not self.options.get("all_projects")):
            raise ValueError("GCP requires explicit scopes; '*' requires all_projects=true")
        self.max_scopes = optional_bound(self.options, "max_scopes", 1, 100000)
        if self.max_scopes is not None and len(self.scopes) > self.max_scopes:
            raise ValueError("scope limit exceeded")
        self.max_pages = optional_bound(self.options, "max_pages", 1, 100000)
        self.max_items = optional_bound(self.options, "max_resources", 1, 10000000)
        self.page_size = bound(self.options, "page_size", 100, 1, 1000)
        self.workers = bound(self.options, "concurrency", 4, 1, 16)
        self.max_calls = optional_bound(self.options, "max_calls", 1, 100000)
        self.collections = {}
        self.lock = threading.Lock()
        self.total_items = 0
        self.seen_items = set()
        self.scope_errors = []
        self.transport = transport
        self.auth_error = None
        self.read_time = datetime.now(timezone.utc).isoformat()

    def read(self, url, scope, *, params=None, body=None, method="GET", operation=None):
        return self.transport.request(method, url, params=params, body=body, scope=scope, operation=operation)

    def pages(self, url, scope, *, key="items", params=None, body=None, method="GET", aggregate=None,
              single=False, transform=None, operation=None, page_size_key="pageSize"):
        params = dict(params or {})
        if not single and page_size_key:
            params.setdefault(page_size_key, min(self.page_size, 500 if "compute.googleapis.com" in url else 1000))
        seen = set()
        for page in count():
            data, request_id = self.read(url, scope, params=params, body=body, method=method, operation=operation)
            def malformed(code):
                error = ReadError("malformed", code)
                error.request_id = request_id
                return error
            if not isinstance(data, dict):
                raise malformed("malformed_response")
            incomplete = isinstance(data.get("warning"), dict) and data["warning"].get("code") not in (None, "NO_RESULTS_ON_PAGE")
            items = [data] if single else data.get("items" if aggregate else key, {} if aggregate else [])
            if aggregate:
                if not isinstance(items, dict):
                    raise malformed("malformed_aggregated_list")
                flattened = []
                for location, group in sorted(items.items()):
                    if not isinstance(group, dict) or not isinstance(group.get(aggregate, []), list):
                        raise malformed("malformed_aggregated_list")
                    if any(not isinstance(entry, dict) for entry in group.get(aggregate, [])):
                        raise malformed("malformed_aggregated_list")
                    if isinstance(group.get("warning"), dict) and group["warning"].get("code") not in (None, "NO_RESULTS_ON_PAGE"):
                        incomplete = True
                    flattened.extend({**x, "_aggregated_scope": location} for x in group.get(aggregate, []))
                items = flattened
            if not isinstance(items, list) or any(not isinstance(x, dict) for x in items):
                raise malformed("malformed_list")
            if transform:
                items = [transform(item) for item in items]
            yield items, request_id
            if incomplete:
                raise ReadError("unavailable", "partial_api_warning")
            if data.get("unreachables") or data.get("unreachable") or data.get("missingZones"):
                raise ReadError("unavailable", "unreachable_locations")
            token = data.get("nextPageToken")
            if single or not token:
                return
            if not isinstance(token, str) or token in seen:
                raise ReadError("malformed", "repeated_pagination_token")
            seen.add(token)
            if self.max_pages is not None and page + 1 >= self.max_pages:
                raise ReadError("unavailable", "page_limit")
            if body is not None:
                body = {**body, "pageToken": token}
            else:
                params["pageToken"] = token

    def envelope(self, kind, scope, service, fetch):
        items, source_requests = {}, []
        state, error = "collected", None
        try:
            for page, request_id in fetch():
                source_requests.append(request_id)
                for raw in page:
                    item = sanitize(raw)
                    rid = item_identity(kind, scope, item)
                    if rid is None:
                        from peaso.snapshot import digest
                        rid = digest(item)
                    if rid in items:
                        continue
                    with self.lock:
                        identity = (kind, scope, rid)
                        if identity not in self.seen_items:
                            if self.max_items is not None and self.total_items >= self.max_items:
                                raise ReadError("unavailable", "resource_limit")
                            self.seen_items.add(identity)
                            self.total_items += 1
                    item["_resource_id"] = rid
                    item["native_id"] = rid
                    details = [ref for detail in item.get("_coverage", {}).values()
                               for ref in detail.get("source_requests", [])]
                    item["_provenance"] = {"source_requests": sorted(set([request_id, *details])), "scope": scope,
                                           "collected_at": self.read_time}
                    item["_relationships"] = relationships(item)
                    items[rid] = item
        except ReadError as exc:
            state, error = exc.status, {"kind": exc.status, **exc.error}
            if getattr(exc, "request_id", None):
                source_requests.append(exc.request_id)
        except Exception:
            state, error = "unavailable", {"kind": "unavailable", "code": "collector_error"}
        if error and items:
            state = "partial"
        if state == "collected" and not items:
            state = "empty"
        result = {"type": kind, "scope": scope, "service": service, "status": wire_status(state),
            "coverage_status": state, "items": list(items.values()), "source_requests": sorted(set(source_requests))}
        if error:
            result["error"] = error
        return result

    def add(self, kind, scope, service, fetch):
        envelope = self.envelope(kind, scope, service, fetch)
        with self.lock:
            key = (kind, scope)
            previous = self.collections.get(key)
            if previous:
                output = {x["_resource_id"]: x for x in previous["items"]}
                output.update({x["_resource_id"]: x for x in envelope["items"]})
                envelope["items"] = list(output.values())
                envelope["source_requests"] = sorted(set(previous["source_requests"] + envelope["source_requests"]))
                if previous.get("error") or envelope.get("error"):
                    envelope["error"] = envelope.get("error") or previous["error"]
                    state = "partial" if output else envelope["error"]["kind"]
                    envelope["status"], envelope["coverage_status"] = wire_status(state), state
                elif output:
                    envelope["status"] = envelope["coverage_status"] = "collected"
            self.collections[key] = envelope
        return envelope

    def hydrate(self, item, field, url, scope, *, params=None, body=None, method="GET"):
        output = dict(item)
        coverage = output.setdefault("_coverage", {})
        try:
            value, request_id = self.read(url, scope, params=params, body=body, method=method)
            if not isinstance(value, dict):
                raise ReadError("malformed", "malformed_response")
            output[field] = sanitize(value)
            coverage[field] = {"status": "collected", "collection_status": "collected", "source_requests": [request_id]}
        except ReadError as exc:
            coverage[field] = {"status": exc.status, "collection_status": wire_status(exc.status), "error": exc.error,
                "source_requests": [exc.request_id] if getattr(exc, "request_id", None) else []}
            output[field] = {"collection_status": wire_status(exc.status), "error": exc.error}
        return output

    def items(self, kind):
        return [(scope, item) for (item_kind, scope), collection in sorted(self.collections.items())
                if item_kind == kind for item in collection["items"]]

    def run_jobs(self, jobs):
        # Executor.map consumes bounded scope/type jobs, never one future per asset.
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="gcp-read") as pool:
            list(pool.map(lambda job: self.add(*job), jobs))

    def discover(self):
        if "*" in self.scopes or self.options.get("all_projects"):
            result = self.add("project", "discovery", "cloudresourcemanager", lambda: self.pages(
                "https://cloudresourcemanager.googleapis.com/v3/projects:search", "discovery", key="projects",
                params={"query": "state:ACTIVE"}))
            if result["coverage_status"] not in ("collected", "empty"):
                self.scope_errors.append({"scope": "discovery", "operation": "projects:search", "status": result["coverage_status"],
                    "error": result.get("error"), "source_requests": result["source_requests"]})
            discovered = [normalize_scope(item.get("projectId") or item["name"]) for item in result["items"]]
            self.scopes = [s for s in self.scopes if s != "*"] + discovered
        if self.options.get("discover_projects"):
            for scope in self.scopes[:]:
                if not scope.startswith(("organizations/", "folders/")):
                    continue
                result = self.add("project", scope, "cloudasset", lambda scope=scope: self.pages(
                    f"https://cloudasset.googleapis.com/v1/{scope}/assets", scope, key="assets",
                    params={"assetTypes": ["cloudresourcemanager.googleapis.com/Project"], "contentType": "RESOURCE"},
                    transform=lambda asset: {**asset.get("resource", {}).get("data", {}), "_asset_name": asset.get("name")}))
                for item in result["items"]:
                    project = item.get("projectId") or item.get("project_id")
                    if project:
                        self.scopes.append(normalize_scope(project))
        if self.options.get("all_hierarchy"):
            for kind, key in (("organization", "organizations"), ("folder", "folders")):
                result = self.add(kind, "discovery", "cloudresourcemanager", lambda key=key: self.pages(
                    f"https://cloudresourcemanager.googleapis.com/v3/{key}:search", "discovery", key=key))
                if result["coverage_status"] not in ("collected", "empty"):
                    self.scope_errors.append({"scope": "discovery", "operation": key + ":search", "status": result["coverage_status"],
                        "error": result.get("error"), "source_requests": result["source_requests"]})
                self.scopes.extend(normalize_scope(item["name"]) for item in result["items"])
        self.scopes = list(dict.fromkeys(s for s in self.scopes if not s.startswith("projects/") or
                                        self.allowed is None or s in self.allowed))
        # Remove discovery evidence about projects excluded by restrictions.
        if self.allowed is not None:
            for (kind, _), collection in self.collections.items():
                if kind == "project":
                    collection["items"] = [x for x in collection["items"] if normalize_scope(
                        x.get("projectId") or x.get("project_id") or x.get("name", "excluded")) in self.allowed]
                    if not collection["items"] and collection["status"] == "collected":
                        collection["status"] = collection["coverage_status"] = "empty"
        if self.max_scopes is not None and len(self.scopes) > self.max_scopes:
            self.scopes = self.scopes[:self.max_scopes]
            self.scope_errors.append({"code": "scope_limit", "status": "partial"})

    def scope_jobs(self, scope):
        jobs = []
        def add(kind, service, factory):
            if kind in self.needed:
                jobs.append((kind, scope, service, factory))
        crm = "https://cloudresourcemanager.googleapis.com"
        scope_type = {"projects": "project", "organizations": "organization", "folders": "folder"}[scope.split("/")[0]]
        def scope_metadata():
            for items, request_id in self.pages(f"{crm}/v3/{scope}", scope, single=True):
                if scope_type == "project":
                    hydrated = []
                    for item in items:
                        item = self.hydrate(item, "computeConfig", f"https://compute.googleapis.com/compute/v1/{scope}", scope)
                        config = item.get("computeConfig", {})
                        for field in ("commonInstanceMetadata", "defaultServiceAccount", "xpnProjectStatus"):
                            if field in config:
                                item[field] = config[field]
                        hydrated.append(item)
                    items = hydrated
                yield items, request_id
        add(scope_type, "cloudresourcemanager", scope_metadata)
        def policies():
            failure = None
            try:
                for items, request_id in self.pages(f"{crm}/v3/{scope}:getIamPolicy", scope, single=True, method="POST",
                    body={"options": {"requestedPolicyVersion": 3}}):
                    yield [{"name": scope, **item} for item in items], request_id
            except ReadError as exc:
                failure = exc
            if self.options.get("resource_iam", True) and not (self.allowed is not None and scope_type != "project"):
                yield from self.pages(f"https://cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies", scope,
                    key="results", transform=lambda item: {"name": item.get("resource"), **item.get("policy", {}),
                        "assetType": item.get("assetType"), "project": item.get("project"), "folders": item.get("folders", [])})
            if failure:
                raise failure
        add("iam_policy", "iam/cloudasset", policies)
        attachment = quote("cloudresourcemanager.googleapis.com/" + scope, safe="")
        def deny_policies():
            for items, request_id in self.pages(f"https://iam.googleapis.com/v2/policies/{attachment}/denypolicies", scope, key="policies"):
                hydrated = []
                for item in items:
                    if "rules" not in item and item.get("name"):
                        name = item['name']
                        # Attachment point slashes are encoded within the policy
                        # name, not interpreted as extra API path components.
                        item = self.hydrate(item, "policyDetails", f"https://iam.googleapis.com/v2/{name}", scope)
                        if "rules" in item.get("policyDetails", {}):
                            item["rules"] = item["policyDetails"]["rules"]
                    hydrated.append(item)
                yield hydrated, request_id
        add("iam_deny_policy", "iam", deny_policies)
        add("policy_binding", "iam", lambda: self.pages(f"https://iam.googleapis.com/v3/{scope}/locations/global/policyBindings",
            scope, key="policyBindings"))
        if scope_type == "organization":
            add("principal_access_boundary_policy", "iam", lambda: self.pages(
                f"https://iam.googleapis.com/v3/{scope}/locations/global/principalAccessBoundaryPolicies", scope,
                key="principalAccessBoundaryPolicies"))
        if scope_type in ("project", "organization"):
            add("iam_role", "iam", lambda: self.pages(f"https://iam.googleapis.com/v1/{scope}/roles", scope,
                key="roles", params={"view": "FULL", "showDeleted": "true"}))
        if "asset" in self.needed and not (self.allowed is not None and scope_type != "project"):
            asset_types = self.options.get("asset_types")
            if asset_types is not None and (not isinstance(asset_types, list) or len(asset_types) > 100 or
                                           any(not isinstance(x, str) for x in asset_types)):
                raise ValueError("asset_types must be a list of at most 100 names/patterns")
            params = {"contentType": "RESOURCE", "readTime": self.read_time}
            if asset_types:
                params["assetTypes"] = asset_types
            add("asset", "cloudasset", lambda: self.pages(f"https://cloudasset.googleapis.com/v1/{scope}/assets",
                scope, key="assets", params=params))
        add("log_sink", "logging", lambda: self.pages(f"https://logging.googleapis.com/v2/{scope}/sinks", scope, key="sinks"))
        if scope_type == "organization":
            add("workforce_pool", "iam", lambda: self.pages("https://iam.googleapis.com/v1/locations/global/workforcePools",
                scope, key="workforcePools", params={"parent": scope}))
        if scope_type in ("organization", "folder"):
            def hierarchical_firewalls():
                yield from self.pages("https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies",
                    scope, params={"parentId": scope}, page_size_key="maxResults")
            add("firewall_policy", "compute", hierarchical_firewalls)
        for kind, suffix, key in (("recommendation", "recommenders/google.iam.policy.Recommender/recommendations", "recommendations"),
                                 ("insight", "insightTypes/google.iam.policy.Insight/insights", "insights")):
            def rec_pages(suffix=suffix, key=key):
                locations = self.options.get("recommender_locations", ["global"])
                if not isinstance(locations, list) or len(locations) > 50 or any(not re.fullmatch(r"[a-z0-9-]+", x) for x in locations):
                    raise ValueError("invalid recommender_locations")
                for location in locations:
                    yield from self.pages(f"https://recommender.googleapis.com/v1/{scope}/locations/{location}/{suffix}", scope, key=key)
            add(kind, "recommender", rec_pages)
        if scope_type != "project":
            return jobs
        project = quote(scope.split("/", 1)[1], safe="")
        compute = f"https://compute.googleapis.com/compute/v1/projects/{project}"
        for kind, endpoint, key, aggregated in COMPUTE:
            add(kind, "compute", lambda endpoint=endpoint, key=key, aggregated=aggregated: self.pages(
                f"{compute}/{endpoint}", scope, key=key, aggregate=key if aggregated else None,
                params={"returnPartialSuccess": "true"} if aggregated else None, page_size_key="maxResults"))
        def buckets():
            for items, request_id in self.pages("https://storage.googleapis.com/storage/v1/b", scope,
                params={"project": project, "projection": "full"}, page_size_key="maxResults"):
                yield [self.hydrate(item, "iamPolicy", "https://storage.googleapis.com/storage/v1/b/" +
                    quote(item["name"], safe="") + "/iam", scope, params={"optionsRequestedPolicyVersion": 3}) for item in items], request_id
        add("bucket", "storage", buckets)
        add("sql_instance", "sqladmin", lambda: self.pages(f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances",
            scope, page_size_key="maxResults"))
        add("gke_cluster", "container", lambda: self.pages(f"https://container.googleapis.com/v1/{scope}/locations/-/clusters",
            scope, key="clusters", page_size_key=None))
        add("app_engine_application", "appengine", lambda: self.pages(f"https://appengine.googleapis.com/v1/apps/{project}",
            scope, single=True))
        def service_accounts():
            for items, request_id in self.pages(f"https://iam.googleapis.com/v1/{scope}/serviceAccounts", scope, key="accounts"):
                yield [self.hydrate(item, "iamPolicy", f"https://iam.googleapis.com/v1/{item['name']}:getIamPolicy",
                    scope, params={"options.requestedPolicyVersion": 3}) for item in items], request_id
        add("service_account", "iam", service_accounts)
        add("workload_identity_pool", "iam", lambda: self.pages(f"https://iam.googleapis.com/v1/{scope}/locations/global/workloadIdentityPools",
            scope, key="workloadIdentityPools"))
        def key_rings():
            selected_locations = self.options.get("kms_locations")
            if selected_locations is not None:
                if not isinstance(selected_locations, list) or len(selected_locations) > 100 or any(
                    not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x) for x in selected_locations):
                    raise ValueError("kms_locations must contain at most 100 region names")
                locations = [f"{scope}/locations/{x}" for x in dict.fromkeys(selected_locations)]
            else:
                locations = []
                for items, request_id in self.pages(f"https://cloudkms.googleapis.com/v1/{scope}/locations", scope, key="locations"):
                    locations.extend(item["name"] for item in items)
                    yield [], request_id
            for location in locations:
                yield from self.pages(f"https://cloudkms.googleapis.com/v1/{location}/keyRings", scope, key="keyRings")
        add("kms_key_ring", "cloudkms", key_rings)
        def secrets():
            for items, request_id in self.pages(f"https://secretmanager.googleapis.com/v1/{scope}/secrets", scope, key="secrets"):
                yield [self.hydrate(item, "iamPolicy", f"https://secretmanager.googleapis.com/v1/{item['name']}:getIamPolicy",
                    scope, params={"options.requestedPolicyVersion": 3}) for item in items], request_id
        add("secret", "secretmanager", secrets)
        def datasets():
            for items, request_id in self.pages(f"https://bigquery.googleapis.com/bigquery/v2/{scope}/datasets", scope,
                key="datasets", params={"all": "true"}, page_size_key="maxResults"):
                hydrated = []
                for item in items:
                    dataset_id = item["datasetReference"]["datasetId"]
                    name = f"{scope}/datasets/{dataset_id}"
                    item = self.hydrate({**item, "name": name}, "datasetDetails",
                        f"https://bigquery.googleapis.com/bigquery/v2/{scope}/datasets/{quote(dataset_id, safe='')}", scope,
                        params={"accessPolicyVersion": 3, "datasetView": "FULL"})
                    if item["_coverage"]["datasetDetails"]["status"] == "collected":
                        details = item.pop("datasetDetails")
                        item.update(details)
                    hydrated.append(item)
                yield hydrated, request_id
        add("bigquery_dataset", "bigquery", datasets)
        def region_metadata(service, version, segment, key, location_option):
            locations = self.options.get(location_option, self.options.get("regions"))
            if locations is not None:
                if not isinstance(locations, list) or len(locations) > 100 or any(
                    not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x) for x in locations):
                    raise ValueError("regional metadata locations must contain at most 100 region names")
                locations = list(dict.fromkeys(locations))
            else:
                locations = []
                for items, request_id in self.pages(f"https://{service}.googleapis.com/{version}/{scope}/locations",
                    scope, key="locations"):
                    locations.extend(item.get("locationId") or item["name"].rsplit("/", 1)[1] for item in items)
                    yield [], request_id
            failures = []
            for location in locations:
                try:
                    for items, request_id in self.pages(f"https://{service}.googleapis.com/{version}/{scope}/locations/{location}/{segment}",
                        scope, key=key):
                        yield [self.hydrate(item, "iamPolicy", f"https://{service}.googleapis.com/{version}/{item['name']}:getIamPolicy",
                            scope, params={"options.requestedPolicyVersion": 3}) for item in items], request_id
                except ReadError as exc:
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("artifact_repository", "artifactregistry", lambda: region_metadata("artifactregistry", "v1", "repositories",
            "repositories", "artifactregistry_locations"))
        add("cloudrun_service", "run", lambda: region_metadata("run", "v2", "services", "services", "cloudrun_locations"))
        def functions():
            for items, request_id in self.pages(f"https://cloudfunctions.googleapis.com/v2/{scope}/locations/-/functions",
                scope, key="functions"):
                yield [self.hydrate(item, "iamPolicy", f"https://cloudfunctions.googleapis.com/v2/{item['name']}:getIamPolicy",
                    scope, params={"options.requestedPolicyVersion": 3}) for item in items], request_id
        add("function", "cloudfunctions", functions)
        def shared_vpc():
            failure = None
            try:
                data, request_id = self.read(f"{compute}/getXpnHost", scope)
                yield [{"name": f"{scope}/getXpnHost", "relationshipType": "getXpnHost", "host": data,
                    "hostProject": data.get("name"), "serviceProject": scope}], request_id
            except ReadError as exc:
                failure = exc
            for items, request_id in self.pages(f"{compute}/getXpnResources", scope, key="resources", page_size_key="maxResults"):
                yield [{"name": f"{scope}/getXpnResources/{item.get('id')}", "relationshipType": "getXpnResources",
                    "hostProject": scope, "serviceProject": item.get("id"), "resources": [item]} for item in items], request_id
            if failure:
                raise failure
        add("shared_vpc", "compute", shared_vpc)
        if "activity" in self.needed:
            days = bound(self.options, "activity_days", 30, 1, 365)
            since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            def activity(item):
                auth = item.get("protoPayload", {}).get("authenticationInfo", {})
                return {"name": item.get("insertId") or item.get("timestamp"), "timestamp": item.get("timestamp"),
                    "principalEmail": auth.get("principalEmail"), "serviceAccountKeyName": auth.get("serviceAccountKeyName"),
                    "serviceName": item.get("protoPayload", {}).get("serviceName"),
                    "methodName": item.get("protoPayload", {}).get("methodName"), "logName": item.get("logName"),
                    "coverageWindow": {"since": since, "days": days, "absenceProvesUnused": False}}
            add("activity", "logging", lambda: self.pages("https://logging.googleapis.com/v2/entries:list", scope,
                key="entries", method="POST", page_size_key=None,
                body={"resourceNames": [scope], "filter": f'logName:"cloudaudit.googleapis.com" AND timestamp>="{since}" '
                    'AND protoPayload.authenticationInfo.principalEmail:"gserviceaccount.com"',
                    "orderBy": "timestamp desc", "pageSize": min(self.page_size, 1000)}, transform=activity))
        return jobs

    def inherited(self):
        if not self.options.get("include_inherited", True) or not self.needed.intersection(
            {"iam_policy", "iam_deny_policy", "iam_role", "project", "folder", "organization"}):
            return
        parents = set()
        for scope in self.scopes[:]:
            if not scope.startswith("projects/"):
                continue
            try:
                data, request_id = self.read(f"https://cloudresourcemanager.googleapis.com/v1/{scope}:getAncestry",
                    scope, method="POST", body={})
                ancestors = data.get("ancestor", [])
                if not isinstance(ancestors, list):
                    raise ReadError("malformed", "malformed_ancestry")
                for ancestor in ancestors:
                    resource = ancestor.get("resourceId", {})
                    if resource.get("type") in ("folder", "organization"):
                        parent = normalize_scope(resource["type"] + "s/" + str(resource["id"]))
                        parents.add(parent)
                if ("project", scope) in self.collections:
                    for item in self.collections[("project", scope)]["items"]:
                        item["_ancestry"] = sanitize(ancestors)
                        item["_provenance"]["source_requests"].append(request_id)
            except ReadError as exc:
                self.scope_errors.append({"scope": scope, "operation": "getAncestry", "status": exc.status,
                    "error": exc.error, "source_requests": [exc.request_id] if getattr(exc, "request_id", None) else []})
        self.inherited_scopes = sorted(parents - set(self.scopes))
        remaining = self.max_scopes - len(self.scopes) if self.max_scopes is not None else None
        if remaining is not None and len(self.inherited_scopes) > remaining:
            self.inherited_scopes = self.inherited_scopes[:max(0, remaining)]
            self.scope_errors.append({"code": "inherited_scope_limit", "status": "partial"})
        jobs = []
        for scope in self.inherited_scopes:
            # Ancestors supply inheritance evidence, never select sibling projects
            # or broad ancestor asset searches through implicit scope expansion.
            for kind, scope, service, fetch in self.scope_jobs(scope):
                if kind in ("iam_policy", "iam_deny_policy", "iam_role", "folder", "organization"):
                    if kind == "iam_policy":
                        def fetch(scope=scope):
                            for items, request_id in self.pages(f"https://cloudresourcemanager.googleapis.com/v3/{scope}:getIamPolicy",
                                scope, method="POST", body={"options": {"requestedPolicyVersion": 3}}, single=True):
                                yield [{"name": scope, **item} for item in items], request_id
                    jobs.append((kind, scope, service, fetch))
        self.run_jobs(jobs)

    def dependent_jobs(self):
        jobs = []
        def add(kind, scope, service, fetch):
            jobs.append((kind, scope, service, fetch))
        if "service_account_key" in self.needed:
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def keys(scope=scope):
                    accounts = self.collections.get(("service_account", scope))
                    if not accounts or accounts["coverage_status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "service_account_inventory_incomplete")
                    for item in accounts["items"]:
                        name = item.get("name") or f"{scope}/serviceAccounts/{quote(item['email'], safe='')}"
                        yield from self.pages(f"https://iam.googleapis.com/v1/{name}/keys", scope, key="keys", page_size_key=None,
                            transform=lambda key, name=name: {**{k: v for k, v in key.items() if k not in ("privateKeyData", "publicKeyData")},
                                "serviceAccount": name})
                add("service_account_key", scope, "iam", keys)
        for child, parent, segment, key in (
            ("workload_identity_provider", "workload_identity_pool", "providers", "workloadIdentityPoolProviders"),
            ("workforce_provider", "workforce_pool", "providers", "workforcePoolProviders"),
            ("kms_key", "kms_key_ring", "cryptoKeys", "cryptoKeys")):
            if child not in self.needed:
                continue
            scopes = [s for s in self.scopes if s.startswith("organizations/" if parent == "workforce_pool" else "projects/")]
            for scope in scopes:
                def children(scope=scope, parent=parent, segment=segment, key=key):
                    collection = self.collections.get((parent, scope))
                    if not collection or collection["coverage_status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", f"{parent}_inventory_incomplete")
                    for item in collection["items"]:
                        service = "cloudkms" if parent == "kms_key_ring" else "iam"
                        def transform(key, ring=item['name'], scope=scope):
                            output = {**key, "keyRing": ring}
                            return self.hydrate(output, "iamPolicy", f"https://cloudkms.googleapis.com/v1/{key['name']}:getIamPolicy",
                                scope, params={"options.requestedPolicyVersion": 3})
                        yield from self.pages(f"https://{service}.googleapis.com/v1/{item['name']}/{segment}", scope, key=key,
                            transform=transform if parent == "kms_key_ring" else None)
                add(child, scope, "cloudkms" if parent == "kms_key_ring" else "iam", children)
        self.run_jobs(jobs)
        if self.needed.intersection({"group", "group_membership"}):
            self.directory_groups()
        if "iam_role" in self.needed:
            role_scopes = {}
            for scope, policy in self.items("iam_policy"):
                for binding in policy.get("bindings", []):
                    role = binding.get("role")
                    if isinstance(role, str) and re.fullmatch(r"(?:roles/[\w.]+|(?:projects|organizations)/[\w.-]+/roles/[\w.]+)", role):
                        role_scopes.setdefault(role, scope)
            known = {item.get("name") for _, item in self.items("iam_role")}
            jobs = []
            for role in sorted(set(role_scopes) - known):
                scope = role_scopes[role]
                # Cross-project custom roles stay references unless their owning
                # project was selected; project restrictions apply to reads too.
                if role.startswith("projects/") and "/".join(role.split("/")[:2]) not in self.scopes:
                    self.scope_errors.append({"scope": scope, "role": role, "status": "unavailable", "code": "role_owner_not_selected"})
                    continue
                jobs.append(("iam_role", scope, "iam", lambda role=role, scope=scope: self.pages(
                    f"https://iam.googleapis.com/v1/{role}", scope, single=True)))
            self.run_jobs(jobs)

    def directory_groups(self):
        """Resolve declared group references and selected directory group realms."""
        if not self.scopes:
            return
        scope = self.scopes[0]
        references = sorted({member.removeprefix("group:") for _, policy in self.items("iam_policy")
            for binding in policy.get("bindings", []) for member in binding.get("members", [])
            if isinstance(member, str) and member.startswith("group:")})
        customers = set(self.options.get("cloud_identity_customers", []))
        for _, organization in self.items("organization"):
            owner = organization.get("owner", {})
            customer = organization.get("directoryCustomerId") or (owner.get("directoryCustomerId") if isinstance(owner, dict) else None)
            if customer:
                customers.add(customer)
        if any(not isinstance(customer, str) or not re.fullmatch(r"C[A-Za-z0-9_-]+", customer) for customer in customers):
            raise ValueError("cloud_identity_customers must contain Google directory customer IDs")
        def groups():
            failures = []
            for customer in sorted(customers):
                try:
                    yield from self.pages("https://cloudidentity.googleapis.com/v1/groups", scope, key="groups",
                        params={"parent": "customers/" + customer, "view": "FULL", "pageSize": min(self.page_size, 500)})
                except ReadError as exc:
                    failures.append(exc)
            for email in references:
                try:
                    resolved, request_id = self.read("https://cloudidentity.googleapis.com/v1/groups:lookup", scope,
                        params={"groupKey.id": email})
                    name = resolved.get("name")
                    if not isinstance(name, str) or not re.fullmatch(r"groups/[A-Za-z0-9_-]+", name):
                        raise ReadError("malformed", "invalid_group_reference")
                    item = self.hydrate({"name": name, "groupKey": {"id": email}, "referencedPrincipal": "group:" + email},
                        "groupDetails", f"https://cloudidentity.googleapis.com/v1/{name}", scope)
                    if item["_coverage"]["groupDetails"]["status"] == "collected":
                        item.update(item.pop("groupDetails"))
                    yield [item], request_id
                except ReadError as exc:
                    failures.append(exc)
            # Without a known customer realm, reference resolution cannot claim
            # a complete directory inventory, even if all referenced groups read.
            if not customers:
                failures.append(ReadError("unavailable", "directory_customer_scope_unknown"))
            if failures:
                raise failures[0]
        group_collection = self.add("group", scope, "cloudidentity", groups)
        if "group_membership" not in self.needed:
            return
        def memberships():
            failures = []
            for group in group_collection["items"]:
                name = group.get("name")
                if not isinstance(name, str) or not re.fullmatch(r"groups/[A-Za-z0-9_-]+", name):
                    failures.append(ReadError("malformed", "invalid_group_reference"))
                    continue
                for relation, endpoint in (("direct", "memberships"), ("transitive", "memberships:searchTransitiveMemberships")):
                    try:
                        for items, request_id in self.pages(f"https://cloudidentity.googleapis.com/v1/{name}/{endpoint}", scope,
                            key="memberships", params={"view": "FULL", "pageSize": min(self.page_size, 500)} if relation == "direct" else None):
                            transformed = []
                            for index, member in enumerate(items):
                                identifier = member.get("name") or member.get("member") or str(member.get("preferredMemberKey") or member.get("memberKey"))
                                transformed.append({**member, "name": f"{name}/{relation}/{identifier}", "group": name,
                                    "membershipKind": relation, "groupKey": group.get("groupKey"),
                                    "membershipCoverage": {"status": "observed", "completeTransitiveClosure": False}})
                            yield transformed, request_id
                    except ReadError as exc:
                        failures.append(exc)
                        group.setdefault("_coverage", {})[relation + "Memberships"] = {
                            "status": exc.status, "error": exc.error,
                            "source_requests": [exc.request_id] if getattr(exc, "request_id", None) else []}
            if group_collection["status"] not in ("collected", "empty"):
                failures.append(ReadError("unavailable", "group_inventory_incomplete"))
            if failures:
                raise failures[0]
        collected = self.add("group_membership", scope, "cloudidentity", memberships)
        if collected["status"] in ("collected", "empty"):
            for member in collected["items"]:
                member["membershipCoverage"] = {"status": "collected", "completeTransitiveClosure": True,
                    "semantics": "Cloud Identity membership visibility, not effective cloud permissions"}

    def finish(self):
        from peaso.snapshot import make_snapshot
        envelopes = []
        for key, collection in sorted(self.collections.items()):
            if key[0] in self.wanted or key[0] == "project" and self.options.get("all_projects"):
                collection["items"].sort(key=lambda item: item["_resource_id"])
                envelopes.append(collection)
        metadata = {"collection": "read-only", "collector": "native-gcp", "requested_scopes": self.requested_scopes,
            "resolved_scopes": self.scopes, "inherited_scopes": getattr(self, "inherited_scopes", []),
            "auth_method": getattr(getattr(self.transport, "credentials", None), "method", selected_auth_method(self.auth)),
            "calls": getattr(self.transport, "calls", 0), "max_calls": self.max_calls, "max_pages": self.max_pages,
            "max_resources": self.max_items, "max_scopes": self.max_scopes, "concurrency": self.workers, "asset_read_time": self.read_time,
            "intentional_limits": {key: self.options[key] for key in ("max_calls", "max_pages", "max_resources", "max_scopes", "deadline_seconds")
                                   if self.options.get(key) is not None},
            "collection_mode": "intentionally_limited" if any(self.options.get(key) is not None for key in
                ("max_calls", "max_pages", "max_resources", "max_scopes", "deadline_seconds")) else "full",
            "omitted_inventories": sorted(SUPPORTED_TYPES - self.wanted), "supporting_inventories": sorted(self.needed - self.wanted),
            "source_requests": getattr(self.transport, "evidence", []), "scope_coverage": self.scope_errors,
            "project_restrictions": sorted(self.allowed) if self.allowed is not None else None,
            "trusted_scope_ids": self.options.get("trusted_scope_ids", []),
            "trusted_domains": self.options.get("trusted_domains", []),
            "limitations": ["CAI is eventually consistent; direct API reads are collected at their request time",
                "Audit absence never proves inactivity; disabled/denied Data Access logging limits activity evidence",
                "IAM policies and conditions are declared grants, not an effective-access decision",
                "Shared VPC references outside selected projects are not traversed"]}
        # Preserve exactly the user's selection; resolved scopes and ancestry are
        # separately explicit and every collection is individually scoped.
        snapshot_scopes = (self.scopes or ["*"]) if self.auto_scopes else self.requested_scopes
        return make_snapshot("gcp", snapshot_scopes, envelopes, metadata=sanitize(metadata))

    def collect(self):
        owned_transport = self.transport is None
        try:
            if not self.needed:
                return self.finish()
            if self.transport is None:
                credentials = Credentials(self.auth, timeout=bound(self.options, "timeout", 20, 1, 120))
                self.transport = Transport(credentials, self.options)
            self.discover()
            self.run_jobs([job for scope in self.scopes for job in self.scope_jobs(scope)])
            self.inherited()
            self.dependent_jobs()
            # Types lacking a service-level API at this scope are explicitly
            # unsupported, instead of silently looking like an empty collection.
            for scope in self.scopes:
                for kind in sorted(self.wanted):
                    if (kind, scope) not in self.collections:
                        self.add(kind, scope, kind, lambda: (_ for _ in ()).throw(
                            ReadError("unsupported", "inventory_not_supported_at_scope")))
            return self.finish()
        except ReadError as exc:
            for scope in self.scopes:
                for kind in sorted(self.wanted):
                    if (kind, scope) not in self.collections:
                        self.add(kind, scope, kind, lambda exc=exc: (_ for _ in ()).throw(exc))
            return self.finish()
        finally:
            if owned_transport and self.transport is not None:
                self.transport.close()


def collect(connector: dict, requirements: list[str] | None = None) -> dict:
    """Collect the selected native facts, sealed in the engine's snapshot schema."""
    return GCPCollector(connector, requirements).collect()


