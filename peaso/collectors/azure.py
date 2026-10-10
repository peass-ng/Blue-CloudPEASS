"""Native, bounded Azure metadata reads. Tokens never enter snapshot payloads."""
from __future__ import annotations

import base64
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener
from .base import Budget, _bound
from peaso.snapshot import make_snapshot

ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com"

# Preserve provider-native properties (including NotActions, conditions and NSG
# priorities) rather than approximating effective permission or reachability.
ENDPOINTS = {
    "vnet": ("Microsoft.Network/virtualNetworks", "2023-09-01"),
    "nsg": ("Microsoft.Network/networkSecurityGroups", "2023-09-01"),
    "nic": ("Microsoft.Network/networkInterfaces", "2023-09-01"),
    "route_table": ("Microsoft.Network/routeTables", "2023-09-01"),
    "public_ip": ("Microsoft.Network/publicIPAddresses", "2023-09-01"),
    "load_balancer": ("Microsoft.Network/loadBalancers", "2023-09-01"),
    "application_gateway": ("Microsoft.Network/applicationGateways", "2023-09-01"),
    "private_endpoint": ("Microsoft.Network/privateEndpoints", "2023-09-01"),
    "private_dns_zone": ("Microsoft.Network/privateDnsZones", "2020-06-01"),
    "dns_zone": ("Microsoft.Network/dnsZones", "2018-05-01"),
    "vm": ("Microsoft.Compute/virtualMachines", "2023-09-01"),
    "disk": ("Microsoft.Compute/disks", "2023-10-02"),
    "app_service": ("Microsoft.Web/sites", "2023-12-01"),
    "security_pricing": ("Microsoft.Security/pricings", "2024-01-01"),
    "storage_account": ("Microsoft.Storage/storageAccounts", "2023-05-01"),
    "sql_server": ("Microsoft.Sql/servers", "2023-08-01"),
    "aks_cluster": ("Microsoft.ContainerService/managedClusters", "2024-05-01"),
    "vault": ("Microsoft.KeyVault/vaults", "2023-07-01"),
    "resource_group": ("resourcegroups", "2021-04-01"),
}
AUTHORIZATION = {
    "role_assignment": "roleAssignments", "role_definition": "roleDefinitions",
    "deny_assignment": "denyAssignments",
}
DIRECTORY = {
    "directory_user": "users?$select=id,displayName,userPrincipalName,accountEnabled,userType",
    "directory_group": "groups?$select=id,displayName,securityEnabled,groupTypes",
    "directory_service_principal": "servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled",
    "directory_application": "applications?$select=id,appId,displayName,requiredResourceAccess",
    "directory_role_assignment": "roleManagement/directory/roleAssignments",
    "directory_role_definition": "roleManagement/directory/roleDefinitions",
    "directory_audit": "auditLogs/directoryAudits",
}
TYPES = tuple(ENDPOINTS) + tuple(AUTHORIZATION) + tuple(DIRECTORY) + (
    "subscription", "tenant", "management_group", "resource_graph", "activity_log",
    "subnet", "vnet_peering", "diagnostic_setting", "storage_service", "sql_database",
    "sql_firewall_rule", "sql_audit", "sql_security", "secret_metadata", "dns_record",
    "private_dns_link", "directory_membership",
    "app_service_config", "sql_tde",
)


class AzureReadError(RuntimeError):
    def __init__(self, code, status=None):
        super().__init__(code)
        self.code, self.status_code = code, status


def _claims(token):
    try:
        segment = token.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        return value if isinstance(value, dict) else {}
    except (ValueError, IndexError, TypeError):
        return {}


def credential_for(auth):
    """Build one explicitly selected SDK credential; never silently fall back."""
    from azure import identity
    method = auth.get("method", "auto")
    tenant = auth.get("tenant_id")
    client = auth.get("client_id")
    if method == "auto":
        if auth.get("client_secret"):
            method = "client-secret"
        elif auth.get("certificate_path") or auth.get("certificate_data") or auth.get("client_certificate"):
            method = "client-cert"
    if method == "client-secret":
        return identity.ClientSecretCredential(tenant, client, auth["client_secret"])
    if method in ("client-cert", "certificate"):
        inline = auth.get("certificate_data") or auth.get("client_certificate")
        certificate = {"certificate_data": inline.encode() if isinstance(inline, str) else inline} if inline else {"certificate_path": auth["certificate_path"]}
        return identity.CertificateCredential(tenant, client, **certificate, password=auth.get("certificate_password"))
    if method in ("az-cli", "azure-cli"):
        return identity.AzureCliCredential(**({"tenant_id": tenant} if tenant else {}), process_timeout=20)
    if method == "managed-identity":
        return identity.ManagedIdentityCredential(**({"client_id": client} if client else {}))
    if method == "workload-identity":
        if auth.get("federated_token"):
            assertion = auth["federated_token"]
            return identity.ClientAssertionCredential(tenant, client, lambda: assertion)
        return identity.WorkloadIdentityCredential(tenant_id=tenant, client_id=client, token_file_path=auth["token_file"])
    if method == "device-code":
        if not tenant or not client:
            raise ValueError("device-code requires tenant_id and client_id")
        return identity.DeviceCodeCredential(tenant_id=tenant, client_id=client, timeout=120)
    if method not in ("auto", "default"):
        raise ValueError("unsupported Azure authentication method")
    kwargs = {"exclude_interactive_browser_credential": True}
    if tenant:
        kwargs.update(shared_cache_tenant_id=tenant, interactive_browser_tenant_id=tenant,
                      workload_identity_tenant_id=tenant)
    if client:
        kwargs.update(managed_identity_client_id=client, workload_identity_client_id=client)
    return identity.DefaultAzureCredential(**kwargs)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AzureReadError("redirect_rejected")


class AzureTransport:
    """Audience-separated refreshed tokens and origin-checked HTTPS requests."""
    def __init__(self, auth, credential=None):
        self.auth = auth
        self.credential = credential
        self.owned = credential is None
        self.direct = auth.get("method", "auto") in ("auto", "token", "arm-token") and bool(auth.get("arm_token") or auth.get("token"))
        if self.credential is None and not self.direct:
            self.credential = credential_for(auth)
        self.tokens = {}
        self.lock = threading.Lock()
        self.tenant = auth.get("tenant_id")

    def token(self, audience):
        direct = (self.auth.get("arm_token") or self.auth.get("token")) if self.direct and audience == ARM else self.auth.get("graph_token") if audience == GRAPH else None
        with self.lock:
            if direct:
                token = direct
            else:
                if self.credential is None:
                    raise AzureReadError("audience_token_unavailable", 401)
                cached = self.tokens.get(audience)
                if cached is None or cached.expires_on < time.time() + 60:
                    cached = self.credential.get_token(audience + "/.default")
                    self.tokens[audience] = cached
                token = cached.token
            claims = _claims(token)
            tenant = claims.get("tid")
            if self.tenant and tenant and self.tenant.lower() != tenant.lower():
                raise AzureReadError("tenant_mismatch", 401)
            if tenant and not self.tenant:
                self.tenant = tenant
            expected = audience
            actual = claims.get("aud")
            aliases = {ARM: {ARM, ARM + "/", "https://management.core.windows.net/"},
                       GRAPH: {GRAPH, GRAPH + "/", "00000003-0000-0000-c000-000000000000"}}
            if actual and actual not in aliases.get(expected, {expected, expected + "/"}):
                raise AzureReadError("token_audience_mismatch", 401)
            return token

    def request(self, url, *, body=None, audience=ARM):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != urlsplit(audience).netloc or parsed.username or parsed.fragment:
            raise AzureReadError("untrusted_continuation")
        token = self.token(audience)
        payload = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=payload, headers=headers, method="POST" if body is not None else "GET")
        with build_opener(_NoRedirect()).open(request, timeout=20) as response:
            return json.load(response)

    def close(self):
        if self.owned and self.credential is not None:
            self.credential.close()


def _safe_error(exc):
    """Never expose SDK exception bodies, URLs, credentials or response text."""
    code = _status_code(exc)
    if not isinstance(code, (str, int)):
        code = None
    if code in (401, 403, "401", "403") or type(exc).__name__ == "ClientAuthenticationError":
        status = "denied"
    elif code in (408, 504, "408", "504") or isinstance(exc, TimeoutError):
        status = "timeout"
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        status = "malformed"
    else:
        status = "unknown"
    safe_code = str(code) if code and re.fullmatch(r"[A-Za-z0-9_.-]{1,79}", str(code)) else "read_failed"
    return status, {"kind": type(exc).__name__, "code": safe_code}


def _status_code(exc):
    for candidate in (exc, getattr(exc, "__cause__", None)):
        code = getattr(candidate, "status_code", None) or getattr(candidate, "status", None) or getattr(candidate, "code", None)
        if code is not None:
            return code
    return None


def _metadata_only(value, secret=False):
    if isinstance(value, list):
        return [_metadata_only(item, secret) for item in value]
    if not isinstance(value, dict):
        return value
    return {key: _metadata_only(item, secret) for key, item in value.items() if not (secret and key.lower() == "value") and key.lower() not in (
        "password", "adminpassword", "clientsecret", "accesstoken", "token",
        "connectionstring", "primarykey", "secondarykey", "privatekey", "customdata",
        "userdata", "protectedsettings", "protectedsettingsfromkeyvault", "appsettings",
        "machinekey", "decryptionkey", "validationkey", "sourceuri", "accesssas")}


class _Reader:
    """Shared native read scheduler; budgets include retry attempts."""
    def __init__(self, options):
        self.budget = Budget(options)
        self.workers = _bound(options.get("concurrency", 4), "concurrency", 1, 16)
        self.retries = _bound(options.get("retries", 2), "retries", 0, 5)
        self.page_size = _bound(options.get("page_size", 200), "page_size", 1, 1000)
        self.lock = threading.Lock()
        self.collections = []
        self.total = 0

    def call(self, operation, *args, **kwargs):
        for attempt in range(self.retries + 1):
            with self.lock:
                if self.budget.calls >= self.budget.max_calls:
                    raise AzureReadError("call_limit")
                self.budget.calls += 1
            try:
                return operation(*args, **kwargs)
            except Exception as exc:
                code = _status_code(exc)
                if code not in (429, 500, 502, 503, 504, "429", "500", "502", "503", "504") or attempt == self.retries:
                    raise
                time.sleep(min(0.2 * 2**attempt, 2))

    def pages(self, request, url, *, audience=ARM, key="value", next_key="nextLink", body=None):
        origin = urlsplit(url)
        seen = set()
        for _ in range(self.budget.max_pages):
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.netloc != origin.netloc or parsed.path != origin.path or parsed.fragment or parsed.username:
                raise AzureReadError("untrusted_continuation")
            response = self.call(request, url, body=body, audience=audience)
            if not isinstance(response, dict) or not isinstance(response.get(key), list):
                raise ValueError("malformed list")
            yield response[key]
            token = response.get(next_key)
            if not token:
                if body is not None and response.get("resultTruncated") in (True, "true"):
                    raise AzureReadError("graph_truncated")
                return
            if not isinstance(token, str) or token in seen:
                raise ValueError("malformed continuation")
            seen.add(token)
            if body is not None:
                body = {**body, "options": {**body.get("options", {}), "$skipToken": token}}
            else:
                url = token
        raise AzureReadError("page_limit")

    def _read(self, job):
        kind, scope, service, fetch = job
        items = {}
        status, error = "collected", None
        try:
            for page in fetch():
                if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                    raise ValueError("malformed page")
                for item in page:
                    identifier = item.get("id")
                    if not isinstance(identifier, str) or not identifier:
                        raise ValueError("missing authoritative resource identity")
                    scoped_types = set(ENDPOINTS) | {"resource_graph", "subnet", "vnet_peering", "diagnostic_setting", "storage_service", "sql_database", "sql_firewall_rule", "sql_audit", "sql_security", "secret_metadata", "dns_record", "private_dns_link", "app_service_config", "sql_tde"}
                    if service != "kubernetes" and kind in scoped_types and scope.startswith("/subscriptions/") and not (identifier.lower() == scope.lower() or identifier.lower().startswith(scope.lower() + "/")):
                        raise ValueError("resource outside selected ARM scope")
                    normalized = identifier.lower() if service != "kubernetes" else identifier
                    if normalized not in items and len(items) >= self.budget.max_items:
                        raise AzureReadError("resource_limit")
                    items.setdefault(normalized, item if service == "kubernetes" else _metadata_only(item, kind == "secret_metadata" or str(item.get("type", "")).lower().endswith("/secrets")))
        except Exception as exc:
            status, error = _safe_error(exc)
            if items or getattr(exc, "code", "") in ("resource_limit", "page_limit", "call_limit", "graph_truncated"):
                status = "partial"
        if status == "collected" and not items:
            status = "empty"
        result = {"type": kind, "scope": scope, "service": service, "status": status, "items": list(items.values())}
        if error:
            result["error"] = error
        return result

    def run(self, jobs):
        # Results are reduced in request order for deterministic total resource caps.
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            results = pool.map(self._read, jobs)
            for result in results:
                capacity = max(0, self.budget.max_items - self.total)
                if len(result["items"]) > capacity:
                    result["items"] = result["items"][:capacity]
                    result.update(status="partial", error={"code": "resource_limit"})
                self.total += len(result["items"])
                self.collections.append(result)

    def unavailable(self, kind, scope, service, exc):
        status, error = _safe_error(exc)
        self.collections.append({"type": kind, "scope": scope, "service": service, "status": status, "items": [], "error": error})

    def metadata(self):
        return {"collection": "read-only", "calls": self.budget.calls, "max_calls": self.budget.max_calls,
                "max_pages": self.budget.max_pages, "max_resources": self.budget.max_items,
                "concurrency": self.workers, "retries": self.retries}


def _selected(options, requirements):
    wanted = options.get("inventories", list(TYPES)) if requirements is None else requirements
    if not isinstance(wanted, (list, tuple)) or any(kind not in TYPES for kind in wanted):
        raise ValueError("unsupported Azure inventory requirement")
    selected = set(wanted)
    if "directory_membership" in selected:
        selected.add("directory_group")
    if "sql_tde" in selected:
        selected.add("sql_database")
    return selected


def _subscription(scope):
    value = scope.removeprefix("/subscriptions/").strip("/")
    if not value or "/" in value or not all(c.isalnum() or c in "-_." for c in value):
        raise ValueError("invalid subscription scope")
    return "/subscriptions/" + value


def _trusted_scopes(options):
    values = options.get("trusted_scope_ids", [])
    if not isinstance(values, list) or len(values) > 100 or any(not isinstance(value, str) or not value or len(value) > 2048 for value in values):
        raise ValueError("trusted_scope_ids must be an explicit bounded string list")
    return list(dict.fromkeys(values))


def collect(connector, requirements=None, *, transport=None):
    """Return native facts with separate directory, inheritance and usage coverage."""
    options, auth = connector.get("options", {}), connector.get("auth", {})
    wanted = _selected(options, requirements)
    trusted_scopes = _trusted_scopes(options)
    reader = _Reader(options)
    raw_scopes = connector.get("scopes") or ["*"]
    if not isinstance(raw_scopes, list) or len(raw_scopes) > 100 or any(not isinstance(x, str) for x in raw_scopes):
        raise ValueError("scopes must contain at most 100 subscription IDs")
    scopes = list(dict.fromkeys(_subscription(x) for x in raw_scopes if x != "*"))
    discover_all = "*" in raw_scopes
    owned = transport is None
    tenant_scope = "/tenants/" + (auth.get("tenant_id") or "selected")
    now = datetime.now(timezone.utc)
    days = _bound(options.get("activity_days", 30), "activity_days", 1, 90)
    start, end = (now - timedelta(days=days)).isoformat(), now.isoformat()
    try:
        if options.get("hosted"):
            if any(auth.get(key) for key in ("certificate_path", "token_file")):
                raise ValueError("hosted Azure credentials require inline material")
            if not (auth.get("arm_token") or auth.get("token") or auth.get("client_secret") or auth.get("certificate_data") or auth.get("client_certificate") or auth.get("federated_token")):
                raise ValueError("hosted Azure requires tenant-provided explicit credentials")
        if owned:
            transport = AzureTransport(auth)
        request = transport.request
        jobs = []
        if discover_all or "subscription" in wanted:
            reader.run([("subscription", tenant_scope, "Microsoft.Resources", lambda: reader.pages(request, ARM + "/subscriptions?api-version=2022-12-01"))])
            if discover_all:
                scopes = [item["id"] for item in reader.collections[-1]["items"] if isinstance(item.get("subscriptionId"), str)]
                if len(scopes) > 100:
                    scopes = scopes[:100]
                    reader.collections[-1].update(status="partial", error={"code": "scope_limit"})
        if "tenant" in wanted:
            jobs.append(("tenant", tenant_scope, "Microsoft.Resources", lambda: reader.pages(request, ARM + "/tenants?api-version=2022-12-01")))
        if "management_group" in wanted or wanted.intersection(AUTHORIZATION):
            def management_groups():
                incomplete = None
                for page in reader.pages(request, ARM + "/providers/Microsoft.Management/managementGroups?api-version=2020-05-01"):
                    for item in page:
                        try:
                            rid = item["id"]
                            if not rid.startswith("/providers/Microsoft.Management/managementGroups/"):
                                raise ValueError("malformed management group ID")
                            detail = reader.call(request, ARM + rid + "?api-version=2020-05-01&$expand=children&$recurse=true")
                            if not isinstance(detail, dict) or detail.get("id") != rid:
                                raise ValueError("malformed management group detail")
                            yield [detail]
                        except Exception as exc:
                            incomplete = exc
                            yield [{**item, "detail": {"collection_status": _safe_error(exc)[0], "error": _safe_error(exc)[1]}}]
                if incomplete:
                    raise incomplete
            jobs.append(("management_group", tenant_scope, "Microsoft.Management", management_groups))
        # Query each selected subscription before detail reads. The discovery
        # collection is retained even when only downstream inventories are wanted.
        need_resources = wanted.intersection(set(ENDPOINTS) | {"diagnostic_setting", "subnet", "vnet_peering", "secret_metadata", "storage_service", "sql_database", "sql_firewall_rule", "sql_audit", "sql_security", "dns_record", "private_dns_link", "resource_graph", "app_service_config", "sql_tde"})
        if need_resources:
            for scope in scopes:
                body = {"subscriptions": [scope.rsplit("/", 1)[-1]], "query": "Resources | project id, type, name, location, properties, subscriptionId, resourceGroup | order by id asc", "options": {"resultFormat": "objectArray", "$top": reader.page_size}}
                def discovery(body=body, scope=scope):
                    for page in reader.pages(request, ARM + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01", body=body, key="data", next_key="$skipToken"):
                        if any(not isinstance(item, dict) or not str(item.get("id", "")).lower().startswith(scope.lower() + "/") for item in page):
                            raise ValueError("Resource Graph returned another scope")
                        yield page
                jobs.append(("resource_graph", scope, "Microsoft.ResourceGraph", discovery))
        reader.run(jobs)
        jobs = []
        groups = [item["id"] for c in reader.collections if c["type"] == "management_group" for item in c["items"]]
        for scope in list(dict.fromkeys(scopes + groups + (["/"] if wanted.intersection(AUTHORIZATION) else []))):
            for kind, endpoint in AUTHORIZATION.items():
                if kind in wanted:
                    url = ARM + scope.rstrip("/") + "/providers/Microsoft.Authorization/" + endpoint + "?api-version=2022-04-01"
                    if scope == "/" and kind == "role_assignment":
                        url += "&" + urlencode({"$filter": "atScope()"})
                    jobs.append((kind, scope, "Microsoft.Authorization", lambda url=url: reader.pages(request, url)))
        # Discovery supplies IDs; ARM GET provides authoritative current details.
        child_dependencies = {"subnet": "vnet", "vnet_peering": "vnet", "storage_service": "storage_account", "sql_database": "sql_server", "sql_firewall_rule": "sql_server", "sql_audit": "sql_server", "sql_security": "sql_server", "secret_metadata": "vault", "dns_record": "dns_zone", "private_dns_link": "private_dns_zone", "app_service_config": "app_service", "sql_tde": "sql_server"}
        parents = wanted.intersection(ENDPOINTS) | {parent for child, parent in child_dependencies.items() if child in wanted}
        if "diagnostic_setting" in wanted:
            parents |= set(ENDPOINTS) - {"resource_group"}
        for scope in scopes:
            for kind in sorted(parents):
                endpoint, version = ENDPOINTS[kind]
                url = ARM + scope + ("/" if kind == "resource_group" else "/providers/") + endpoint + "?api-version=" + version
                def detail(url=url, version=version, scope=scope):
                    incomplete = None
                    # ARG is eventually consistent. Only an authoritative ARM
                    # list can establish membership or an empty inventory.
                    for page in reader.pages(request, url):
                        detailed = []
                        for item in page:
                            rid = item.get("id") if isinstance(item, dict) else None
                            if not isinstance(rid, str) or not rid.lower().startswith(scope.lower() + "/"):
                                raise ValueError("resource outside selected subscription")
                            if isinstance(item.get("properties"), dict):
                                detailed.append(item)
                                continue
                            try:
                                result = reader.call(request, ARM + rid + "?api-version=" + version)
                                if not isinstance(result, dict) or str(result.get("id", "")).lower() != rid.lower():
                                    raise ValueError("malformed resource detail")
                                detailed.append(result)
                            except Exception as exc:
                                incomplete = exc
                                detailed.append({"id": rid, "type": item.get("type"), "name": item.get("name"), "detail": {"collection_status": _safe_error(exc)[0], "error": _safe_error(exc)[1]}})
                        yield detailed
                    if incomplete:
                        raise incomplete
                jobs.append((kind, scope, endpoint.split("/")[0], detail))
            if "activity_log" in wanted:
                url = ARM + scope + "/providers/Microsoft.Insights/eventtypes/management/values?" + urlencode({"api-version": "2015-04-01", "$filter": f"eventTimestamp ge '{start}' and eventTimestamp le '{end}'"})
                def activities(url=url):
                    for page in reader.pages(request, url):
                        for item in page:
                            if isinstance(item, dict) and not item.get("id") and item.get("eventDataId"):
                                item["id"] = "azure-activity://" + quote(scope, safe="") + "/" + quote(item["eventDataId"], safe="")
                        yield page
                jobs.append(("activity_log", scope, "Microsoft.Insights", activities))
        reader.run(jobs)
        jobs = []
        for collection in list(reader.collections):
            for item in collection["items"]:
                rid = item["id"]
                kind = collection["type"]
                if kind in parents and "diagnostic_setting" in wanted and kind != "resource_group":
                    url = ARM + rid + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
                    jobs.append(("diagnostic_setting", rid, "Microsoft.Insights", lambda url=url: reader.pages(request, url)))
                if kind == "vnet":
                    for child, field in (("subnet", "subnets"), ("vnet_peering", "virtualNetworkPeerings")):
                        if child in wanted:
                            def embedded(item=item, field=field):
                                value = item.get("properties", {}).get(field)
                                if not isinstance(value, list):
                                    raise ValueError("missing child detail")
                                yield value
                            jobs.append((child, rid, "Microsoft.Network", embedded))
                child_paths = []
                if kind == "storage_account" and "storage_service" in wanted:
                    for service in ("blobServices", "fileServices", "queueServices", "tableServices"):
                        child_paths.append(("storage_service", service, "2023-05-01"))
                if kind == "sql_server":
                    child_paths.extend((child, path, "2023-08-01") for child, path in (("sql_database", "databases"), ("sql_firewall_rule", "firewallRules"), ("sql_audit", "auditingSettings"), ("sql_security", "securityAlertPolicies")) if child in wanted)
                if kind == "vault" and "secret_metadata" in wanted:
                    child_paths.append(("secret_metadata", "secrets", "2023-07-01"))
                if kind == "dns_zone" and "dns_record" in wanted:
                    child_paths.append(("dns_record", "all", "2018-05-01"))
                if kind == "private_dns_zone" and "private_dns_link" in wanted:
                    child_paths.append(("private_dns_link", "virtualNetworkLinks", "2020-06-01"))
                if kind == "app_service" and "app_service_config" in wanted:
                    url = ARM + rid + "/config/web?api-version=2023-12-01"
                    def app_config(url=url, rid=rid):
                        detail = reader.call(request, url)
                        if not isinstance(detail, dict) or not str(detail.get("id", "")).lower().startswith(rid.lower() + "/"):
                            raise ValueError("malformed App Service configuration")
                        props = detail.get("properties")
                        if not isinstance(props, dict):
                            raise ValueError("malformed App Service configuration properties")
                        safe_fields = {"minTlsVersion", "scmMinTlsVersion", "ftpsState", "http20Enabled", "remoteDebuggingEnabled", "httpLoggingEnabled", "detailedErrorLoggingEnabled", "requestTracingEnabled", "cors", "ipSecurityRestrictions", "ipSecurityRestrictionsDefaultAction", "scmIpSecurityRestrictions", "scmIpSecurityRestrictionsDefaultAction", "vnetRouteAllEnabled", "alwaysOn"}
                        yield [{**{k: v for k, v in detail.items() if k in ("id", "name", "type", "location")}, "properties": {k: v for k, v in props.items() if k in safe_fields}, "parent_id": rid}]
                    jobs.append(("app_service_config", rid, "Microsoft.Web", app_config))
                for child, path, version in child_paths:
                    url = ARM + rid + "/" + path + "?api-version=" + version
                    # One storage collection per account, not duplicate service scopes.
                    child_scope = rid + "/" + path if child == "storage_service" else rid
                    jobs.append((child, child_scope, ENDPOINTS[kind][0].split("/")[0], lambda url=url: reader.pages(request, url)))
        reader.run(jobs)
        jobs = []
        if "sql_tde" in wanted:
            for c in reader.collections:
                if c["type"] != "sql_database":
                    continue
                for database in c["items"]:
                    rid = database["id"]
                    if rid.rsplit("/", 1)[-1].lower() == "master":
                        continue
                    url = ARM + rid + "/transparentDataEncryption/current?api-version=2023-08-01"
                    def tde(url=url, rid=rid):
                        detail = reader.call(request, url)
                        if not isinstance(detail, dict) or str(detail.get("id", "")).lower() not in (rid.lower(), (rid + "/transparentDataEncryption/current").lower()):
                            raise ValueError("malformed SQL TDE metadata")
                        yield [{**detail, "parent_id": rid}]
                    jobs.append(("sql_tde", rid, "Microsoft.Sql", tde))
            reader.run(jobs)
            jobs = []
        for kind, endpoint in DIRECTORY.items():
            if kind in wanted:
                url = GRAPH + "/v1.0/" + endpoint
                if kind == "directory_audit":
                    url += "?" + urlencode({"$filter": f"activityDateTime ge {start} and activityDateTime le {end}"})
                jobs.append((kind, tenant_scope, "Microsoft.Graph", lambda url=url: reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink")))
        reader.run(jobs)
        if "directory_membership" in wanted:
            jobs = []
            for c in reader.collections:
                if c["type"] == "directory_group":
                    for group in c["items"]:
                        url = GRAPH + "/v1.0/groups/" + quote(group["id"], safe="") + "/members?$select=id"
                        jobs.append(("directory_membership", tenant_scope + "/groups/" + group["id"], "Microsoft.Graph", lambda url=url: reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink")))
            reader.run(jobs)
    except Exception as exc:
        existing = {(c["type"], c["scope"]) for c in reader.collections}
        for scope in scopes or [tenant_scope]:
            for kind in sorted(wanted):
                if (kind, scope) not in existing:
                    reader.unavailable(kind, scope, "azure", exc)
    finally:
        if owned and transport is not None:
            transport.close()
    metadata = reader.metadata()
    directory = [c for c in reader.collections if c["service"] == "Microsoft.Graph"]
    metadata.update(tenant_id=getattr(transport, "tenant", None) or auth.get("tenant_id"),
                    trusted_scope_ids=trusted_scopes,
                    directory_coverage={"status": "not_collected" if not directory else "complete" if all(c["status"] in ("collected", "empty") for c in directory) else "incomplete", "types": {c["type"]: c["status"] for c in directory}},
                    authorization_semantics={"effective_access": "not_computed", "control_data_separation": True, "not_actions_are_exclusions": True, "conditions_preserved": True, "management_group_visibility": "accessible_only"},
                    activity_window={"start": start, "end": end, "retention": "unknown", "complete": False, "reason": "provider retention and directory/data-plane events are not verified"},
                    omitted_inventories=sorted(set(TYPES) - wanted))
    return make_snapshot("azure", scopes, reader.collections, metadata=metadata)
