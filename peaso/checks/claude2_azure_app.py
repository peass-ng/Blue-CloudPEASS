"""claude2_azure APP group: App Service web/API/function apps, plans, environments, slots and Application Insights.

Applicability mirrors the upstream table selection:
* Steampipe ``azure_app_service_web_app`` = sites whose ``kind`` has no ``functionapp`` element;
  ``azure_app_service_function_app`` = sites with a ``functionapp`` element.
* Element classes come from the comma-split ``kind``: api = element ending in ``api``; web = element starting
  with ``app``; function = element starting with ``functionapp``; linux = element equal to ``linux``.
* Prowler ``apps`` = ``kind`` string starting with ``app``; Prowler ``functions`` = ``kind`` starting with ``functionapp``.
Sites outside a predicate's selection are NOT_APPLICABLE. Site configuration is read from the embedded
``configuration`` (GET sites/config/web) and authentication from ``authSettingsV2``; both stay UNKNOWN when absent.
"""
from __future__ import annotations
from .claude2_azure_common import *  # noqa: F401,F403
from .claude2_azure_common import CHECK_IDS

_START = len(CHECK_IDS)

SITE = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/app1"
OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
USER_ACCESS_ADMINISTRATOR = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
RBAC_ADMINISTRATOR = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
ADMIN_ROLES = {OWNER, CONTRIBUTOR, USER_ACCESS_ADMINISTRATOR, RBAC_ADMINISTRATOR}
IDENTITY_TYPES = ("None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned")
FTPS_STATES = ("AllAllowed", "FtpsOnly", "Disabled")
TLS_VERSIONS = ("1.0", "1.1", "1.2", "1.3")


# --- Selection ------------------------------------------------------------------------------------------

def _kind(item):
    return get(item, "kind", str)


def _elements(item):
    return [part.strip().lower() for part in _kind(item).split(",")]


def _function_table(item):
    return any("functionapp" in part for part in _elements(item))


ELEMENT = {
    "api": lambda parts: any(p.endswith("api") for p in parts),
    "web": lambda parts: any(p.startswith("app") for p in parts),
    "function": lambda parts: any(p.startswith("functionapp") for p in parts),
    "linux_function": lambda parts: any(p.startswith("functionapp") for p in parts) and "linux" in parts,
    "exact_api": None,
    "not_exact_api": None,
}


def _applies(item, table, element, prowler):
    """None when the site is in scope, else a NOT_APPLICABLE reason."""
    if prowler == "app":
        return None if _kind(item).startswith("app") else "Prowler app checks select sites whose kind starts with 'app'"
    if prowler == "function":
        return None if _kind(item).startswith("functionapp") else "Prowler function checks select sites whose kind starts with 'functionapp'"
    function = _function_table(item)
    if table == "web" and function:
        return "Upstream web-app table excludes function apps"
    if table == "function" and not function:
        return "Upstream function-app table selects function apps only"
    if element == "exact_api":
        return None if _kind(item) == "api" else "Upstream selects sites whose kind is exactly 'api'"
    if element == "not_exact_api":
        return "Upstream skips sites whose kind is exactly 'api'" if _kind(item) == "api" else None
    if element is not None and not ELEMENT[element](_elements(item)):
        return "Site kind is outside the upstream selection (" + element + ")"
    return None


def _site(kind="app", properties=None, configuration=None, identity=False, auth=None, diagnostics=None):
    data = {"id": SITE, "name": "app1", "kind": kind, "properties": dict(properties or {})}
    if configuration is not None:
        data["configuration"] = {"properties": dict(configuration)}
    if identity is not False:
        data["identity"] = identity
    if auth is not None:
        data["authSettingsV2"] = {"properties": auth}
    if diagnostics is not None:
        data["diagnosticSettings"] = diagnostics
    return data


def app_rule(slug, title, predicate, passing, failing, *, table=None, element=None, prowler=None, severity="medium",
             control="CM-6", remediation=None, dependencies=None, category="hardening", extra_cases=None):
    @claude2(slug, "app_service", title, severity=severity, control=control, remediation=remediation, category=category,
             dependencies=dependencies or ["app_service"])
    def evaluate(item, index):
        reason = _applies(item, table, element, prowler)
        if reason:
            return na(reason, kind=item["kind"])
        return predicate(item, index)
    evaluate.__name__ = "claude2_" + slug
    CASES[cid(slug)] = {"pass": passing, "fail": failing, "missing": {}, **(extra_cases or {})}
    return evaluate


# --- Shared readers --------------------------------------------------------------------------------------

def _config(item):
    return get(item, "configuration.properties", dict)


def _cfg(item, key, expected=None):
    return get(_config(item), key, expected)


def _identity_type(item):
    """'None' when no managed identity; ARM omits ``identity`` when unset (proved by a returned properties object)."""
    if "identity" not in item:
        get(item, "properties", dict)
        return "None"
    identity = get(item, "identity")
    if identity is None:
        return "None"
    if not isinstance(identity, dict):
        raise Unavailable("malformed site identity")
    return enum(identity, "type", IDENTITY_TYPES)


def _identity_result(item, index):
    kind = _identity_type(item)
    return result(kind == "None", identity_type=kind)


def _auth_enabled(item):
    props = get(item, "authSettingsV2.properties", dict)
    platform = optional(props, "platform", {}, dict)
    return optional(platform, "enabled", False, bool)


def _auth_result(item, index):
    enabled = _auth_enabled(item)
    return result(not enabled, authentication_enabled=enabled, semantics="App Service Authentication (Easy Auth) platform switch")


def _bool_site(path):
    def predicate(item, index):
        value = get(item, path, bool)
        return result(not value, field=path, configured=value)
    return predicate


def _ftps_all_allowed(item, index):
    state = enum(_config(item), "ftpsState", FTPS_STATES)
    return result(state == "AllAllowed", ftps_state=state)


def _cors_star(item, index):
    cors = _cfg(item, "cors")
    if cors is None:
        return result(False, cors="not configured")
    if not isinstance(cors, dict):
        raise Unavailable("malformed CORS settings")
    origins = optional(cors, "allowedOrigins", None)
    if origins is None:
        return result(False, allowed_origins=None)
    if not isinstance(origins, list) or any(not isinstance(o, str) for o in origins):
        raise Unavailable("malformed CORS allowedOrigins")
    return result("*" in origins, allowed_origins=origins)


def _tls_below_12(item, index):
    version = _cfg(item, "minTlsVersion", str)
    if version not in TLS_VERSIONS:
        return unknown("unrecognized minimum TLS version", configured=version)
    return result(version < "1.2", min_tls_version=version)


def _remote_debugging_off(item, index):
    enabled = _cfg(item, "remoteDebuggingEnabled", bool)
    return result(enabled, remote_debugging_enabled=enabled)


SITE_CERT = {"clientCertEnabled": True}
NO_CERT = {"clientCertEnabled": False}


# --- API apps ---------------------------------------------------------------------------------------------

app_rule("api_app_client_certificates", "App Service API app requires incoming client certificates", _bool_site("properties.clientCertEnabled"),
         _site("api", SITE_CERT), _site("api", NO_CERT), table="web", element="api", control="IA-2",
         remediation="Enable incoming client certificates (clientCertEnabled) on the API app.", extra_cases={"na": _site("app", NO_CERT)})
app_rule("api_app_cors_no_wildcard", "App Service API app CORS does not allow every origin", _cors_star,
         _site("api", configuration={"cors": {"allowedOrigins": ["https://contoso.com"]}}),
         _site("api", configuration={"cors": {"allowedOrigins": ["*"]}}), table="web", element="api", control="AC-4",
         remediation="Replace the '*' CORS origin with the specific client origins.")
app_rule("api_app_ftps_required", "App Service API app does not allow plain FTP", _ftps_all_allowed,
         _site("api", configuration={"ftpsState": "FtpsOnly"}), _site("api", configuration={"ftpsState": "AllAllowed"}),
         table="web", element="api", control="SC-8", remediation="Set FTP state to FtpsOnly or Disabled.")
app_rule("api_app_min_tls_12", "App Service API app minimum TLS version is 1.2 or later", _tls_below_12,
         _site("api", configuration={"minTlsVersion": "1.2"}), _site("api", configuration={"minTlsVersion": "1.0"}),
         table="web", element="api", severity="high", control="SC-8", remediation="Set the minimum inbound TLS version to 1.2 or 1.3.")
app_rule("api_app_remote_debugging_disabled", "App Service API app (kind 'api') has remote debugging disabled", _remote_debugging_off,
         _site("api", configuration={"remoteDebuggingEnabled": False}), _site("api", configuration={"remoteDebuggingEnabled": True}),
         table="web", element="exact_api", control="CM-7", remediation="Turn off remote debugging on the API app.",
         extra_cases={"na": _site("api,linux", configuration={"remoteDebuggingEnabled": True})})
app_rule("api_app_https_only", "App Service API app redirects HTTP to HTTPS", _bool_site("properties.httpsOnly"),
         _site("api", {"httpsOnly": True}), _site("api", {"httpsOnly": False}), table="web", element="api", control="SC-8",
         remediation="Enable HTTPS Only on the API app.")
app_rule("api_app_managed_identity", "App Service API app uses a managed identity", _identity_result,
         _site("api", identity={"type": "SystemAssigned"}), _site("api", identity={"type": "None"}), table="web", element="api",
         control="IA-2", remediation="Assign a system- or user-assigned managed identity to the API app.")

# --- Web apps ---------------------------------------------------------------------------------------------

app_rule("web_app_remote_debugging_disabled", "App Service web app has remote debugging disabled (kind 'api' skipped)", _remote_debugging_off,
         _site("app", configuration={"remoteDebuggingEnabled": False}), _site("app", configuration={"remoteDebuggingEnabled": True}),
         table="web", element="not_exact_api", control="CM-7", remediation="Turn off remote debugging on the web app.",
         extra_cases={"na": _site("api", configuration={"remoteDebuggingEnabled": True})})
app_rule("web_app_client_certificates", "App Service web app (kind app*) requires incoming client certificates",
         _bool_site("properties.clientCertEnabled"), _site("app", SITE_CERT), _site("app", NO_CERT), table="web", element="web",
         control="IA-2", remediation="Enable incoming client certificates on the web app.", extra_cases={"na": _site("api", NO_CERT)})
app_rule("web_app_incoming_client_cert", "App Service web app has incoming client certificates enabled",
         _bool_site("properties.clientCertEnabled"), _site("api", SITE_CERT), _site("app", NO_CERT), table="web", control="IA-2",
         remediation="Enable incoming client certificates on the web app.", extra_cases={"na": _site("functionapp", NO_CERT)})
app_rule("web_app_ftps_required", "App Service web app (kind app*) does not allow plain FTP", _ftps_all_allowed,
         _site("app", configuration={"ftpsState": "Disabled"}), _site("app,linux", configuration={"ftpsState": "AllAllowed"}),
         table="web", element="web", control="SC-8", remediation="Set FTP state to FtpsOnly or Disabled.")
app_rule("web_app_managed_identity", "App Service web app (kind app*) uses a managed identity", _identity_result,
         _site("app", identity={"type": "UserAssigned"}), _site("app"), table="web", element="web", control="IA-2",
         remediation="Assign a system- or user-assigned managed identity to the web app.")
app_rule("web_app_register_with_entra", "App Service web app configures a managed identity for outbound authentication", _identity_result,
         _site("app", identity={"type": "SystemAssigned"}), _site("app", identity={"type": "None"}), table="web", control="IA-2",
         remediation="Turn on a managed identity for the web app so it authenticates to Azure resources without secrets.")
app_rule("web_app_authentication_enabled", "App Service web app has App Service Authentication enabled", _auth_result,
         _site("app", auth={"platform": {"enabled": True}}), _site("app", auth={"platform": {"enabled": False}}), table="web",
         control="IA-2", remediation="Enable App Service Authentication with an identity provider and require authentication.")


def _always_on(item, index):
    value = _cfg(item, "alwaysOn", bool)
    return result(not value, always_on=value)


app_rule("web_app_always_on", "App Service web app has Always On enabled", _always_on,
         _site("app", configuration={"alwaysOn": True}), _site("app", configuration={"alwaysOn": False}), table="web",
         severity="low", control="CP-10", remediation="Enable Always On so the app is not unloaded when idle.")


def _diagnostic_logs(item, index):
    windows = _windows_iis_site(item)
    if windows is False:
        return na("Detailed errors, IIS web-server logs and failed-request tracing are Windows-only; Linux application and Azure Monitor logs are separate")
    if windows is None:
        return unknown("App Service operating system is not established for Windows-only diagnostic settings")
    config = _config(item)
    flags = {key: get(config, key, bool) for key in ("detailedErrorLoggingEnabled", "httpLoggingEnabled", "requestTracingEnabled")}
    return result(not all(flags.values()), **flags, scope="Windows IIS diagnostic settings only")


def _windows_iis_site(item):
    parts = _elements(item)
    reserved = get(item, "properties", dict).get("reserved")
    if reserved is not None and type(reserved) is not bool:
        raise Unavailable("malformed App Service reserved operating-system fact")
    linux, windows = "linux" in parts, "windows" in parts
    if (linux and windows) or (linux and reserved is False) or (windows and reserved is True):
        raise Unavailable("conflicting App Service operating-system facts")
    if linux or reserved is True:
        return False
    if windows or reserved is False:
        return True
    return None


app_rule("web_app_diagnostic_logs_enabled", "Windows App Service web app enables IIS detailed error, HTTP and failed-request logging",
         _diagnostic_logs,
         _site("app", {"reserved": False}, configuration={"detailedErrorLoggingEnabled": True, "httpLoggingEnabled": True, "requestTracingEnabled": True}),
         _site("app", {"reserved": False}, configuration={"detailedErrorLoggingEnabled": True, "httpLoggingEnabled": False, "requestTracingEnabled": True}),
         table="web", control="AU-12", remediation="For a confirmed Windows app, review and enable the required IIS detailed error, web-server and failed-request logs. Use application/Azure Monitor logging controls for Linux apps.",
         extra_cases={"na": _site("app,linux", {"reserved": True})})


def _failed_request_tracing(item, index):
    windows = _windows_iis_site(item)
    if windows is False:
        return na("IIS failed-request tracing is Windows-only; Linux application and Azure Monitor logs are separate")
    if windows is None:
        return unknown("App Service operating system is not established for IIS failed-request tracing")
    value = get(item, "logsConfiguration.properties.failedRequestsTracing.enabled", bool)
    return result(not value, failed_requests_tracing=value, scope="Windows IIS failed-request tracing only")


app_rule("web_app_failed_request_tracing", "Windows App Service web app enables IIS failed-request tracing", _failed_request_tracing,
         _site("app", {"reserved": False}) | {"logsConfiguration": {"properties": {"failedRequestsTracing": {"enabled": True}}}},
         _site("app", {"reserved": False}) | {"logsConfiguration": {"properties": {"failedRequestsTracing": {"enabled": False}}}}, table="web",
         control="AU-12", remediation="For a confirmed Windows app, review and enable IIS failed-request tracing in App Service logs (sites/config/logs).",
         extra_cases={"na": _site("app,linux", {"reserved": True})})


def _health_check(item, index):
    path = _cfg(item, "healthCheckPath")
    if path is not None and not isinstance(path, str):
        raise Unavailable("malformed healthCheckPath")
    return result(path is None, health_check_path=path)


app_rule("web_app_health_check", "App Service web app configures a health check path", _health_check,
         _site("app", configuration={"healthCheckPath": "/health"}), _site("app", configuration={"healthCheckPath": None}),
         table="web", severity="low", control="CP-10", remediation="Configure a health check path so unhealthy instances are replaced.")


def _vnet_connection(item, index):
    properties = get(item, "properties", dict)
    subnet_observed = "virtualNetworkSubnetId" in properties
    subnet = get(properties, "virtualNetworkSubnetId") if subnet_observed else None
    if subnet is not None and not isinstance(subnet, str):
        raise Unavailable("malformed regional virtualNetworkSubnetId")
    regional_vnet = None
    if subnet:
        regional_vnet = _arm_virtual_network_id(subnet, subnet=True)
        if regional_vnet is None:
            raise Unavailable("malformed regional virtualNetworkSubnetId")
    connections_observed = "vnetConnections" in item
    connection_vnets = []
    if connections_observed:
        for connection in list_of_objects(get(item, "vnetConnections", list)):
            resource_id = get(connection, "properties.vnetResourceId", str)
            if _arm_virtual_network_id(resource_id) is None:
                raise Unavailable("malformed virtualNetworkConnections VNet reference")
            connection_vnets.append(resource_id)
    if regional_vnet or connection_vnets:
        return result(False, regional_subnet_id=subnet or None, vnet_connection_ids=connection_vnets,
                      semantics="Observed regional subnet or native VNet connection configuration; outbound reachability is not proven")
    name = _cfg(item, "vnetName")
    if name is not None and not isinstance(name, str):
        raise Unavailable("malformed vnetName")
    if name:
        return unknown("Legacy vnetName is only a connection name; native VNet or subnet reference is not observed",
                       vnet_name=name)
    coverage = item.get("_coverage", {})
    connection_coverage = coverage.get("vnetConnections") if isinstance(coverage, dict) else None
    if not subnet_observed or not connections_observed or not isinstance(connection_coverage, dict) or connection_coverage.get("status") not in ("collected", "empty"):
        return unknown("regional subnet or VNet connection absence is not completely observed")
    return result(True, regional_subnet_id=None, vnet_connection_ids=[], vnet_name=name,
                  semantics="No regional subnet or native VNet connection in complete observed configuration; outbound reachability is not probed")


def _arm_virtual_network_id(value, *, subnet=False):
    if not isinstance(value, str):
        return None
    parts = value.strip("/").split("/")
    if len(parts) != (10 if subnet else 8):
        return None
    if (parts[0].casefold() != "subscriptions" or not parts[1] or parts[2].casefold() != "resourcegroups"
            or not parts[3] or parts[4].casefold() != "providers" or parts[5].casefold() != "microsoft.network"
            or parts[6].casefold() != "virtualnetworks" or not parts[7]):
        return None
    if subnet and (parts[8].casefold() != "subnets" or not parts[9]):
        return None
    return "/" + "/".join(parts[:8])


app_rule("web_app_vnet_connection", "App Service web app declares a regional subnet or native VNet connection", _vnet_connection,
         _site("app", {"virtualNetworkSubnetId": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Network/virtualNetworks/v/subnets/a"}),
         _site("app", {"virtualNetworkSubnetId": None}, configuration={"vnetName": None})
         | {"vnetConnections": [], "_coverage": {"vnetConnections": {"status": "empty"}}}, table="web",
         control="SC-7", remediation="Review the app's regional subnet and native VNet connection configuration with the network owner before changing integration; a legacy vnetName alone is not proof of an active connection.")


def _http_log_category(item, index):
    hits = [get(s, "name", str) for s in diagnostic_settings(item)
            if any(get(log, "enabled", bool) and log.get("category") == "AppServiceHTTPLogs" for log in diagnostic_logs(s))]
    return result(not hits, settings=hits)


app_rule("web_app_diagnostic_http_log_category", "App Service web app diagnostic setting enables the AppServiceHTTPLogs category",
         _http_log_category, _site("app", diagnostics=diag_case(diag_log("AppServiceHTTPLogs"))["diagnosticSettings"]),
         _site("app", diagnostics=diag_case(diag_log("AppServiceHTTPLogs", enabled=False))["diagnosticSettings"]), table="web",
         control="AU-12", remediation="Add a diagnostic setting that sends the AppServiceHTTPLogs category to a log destination.")


def _workers(item, index):
    workers = _cfg(item, "numberOfWorkers", int)
    return result(workers <= 1, number_of_workers=workers)


app_rule("app_workers_more_than_one", "App Service app runs on more than one worker instance", _workers,
         _site("app", configuration={"numberOfWorkers": 2}), _site("app", configuration={"numberOfWorkers": 1}),
         severity="low", control="CP-10", remediation="Scale the app to at least two instances for availability.")

# --- Function apps ----------------------------------------------------------------------------------------

app_rule("function_app_client_certificates", "Function app has incoming client certificates enabled", _bool_site("properties.clientCertEnabled"),
         _site("functionapp", SITE_CERT), _site("functionapp,linux", NO_CERT), table="function", control="IA-2",
         remediation="Enable incoming client certificates on the function app.", extra_cases={"na": _site("app", NO_CERT)})
app_rule("function_app_ftps_required", "Function app does not allow plain FTP", _ftps_all_allowed,
         _site("functionapp", configuration={"ftpsState": "FtpsOnly"}), _site("functionapp", configuration={"ftpsState": "AllAllowed"}),
         table="function", element="function", control="SC-8", remediation="Set FTP state to FtpsOnly or Disabled.")


def _http2(item, index):
    value = _cfg(item, "http20Enabled", bool)
    return result(not value, http20_enabled=value)


app_rule("function_app_linux_http2", "Linux function app enables HTTP/2", _http2,
         _site("functionapp,linux", configuration={"http20Enabled": True}), _site("functionapp,linux", configuration={"http20Enabled": False}),
         table="function", element="linux_function", severity="low", control="SC-8", remediation="Enable HTTP 2.0 on the function app.",
         extra_cases={"na": _site("functionapp", configuration={"http20Enabled": False})})
app_rule("function_app_managed_identity", "Function app uses a managed identity", _identity_result,
         _site("functionapp", identity={"type": "SystemAssigned, UserAssigned"}), _site("functionapp"), table="function",
         element="function", control="IA-2", remediation="Assign a managed identity to the function app.")
app_rule("function_app_authentication_enabled", "Function app has App Service Authentication enabled", _auth_result,
         _site("functionapp", auth={"platform": {"enabled": True}}), _site("functionapp", auth={}), table="function", control="IA-2",
         remediation="Enable App Service Authentication on the function app.")


def _public_any_allow(item, index):
    rules = _cfg(item, "ipSecurityRestrictions")
    if rules is None:
        return result(False, ip_security_restrictions=None)
    hits = [r.get("name") for r in list_of_objects(rules) if r.get("ipAddress") == "Any" and r.get("action") == "Allow"]
    return result(bool(hits), allow_any_rules=hits)


app_rule("function_app_restrict_public_access", "Function app access restrictions do not allow any source", _public_any_allow,
         _site("functionapp", configuration={"ipSecurityRestrictions": [{"name": "corp", "ipAddress": "203.0.113.0/24", "action": "Allow"}]}),
         _site("functionapp", configuration={"ipSecurityRestrictions": [{"name": "Allow all", "ipAddress": "Any", "action": "Allow"}]}),
         table="function", severity="high", control="SC-7", category="exposure",
         remediation="Replace the 'Allow all' (Any) access restriction with specific source ranges or service tags.")

# --- Prowler app / function scope ---------------------------------------------------------------------------

app_rule("prowler_app_client_certificates_required", "App Service app (kind app*) requires client certificates (mode Required)",
         lambda item, index: result(not (get(item, "properties.clientCertEnabled", bool) and get(item, "properties.clientCertMode", str) == "Required"),
                                    client_cert_enabled=item["properties"]["clientCertEnabled"], client_cert_mode=item["properties"]["clientCertMode"]),
         _site("app", {"clientCertEnabled": True, "clientCertMode": "Required"}), _site("app", {"clientCertEnabled": False, "clientCertMode": "Required"}),
         prowler="app", control="IA-2", remediation="Enable incoming client certificates with mode Required.")


def _http_logs_or_all(item, index):
    hits = []
    for setting in diagnostic_settings(item):
        for log in diagnostic_logs(setting):
            if get(log, "enabled", bool) and (log.get("category") == "AppServiceHTTPLogs" or log.get("categoryGroup") == "allLogs"):
                hits.append(get(setting, "name", str))
    return result(not hits, settings=sorted(set(hits)))


app_rule("prowler_app_http_logs", "App Service app (kind app*) sends HTTP logs (or allLogs) through a diagnostic setting",
         _http_logs_or_all, _site("app", diagnostics=diag_case(diag_log(group="allLogs"))["diagnosticSettings"]),
         _site("app", diagnostics=[]), prowler="app", control="AU-12",
         remediation="Add a diagnostic setting with the AppServiceHTTPLogs category (or the allLogs group) enabled.")
app_rule("prowler_app_authentication", "App Service app (kind app*) has authentication set up", _auth_result,
         _site("app", auth={"platform": {"enabled": True}}), _site("app", auth={"platform": {}}), prowler="app", control="IA-2",
         remediation="Enable App Service Authentication with an identity provider.")
app_rule("prowler_app_identity", "App Service app (kind app*) has a managed identity configured", _identity_result,
         _site("app", identity={"type": "SystemAssigned"}), _site("app", identity={"type": "None"}), prowler="app", control="IA-2",
         remediation="Assign a managed identity to the app.")
app_rule("prowler_function_identity", "Function app has a managed identity configured", _identity_result,
         _site("functionapp", identity={"type": "UserAssigned"}), _site("functionapp", identity=None), prowler="function",
         control="IA-2", remediation="Assign a managed identity to the function app.")


def _ftps_disabled(item, index):
    state = enum(_config(item), "ftpsState", FTPS_STATES)
    return result(state != "Disabled", ftps_state=state)


app_rule("prowler_function_ftp_ftps_disabled", "Function app disables both FTP and FTPS deployment", _ftps_disabled,
         _site("functionapp", configuration={"ftpsState": "Disabled"}), _site("functionapp", configuration={"ftpsState": "FtpsOnly"}),
         prowler="function", control="CM-7", remediation="Set FTP state to Disabled and deploy through other mechanisms.")


def _public_network(item, index):
    value = get(item, "properties.publicNetworkAccess")
    if value == "Disabled":
        return result(False, public_network_access=value)
    if value == "Enabled":
        return result(True, public_network_access=value)
    return unknown("publicNetworkAccess unset; effective access depends on private endpoints", public_network_access=value)


app_rule("prowler_function_not_public", "Function app disables public network access", _public_network,
         _site("functionapp", {"publicNetworkAccess": "Disabled"}), _site("functionapp", {"publicNetworkAccess": "Enabled"}),
         prowler="function", severity="high", control="SC-7", category="exposure",
         remediation="Disable public network access and reach the function app through private endpoints.",
         extra_cases={"unset": _site("functionapp", {"publicNetworkAccess": None})})


def _vnet_subnet(item, index):
    subnet = get(item, "properties.virtualNetworkSubnetId")
    if subnet is not None and not isinstance(subnet, str):
        raise Unavailable("malformed virtualNetworkSubnetId")
    return result(not subnet, virtual_network_subnet_id=subnet or None)


app_rule("prowler_function_vnet_integration", "Function app has virtual network integration", _vnet_subnet,
         _site("functionapp", {"virtualNetworkSubnetId": SITE + "/subnet"}), _site("functionapp", {"virtualNetworkSubnetId": None}),
         prowler="function", control="SC-7", remediation="Enable regional virtual network integration for the function app.")


def _principals(item):
    identity = get(item, "identity", dict)
    ids = []
    if isinstance(identity.get("principalId"), str):
        ids.append(identity["principalId"])
    users = identity.get("userAssignedIdentities") or {}
    if not isinstance(users, dict):
        raise Unavailable("malformed userAssignedIdentities")
    for value in users.values():
        if isinstance(value, dict) and isinstance(value.get("principalId"), str):
            ids.append(value["principalId"])
    if not ids:
        raise Unavailable("managed identity principal id not collected")
    return set(ids)


def _admin_identity(item, index):
    if _identity_type(item) == "None":
        return na("Function app has no managed identity")
    principals = _principals(item)
    roles = []
    for assignment in scoped(index, "role_assignment"):
        if get(assignment, "properties.principalId", str) in principals:
            role = get(assignment, "properties.roleDefinitionId", str).rsplit("/", 1)[-1].lower()
            if role in ADMIN_ROLES:
                roles.append(role)
    return result(bool(roles), admin_role_ids=sorted(set(roles)), semantics="Subscription-visible RBAC assignments; groups not expanded")


def _ra(role, principal="mi1"):
    return {"properties": {"principalId": principal, "roleDefinitionId": "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/" + role}}


_FN_MI = _site("functionapp", identity={"type": "SystemAssigned", "principalId": "mi1"})
app_rule("prowler_function_identity_not_admin", "Function app managed identity holds no Owner/Contributor/UAA/RBAC Administrator role",
         _admin_identity, _FN_MI, _FN_MI, prowler="function", severity="high", control="AC-6", category="least_privilege",
         dependencies=["app_service", "role_assignment"],
         remediation="Replace privileged role assignments of the function identity with least-privilege data-plane roles.")
CASES[cid("prowler_function_identity_not_admin")].update({
    "pass_index": scope_index({"role_assignment": [_ra("acdd72a7-3385-48ef-bd42-f606fba81ae7")]}),
    "fail_index": scope_index({"role_assignment": [_ra(CONTRIBUTOR)]})})

# --- Uncollected App Service resource types (UNKNOWN until the collector gathers them) ------------------------

PLAN_LOW_SKUS = ("F1", "D1", "B1", "B2", "B3")


@claude2("app_service_plan_minimum_sku", "app_service_plan", "App Service plan is not a Free, Shared or Basic SKU", severity="low",
         control="CP-10", remediation="Move production apps to a Standard, Premium or Isolated plan with SLA and scale-out.")
def plan_sku(item, index):
    name = get(item, "sku.name", str)
    return result(name in PLAN_LOW_SKUS, sku_name=name)
CASES[cid("app_service_plan_minimum_sku")] = {"pass": {"sku": {"name": "P1v3"}}, "fail": {"sku": {"name": "B1"}}, "missing": {}}


@claude2("app_service_environment_internal_encryption", "app_service_environment",
         "App Service Environment enables internal encryption (InternalEncryption cluster setting)", control="SC-28",
         remediation="Set the InternalEncryption cluster setting to true on the App Service Environment.")
def ase_encryption(item, index):
    settings = list_of_objects(get(item, "properties.clusterSettings", list))
    hit = any(s.get("name") == "InternalEncryption" and s.get("value") == "true" for s in settings)
    return result(not hit, internal_encryption=hit)
CASES[cid("app_service_environment_internal_encryption")] = {
    "pass": {"properties": {"clusterSettings": [{"name": "InternalEncryption", "value": "true"}]}},
    "fail": {"properties": {"clusterSettings": []}}, "missing": {}}


@claude2("web_app_slot_https_only", "app_service_slot", "App Service deployment slot requires HTTPS", control="SC-8",
         remediation="Enable HTTPS Only on every deployment slot.")
def slot_https(item, index):
    value = get(item, "properties.httpsOnly", bool)
    return result(not value, https_only=value)
CASES[cid("web_app_slot_https_only")] = {"pass": {"properties": {"httpsOnly": True}}, "fail": {"properties": {"httpsOnly": False}}, "missing": {}}


# --- Application Insights --------------------------------------------------------------------------------------

INSIGHTS = "microsoft.insights/components"


def _insights(item):
    if get(item, "type", str).lower() != INSIGHTS:
        raise Unavailable("unexpected Application Insights resource type")
    return get(item, "properties", dict)


@claude2("application_insights_public_access_blocked", "application_insights",
         "Application Insights blocks public network ingestion and query", severity="medium", control="SC-7", category="exposure",
         remediation="Set publicNetworkAccessForIngestion and publicNetworkAccessForQuery to Disabled and use Private Link (AMPLS).")
def insights_public(item, index):
    props = _insights(item)
    ingestion = enum(props, "publicNetworkAccessForIngestion", ("Enabled", "Disabled"))
    query = enum(props, "publicNetworkAccessForQuery", ("Enabled", "Disabled"))
    return result(not (ingestion == "Disabled" and query == "Disabled"), ingestion=ingestion, query=query,
                  semantics="Implements the control title; the pinned upstream CASE is inverted (passes when both are Enabled)")
CASES[cid("application_insights_public_access_blocked")] = {
    "pass": {"type": "Microsoft.Insights/components", "properties": {"publicNetworkAccessForIngestion": "Disabled", "publicNetworkAccessForQuery": "Disabled"}},
    "fail": {"type": "Microsoft.Insights/components", "properties": {"publicNetworkAccessForIngestion": "Enabled", "publicNetworkAccessForQuery": "Disabled"}},
    "missing": {}}


@claude2("application_insights_workspace_based", "application_insights", "Application Insights is linked to a Log Analytics workspace",
         severity="low", control="AU-9", remediation="Migrate the component to a workspace-based Application Insights resource.")
def insights_workspace(item, index):
    workspace = get(_insights(item), "WorkspaceResourceId")
    if workspace is not None and not isinstance(workspace, str):
        raise Unavailable("malformed WorkspaceResourceId")
    return result(not workspace, workspace_resource_id=workspace)
CASES[cid("application_insights_workspace_based")] = {
    "pass": {"type": "Microsoft.Insights/components", "properties": {"WorkspaceResourceId": "/w"}},
    "fail": {"type": "Microsoft.Insights/components", "properties": {"WorkspaceResourceId": None}}, "missing": {}}


@scope_check("application_insights_configured", "application_insights", "Subscription has at least one Application Insights component",
             dependencies=["application_insights", "app_service"], severity="low", control="AU-12",
             remediation="Instrument applications with an Application Insights component.")
def insights_configured(item, index):
    # Application Insights instruments application code; a subscription without App Service/Functions apps has none to instrument.
    if not scoped(index, "app_service"):
        return na("Subscription has no App Service or Functions apps to instrument")
    components = scoped(index, "application_insights")
    return result(not components, components=len(components))
_SITE = [{"id": SUB + "/resourceGroups/r/providers/Microsoft.Web/sites/a", "kind": "app"}]
CASES[cid("application_insights_configured")] = {
    "pass": SCOPE, "fail": SCOPE, "not_applicable": SCOPE,
    "pass_index": scope_index({"application_insights": [{"type": "Microsoft.Insights/components", "properties": {}}], "app_service": _SITE}),
    "fail_index": scope_index({"application_insights": [], "app_service": _SITE}),
    "not_applicable_index": scope_index({"application_insights": [], "app_service": []})}


APP_IDS = tuple(CHECK_IDS[_START:])
