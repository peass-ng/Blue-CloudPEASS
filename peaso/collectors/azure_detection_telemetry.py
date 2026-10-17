"""Bounded, source-filtered Azure Monitor aggregates; never retain raw log events.

Reviewed policy selects identities and windows, never factual routing or query
results. Diagnostic configuration and workspace identity come from ARM; counts,
timestamps and operations come from the separately authenticated Logs endpoint.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

ARM = "https://management.azure.com"
LOGS = "https://api.loganalytics.io"
API = "https://api.loganalytics.azure.com/v1/workspaces/"
KIND = "azure_detection_telemetry"
CONTRACTS = {"sw11-v1", "sw12-v1"}
_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
_TABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_RESOURCE = re.compile(r"/[A-Za-z0-9._()/-]+")


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("missing aggregate timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("aggregate timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


def _identity(value, scope, *, workspace=False, verified_tenant=None):
    if not isinstance(value, str) or not _RESOURCE.fullmatch(value):
        raise ValueError("invalid ARM identity")
    value = value.rstrip("/").casefold()
    if any(part in ("", ".", "..") for part in value[1:].split("/")):
        raise ValueError("noncanonical ARM identity")
    if not workspace and verified_tenant and value == "/tenants/" + verified_tenant.casefold() and _GUID.fullmatch(verified_tenant):
        return value
    if not (value == scope.casefold() or value.startswith(scope.casefold() + "/")):
        raise ValueError("foreign telemetry source")
    if workspace and not re.fullmatch(re.escape(scope.casefold()) +
            r"/resourcegroups/[^/]+/providers/microsoft\.operationalinsights/workspaces/[^/]+", value):
        raise ValueError("invalid workspace identity")
    return value


def _seconds(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 2678400:
        raise ValueError("telemetry window must be 1 second to 31 days")
    return value


def _targets(options, scope, verified_tenant=None):
    policy = options.get("compliance_policy", {})
    if not isinstance(policy, dict):
        raise ValueError("invalid detection policy")
    found = []
    for dialect, name, scope_field in (("sw11-v1", "azure_attack_detection", "subscription_scope"),
                                       ("sw12-v1", "sw12", "scope")):
        review = policy.get(name)
        if review is None:
            continue
        if not isinstance(review, dict) or str(review.get(scope_field, "")).casefold() != scope.casefold():
            continue
        if review.get("status") != "collected" or not isinstance(review.get("checks"), dict):
            raise ValueError("unavailable detection policy")
        if len(review["checks"]) > 64:
            raise ValueError("unbounded check review")
        for cid, check in review["checks"].items():
            if not isinstance(cid, str) or not cid.startswith("azure.other.") or not isinstance(check, dict):
                raise ValueError("invalid check review")
            requirements = check.get("requirements", [])
            if not isinstance(requirements, list) or len(requirements) > 256:
                raise ValueError("unbounded telemetry requirements")
            for req in requirements:
                if not isinstance(req, dict):
                    raise ValueError("invalid telemetry requirement")
                workspace = _identity(req.get("workspace_id"), scope, workspace=True)
                if dialect == "sw11-v1":
                    sources = req.get("sources", [])
                    if not isinstance(sources, list) or len(sources) > 256:
                        raise ValueError("unbounded telemetry sources")
                else:
                    sources = [{"resource_id": req.get("source_id"), "table": req.get("table"),
                                "lookback_seconds": req.get("max_window_seconds")}]
                for source in sources:
                    if not isinstance(source, dict):
                        raise ValueError("invalid telemetry source")
                    rid = _identity(source.get("resource_id"), scope, verified_tenant=verified_tenant)
                    table = source.get("table")
                    if not isinstance(table, str) or not _TABLE.fullmatch(table):
                        raise ValueError("invalid telemetry table")
                    seconds = _seconds(source.get("lookback_seconds"))
                    pattern = req.get("pattern_id")
                    if not isinstance(pattern, str) or not pattern.strip() or len(pattern) > 256:
                        raise ValueError("invalid telemetry pattern")
                    found.append((dialect, cid, workspace, rid, table, seconds, pattern))
                    if len(found) > 256:
                        raise ValueError("telemetry target budget exceeded")
    return list(dict.fromkeys(found))


def _aggregate(response, start, end):
    # HTTP 200 can contain PartialError alongside tables: it is never complete.
    if not isinstance(response, dict) or "error" in response or "partialError" in response:
        raise ValueError("incomplete Logs query")
    tables = response.get("tables")
    if not isinstance(tables, list) or len(tables) != 1 or not isinstance(tables[0], dict):
        raise ValueError("ambiguous Logs query result")
    table = tables[0]
    columns, rows = table.get("columns"), table.get("rows")
    expected = [("event_count", "long"), ("last_ingested_at", "datetime"),
                ("last_event_at", "datetime"), ("operations", "dynamic")]
    if (not isinstance(columns, list) or any(not isinstance(c, dict) for c in columns)
            or [(c.get("name"), c.get("type")) for c in columns] != expected
            or not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], list)
            or len(rows[0]) != 4):
        raise ValueError("malformed Logs aggregate")
    count, ingested, latest, operations = rows[0]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("invalid event count")
    if count:
        for value in (ingested, latest):
            if not start <= _instant(value) <= end:
                raise ValueError("aggregate timestamp outside measured interval")
    elif ingested not in (None, "") or latest not in (None, ""):
        raise ValueError("empty aggregate contradicts timestamps")
    if isinstance(operations, str):
        operations = json.loads(operations)
    if (not isinstance(operations, list) or len(operations) > 256
            or any(not isinstance(op, str) or len(op) > 1024 for op in operations)
            or (not count and operations)):
        raise ValueError("malformed operation aggregate")
    safe_operations = sorted(set(op for op in operations
        if re.fullmatch(r"[A-Za-z0-9_./: ()-]{1,256}", op) and not re.match(r"(?i)^Bearer\s", op)))
    return count, ingested or None, latest or None, safe_operations


def _route(settings, source, workspace, table):
    """Map only documented diagnostic families; custom/DCR routes stay unknown."""
    families = {
        "StorageBlobLogs": ("microsoft.storage/storageaccounts/", {"StorageRead", "StorageWrite", "StorageDelete"}),
        "StorageFileLogs": ("microsoft.storage/storageaccounts/", {"StorageRead", "StorageWrite", "StorageDelete"}),
        "StorageQueueLogs": ("microsoft.storage/storageaccounts/", {"StorageRead", "StorageWrite", "StorageDelete"}),
        "StorageTableLogs": ("microsoft.storage/storageaccounts/", {"StorageRead", "StorageWrite", "StorageDelete"}),
        "AZKVAuditLogs": ("microsoft.keyvault/vaults/", {"AuditEvent"}),
        "AzureDiagnostics": ("microsoft.keyvault/vaults/", {"AuditEvent"}),
        "ContainerRegistryRepositoryEvents": ("microsoft.containerregistry/registries/", {"ContainerRegistryRepositoryEvents"}),
        "FunctionAppLogs": ("microsoft.web/sites/", {"FunctionAppLogs"}),
        "AzureActivity": ("/subscriptions/", {"Administrative", "Security", "Policy", "ServiceHealth", "Alert", "Recommendation", "Autoscale", "ResourceHealth"}),
        "AuditLogs": ("/providers/microsoft.aadiam", {"AuditLogs"}),
        "SigninLogs": ("/providers/microsoft.aadiam", {"SignInLogs"}),
    }
    relation = families.get(table)
    if relation is None or relation[0] not in source:
        return None, []
    # Activity logs are subscription scoped; a resource-scoped setting does not
    # establish an activity export. Storage tables require the exact service.
    if table == "AzureActivity" and not re.fullmatch(r"/subscriptions/[^/]+", source):
        return None, []
    service = {"StorageBlobLogs": "/blobservices/", "StorageFileLogs": "/fileservices/",
               "StorageQueueLogs": "/queueservices/", "StorageTableLogs": "/tableservices/"}.get(table)
    if service and service not in source:
        return None, []
    evidence, partially_enabled, seen = [], False, set()
    for setting in settings:
        if not isinstance(setting, dict) or not isinstance(setting.get("id"), str):
            raise ValueError("malformed diagnostic setting")
        rid = setting["id"]
        if source == "/providers/microsoft.aadiam":
            from .azure_entra_diagnostics_native import setting_id
            rid = setting_id(rid)
        sid = rid.casefold()
        prefix = source + ("/diagnosticsettings/" if source == "/providers/microsoft.aadiam" else "/providers/microsoft.insights/diagnosticsettings/")
        if not sid.startswith(prefix):
            raise ValueError("foreign diagnostic setting")
        if sid in seen or "/" in sid.split("/diagnosticsettings/", 1)[1]:
            raise ValueError("ambiguous diagnostic setting identity")
        seen.add(sid)
        props = setting.get("properties")
        if not isinstance(props, dict) or not isinstance(props.get("logs", []), list):
            raise ValueError("malformed diagnostic log configuration")
        destination = props.get("workspaceId")
        if destination is not None and (not isinstance(destination, str) or not destination.startswith("/")):
            raise ValueError("malformed diagnostic destination")
        if (destination or "").casefold() != workspace:
            continue
        if table not in ("AzureDiagnostics", "AzureActivity", "AuditLogs", "SigninLogs") and props.get("logAnalyticsDestinationType") != "Dedicated":
            continue
        if table == "AzureDiagnostics" and props.get("logAnalyticsDestinationType") == "Dedicated":
            continue
        categories, all_logs = set(), False
        for log in props.get("logs", []):
            if not isinstance(log, dict) or not isinstance(log.get("enabled"), bool):
                raise ValueError("incomplete diagnostic category")
            if log["enabled"]:
                all_logs |= log.get("categoryGroup") == "allLogs" and source != "/providers/microsoft.aadiam"
                categories.add(log.get("category"))
        if all_logs or relation[1] <= categories:
            evidence.append(rid)
        partially_enabled |= bool(categories & relation[1])
    return (True if evidence else None if partially_enabled else False), sorted(set(evidence))


def _observe(reader, request, scope, key, seconds, verified_tenant):
    workspace, source, table = key
    detail = reader.call(request, ARM + workspace + "?api-version=2023-09-01")
    if (not isinstance(detail, dict) or str(detail.get("id", "")).casefold() != workspace
            or not isinstance(detail.get("properties"), dict)):
        raise ValueError("workspace identity unresolved")
    customer = detail["properties"].get("customerId")
    if not isinstance(customer, str) or not _GUID.fullmatch(customer):
        raise ValueError("workspace customer identity unresolved")
    diagnostic_source = scope.casefold() if table == "AzureActivity" else source
    query_source = source
    tenant_source = source.startswith("/tenants/")
    if tenant_source:
        if table not in ("AuditLogs", "SigninLogs"):
            raise ValueError("tenant feed table unsupported")
        diagnostic_source = "/providers/microsoft.aadiam"
    services = {"StorageBlobLogs": "blobServices", "StorageFileLogs": "fileServices",
                "StorageQueueLogs": "queueServices", "StorageTableLogs": "tableServices"}
    if table in services and re.fullmatch(r".+/providers/microsoft\.storage/storageaccounts/[^/]+", source):
        diagnostic_source = query_source = source + "/" + services[table].casefold() + "/default"
    diagnostic_url = (ARM + diagnostic_source + "/diagnosticSettings?api-version=2017-04-01" if tenant_source
        else ARM + diagnostic_source + "/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview")
    settings = [row for page in reader.pages(request, diagnostic_url) for row in page]
    routing, evidence = _route(settings, diagnostic_source, workspace, table)
    end = datetime.now(timezone.utc)
    start = end - timedelta(seconds=seconds)
    source_filter = ("AADTenantId =~ " + json.dumps(verified_tenant) if tenant_source else
        "_SubscriptionId =~ " + json.dumps(scope.rsplit("/", 1)[-1]) if query_source == scope.casefold()
        else "_ResourceId =~ " + json.dumps(query_source))
    query = (table + " | where TimeGenerated between (datetime(" + start.isoformat() +
        ") .. datetime(" + end.isoformat() + ")) | where " + source_filter +
        " | extend _op=tostring(column_ifexists('OperationName', column_ifexists('OperationNameValue', '')))"
        " | summarize event_count=count(), last_ingested_at=max(ingestion_time()),"
        " last_event_at=max(TimeGenerated), operations=make_set(_op, 256)")
    response = reader.call(request, API + customer + "/query", audience=LOGS,
        body={"query": query, "timespan": start.isoformat() + "/" + end.isoformat()})
    count, ingested, latest, operations = _aggregate(response, start, end)
    return (seconds, start, end, count, ingested, latest, operations, routing, evidence, bool(settings), query_source, diagnostic_source)


def collect(reader, request, scopes, wanted, options, *, verified_tenant=None):
    if KIND not in wanted:
        return
    jobs = []
    for scope in scopes:
        def fetch(scope=scope):
            targets = _targets(options, scope, verified_tenant)
            if not targets:
                from .azure import AzureReadError
                raise AzureReadError("reviewed_detection_sources_unavailable")
            if any(target[3].startswith("/tenants/") for target in targets):
                subscription = reader.call(request, ARM + scope + "?api-version=2022-12-01")
                if (not isinstance(subscription, dict) or str(subscription.get("id", "")).casefold() != scope.casefold()
                        or str(subscription.get("tenantId", "")).casefold() != verified_tenant.casefold()):
                    raise ValueError("source tenant/subscription authority unresolved")
                with reader.lock:
                    if not hasattr(reader, "native_subscription_tenants"):
                        reader.native_subscription_tenants = {}
                    reader.native_subscription_tenants[scope] = verified_tenant
            # Shared query work is deduplicated across checks and dialects.
            observations = {}
            maxima = {}
            for _, _, workspace, source, table, seconds, _ in targets:
                key = (workspace, source, table)
                maxima[key] = max(seconds, maxima.get(key, 0))
            errors, first_error = {}, None
            for key, seconds in maxima.items():
                try:
                    observations[key] = _observe(reader, request, scope, key, seconds, verified_tenant)
                except Exception as exc:
                    from .azure import _safe_error
                    errors[key] = _safe_error(exc)
                    first_error = first_error or exc
            if errors and not observations:
                raise first_error
            emitted = set()
            for dialect, cid, workspace, source, table, _, pattern in targets:
                key = (workspace, source, table)
                observation = observations.get(key)
                failure = errors.get(key)
                if observation is not None and dialect == "sw11-v1" and observation[7] is None:
                    failure = ("not_collected", {"code": "source_diagnostic_table_mapping_unresolved"})
                if failure is not None:
                    identity = ("|".join(key) if dialect == "sw11-v1" else "sw12:" +
                        hashlib.sha256(json.dumps([cid, workspace, source, pattern], separators=(",", ":")).encode()).hexdigest())
                    row = {"id": identity, "workspace_id": workspace, "table": table,
                        **({"source_resource_id": source} if dialect == "sw11-v1" else
                           {"check_id": cid, "source_id": source, "pattern_id": pattern}),
                        "_coverage": {"observation": {"status": failure[0], "error": failure[1]}},
                        "_provenance": {"contract": dialect, "source_operation": KIND,
                            "read_only": True, "native_response_complete": False}}
                    if source.startswith("/tenants/"):
                        row["_provenance"].update(tenant_id=verified_tenant, tenant_verified=True)
                    if identity not in emitted:
                        emitted.add(identity)
                        yield [row]
                    continue
                seconds, start, end, count, ingested, latest, operations, routing, evidence, has_settings, query_source, diagnostic_source = observation
                base = {"workspace_id": workspace, "table": table}
                if dialect == "sw11-v1":
                    identity = "|".join((workspace, source, table))
                    row = {**base, "id": identity, "source_resource_id": source,
                        "export_enabled": routing is True, "routing_verified": routing is True,
                        "queried_at": end.isoformat(), "lookback_seconds": seconds,
                        "row_count": count, "last_ingested_at": ingested,
                        "_provenance": {"contract": dialect, "source_operation": "logs.query",
                            "query_source_resource_id": query_source, "diagnostic_source_resource_id": diagnostic_source,
                            "read_only": True, "source_filter_verified": True}}
                    if routing is False:
                        row["_provenance"].update(source_operation="diagnostic_settings.list",
                            export_inventory_status="collected" if has_settings else "empty",
                            export_observed_at=end.isoformat(), export_max_age_seconds=3600)
                    elif routing is None:
                        # Unrecognized routing cannot establish export disabled.
                        raise ValueError("source diagnostic table mapping unresolved")
                else:
                    identity = "sw12:" + hashlib.sha256(json.dumps([cid, workspace, source, pattern], separators=(",", ":")).encode()).hexdigest()
                    row = {**base, "id": identity, "check_id": cid, "source_id": source,
                        "pattern_id": pattern, "routing_enabled": routing is True,
                        "routing_evidence_ids": evidence, "event_feed_status": "available" if routing is not None else "unresolved",
                        "query_window": {"start": start.isoformat(), "end": end.isoformat()},
                        "event_count": count, "latest_event_at": latest, "supported_operations": operations,
                        "_provenance": {"contract": dialect, "source_operation": KIND,
                            "query_source_resource_id": query_source, "diagnostic_source_resource_id": diagnostic_source,
                            "read_only": True, "native_response_complete": True}}
                if source.startswith("/tenants/"):
                    row["_provenance"].update(tenant_id=verified_tenant, tenant_verified=True)
                if identity not in emitted:
                    emitted.add(identity)
                    yield [row]
        jobs.append((KIND, scope, "Azure.Monitor.Logs", fetch))
    reader.run(jobs)
