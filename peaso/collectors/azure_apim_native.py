"""Opt-in, read-only APIM metadata extension for the 2024-05-01 ARM API.

Call after api_management parent discovery only when apim_native is wanted. The
host's _Reader supplies pagination, retry, rate/call limits, and authentication.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

API_VERSION = "2024-05-01"
ARM = "https://management.azure.com"
SERVICE_RE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.apimanagement/service/[^/]+", re.I)


def _child_id(value, parent, segment):
    rid = value.get("id") if isinstance(value, dict) else None
    if not isinstance(rid, str) or not re.fullmatch(re.escape(parent) + "/" + segment + r"/[^/?#]+", rid, re.I):
        raise ValueError("foreign or malformed APIM child identity")
    return rid


def _revision_id(value, parent):
    """Resolve only the exact service-relative spelling of this API revision."""
    if not isinstance(value, str) or not isinstance(parent, str):
        raise ValueError("malformed APIM revision identity")
    match = re.fullmatch(r"(.+)/apis/([^/;?#%\\\s]+)", parent, re.I)
    if (match is None or not SERVICE_RE.fullmatch(match.group(1))
            or re.search(r"[%?#\\\s]", parent)
            or any(part in (".", "..") for part in parent.split("/"))):
        raise ValueError("unverified APIM revision parent")
    suffix = r"(?:;rev=[A-Za-z0-9][A-Za-z0-9._-]*)?"
    relative = "/apis/" + match.group(2)
    if re.fullmatch(re.escape(relative) + suffix, value, re.I):
        return match.group(1) + value
    if not re.fullmatch(re.escape(parent) + suffix, value, re.I):
        raise ValueError("foreign or malformed APIM revision identity")
    return value


def _read(reader, request, parent, segment, project, *, response_id="id"):
    url = ARM + parent + "/" + segment + "?api-version=" + API_VERSION
    def fetch():
        seen = set()
        total = None
        def counted_request(*args, **kwargs):
            nonlocal total
            response = request(*args, **kwargs)
            if isinstance(response, dict) and "count" in response:
                value = response["count"]
                if type(value) is not int or value < 0:
                    raise ValueError("malformed APIM total count")
                if total is not None and value != total:
                    raise ValueError("unstable APIM total count")
                total = value
            return response
        for page in reader.pages(counted_request, url):
            safe = []
            for raw in page:
                if not isinstance(raw, dict):
                    raise ValueError("malformed APIM row")
                row = {"id": raw.get(response_id)}
                if segment == "revisions":
                    row["id"] = _revision_id(row["id"], parent)
                else:
                    _child_id(row, parent, segment)
                identity = row["id"].casefold()
                if identity in seen:
                    raise ValueError("duplicate APIM child identity")
                seen.add(identity)
                safe.append(project(raw, row["id"]))
            yield safe
        if total is not None and total != len(seen):
            raise ValueError("APIM total count differs from returned rows")
    result = reader._read(("apim_" + segment.replace("/", "_"), parent, "Microsoft.ApiManagement", fetch))
    # Embedded items debit the same explicit max_resources budget as top-level
    # native collections. The default remains uncapped.
    with reader.lock:
        if reader.budget.max_items is not None:
            capacity = max(0, reader.budget.max_items - reader.total)
            if len(result["items"]) > capacity:
                result["items"] = result["items"][:capacity]
                result.update(status="partial", error={"code": "resource_limit"})
        reader.total += len(result["items"])
    return result


def _api(row, rid, operation="Apis_ListByService"):
    props = row.get("properties")
    if not isinstance(props, dict):
        raise ValueError("malformed APIM API properties")
    result = {"id": rid, "properties": {k: props[k] for k in ("protocols", "isCurrent", "isOnline", "apiRevision") if k in props},
            "_provenance": {"source_operation": operation, "api_version": API_VERSION, "read_only": True}}
    if 'type' in props:
        if props['type'] not in ('http', 'odata', 'soap', 'websocket', 'graphql', 'grpc'):
            raise ValueError('native APIM API type malformed')
        # Keep the established SW24 configuration digest representation stable.
        result['apiType'] = props['type']
        result['_provenance']['api_type_source'] = 'properties.type'
    return result


def _hydrate_api(value, api_id, api_by_id, revisions):
    """Accept a current base-ID alias only with independent native bindings."""
    native_id = value.get("id") if isinstance(value, dict) else None
    if not isinstance(native_id, str):
        raise ValueError("malformed APIM API revision GET")
    if native_id.casefold() == api_id.casefold():
        return _api(value, api_id, "Apis_Get")
    match = re.fullmatch(r"(.+);rev=([A-Za-z0-9][A-Za-z0-9._-]*)", api_id)
    if match is None:
        raise ValueError("unbound APIM current revision alias")
    base, revision = match.groups()
    if _revision_id(api_id, base).casefold() != api_id.casefold() or native_id.casefold() != base.casefold():
        raise ValueError("foreign APIM current revision alias")
    listed = api_by_id.get(base.casefold(), {})
    base_props = listed.get("properties", {})
    props = value.get("properties")
    if (listed.get("_provenance", {}).get("source_operation") != "Apis_ListByService"
            or not isinstance(props, dict)
            or type(props.get("apiRevision")) is not str or props["apiRevision"] != revision
            or props.get("isCurrent") is not True
            or type(base_props.get("apiRevision")) is not str or base_props["apiRevision"] != revision
            or base_props.get("isCurrent") is not True):
        raise ValueError("native APIM current revision binding unavailable")
    inventories = [result for parent, result in revisions if parent.casefold() == base.casefold()]
    if len(inventories) != 1 or inventories[0]["status"] not in ("collected", "empty"):
        raise ValueError("APIM revision alias inventory unavailable")
    current = [row for row in inventories[0]["items"] if row["isCurrent"]]
    if (len(current) != 1 or current[0]["id"].casefold() != api_id.casefold()
            or current[0]["isOnline"] is not True):
        raise ValueError("APIM revision alias is not uniquely current and online")
    hydrated = _api(value, api_id, "Apis_Get")
    hydrated["_provenance"].update(native_response_id=native_id, requested_api_id=api_id,
        identity_binding="current_revision_LIST_and_base_API_LIST")
    return hydrated


def _revision(row, rid):
    if type(row.get("isOnline")) is not bool or type(row.get("isCurrent")) is not bool:
        raise ValueError("malformed APIM revision state")
    return {"id": rid, "isOnline": row["isOnline"], "isCurrent": row["isCurrent"],
            "_provenance": {"source_operation": "ApiRevision_ListByService", "api_version": API_VERSION, "read_only": True}}


def _logger(row, rid):
    props = row.get("properties")
    if not isinstance(props, dict):
        raise ValueError("malformed APIM logger properties")
    # In particular, do not retain credentials, instrumentation keys, or connection strings.
    return {"id": rid, "properties": {k: props[k] for k in ("loggerType", "resourceId") if k in props},
            "_provenance": {"source_operation": "Logger_ListByService", "api_version": API_VERSION, "read_only": True}}


def _diagnostic(row, rid):
    props = row.get("properties")
    if not isinstance(props, dict):
        raise ValueError("malformed APIM diagnostic properties")
    sample = props.get("sampling")
    projected = {k: props[k] for k in ("loggerId", "alwaysLog", "verbosity") if k in props}
    if "sampling" in props:
        if not isinstance(sample, dict):
            raise ValueError("malformed APIM sampling")
        projected["sampling"] = {k: sample[k] for k in ("samplingType", "percentage") if k in sample}
    for side in ("frontend", "backend"):
        if side in props:
            side_value = props[side]
            if not isinstance(side_value, dict):
                raise ValueError("malformed APIM HTTP diagnostic")
            projected[side] = {}
            for direction in ("request", "response"):
                if direction in side_value:
                    entry = side_value[direction]
                    if not isinstance(entry, dict):
                        raise ValueError("malformed APIM HTTP diagnostic direction")
                    body = entry.get("body")
                    projected[side][direction] = {"body": {"bytes": body["bytes"]}} if isinstance(body, dict) and "bytes" in body else {}
    return {"id": rid, "properties": projected,
            "_provenance": {"source_operation": "Diagnostic_List", "api_version": API_VERSION, "read_only": True}}


def _attach(container, field, result):
    container.setdefault("_coverage", {})[field] = {k: result[k] for k in ("status", "error") if k in result}
    if result["status"] in ("collected", "empty"):
        container[field] = result["items"]


def collect_apim(reader, request, parent_collections):
    """Return one private fact collection per subscription, coalescing each ARM parent.

    Work is O(services + APIs + revisions + diagnostics). Every distinct URL is
    read once; the host reader follows all nextLinks unless an explicit cap is set.
    """
    by_scope = {}
    service_items = {}
    for collection in parent_collections:
        if collection.get("type") != "api_management":
            continue
        scope = collection["scope"]
        by_scope.setdefault(scope, [])
        if collection.get("status") not in ("collected", "empty"):
            by_scope[scope] = None
            continue
        if by_scope[scope] is None:
            continue
        for item in collection["items"]:
            rid = item.get("id")
            if not isinstance(rid, str) or not SERVICE_RE.fullmatch(rid) or not rid.casefold().startswith(scope.casefold() + "/"):
                by_scope[scope] = None
                break
            service_items.setdefault(rid.casefold(), (scope, rid))
    def service_work(pair):
        scope, rid = pair
        fact = {"id": rid, "parent_id": rid, "_provenance": {"source_operation": "APIM_native_metadata", "api_version": API_VERSION, "read_only": True}}
        apis = _read(reader, request, rid, "apis", _api)
        _attach(fact, "apis", apis)
        if apis["status"] not in ("collected", "empty"):
            return scope, fact
        loggers = _read(reader, request, rid, "loggers", _logger)
        _attach(fact, "loggers", loggers)
        service_diags = _read(reader, request, rid, "diagnostics", _diagnostic)
        _attach(fact, "diagnostics", service_diags)
        # Revision lists are authoritative for non-current, online API revisions.
        api_by_id = {api["id"].casefold(): api for api in fact["apis"]}
        base_ids = {api["id"].split(";rev=", 1)[0].casefold(): api["id"].split(";rev=", 1)[0] for api in fact["apis"]}
        revisions = [(base, _read(reader, request, base, "revisions", _revision, response_id="apiId"))
                     for base in base_ids.values()]
        fact["_coverage"]["revisions"] = {"status": "collected" if all(v["status"] in ("collected", "empty") for _, v in revisions) and (not fact["apis"] or all(v["items"] for _, v in revisions)) else "partial"}
        if fact["_coverage"]["revisions"]["status"] != "collected":
            return scope, fact
        online_ids = {}
        for base, result in revisions:
            for row in result["items"]:
                if row["isOnline"]:
                    online_ids[row["id"].casefold()] = row["id"]
        fact["online_api_ids"] = list(online_ids.values())
        # A revision may be omitted from Apis_ListByService; GET only that ID.
        for key, api_id in online_ids.items():
            if key in api_by_id:
                continue
            try:
                value = reader.call(request, ARM + api_id + "?api-version=" + API_VERSION)
                hydrated = _hydrate_api(value, api_id, api_by_id, revisions)
                with reader.lock:
                    if reader.budget.max_items is not None and reader.total >= reader.budget.max_items:
                        raise ValueError("resource_limit")
                    reader.total += 1
                api_by_id[key] = hydrated
                fact["apis"].append(hydrated)
            except Exception as exc:
                code = "resource_limit" if str(exc) == "resource_limit" else "revision_get_unavailable"
                fact["_coverage"]["revisions"] = {"status": "partial", "error": {"code": code}}
                return scope, fact
        for api_id in online_ids.values():
            _attach(api_by_id[api_id.casefold()], "diagnostics",
                    _read(reader, request, api_id, "diagnostics", _diagnostic))
        return scope, fact
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:
        for scope, fact in pool.map(service_work, service_items.values()):
            if by_scope.get(scope) is not None:
                by_scope[scope].append(fact)
    result = []
    for scope, items in by_scope.items():
        if items is None:
            result.append({"type": "apim_native", "scope": scope, "service": "Microsoft.ApiManagement", "status": "partial", "items": [], "error": {"code": "parent_inventory_unavailable"}})
        else:
            result.append({"type": "apim_native", "scope": scope, "service": "Microsoft.ApiManagement", "status": "collected" if items else "empty", "items": items})
    return result
