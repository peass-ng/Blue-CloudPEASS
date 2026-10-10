"""Tenant isolation is enforced at every database/artifact boundary."""
from contextlib import asynccontextmanager
from functools import lru_cache
import json
import os
from pathlib import Path
import time
from typing import Literal
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from peaso.auth import Authenticator, CredentialCipher, redact
from peaso.auth.secrets import credential_values
from peaso.storage import SQLiteStore, StoreError, FileArtifacts
from peaso.storage.runtime import stores, WorkflowDispatcher
from peaso.storage.reports import finding_summary
from .config import Settings
from .models import ConnectorCreate, ConnectorPatch, ScanCreate, ScheduleCreate, SchedulePatch, ReachabilityQuery
from .validation import validate_connector, validate_selectors, auth_capabilities


def create_app(settings=None, *, store=None, authenticator=None, artifacts=None):
    settings = settings or Settings()
    if store is None or artifacts is None:
        runtime_store, runtime_artifacts = stores(settings)
        store, artifacts = store or runtime_store, artifacts or runtime_artifacts
    cipher = CredentialCipher(settings.identity_dir)
    authenticator = authenticator or Authenticator(settings)
    if isinstance(authenticator, Authenticator):
        authenticator.store = store
    dispatcher = WorkflowDispatcher()
    app = FastAPI(title="PEASO defensive cloud posture API", version="1.0.0")
    app.state.settings, app.state.store = settings, store
    app.state.cipher, app.state.authenticator, app.state.artifacts = cipher, authenticator, artifacts
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.origins), allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type", "Idempotency-Key"], allow_credentials=settings.auth_mode == "cognito")

    @app.middleware("http")
    async def protect(request: Request, call_next):
        origin = request.headers.get("origin")
        if origin and origin not in settings.origins:
            return JSONResponse({"detail": "Origin not allowed"}, status_code=403)
        if settings.auth_mode == "local":
            host = request.url.hostname
            if host not in {"localhost", "127.0.0.1", "::1"}:
                return JSONResponse({"detail": "Host not allowed"}, status_code=403)
        try:
            content_length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return JSONResponse({"detail": "Invalid request length"}, status_code=400)
        if content_length > 16 * 1024 * 1024:
            return JSONResponse({"detail": "Request too large"}, status_code=413)
        try:
            response = await call_next(request)
        except Exception:
            return JSONResponse({"detail": "Request processing failed"}, status_code=500)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(StoreError)
    async def storage_error(request, exc):
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's default error response includes rejected input (credentials).
        return JSONResponse({"detail": [{"loc": e["loc"], "type": e["type"], "msg": "Invalid field"} for e in exc.errors()]}, status_code=422)

    def identity(request: Request, authorization: str | None = Header(default=None)):
        if not authorization and settings.auth_mode == "cognito":
            cookie = request.cookies.get("__Secure-ht_refresh")
            if cookie:
                if request.method not in {"GET", "HEAD", "OPTIONS"} and request.headers.get("origin") not in settings.origins:
                    raise HTTPException(403, "Origin required for cookie-authenticated writes")
                return authenticator.authenticate_refresh(cookie)
        return authenticator.authenticate(authorization)

    def public_connector(row):
        data = json.loads(row["data"])
        auth = cipher.decrypt(row["auth"])
        # Data was sanitized before the generated routing ID was appended.
        # Snapshot payloads are private evidence, available only through owned reports.
        if "options" in data:
            data["options"].pop("snapshot", None)
        data["auth"] = {"configured": bool(auth["auth"]), "fields": sorted(auth["auth"])}
        return data

    def owned_bundle(tenant, ident):
        row = store.job(tenant, ident)
        if row["status"] != "completed" or not row["report"]:
            raise HTTPException(409, "Report is available after scan completion")
        return row, artifacts.get(tenant, row["report"])

    def owned_report(tenant, ident):
        row, bundle = owned_bundle(tenant, ident)
        value = artifacts.get(tenant, bundle["report_json"]) if bundle.get("bundle_version") == 1 else bundle
        value["runtime"] = store.public_job(row)["runtime"]
        return value

    def signed_download(tenant, reference, format="json", filename=None):
        return {"download_url": artifacts.presign(tenant, reference, filename), "expires_in": 300, "format": format}

    @lru_cache(maxsize=4)
    def finding_index(tenant, report_reference, references):
        # Cache only immutable, credential-free summaries, never download URLs.
        return tuple(item for reference in references for item in artifacts.get(tenant, reference)["items"])

    @app.get("/api/health")
    def health():
        if hasattr(store, "health"):
            store.health()
        else:
            with store.connect() as db:
                db.execute("SELECT 1")
        return {"status": "ok", "auth_mode": settings.auth_mode, "source_url": os.getenv("PEASO_SOURCE_URL"), "source_version": os.getenv("PEASO_SOURCE_VERSION")}

    @app.get("/api/me")
    def me(user=Depends(identity)):
        return {"tenant_id": user.tenant_id, "plan": "paid" if user.paid else "free", "weekly_limit": user.weekly_limit, "weekly_used": store.usage(user.tenant_id), "auth_mode": settings.auth_mode, "runtime_mode": "hosted" if settings.auth_mode == "cognito" else "local", "connector_auth_methods": auth_capabilities(settings), "scan_timeout_seconds": settings.scan_timeout}

    @app.get("/api/connectors")
    def connectors(user=Depends(identity)):
        return {"items": [public_connector(row) for row in store.connectors(user.tenant_id)]}

    @app.post("/api/connectors", status_code=201)
    def add_connector(body: ConnectorCreate, user=Depends(identity)):
        data = body.model_dump()
        auth = data.pop("auth")
        validate_connector(body.provider, auth, data["options"], settings)
        data["input_mode"] = "offline_snapshot" if "snapshot" in data["options"] else "demo" if data["options"].get("demo") else "live"
        # Encrypt the whole connector input too: secrets can hide in arbitrary options.
        private_input = {"auth": auth, "options": data.pop("options")}
        data["options"] = redact(private_input["options"], tuple(credential_values(auth)))
        data["options"].pop("snapshot", None)
        provider, input_mode = data.pop("provider"), data.pop("input_mode")
        public = dict(redact(data, tuple(credential_values(auth))), provider=provider, input_mode=input_mode)
        value = store.add_connector(user.tenant_id, public, cipher.encrypt(private_input))
        return connector(value["id"], user)

    @app.get("/api/connectors/{ident}")
    def connector(ident: str, user=Depends(identity)):
        row = store.connector(user.tenant_id, ident)
        data = json.loads(row["data"])
        private = cipher.decrypt(row["auth"])
        data["auth"] = {"configured": bool(private["auth"]), "fields": sorted(private["auth"])}
        if settings.auth_mode == "cognito" and private["auth"].get("external_id") and private["auth"].get("method") in {"assume_role", "task_role"} and not private["auth"].get("aws_access_key_id"):
            data["onboarding"] = {"external_id": private["auth"]["external_id"], "role_arn": private["auth"].get("role_arn")}
        return data

    @app.patch("/api/connectors/{ident}")
    def update_connector(ident: str, body: ConnectorPatch, user=Depends(identity)):
        row = store.connector(user.tenant_id, ident)
        private = cipher.decrypt(row["auth"])
        patch = body.model_dump(exclude_none=True)
        if "auth" in patch:
            private["auth"] = patch.pop("auth")
        if "options" in patch:
            private["options"] = patch["options"]
            patch["options"] = redact(patch["options"], tuple(credential_values(private["auth"])))
            patch["options"].pop("snapshot", None)
        validate_connector(json.loads(row["data"])["provider"], private["auth"], private["options"], settings, server_external_id="auth" not in body.model_fields_set)
        patch["input_mode"] = "offline_snapshot" if "snapshot" in private["options"] else "demo" if private["options"].get("demo") else "live"
        input_mode = patch.pop("input_mode")
        store.update_connector(user.tenant_id, ident, dict(redact(patch, tuple(credential_values(private["auth"]))), input_mode=input_mode), cipher.encrypt(private))
        return connector(ident, user)

    @app.delete("/api/connectors/{ident}", status_code=204)
    def delete_connector(ident: str, user=Depends(identity)):
        store.delete_connector(user.tenant_id, ident)
        return Response(status_code=204)

    @app.get("/api/scans")
    def scans(user=Depends(identity)):
        store.expire()
        return {"items": store.jobs(user.tenant_id)}

    @app.post("/api/scans", status_code=201)
    def add_scan(body: ScanCreate, user=Depends(identity), idempotency_key: str | None = Header(default=None)):
        if idempotency_key is not None and (not idempotency_key or len(idempotency_key) > 200):
            raise HTTPException(422, "Invalid idempotency key")
        owned = store.connector(user.tenant_id, body.connector_id)
        validate_selectors(body.model_dump(), json.loads(owned["data"])["provider"])
        value = store.enqueue(user.tenant_id, body.model_dump(), user.weekly_limit, settings.scan_timeout, idempotency_key)
        if value["status"] == "queued":
            dispatcher.dispatch(user.tenant_id, value)
        return value

    @app.get("/api/scans/{ident}")
    def scan(ident: str, user=Depends(identity)):
        store.expire()
        return store.public_job(store.job(user.tenant_id, ident))

    @app.post("/api/scans/{ident}/cancel")
    def cancel(ident: str, user=Depends(identity)):
        return store.cancel(user.tenant_id, ident)

    @app.get("/api/scans/{ident}/report")
    def report(ident: str, format: Literal["json", "markdown"] = "json", user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        ext = "md" if format == "markdown" else "json"
        filename = f"peaso-{row['id']}.{ext}"
        if bundle.get("bundle_version") == 1:
            reference = bundle["report_markdown" if format == "markdown" else "report_json"]
            if hasattr(artifacts, "presign"):
                return signed_download(user.tenant_id, reference, format, filename)
            if format == "markdown":
                return Response(artifacts.get_text(user.tenant_id, reference), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
        value = owned_report(user.tenant_id, ident)
        if format == "markdown":
            from peaso.reports import render_markdown
            content, media, ext = render_markdown(value), "text/markdown", "md"
        else:
            content, media, ext = json.dumps(value, indent=2), "application/json", "json"
        return Response(content, media_type=media, headers={"Content-Disposition": f'attachment; filename="peaso-{store.job(user.tenant_id, ident)["id"]}.{ext}"'})

    @app.get("/api/scans/{ident}/findings")
    def findings(ident: str, categories: str | None = None, framework: str | None = None, severity: str | None = None, service: str | None = None, status: str | None = None, search: str | None = None, group_by: Literal["service", "check_id", "resource_id"] = "service", offset: int = Query(default=0, ge=0), limit: int = Query(default=500, ge=1, le=500), user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        requested_frameworks = {item.strip().lower() for item in framework.split(",")} if framework else set()
        from peaso.engine import FRAMEWORK_ALIASES
        requested_frameworks.update(FRAMEWORK_ALIASES.get(item, item).lower() for item in tuple(requested_frameworks))
        version_checks = {check for version, checks in bundle.get("framework_filters", {}).items() if version.lower() in requested_frameworks for check in checks}
        def selected(finding):
            for name, query in (("category", categories), ("severity", severity), ("service", service), ("status", status)):
                if query and str(finding.get(name, "")).lower() not in {item.strip().lower() for item in query.split(",")}:
                    return False
            if framework and not {str(item).lower() for item in finding.get("frameworks", [])} & requested_frameworks and finding["check_id"] not in version_checks:
                return False
            return not search or search.casefold() in json.dumps(finding).casefold()
        selected_rows = []
        facets = {"services": set(), "statuses": set(), "frameworks": set()}
        groups = [finding_index(user.tenant_id, row["report"], tuple(chunk["index_reference"] for chunk in bundle["finding_chunks"]))] if bundle.get("bundle_version") == 1 else [bundle.get("findings", [])]
        for group in groups:
            for value in group:
                if not categories or str(value.get("category", "")).lower() in {item.strip().lower() for item in categories.split(",")}:
                    facets["services"].add(value.get("service", ""))
                    facets["statuses"].add(value.get("status", ""))
                    facets["frameworks"].update(value.get("frameworks", []))
                if not selected(value):
                    continue
                selected_rows.append(finding_summary(value))
        selected_rows.sort(key=lambda item: (str(item.get(group_by, "")), item["id"]))
        count = len(selected_rows)
        output = selected_rows[offset:offset + limit]
        return {"items": output, "offset": offset, "limit": limit, "total": count, "has_more": offset + len(output) < count, "next_offset": offset + len(output) if offset + len(output) < count else None, "facets": {key: sorted(value) for key, value in facets.items()}}

    # :path because finding ids embed ARNs/resource paths with "/" (raw or %2F-encoded both arrive decoded).
    @app.get("/api/scans/{ident}/findings/{finding_id:path}")
    def finding_detail(ident: str, finding_id: str, user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        groups = (artifacts.get(user.tenant_id, chunk["reference"])["items"] for chunk in bundle["finding_chunks"] if chunk["first_id"] <= finding_id <= chunk["last_id"]) if bundle.get("bundle_version") == 1 else [bundle.get("findings", [])]
        for group in groups:
            for value in group:
                if value["id"] == finding_id:
                    if value.get("_detail_reference"):
                        if hasattr(artifacts, "presign"):
                            return signed_download(user.tenant_id, value["_detail_reference"])
                        return artifacts.get(user.tenant_id, value["_detail_reference"])
                    if len(json.dumps(value).encode()) > 4 * 1024 * 1024 and hasattr(artifacts, "presign"):
                        raise HTTPException(413, "Finding exceeds the API detail budget; download the complete JSON report for this evidence")
                    return value
        raise HTTPException(404, "Finding not found")

    @app.get("/api/scans/{ident}/summary")
    def summary(ident: str, user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        value = dict(bundle["summary"]) if bundle.get("bundle_version") == 1 else {key: value for key, value in bundle.items() if key not in {"findings", "resources", "coverage", "graphs", "snapshot"}}
        value.update(runtime=store.public_job(row)["runtime"], finding_count=bundle.get("finding_count", len(bundle.get("findings", []))), coverage_count=bundle.get("coverage_count", len(bundle.get("coverage", []))))
        return value

    @app.get("/api/scans/{ident}/coverage")
    def coverage(ident: str, offset: int = Query(default=0, ge=0), limit: int = Query(default=500, ge=1, le=500), user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        output, count = [], 0
        groups = (artifacts.get(user.tenant_id, reference)["items"] for reference in bundle["coverage_chunks"]) if bundle.get("bundle_version") == 1 else [bundle.get("coverage", [])]
        for group in groups:
            for value in group:
                if offset <= count < offset + limit:
                    output.append(value)
                count += 1
        return {"items": output, "offset": offset, "limit": limit, "total": count, "has_more": offset + len(output) < count, "next_offset": offset + len(output) if offset + len(output) < count else None}

    @app.post("/api/scans/{ident}/reachability")
    def reachability(ident: str, body: ReachabilityQuery, user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        reference = bundle.get("network_snapshot")
        if not reference:
            raise HTTPException(409, "This report has no scoped network facts; collect a new scan")
        snapshot = artifacts.get(user.tenant_id, reference)
        from peaso.analysis.reachability import evaluate_reachability
        try:
            result = evaluate_reachability(snapshot, **body.model_dump())
        except ValueError:
            raise HTTPException(422, "Invalid selected flow query") from None
        if result.get("snapshot_id") != bundle["summary"]["snapshot_id"]:
            raise HTTPException(409, "Captured network facts do not match the owned report")
        return result

    @app.get("/api/scans/{ident}/graphs/{kind}")
    def graph(ident: str, kind: Literal["network", "iam", "privesc"], max_nodes: int | None = Query(default=None, ge=1, le=100000), user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        if kind == "privesc":
            # Already aggregated: never project_graph it (dropping an aggregate drops every member reached through it).
            if bundle.get("bundle_version") == 1 and hasattr(artifacts, "presign") and bundle.get("graphs", {}).get("privesc"):
                if max_nodes is not None and max_nodes != 500:
                    raise HTTPException(422, "Hosted graphs support max_nodes=500 or a complete graph without max_nodes")
                return signed_download(user.tenant_id, bundle["graph_projections" if max_nodes is not None else "graphs"]["privesc"])
            value = privesc_graph(user.tenant_id, bundle)
            if max_nodes is not None:
                from peaso.storage.reports import privesc_projection
                return privesc_projection(value, max_nodes)
            return value
        if bundle.get("bundle_version") == 1:
            reference = bundle["graphs"][kind]
            if hasattr(artifacts, "presign"):
                if max_nodes is not None:
                    if max_nodes != 500:
                        raise HTTPException(422, "Hosted graphs support max_nodes=500 or a complete graph without max_nodes")
                    reference = bundle["graph_projections"][kind]
                return signed_download(user.tenant_id, reference)
            value = artifacts.get(user.tenant_id, reference)
        else:
            value = bundle.get("graphs", {}).get(kind, {"nodes": [], "edges": []})
        if max_nodes is not None:
            from peaso.analysis import project_graph
            # The report retains the complete graph; projection is only a response view.
            return project_graph(value, max_nodes)
        return value

    @lru_cache(maxsize=4)
    def privesc_artifact_index(tenant, reference):
        # Immutable, tenant-scoped artifact; the cache key includes the tenant-checked reference.
        from peaso.privesc.queries import GraphIndex
        return GraphIndex(artifacts.get(tenant, reference))

    def privesc_graph(tenant, bundle):
        if bundle.get("bundle_version") == 1:
            reference = bundle.get("graphs", {}).get("privesc")
            return artifacts.get(tenant, reference) if reference else {"nodes": [], "edges": []}
        return bundle.get("graphs", {}).get("privesc") or {"nodes": [], "edges": []}

    def privesc_index(tenant, ident):
        row, bundle = owned_bundle(tenant, ident)
        try:
            from peaso.privesc.queries import GraphIndex
        except ImportError:
            raise HTTPException(503, "Privilege-escalation queries are not available in this deployment") from None
        reference = bundle.get("graphs", {}).get("privesc") if bundle.get("bundle_version") == 1 else None
        index = privesc_artifact_index(tenant, reference) if reference else GraphIndex(privesc_graph(tenant, bundle))
        return row, bundle, index

    def page(items, offset, limit):
        output = items[offset:offset + limit]
        more = offset + len(output) < len(items)
        return {"items": output, "offset": offset, "limit": limit, "total": len(items), "has_more": more, "next_offset": offset + len(output) if more else None}

    def known_privesc_node(index, node_id):
        return node_id in index.nodes or node_id in index.member_of_target or node_id in index.member_of_source or node_id in index.out

    @app.get("/api/scans/{ident}/privesc/admins")
    def privesc_admins(ident: str, max_depth: int = Query(default=6, ge=1, le=20), include_unknown: bool = True, offset: int = Query(default=0, ge=0), limit: int = Query(default=500, ge=1, le=500), user=Depends(identity)):
        from peaso.privesc import queries
        row, bundle, index = privesc_index(user.tenant_id, ident)
        return page(queries.reach_admin(index, max_depth=max_depth, include_unknown=include_unknown), offset, limit)

    @app.get("/api/scans/{ident}/privesc/paths")
    def privesc_paths(ident: str, source: str | None = Query(default=None, max_length=2000), source_alias: str | None = Query(default=None, alias="from", max_length=2000),
                      target: str | None = Query(default=None, max_length=2000), target_alias: str | None = Query(default=None, alias="to", max_length=2000),
                      max_depth: int = Query(default=6, ge=1, le=20), limit: int = Query(default=10, ge=1, le=100), include_unknown: bool = True, user=Depends(identity)):
        from peaso.privesc import queries
        source, target = source or source_alias, target or target_alias
        if not source:
            raise HTTPException(422, "source (or from) is required")
        row, bundle, index = privesc_index(user.tenant_id, ident)
        if not known_privesc_node(index, source):
            raise HTTPException(404, "Principal not found in the privilege-escalation map")
        items = queries.shortest_paths(index, source, target, max_depth=max_depth, limit=limit, include_unknown=include_unknown)
        return {"items": items, "total": len(items), "source": source, "target": target, "max_depth": max_depth, "limit": limit}

    @app.get("/api/scans/{ident}/privesc/broad")
    def privesc_broad(ident: str, min_targets: int = Query(default=50, ge=1, le=10_000_000), include_unknown: bool = False, offset: int = Query(default=0, ge=0), limit: int = Query(default=500, ge=1, le=500), user=Depends(identity)):
        from peaso.privesc import queries
        row, bundle, index = privesc_index(user.tenant_id, ident)
        return page(queries.broad_reach(index, min_targets=min_targets, include_unknown=include_unknown), offset, limit)

    @app.get("/api/scans/{ident}/privesc/principals/{principal_id:path}")
    def privesc_principal(ident: str, principal_id: str, user=Depends(identity)):
        from peaso.privesc import queries
        row, bundle, index = privesc_index(user.tenant_id, ident)
        if not known_privesc_node(index, principal_id):
            raise HTTPException(404, "Principal not found in the privilege-escalation map")
        if bundle.get("bundle_version") == 1:
            summaries = finding_index(user.tenant_id, row["report"], tuple(chunk["index_reference"] for chunk in bundle["finding_chunks"]))
        else:
            summaries = [finding_summary(f) for f in bundle.get("findings", [])]
        findings = [f for f in summaries if f.get("category") == "privesc"]
        card = queries.principal_card(index, principal_id, findings)
        for key in ("outgoing", "incoming", "findings"):
            card[key + "_total"] = len(card.get(key, []))
            card[key] = card.get(key, [])[:500]
        from peaso.engine import privesc_technique_details
        catalog_details = privesc_technique_details(sorted({t for key in ("outgoing", "incoming") for e in card[key] for t in e.get("techniques", [])}))
        for key in ("outgoing", "incoming"):
            # Edges are cached graph objects: copy before decorating.
            card[key] = [dict(edge, technique_details=[dict(catalog_details[t], edge_confidence=edge.get("confidence"),
                                                            evidence=edge.get("evidence_refs", [])) for t in edge.get("techniques", [])])
                         for edge in card[key]]
        card["technique_details"] = catalog_details
        return card

    @app.get("/api/schedules")
    def schedules(user=Depends(identity)):
        return {"items": store.schedules(user.tenant_id)}

    @app.post("/api/schedules", status_code=201)
    def add_schedule(body: ScheduleCreate, user=Depends(identity)):
        owned = store.connector(user.tenant_id, body.connector_id)
        validate_selectors(body.model_dump(), json.loads(owned["data"])["provider"])
        data = body.model_dump(exclude={"enabled", "next_run_at"})
        next_run = body.next_run_at.timestamp() if body.next_run_at else time.time() + body.interval_hours * 3600
        return store.add_schedule(user.tenant_id, data, next_run, body.enabled)

    @app.patch("/api/schedules/{ident}")
    def update_schedule(ident: str, body: SchedulePatch, user=Depends(identity)):
        return store.update_schedule(user.tenant_id, ident, body.model_dump(exclude_none=True, exclude={"enabled", "next_run_at"}), body.next_run_at.timestamp() if body.next_run_at else None, body.enabled)

    @app.delete("/api/schedules/{ident}", status_code=204)
    def delete_schedule(ident: str, user=Depends(identity)):
        store.delete_schedule(user.tenant_id, ident)
        return Response(status_code=204)

    @app.get("/api/catalog")
    def catalog(user=Depends(identity)):
        from peaso.engine import get_catalog
        return get_catalog()

    # Built frontend is served by the same API origin when available.
    static = Path(__file__).resolve().parents[1] / "frontend_dist"
    if static.is_dir():
        from fastapi.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=static, html=True), name="frontend")
    return app
