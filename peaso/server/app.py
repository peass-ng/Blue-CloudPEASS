"""Tenant isolation is enforced at every database/artifact boundary."""
from contextlib import asynccontextmanager
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
from .config import Settings
from .models import ConnectorCreate, ConnectorPatch, ScanCreate, ScheduleCreate, SchedulePatch
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

    def owned_report(tenant, ident):
        row = store.job(tenant, ident)
        if row["status"] != "completed" or not row["report"]:
            raise HTTPException(409, "Report is available after scan completion")
        value = artifacts.get(tenant, row["report"])
        value["runtime"] = store.public_job(row)["runtime"]
        return value

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
        return {"tenant_id": user.tenant_id, "plan": "paid" if user.paid else "free", "weekly_limit": user.weekly_limit, "weekly_used": store.usage(user.tenant_id), "auth_mode": settings.auth_mode, "runtime_mode": "hosted" if settings.auth_mode == "cognito" else "local", "connector_auth_methods": auth_capabilities(settings)}

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
        if settings.auth_mode == "cognito" and private["auth"].get("external_id"):
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
        value = owned_report(user.tenant_id, ident)
        if format == "markdown":
            from peaso.reports import render_markdown
            content, media, ext = render_markdown(value), "text/markdown", "md"
        else:
            content, media, ext = json.dumps(value, indent=2), "application/json", "json"
        return Response(content, media_type=media, headers={"Content-Disposition": f'attachment; filename="peaso-{store.job(user.tenant_id, ident)["id"]}.{ext}"'})

    @app.get("/api/scans/{ident}/findings")
    def findings(ident: str, categories: str | None = None, framework: str | None = None, severity: str | None = None, service: str | None = None, status: str | None = None, search: str | None = None, user=Depends(identity)):
        values = owned_report(user.tenant_id, ident).get("findings", [])
        def selected(finding):
            for name, query in (("category", categories), ("severity", severity), ("service", service), ("status", status)):
                if query and str(finding.get(name, "")).lower() not in {item.strip().lower() for item in query.split(",")}:
                    return False
            if framework and not {str(item).lower() for item in finding.get("frameworks", [])} & {item.strip().lower() for item in framework.split(",")}:
                return False
            return not search or search.casefold() in json.dumps(finding).casefold()
        return {"items": [finding for finding in values if selected(finding)]}

    @app.get("/api/scans/{ident}/graphs/{kind}")
    def graph(ident: str, kind: Literal["network", "iam"], max_nodes: int | None = Query(default=None, ge=1, le=100000), user=Depends(identity)):
        value = owned_report(user.tenant_id, ident).get("graphs", {}).get(kind, {"nodes": [], "edges": []})
        if max_nodes is not None:
            from peaso.analysis import project_graph
            # The report retains the complete graph; projection is only a response view.
            return project_graph(value, max_nodes)
        return value

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
