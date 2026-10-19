"""Tenant isolation is enforced at every database/artifact boundary."""
from contextlib import asynccontextmanager
from collections import OrderedDict
from concurrent.futures import CancelledError, Future
from dataclasses import replace
from functools import lru_cache
import json
import hashlib
import logging
import os
from pathlib import Path
import re
import time
from threading import Lock
import unicodedata
import uuid
from typing import Literal
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from peaso.auth import Authenticator, CredentialCipher, Identity, redact
from peaso.auth.api_keys import ApiKeyCreate, MAX_LIST_PAGE, active as active_api_key, matches as matches_api_key, mint_key, parse_key, public as public_api_key, valid_key_id
from peaso.auth.secrets import credential_values
from peaso.storage import SQLiteStore, StoreError, FileArtifacts
from peaso.storage.runtime import stores, WorkflowDispatcher
from peaso.storage.reports import finding_summary
from .config import Settings
from .models import ConnectorCreate, ConnectorCheck, ConnectorPatch, ScanCreate, AttackLogSource, AttackLogRun, ScheduleCreate, SchedulePatch, ReachabilityQuery, ReachabilityBatchQuery, ReachabilityMatrixQuery, ReachabilityGridQuery, WorkspaceCreate, WorkspaceInvite, WorkspaceRole
from .validation import validate_connector, validate_selectors, auth_capabilities, COLLECTOR_ROLE_ARN, CUSTOMER_ROLE_TEMPLATE_URL, EXTERNAL_ID_PREFIX


def _safe_api_failure_details(exc):
    """Log bounded exception class and trusted code coordinates only."""
    allowed = {"ValueError", "TypeError", "KeyError", "IndexError", "AttributeError", "ImportError",
               "ModuleNotFoundError", "PermissionError", "TimeoutError", "RuntimeError", "AssertionError"}
    name = type(exc).__name__
    details = {"exception_type": name if name in allowed else "provider_error",
               "source_file": "unavailable", "source_function": "unavailable", "source_line": 0}
    root = Path(__file__).resolve().parents[1]
    trace = exc.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        try:
            relative = Path(code.co_filename).resolve().relative_to(root)
        except (ValueError, OSError):
            trace = trace.tb_next
            continue
        function = code.co_name
        if (relative.suffix == ".py" and all(part.replace("_", "").replace(".", "").isalnum() for part in relative.parts)
                and function.isidentifier() and len(function) <= 128):
            details.update(source_file="peaso/" + relative.as_posix(),
                           source_function=function, source_line=trace.tb_lineno)
        trace = trace.tb_next
    return details


def _credential_target_coverage(bundle):
    """Expose bounded collector target skips alongside report coverage rows."""
    summary = bundle.get("summary", bundle)
    metadata = summary.get("snapshot_metadata", {})
    rows = metadata.get("scan_coverage", []) if isinstance(metadata, dict) else []
    if not isinstance(rows, list):
        return []
    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        account, arn = row.get("account"), row.get("role_arn")
        if (row.get("level") == "credential_target" and row.get("status") == "not_collected"
                and row.get("error_code") == "duplicate_account_target"
                and isinstance(account, str) and re.fullmatch(r"[0-9]{12}", account)
                and isinstance(arn, str) and re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}", arn)):
            result.append({"level": "credential_target", "scope": account, "account": account,
                "role_arn": arn, "status": "not_collected", "code": "duplicate_account_target",
                "error_code": "duplicate_account_target"})
    return result


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
    app = FastAPI(title="HackTricks CSPM API", version="1.0.0")
    app.state.settings, app.state.store = settings, store
    app.state.cipher, app.state.authenticator, app.state.artifacts = cipher, authenticator, artifacts
    # A small per-app index for immutable pre-count report manifests. Entries
    # contain counts only; no coverage rows, credentials, or artifact payloads.
    coverage_counts = OrderedDict()
    coverage_inflight = {}
    coverage_counts_lock = Lock()
    max_legacy_coverage_chunks = 1024
    def prepared_auth(user, prepared_id, provider):
        if not isinstance(prepared_id, str):
            raise HTTPException(422, "Prepare the hosted connector before checking access")
        try:
            record = cipher.decrypt(prepared_id)
        except Exception:
            record = None
        if not record or record.get("tenant") != user.tenant_id or record.get("provider") != provider or record.get("expires", 0) < time.time():
            raise HTTPException(422, "Hosted setup has expired; reopen the setup guide")
        return record["auth"]

    def connector_digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

    def verify_check_token(user, token, payload):
        if not token:
            raise HTTPException(422, "Run Check access before saving this connector")
        try:
            record = cipher.decrypt(token)
        except Exception:
            record = None
        if (not record or record.get("tenant") != user.tenant_id or record.get("expires", 0) < time.time()
                or record.get("digest") != connector_digest(payload)
                or record.get("status") not in {"pass", "warning"}):
            raise HTTPException(422, "Access check expired or connector settings changed; check access again")
        if record.get("credential_expires_at") and record["credential_expires_at"] < time.time() + 3600:
            raise HTTPException(422, "Temporary credential has less than one hour remaining; check access again")
    app.state.legacy_coverage_count_index = coverage_counts
    app.state.legacy_coverage_count_inflight = coverage_inflight
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
        except Exception as exc:
            details = _safe_api_failure_details(exc)
            logging.getLogger("peaso.server").error(
                "requestfailed type=%s source=%s:%s function=%s",
                details["exception_type"], details["source_file"],
                details["source_line"], details["source_function"],
                extra={
                    "method": request.method if request.method in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"} else "<other>",
                    "route": getattr(request.scope.get("route"), "path", "<unmatched>"),
                    "request_id": uuid.uuid4().hex,
                    **details,
                },
            )
            return JSONResponse({"detail": "Request processing failed"}, status_code=500)
        if "cache-control" not in response.headers:  # catalog views opt into ETag revalidation
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

    def account_identity(request: Request, authorization: str | None = Header(default=None)):
        if authorization and authorization.startswith("Bearer ") and parse_key(authorization[7:]):
            token = authorization[7:]
            key_id = parse_key(token)
            value = store.api_key(key_id) if key_id else None
            if not value or not matches_api_key(token, value["secret_sha256"]) or not active_api_key(value):
                raise HTTPException(401, "Invalid authentication")
            if request.method not in {"GET", "HEAD"} or request.url.path.startswith("/api/api-keys"):
                raise HTTPException(403, "API key is read-only")
            if settings.auth_mode == "cognito":
                if not isinstance(authenticator, Authenticator):
                    raise HTTPException(503, "Identity verification temporarily unavailable")
                attributes = authenticator.live_user(value["tenant"], value.get("cognito_username"))
                paid, plan_source, plan_expires_at = authenticator.entitlement(value["tenant"], username=value.get("cognito_username"), attributes=attributes)
                email, name, email_verified = authenticator.public_profile(attributes)
            else:
                paid, plan_source, plan_expires_at = False, None, None
                email, name, email_verified = None, None, None
            if not store.touch_api_key(value["tenant"], key_id):
                raise HTTPException(401, "Invalid authentication")
            return Identity(value["tenant"], paid, auth_kind="api_key", cognito_username=value.get("cognito_username"),
                            email=email, email_verified=email_verified, name=name,
                            plan_source=plan_source, plan_expires_at=plan_expires_at)
        if not authorization and settings.auth_mode == "cognito":
            cookie = request.cookies.get("__Secure-ht_refresh")
            if cookie:
                if request.method not in {"GET", "HEAD", "OPTIONS"} and request.headers.get("origin") not in settings.origins:
                    raise HTTPException(403, "Origin required for cookie-authenticated writes")
                return authenticator.authenticate_refresh(cookie)
        return authenticator.authenticate(authorization)

    def identity(request: Request, account=Depends(account_identity)):
        selected = request.headers.get("x-workspace-id")
        if not selected or selected == "personal":
            return account
        if account.auth_kind == "api_key" or not re.fullmatch(r"ws_[a-f0-9]{32}", selected):
            raise HTTPException(403, "Workspace access denied")
        role = store.workspace_role(selected, account.tenant_id)
        if role not in {"read", "write", "admin"}:
            raise HTTPException(403, "Workspace access denied")
        read_only_probe = request.method == "POST" and re.fullmatch(r"/api/scans/[a-f0-9]{32}/reachability(?:/(?:batch|matrix|grid))?", request.url.path)
        if role == "read" and request.method not in {"GET", "HEAD"} and not read_only_probe:
            raise HTTPException(403, "Write access is required")
        return replace(account, tenant_id=selected, workspace_role=role)

    def onboarding_details(auth):
        if settings.auth_mode != "cognito" or not auth.get("external_id") or auth.get("method") not in {"assume_role", "task_role"} or auth.get("aws_access_key_id"):
            return None
        from peaso.server.validation import COLLECTOR_ROLE_ARN, CUSTOMER_ROLE_TEMPLATE_URL
        public_template_url = os.getenv("PEASO_PUBLIC_CUSTOMER_ROLE_TEMPLATE_URL", "")
        if not re.fullmatch(
            r"https://hacktricks-cspm-templates-202533532952\.s3\.us-east-1\.amazonaws\.com/customer-role-[a-f0-9]{64}\.json",
            public_template_url,
        ):
            public_template_url = None
        targets = [auth["role_arn"]] if auth.get("role_arn") else []
        targets.extend(item if isinstance(item, str) else item["role_arn"] for item in auth.get("assume_roles", []))
        return {"external_id": auth["external_id"], "collector_role_arn": COLLECTOR_ROLE_ARN,
                "target_role_arns": list(dict.fromkeys(targets)),
                "template_url": CUSTOMER_ROLE_TEMPLATE_URL,
                "quick_create_template_url": public_template_url}

    def gcp_onboarding_details(auth):
        if settings.auth_mode != "cognito" or auth.get("method") != "platform-service-account":
            return None
        from peaso.gcp_platform import PLATFORM_EMAIL, PROOF_VALUE
        return {"service_account_email": PLATFORM_EMAIL,
                "project_label_key": auth["project_proof_label"],
                "project_label_value": PROOF_VALUE}

    def public_connector(row, *, include_onboarding=True):
        data = json.loads(row["data"])
        auth = cipher.decrypt(row["auth"])
        # Data was sanitized before the generated routing ID was appended.
        # Snapshot payloads are private evidence, available only through owned reports.
        if "options" in data:
            data["options"].pop("snapshot", None)
        data["auth"] = {"configured": bool(auth["auth"]), "fields": sorted(auth["auth"])}
        onboarding = onboarding_details(auth["auth"]) if include_onboarding else None
        if onboarding:
            data["onboarding"] = onboarding
        gcp_onboarding = gcp_onboarding_details(auth["auth"]) if include_onboarding else None
        if gcp_onboarding:
            data["gcp_onboarding"] = gcp_onboarding
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

    def check_labels(bundle):
        """check_id -> framework labels (stored once per check); {} for bundles with per-finding labels."""
        value = bundle.get("check_frameworks")
        return value if isinstance(value, dict) else {}

    def with_labels(finding, labels):
        if "frameworks" in finding or not labels:
            return finding
        from peaso.engine import finding_frameworks
        return dict(finding, frameworks=finding_frameworks(finding, labels))

    def check_fields(bundle):
        """The owned report's archived per-check metadata; {} if absent."""
        value = bundle.get("check_meta")
        return value if isinstance(value, dict) else {}

    def with_meta(finding, meta, bundle=None):
        # Per-check fields are hydrated before any filter, facet or summary so every consumer sees full rows.
        if not meta or finding.get("check_id") not in meta:
            return finding
        from peaso.engine import hydrate_finding
        bundle = bundle or {}
        return hydrate_finding(finding, None, meta, bundle.get("check_meta_encoding"),
                               bundle.get("remediation_templates"))

    def with_remediation(finding, bundle):
        from peaso.checks.catalog import description_for
        from peaso.finding_presentation import refresh_finding_presentation, evaluator_contract_fingerprint
        from peaso.remediation import bind_command, exposure_details, template as current_template
        finding = with_meta(finding, check_fields(bundle), bundle)
        cid = finding.get("check_id")
        templates = bundle.get("remediation_templates") or {}
        archived = templates.get(cid) if isinstance(templates, dict) else None
        if isinstance(archived, dict):
            details = dict(archived)
            details["cli"] = [dict(command, code=bind_command(command["code"], finding))
                              for command in archived.get("cli", [])
                              if isinstance(command, dict) and isinstance(command.get("code"), str)]
            finding = dict(finding, remediation_details=details)
        reviewed = current_template(cid, finding.get("provider")) if isinstance(cid, str) else None
        if isinstance(cid, str) and cid.startswith("analysis."):
            # These projections describe explicit stored witness fields, not a
            # current re-evaluation of archived provider configuration.
            finding = dict(finding, guidance_refresh={"version": "archived-finding-presentation-v1",
                "status": "evidence_projection", "allow_summary": True})
            if isinstance(reviewed, dict):
                details = dict(finding.get("remediation_details") or {"cli": []})
                details.update({key: reviewed[key] for key in ("summary", "steps", "caveats") if key in reviewed})
                if not details.get("references") and reviewed.get("references"):
                    details["references"] = reviewed["references"]
                finding = dict(finding, remediation=reviewed["summary"], remediation_details=details)
            allow_summary = True
        elif description_for(cid) is None:
            # Unowned projections (including privilege analysis) retain their
            # original presentation; native-check proof is not applicable.
            allow_summary = True
        else:
            finding, allow_summary = refresh_finding_presentation(finding, description_for(cid), reviewed,
                archived_template=archived, current_evaluator_contract=evaluator_contract_fingerprint())
        if not allow_summary:
            return finding
        from peaso.finding_observation import evidence_summary
        observation = evidence_summary(finding)
        if observation:
            finding = dict(finding, evidence_summary=observation)
        details = finding.get("remediation_details")
        return dict(finding, remediation_details=exposure_details(finding, details)) if isinstance(details, dict) else finding

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
    def me(user=Depends(account_identity)):
        from peaso.gcp_platform import PLATFORM_EMAIL, enabled as gcp_platform_enabled
        return {"tenant_id": user.tenant_id, **({"email": user.email} if user.email else {}),
                **({"email_verified": user.email_verified} if user.email and user.email_verified is not None else {}),
                **({"name": user.name} if user.name else {}), "plan": "paid" if user.paid else "free",
                "auth_kind": user.auth_kind, "weekly_limit": user.weekly_limit, "weekly_used": store.usage(user.tenant_id),
                "plan_source": user.plan_source,
                **({"plan_expires_at": user.plan_expires_at} if user.plan_expires_at is not None else {}),
                "auth_mode": settings.auth_mode, "runtime_mode": "hosted" if settings.auth_mode == "cognito" else "local",
                "connector_auth_methods": auth_capabilities(settings), "scan_timeout_seconds": settings.scan_timeout,
                **({"gcp_platform_service_account_email": PLATFORM_EMAIL} if gcp_platform_enabled(settings) else {})}

    def key_manager(user=Depends(account_identity)):
        if user.auth_kind != "user":
            raise HTTPException(403, "User sign-in required")
        return user

    def workspace_admin(workspace_id, user):
        if not re.fullmatch(r"ws_[a-f0-9]{32}", workspace_id) or store.workspace_role(workspace_id, user.tenant_id) != "admin":
            raise HTTPException(403, "Workspace admin access required")
        return store.workspace(workspace_id)

    @app.get("/api/workspaces")
    def list_workspaces(user=Depends(account_identity)):
        own = {"id": "personal", "name": "Personal Workspace", "role": "admin", "personal": True}
        return {"items": [own] + store.workspaces(user.tenant_id)}

    @app.post("/api/workspaces", status_code=201)
    def create_workspace(body: WorkspaceCreate, user=Depends(account_identity)):
        if user.auth_kind != "user" or not user.paid:
            raise HTTPException(403, "A paid HackTricks Tools account is required to create a workspace")
        name = " ".join(body.name.split())
        if len(name) < 3 or len(name) > 80 or not all(char.isprintable() for char in name):
            raise HTTPException(422, "Enter a workspace name between 3 and 80 characters")
        return store.create_workspace(user.tenant_id, name, unicodedata.normalize("NFKC", name).casefold(), user.email or "")

    @app.get("/api/workspaces/invitations")
    def workspace_invitations(user=Depends(account_identity)):
        if user.auth_kind != "user":
            raise HTTPException(403, "User sign-in required")
        return {"items": store.workspace_invitations(user.tenant_id)}

    @app.post("/api/workspaces/invitations/{workspace_id}/accept")
    def accept_workspace_invitation(workspace_id: str, user=Depends(account_identity)):
        if user.auth_kind != "user":
            raise HTTPException(403, "User sign-in required")
        store.respond_workspace_invitation(workspace_id, user.tenant_id, True)
        return {"accepted": True}

    @app.post("/api/workspaces/invitations/{workspace_id}/decline")
    def decline_workspace_invitation(workspace_id: str, user=Depends(account_identity)):
        if user.auth_kind != "user":
            raise HTTPException(403, "User sign-in required")
        store.respond_workspace_invitation(workspace_id, user.tenant_id, False)
        return {"declined": True}

    @app.get("/api/workspaces/{workspace_id}/people")
    def list_workspace_people(workspace_id: str, user=Depends(account_identity)):
        workspace_admin(workspace_id, user)
        members, invitations = store.workspace_people(workspace_id)
        return {"members": members, "invitations": invitations}

    @app.post("/api/workspaces/{workspace_id}/invitations", status_code=201)
    def invite_workspace_person(workspace_id: str, body: WorkspaceInvite, user=Depends(account_identity)):
        workspace_admin(workspace_id, user)
        if user.auth_kind != "user" or settings.auth_mode != "cognito":
            raise HTTPException(403, "User sign-in required")
        email = body.email.strip()
        if email != body.email or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise HTTPException(422, "Enter a valid account email")
        try:
            recipient = authenticator.find_user_by_email(email)
        except Exception:
            raise HTTPException(503, "Account directory unavailable") from None
        if not recipient:
            raise HTTPException(404, "No verified HackTricks Tools account has this email")
        if recipient["user_id"] == user.tenant_id:
            raise HTTPException(422, "You are already in this workspace")
        store.invite_workspace(workspace_id, recipient["user_id"], recipient["email"], body.role, user.tenant_id)
        return {"email": recipient["email"], "role": body.role}

    @app.delete("/api/workspaces/{workspace_id}/invitations/{member_id}", status_code=204)
    def revoke_workspace_invitation(workspace_id: str, member_id: str, user=Depends(account_identity)):
        workspace_admin(workspace_id, user)
        store.revoke_workspace_invitation(workspace_id, member_id)
        return Response(status_code=204)

    @app.patch("/api/workspaces/{workspace_id}/members/{member_id}")
    def change_workspace_role(workspace_id: str, member_id: str, body: WorkspaceRole, user=Depends(account_identity)):
        workspace_admin(workspace_id, user)
        store.set_workspace_role(workspace_id, member_id, body.role)
        return {"user_id": member_id, "role": body.role}

    @app.delete("/api/workspaces/{workspace_id}/members/{member_id}", status_code=204)
    def remove_workspace_person(workspace_id: str, member_id: str, user=Depends(account_identity)):
        workspace_admin(workspace_id, user)
        store.remove_workspace_member(workspace_id, member_id)
        return Response(status_code=204)

    @app.get("/api/api-keys")
    def list_api_keys(after: str | None = None, limit: int = Query(default=50, ge=1, le=MAX_LIST_PAGE), user=Depends(key_manager)):
        if after is not None and not valid_key_id(after):
            raise HTTPException(422, "Invalid API key cursor")
        rows, next_cursor = store.api_keys(user.tenant_id, after, limit)
        return {"items": [public_api_key(row) for row in rows], "next_cursor": next_cursor}

    @app.post("/api/api-keys", status_code=201)
    def create_api_key(body: ApiKeyCreate, user=Depends(key_manager)):
        now = time.time()
        expiry = body.expires_at.timestamp() if body.expires_at else None
        if expiry is not None and expiry <= now:
            raise HTTPException(422, "Expiry must be in the future")
        key_id, plaintext, digest = mint_key()
        record = {"id": key_id, "name": body.name, "prefix": f"hacktricks_cspm_{key_id}_",
                  "secret_sha256": digest, "created_at": now, "expires_at": expiry,
                  "cognito_username": user.cognito_username if settings.auth_mode == "cognito" else None}
        stored = store.create_api_key(user.tenant_id, record)
        return {**public_api_key(stored), "key": plaintext}

    @app.delete("/api/api-keys/{key_id}", status_code=204)
    def revoke_api_key(key_id: str, user=Depends(key_manager)):
        if not valid_key_id(key_id):
            raise HTTPException(404, "API key not found")
        store.revoke_api_key(user.tenant_id, key_id)
        return Response(status_code=204)

    @app.get("/api/connectors")
    def connectors(user=Depends(identity)):
        return {"items": [public_connector(row, include_onboarding=user.auth_kind != "api_key" and user.workspace_role != "read")
                          for row in store.connectors(user.tenant_id)]}

    @app.post("/api/connectors/prepare")
    def prepare_connector(body: dict, user=Depends(identity)):
        provider, method = body.get("provider"), body.get("method")
        if settings.auth_mode != "cognito" or (provider, method) not in {("aws", "assume_role"), ("gcp", "platform-service-account")}:
            raise HTTPException(422, "This authentication method does not need hosted preparation")
        if provider == "gcp":
            from peaso.gcp_platform import enabled, new_proof_label, PLATFORM_EMAIL, PROOF_VALUE
            if not enabled(settings):
                raise HTTPException(422, "Hosted GCP service account is unavailable")
            generated = {"project_proof_label": new_proof_label()}
            public = {"service_account_email": PLATFORM_EMAIL, "project_label_key": generated["project_proof_label"], "project_label_value": PROOF_VALUE}
        else:
            import secrets
            generated = {"external_id": EXTERNAL_ID_PREFIX + secrets.token_urlsafe(24)}
            public = {"external_id": generated["external_id"], "collector_role_arn": COLLECTOR_ROLE_ARN, "template_url": CUSTOMER_ROLE_TEMPLATE_URL}
        prepared_id = cipher.encrypt({"tenant": user.tenant_id, "provider": provider, "auth": generated, "expires": time.time() + 3600})
        return {"prepared_id": prepared_id, **public}

    @app.post("/api/connectors/check-access")
    def connector_check_access(body: ConnectorCheck, user=Depends(identity)):
        submitted = body.model_dump(exclude={"credential_expires_at", "connector_id", "check_token"})
        auth = dict(body.auth)
        if body.connector_id and not auth:
            row = store.connector(user.tenant_id, body.connector_id)
            auth = dict(cipher.decrypt(row["auth"])["auth"])
        if body.prepared_id:
            auth.update(prepared_auth(user, body.prepared_id, body.provider))
        options = dict(body.options)
        validate_connector(body.provider, auth, options, settings,
                           server_external_id=bool(body.prepared_id or body.connector_id), scopes=body.scopes)
        from .access_check import check_access
        result = check_access(body.provider, auth, body.scopes, options, settings,
                              credential_expires_at=body.credential_expires_at)
        if result["status"] in {"pass", "warning"} and not body.connector_id:
            result["check_token"] = cipher.encrypt({"tenant": user.tenant_id,
                "digest": connector_digest(submitted), "status": result["status"], "expires": time.time() + 600,
                "credential_expires_at": body.credential_expires_at.timestamp() if body.credential_expires_at else None})
        return result

    @app.post("/api/connectors", status_code=201)
    def add_connector(body: ConnectorCreate, user=Depends(identity)):
        data = body.model_dump()
        auth = data.pop("auth")
        check_token = data.pop("check_token", None)
        if settings.require_connector_access_check and "snapshot" not in data["options"] and not data["options"].get("demo"):
            verify_check_token(user, check_token, {**data, "auth": auth})
        prepared_id = data.pop("prepared_id", None)
        if prepared_id:
            auth.update(prepared_auth(user, prepared_id, body.provider))
        validate_connector(body.provider, auth, data["options"], settings,
                           server_external_id=bool(prepared_id), scopes=data["scopes"])
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
        onboarding = onboarding_details(private["auth"]) if user.auth_kind != "api_key" and user.workspace_role != "read" else None
        if onboarding:
            data["onboarding"] = onboarding
        gcp_onboarding = gcp_onboarding_details(private["auth"]) if user.auth_kind != "api_key" and user.workspace_role != "read" else None
        if gcp_onboarding:
            data["gcp_onboarding"] = gcp_onboarding
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
        validate_connector(json.loads(row["data"])["provider"], private["auth"], private["options"], settings,
                           server_external_id="auth" not in body.model_fields_set,
                           scopes=patch.get("scopes", json.loads(row["data"])["scopes"]))
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
        if user.auth_kind != "api_key":
            store.expire()
        # Jobs contain the frozen connector input, including deleted connectors.
        # Decrypt each distinct identity once; return only the human name.
        hints = {}
        return {"items": store.jobs(user.tenant_id, transform=lambda row: public_scan(row, hints))}

    def public_scan(row, hints=None):
        from .scan_names import display_name, identity_hint
        from cryptography.fernet import InvalidToken
        value = store.public_job(row)
        frozen = json.loads(row["connector"])
        data = frozen["data"]
        cache = hints if hints is not None else {}
        scopes = data.get("scopes") or []
        # Historical/imported jobs may not retain encrypted credentials. Naming
        # is optional metadata and must not make their list/detail unavailable.
        encrypted_auth = frozen.get("auth")
        encrypted_auth = encrypted_auth if isinstance(encrypted_auth, str) else None
        key = (data.get("provider"), encrypted_auth, tuple(scopes))
        if key not in cache:
            try:
                private = cipher.decrypt(encrypted_auth) if encrypted_auth else {}
                cache[key] = identity_hint(data.get("provider"), private, scopes)
            except (InvalidToken, ValueError, TypeError, KeyError):
                cache[key] = (None, [], None)
        return dict(value, display_name=display_name(value, data, cache[key]))

    def attack_source(body, user):
        if body.kind == "aws_cloudtrail_s3" and (not body.bucket or not body.prefix or not body.prefix.endswith("/")):
            raise HTTPException(422, "Enter an S3 bucket and a CloudTrail prefix ending in /.")
        if body.kind in {"gcp_audit", "gke_audit"} and not body.project_id:
            raise HTTPException(422, "Select a GCP project that owns the audit logs.")
        if body.kind == "gke_audit" and not body.cluster_id:
            raise HTTPException(422, "Enter the GKE cluster name.")
        if body.kind == "azure_activity_log" and not body.subscription_id:
            raise HTTPException(422, "Select an Azure subscription.")
        row = store.connector(user.tenant_id, body.connector_id)
        data = json.loads(row["data"])
        provider = "aws" if body.kind.startswith("aws_") else "gcp" if body.kind in {"gcp_audit", "gke_audit"} else "azure"
        if data.get("provider") != provider or data.get("input_mode") != "live":
            raise HTTPException(422, "Choose a live connector for the selected audit source.")
        private = cipher.decrypt(row["auth"])
        connector_fingerprint = hashlib.sha256(
            (row["data"] + "\0" + row["auth"]).encode("utf-8")
        ).hexdigest()
        return provider, private["auth"], data.get("scopes", []), private["options"], connector_fingerprint

    def attack_log_error(code):
        return {
            "role_not_in_connector": "The selected role is not configured in this connector.",
            "platform_account_forbidden": "The HackTricks platform account cannot be a log target.",
            "select_connector_role": "Select a target account role from this connector.",
            "role_account_mismatch": "The assumed role returned a different account than its ARN.",
            "account_outside_connector_scope": "Add this AWS account to the connector scopes before reading its logs.",
            "region_outside_connector_scope": "Add this AWS account and Region to the connector scopes before reading its logs.",
            "prefix_must_select_target_account_cloudtrail": "The S3 base prefix must contain the selected account ID followed by /CloudTrail/.",
            "select_cloudtrail_day": "Choose a CloudTrail log day.",
            "invalid_cloudtrail_day": "Choose a valid CloudTrail log day.",
            "future_cloudtrail_day": "The selected CloudTrail day is in the future.",
            "object_size_changed": "A CloudTrail object changed while it was being read; retry the analysis.",
            "decompressed_object_too_large": "A CloudTrail object exceeds the bounded preview size; select a smaller source window.",
            "malformed_cloudtrail_object": "A selected S3 object is not a valid CloudTrail gzip record set.",
            "log_prefix_listing_incomplete": "The selected S3 prefix contains more pages than this preview can inspect; choose a narrower prefix.",
            "select_valid_customer_project": "Enter a valid customer GCP project ID.",
            "platform_project_forbidden": "Choose a different project for audit logs.",
            "project_outside_connector_scope": "Add this project to the GCP connector scope before reading its logs.",
            "select_valid_gke_cluster": "Enter a valid GKE cluster name.",
            "platform_identity_unavailable": "The hosted GCP service account is unavailable.",
            "customer_project_not_approved": "The project is missing this connector's approval label.",
            "log_read_denied": "The connector cannot read this audit source. Grant the logging roles shown below and retry.",
            "log_source_not_found": "The selected audit source or project was not found.",
            "log_read_rate_limited": "The audit service rate limited this read. Retry shortly.",
            "log_read_unavailable": "The audit source could not be read right now.",
            "log_response_too_large": "The audit response exceeds the preview limit.",
            "invalid_log_response": "The audit service returned an invalid response.",
            "select_valid_azure_subscription": "Enter a valid Azure subscription ID.",
            "invalid_connector_scope": "The Azure connector has an invalid subscription scope.",
            "subscription_outside_connector_scope": "Add this subscription to the Azure connector scope before reading its logs.",
            "invalid_azure_log_continuation": "Azure returned an invalid Activity Log continuation; analysis stopped.",
            "invalid_azure_log_response": "Azure returned an invalid Activity Log response.",
            "azure_log_read_failed": "The connector cannot read this subscription's Activity Log. Grant Monitoring Reader and retry.",
            "azure_log_foreign_subscription": "Azure returned events from outside the selected subscription; analysis stopped.",
            "entra_connector_tenant_required": "Set a valid tenant ID on the Azure connector before reading Entra audit logs.",
            "entra_source_tenant_mismatch": "The requested tenant differs from this connector's tenant.",
            "entra_graph_token_unavailable": "The connector could not obtain a Microsoft Graph token.",
            "entra_graph_tenant_mismatch": "The Microsoft Graph token belongs to another tenant.",
            "entra_graph_audience_mismatch": "The connector token is not for Microsoft Graph.",
            "entra_log_read_failed": "Grant Microsoft Graph AuditLog.Read.All application permission and admin consent, then retry.",
            "invalid_entra_log_response": "Microsoft Graph returned an invalid directory audit response.",
            "invalid_entra_log_continuation": "Microsoft Graph returned an invalid directory audit continuation; analysis stopped.",
        }.get(code, "The selected log source could not be read.")

    @app.post("/api/attack-analysis/check-access")
    def attack_log_check_access(body: AttackLogSource, user=Depends(identity)):
        provider, auth, scopes, options, connector_fingerprint = attack_source(body, user)
        from .attack_logs import LogAccessError, check_aws_source
        from .gcp_attack_logs import GcpLogAccessError
        try:
            if provider == "aws":
                result = check_aws_source(auth, options, body, scopes)
            elif provider == "gcp":
                from .gcp_attack_logs import check_gcp_source
                result = check_gcp_source(auth, scopes, options, settings, body)
            elif body.kind == "entra_directory_audit":
                from .entra_attack_logs import check_entra_source
                result = check_entra_source(auth, scopes, options, body)
            else:
                from .azure_attack_logs import check_azure_source
                result = check_azure_source(auth, scopes, options, body)
        except (LogAccessError, GcpLogAccessError) as exc:
            return {"status": "blocked", "reason": attack_log_error(exc.code)}
        except Exception:
            if body.kind == "entra_directory_audit":
                return {"status": "blocked", "reason": "Could not read Microsoft Graph directory audits with this Azure connector. Check its tenant, Graph permission and admin consent."}
            return {"status": "blocked", "reason": "Could not read this log source with the selected connector. Verify CloudTrail LookupEvents or S3 ListBucket/GetObject and, for encrypted objects, KMS Decrypt."}
        if result["source_status"] != "accessible":
            return {"status": "warning", **result}
        try:
            from peaso.attack_detection import load_rules
            product = "kubernetes" if body.kind == "gke_audit" else provider
            rules = load_rules(product=product)
            if (body.kind == "entra_directory_audit" and not any(
                    rule.selection.get("event.source") == "entra.directoryAudit" for rule in rules)):
                return {"status": "warning", **result,
                        "reason": "No reviewed Entra role-assignment rule is available in the pinned pack."}
        except Exception:
            return {"status": "blocked", **result, "reason": "Reviewed detection rules are unavailable. Check the pinned rule repository and retry."}
        payload = body.model_dump()
        token = cipher.encrypt({"tenant": user.tenant_id, "digest": connector_digest(payload),
                                "connector_fingerprint": connector_fingerprint,
                                "expires": time.time() + 600})
        return {"status": "pass", **result, "check_token": token}

    @app.post("/api/attack-analysis/run")
    def attack_log_run(body: AttackLogRun, user=Depends(identity)):
        payload = body.model_dump(exclude={"check_token"})
        try:
            checked = cipher.decrypt(body.check_token)
        except Exception:
            checked = None
        if (not checked or checked.get("tenant") != user.tenant_id
                or checked.get("digest") != connector_digest(payload)
                or checked.get("expires", 0) < time.time()):
            raise HTTPException(422, "Check log access again before starting analysis.")
        provider, auth, scopes, options, connector_fingerprint = attack_source(body, user)
        if checked.get("connector_fingerprint") != connector_fingerprint:
            raise HTTPException(422, "Connector settings changed; check log access again.")
        from .attack_logs import LogAccessError, analyze_aws_source
        from .gcp_attack_logs import GcpLogAccessError
        from peaso.attack_detection.rules import RuleSourceError
        try:
            if provider == "aws":
                return analyze_aws_source(auth, options, body, scopes)
            if provider == "gcp":
                from .gcp_attack_logs import analyze_gcp_source
                return analyze_gcp_source(auth, scopes, options, settings, body)
            if body.kind == "entra_directory_audit":
                from .entra_attack_logs import analyze_entra_source
                return analyze_entra_source(auth, scopes, options, body)
            from .azure_attack_logs import analyze_azure_source
            return analyze_azure_source(auth, scopes, options, body)
        except (LogAccessError, GcpLogAccessError) as exc:
            raise HTTPException(422, "Log analysis stopped: " + attack_log_error(exc.code)) from None
        except RuleSourceError:
            raise HTTPException(503, "Reviewed detection rules are unavailable; retry after the pinned rule repository is restored.") from None
        except Exception:
            raise HTTPException(502, "Log source could not be read. Check connector and log access again.") from None

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
        if user.auth_kind != "api_key":
            store.expire()
        return public_scan(store.job(user.tenant_id, ident))

    @app.post("/api/scans/{ident}/cancel")
    def cancel(ident: str, user=Depends(identity)):
        return store.cancel(user.tenant_id, ident)

    @app.get("/api/scans/{ident}/report")
    def report(ident: str, format: Literal["json", "markdown"] = "json", user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        ext = "md" if format == "markdown" else "json"
        filename = f"hacktricks-cspm-{row['id']}.{ext}"
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
        return Response(content, media_type=media, headers={"Content-Disposition": f'attachment; filename="hacktricks-cspm-{store.job(user.tenant_id, ident)["id"]}.{ext}"'})

    @app.get("/api/scans/{ident}/findings")
    def findings(ident: str, categories: str | None = None, framework: str | None = None, severity: str | None = None, service: str | None = None, status: str | None = None, search: str | None = None, group_by: Literal["service", "check_id", "resource_id"] = "service", sort_by: Literal["severity", "title", "service", "account", "status", "resource_id"] | None = None, sort_order: Literal["asc", "desc"] = "asc", offset: int = Query(default=0, ge=0), limit: int = Query(default=500, ge=1, le=500), user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        summary = bundle.get("summary", bundle)
        metadata = summary.get("snapshot_metadata", {}) if isinstance(summary, dict) else {}
        cluster_id = metadata.get("cluster_id", "") if isinstance(metadata, dict) else ""

        def account_label(finding):
            provider = str(finding.get("provider", "")).lower()
            scope = str(finding.get("scope") or "")
            if provider == "aws":
                return scope.split("/", 1)[0]
            if provider == "gcp":
                match = re.match(r"^(?:projects|organizations|folders)/([^/]+)", scope, re.IGNORECASE)
                return match.group(1) if match else scope.split("/", 1)[0]
            if provider == "azure":
                match = re.search(r"(?:^|/)(?:subscriptions|tenants)/([^/]+)", scope, re.IGNORECASE)
                return match.group(1) if match else scope.split("/", 1)[0]
            if provider == "k8s":
                if isinstance(cluster_id, str) and cluster_id:
                    return cluster_id
                for key in ("native_resource_id", "resource_id"):
                    identifier = str(finding.get(key) or "")
                    if identifier.startswith("k8s://"):
                        return identifier[6:].split("/", 1)[0]
                return ""
            return scope

        requested_frameworks = {item.strip().lower() for item in framework.split(",")} if framework else set()
        from peaso.engine import FRAMEWORK_ALIASES
        from peaso.checks.catalog import expand_framework_selectors
        requested_frameworks.update(FRAMEWORK_ALIASES.get(item, item).lower() for item in tuple(requested_frameworks))
        # Family labels and canonical names also select their checklist versions (ids) and vice versa.
        requested_frameworks = {str(item).lower() for item in expand_framework_selectors(requested_frameworks)}
        version_checks = {check for version, checks in bundle.get("framework_filters", {}).items() if version.lower() in requested_frameworks for check in checks}
        labels = check_labels(bundle)
        meta = check_fields(bundle)
        # Framework selection is resolved once per check from check_frameworks, not per finding label list.
        label_checks = {check for check, names in labels.items() if {str(name).lower() for name in names} & requested_frameworks} if framework else set()
        filters = {name: {item.strip().lower() for item in query.split(",")} if query else None
                   for name, query in (("category", categories), ("severity", severity), ("service", service), ("status", status))}
        search_text = search.casefold() if search else None
        missing = object()

        def field(value, name):
            if name in value:
                return value[name]
            defaults = meta.get(value.get("check_id"))
            return defaults.get(name, missing) if isinstance(defaults, dict) else missing

        def selected(finding):
            for name, choices in filters.items():
                if choices is not None:
                    item = field(finding, name)
                    if str(item if item is not missing else "").lower() not in choices:
                        return False
            if framework and finding["check_id"] not in version_checks:
                if "frameworks" in finding or not labels:
                    if not {str(item).lower() for item in finding.get("frameworks", [])} & requested_frameworks:
                        return False
                elif finding["check_id"] not in label_checks:
                    return False
            return not search_text or search_text in json.dumps(with_labels(with_meta(finding, meta, bundle), labels)).casefold()

        def sort_card(value):
            # Summary truncation affects sort order for long archived fields.
            # Materialize only the keys that the chosen sort or account label reads.
            keys = {"id", group_by}
            if sort_by == "resource_id":
                keys.update(("resource_name", "native_resource_id", "resource_id"))
            elif sort_by == "account":
                keys.update(("provider", "scope", "native_resource_id", "resource_id"))
            elif sort_by:
                keys.add(sort_by)
            selected_fields = {}
            for key in keys:
                item = field(value, key)
                if item is not missing:
                    selected_fields[key] = item
            card = finding_summary(selected_fields)
            if sort_by == "account":
                card["account"] = account_label(card)
            return card

        selected_rows = []
        facets = {"services": set(), "statuses": set(), "frameworks": set()}
        facet_checks = set()
        groups = [finding_index(user.tenant_id, row["report"], tuple(chunk["index_reference"] for chunk in bundle["finding_chunks"]))] if bundle.get("bundle_version") == 1 else [bundle.get("findings", [])]
        for group in groups:
            for value in group:
                category = field(value, "category")
                if filters["category"] is None or str(category if category is not missing else "").lower() in filters["category"]:
                    service_value = field(value, "service")
                    facets["services"].add(service_value if service_value is not missing else "")
                    facets["statuses"].add(value.get("status", ""))
                    if "frameworks" in value or not labels:
                        facets["frameworks"].update(value.get("frameworks", []))
                    else:
                        facet_checks.add(value["check_id"])
                if not selected(value):
                    continue
                selected_rows.append((value, sort_card(value)))
        for check in facet_checks:
            facets["frameworks"].update(labels.get(check, []))
        if sort_by is None:
            selected_rows.sort(key=lambda pair: (str(pair[1].get(group_by, "")), pair[1]["id"]))
        else:
            severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
            def sort_value(item):
                if sort_by == "severity":
                    value = str(item.get("severity") or "").casefold()
                    return (severity_rank.get(value, 5), value)
                if sort_by == "resource_id":
                    value = item.get("resource_name") or item.get("native_resource_id") or item.get("resource_id") or ""
                else:
                    value = item.get(sort_by) or ""
                return str(value).casefold()
            selected_rows.sort(key=lambda pair: pair[1]["id"])
            selected_rows.sort(key=lambda pair: sort_value(pair[1]), reverse=sort_order == "desc")
        count = len(selected_rows)
        output = []
        for value, _ in selected_rows[offset:offset + limit]:
            # Preserve the legacy list shape, including archived metadata added
            # after the bounded summary, while hydrating only the selected page.
            item = with_labels(with_meta(finding_summary(with_meta(value, meta, bundle)), meta, bundle), labels)
            output.append(dict(item, account=account_label(item)))
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
                            envelope = signed_download(user.tenant_id, value["_detail_reference"])
                            # The artifact is intentionally served directly for large evidence. Attach only
                            # the reviewed, bounded remediation template from this authorized manifest;
                            # native evidence never crosses into its command placeholders.
                            presented = with_remediation(value, bundle)
                            from peaso.finding_presentation import PRESENTATION_FIELDS
                            presentation = {key: presented[key] for key in PRESENTATION_FIELDS if key in presented}
                            if len(json.dumps(presentation).encode()) <= 64 * 1024:
                                envelope["finding_presentation"] = presentation
                                if isinstance(presentation.get("remediation_details"), dict):
                                    envelope["remediation_details"] = presentation["remediation_details"]
                            return envelope
                        return with_remediation(artifacts.get(user.tenant_id, value["_detail_reference"]), bundle)
                    if len(json.dumps(value).encode()) > 4 * 1024 * 1024 and hasattr(artifacts, "presign"):
                        raise HTTPException(413, "Finding exceeds the API detail budget; download the complete JSON report for this evidence")
                    return with_remediation(with_labels(with_meta(value, check_fields(bundle), bundle), check_labels(bundle)), bundle)
        raise HTTPException(404, "Finding not found")

    @app.get("/api/scans/{ident}/summary")
    def summary(ident: str, user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        value = dict(bundle["summary"]) if bundle.get("bundle_version") == 1 else {key: value for key, value in bundle.items() if key not in {"findings", "resources", "coverage", "graphs", "snapshot", "check_frameworks", "check_meta"}}
        value.update(runtime=store.public_job(row)["runtime"], finding_count=bundle.get("finding_count", len(bundle.get("findings", []))), coverage_count=bundle.get("coverage_count", len(bundle.get("coverage", []))) + len(_credential_target_coverage(bundle)))
        return value

    @app.get("/api/scans/{ident}/least-privilege")
    def least_privilege(ident: str, search: str = "", offset: int = Query(default=0, ge=0),
                        limit: int = Query(default=100, ge=1, le=500), user=Depends(identity)):
        """One row per principal, backed by the immutable scan's native evidence."""
        row, bundle = owned_bundle(user.tenant_id, ident)
        if bundle.get("least_privilege"):
            projection = artifacts.get(user.tenant_id, bundle["least_privilege"])
        else:
            # Historical reports predate the compact projection artifact. Their
            # native resource chunks still carry the evidence needed to build it.
            from peaso.least_privilege import project
            provider = bundle.get("summary", bundle).get("provider", "")
            if bundle.get("bundle_version") == 1 and bundle.get("resource_chunks"):
                resource_rows = [dict(item, provider=provider)
                    for chunk in bundle["resource_chunks"]
                    for item in artifacts.get(user.tenant_id, chunk["reference"])["items"]]
                projection = project(provider, resource_rows)
            else:
                projection = project(provider, bundle.get("resources", []))
        needle = search.strip().casefold()[:200]
        candidates = projection["items"]
        if needle:
            candidates = [card for card in candidates if needle in card["principal"].casefold()
                or needle in card.get("label", "").casefold()
                or any(needle in scope.casefold() for scope in card["scopes"])]
        page = candidates[offset:offset + limit]
        return {"items": page, "total": len(candidates), "offset": offset,
            "next_offset": offset + len(page) if offset + len(page) < len(candidates) else None,
            "coverage": projection["coverage"]}

    @app.get("/api/scans/{ident}/coverage")
    def coverage(ident: str, offset: int = Query(default=0, ge=0), limit: int = Query(default=500, ge=1, le=500), user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        output, count = [], 0
        references = bundle.get("coverage_chunks", []) if bundle.get("bundle_version") == 1 else []
        counts = bundle.get("coverage_chunk_counts")
        counted = (bundle.get("bundle_version") == 1 and isinstance(counts, list) and len(counts) == len(references)
                   and all(type(value) is int and value >= 0 for value in counts)
                   and sum(counts) == bundle.get("coverage_count"))
        if counted:
            for reference, size in zip(references, counts):
                end = count + size
                if offset < end and offset + limit > count:
                    group = artifacts.get(user.tenant_id, reference)["items"]
                    if len(group) != size:
                        raise HTTPException(409, "Coverage artifact count does not match the owned report")
                    output.extend(group[max(0, offset - count):min(size, offset + limit - count)])
                count = end
        elif bundle.get("bundle_version") == 1 and "coverage_chunk_counts" not in bundle and isinstance(references, list) and len(references) <= max_legacy_coverage_chunks and all(isinstance(ref, str) and 0 < len(ref) <= 512 for ref in references):
            # Old immutable manifests have no sidecar. Key every count vector by
            # the authorized tenant, manifest reference, and ordered chunk refs.
            key = (user.tenant_id, row["report"], tuple(references))
            with coverage_counts_lock:
                sizes = coverage_counts.get(key)
                if sizes is not None:
                    coverage_counts.move_to_end(key)
                    flight, leader = None, False
                else:
                    flight = coverage_inflight.get(key)
                    leader = flight is None
                    if leader and len(coverage_inflight) < 4:
                        flight = Future()
                        coverage_inflight[key] = flight
            if sizes is None and flight is not None and not leader:
                # A stalled or cancelled leader cannot pin a follower forever.
                # The follower then scans independently, like an overflow request.
                try:
                    sizes = flight.result(timeout=5)
                except (TimeoutError, CancelledError):
                    flight = None
            if sizes is None:
                # Capture just this page while counting, so a cold request reads
                # each chunk once and keeps at most one chunk plus the page live.
                try:
                    measured = []
                    for reference in references:
                        group = artifacts.get(user.tenant_id, reference)["items"]
                        size = len(group)
                        if offset < count + size and offset + limit > count:
                            output.extend(group[max(0, offset - count):min(size, offset + limit - count)])
                        measured.append(size)
                        count += size
                except BaseException as exc:
                    if flight is not None:
                        with coverage_counts_lock:
                            coverage_inflight.pop(key, None)
                            flight.set_exception(exc)
                    raise
                sizes = tuple(measured)
                with coverage_counts_lock:
                    coverage_counts[key] = sizes
                    coverage_counts.move_to_end(key)
                    if len(coverage_counts) > 4:
                        coverage_counts.popitem(last=False)
                    if flight is not None:
                        coverage_inflight.pop(key, None)
                        flight.set_result(sizes)
            else:
                for reference, size in zip(references, sizes):
                    if offset < count + size and offset + limit > count:
                        group = artifacts.get(user.tenant_id, reference)["items"]
                        if len(group) != size:
                            raise HTTPException(409, "Coverage artifact count does not match the owned report")
                        output.extend(group[max(0, offset - count):min(size, offset + limit - count)])
                    count += size
        else:
            # Malformed sidecars and legacy inline reports preserve the full
            # scan path, including its existing error behavior.
            groups = (artifacts.get(user.tenant_id, reference)["items"] for reference in references) if bundle.get("bundle_version") == 1 else [bundle.get("coverage", [])]
            for group in groups:
                for value in group:
                    if offset <= count < offset + limit:
                        output.append(value)
                    count += 1
        for value in _credential_target_coverage(bundle):
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

    @app.post("/api/scans/{ident}/reachability/batch")
    def reachability_batch(ident: str, body: ReachabilityBatchQuery, user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        reference = bundle.get("network_snapshot")
        if not reference:
            raise HTTPException(409, "This report has no scoped network facts; collect a new scan")
        snapshot = artifacts.get(user.tenant_id, reference)
        from peaso.analysis.reachability import evaluate_reachability_batch
        try:
            results = evaluate_reachability_batch(snapshot, **body.model_dump())
        except ValueError:
            raise HTTPException(422, "Invalid selected flow query") from None
        if any(result.get("snapshot_id") != bundle["summary"]["snapshot_id"] for result in results):
            raise HTTPException(409, "Captured network facts do not match the owned report")
        return {"snapshot_id": bundle["summary"]["snapshot_id"], "results": results}

    @app.post("/api/scans/{ident}/reachability/matrix")
    def reachability_matrix(ident: str, body: ReachabilityMatrixQuery, user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        reference = bundle.get("network_snapshot")
        if not reference:
            raise HTTPException(409, "This report has no scoped network facts; collect a new scan")
        snapshot = artifacts.get(user.tenant_id, reference)
        from peaso.analysis.reachability import evaluate_reachability_matrix
        try:
            results = evaluate_reachability_matrix(snapshot, **body.model_dump())
        except ValueError:
            raise HTTPException(422, "Invalid selected flow query") from None
        if any(result.get("snapshot_id") != bundle["summary"]["snapshot_id"] for result in results):
            raise HTTPException(409, "Captured network facts do not match the owned report")
        return {"snapshot_id": bundle["summary"]["snapshot_id"], "results": results}

    @app.post("/api/scans/{ident}/reachability/grid")
    def reachability_grid(ident: str, body: ReachabilityGridQuery, user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        reference = bundle.get("network_snapshot")
        if not reference:
            raise HTTPException(409, "This report has no scoped network facts; collect a new scan")
        snapshot = artifacts.get(user.tenant_id, reference)
        from peaso.analysis.reachability import evaluate_reachability_grid
        try:
            results = evaluate_reachability_grid(snapshot, **body.model_dump())
        except ValueError:
            raise HTTPException(422, "Invalid selected flow query") from None
        if any(result.get("snapshot_id") != bundle["summary"]["snapshot_id"] for result in results):
            raise HTTPException(409, "Captured network facts do not match the owned report")
        return {"snapshot_id": bundle["summary"]["snapshot_id"], "results": results}

    @app.get("/api/scans/{ident}/graphs/{kind}")
    def graph(ident: str, kind: Literal["network", "iam", "privesc"], max_nodes: int | None = Query(default=None, ge=1, le=100000), user=Depends(identity)):
        row, bundle = owned_bundle(user.tenant_id, ident)
        if kind == "privesc":
            # Already aggregated: never project_graph it (dropping an aggregate drops every member reached through it).
            from peaso.privesc.queries import known_target_graph
            if bundle.get("bundle_version") == 1 and hasattr(artifacts, "presign") and bundle.get("graphs", {}).get("privesc"):
                if max_nodes is not None and max_nodes != 500:
                    raise HTTPException(422, "Hosted graphs support max_nodes=500 or a complete graph without max_nodes")
                raw = artifacts.get(user.tenant_id, bundle["graphs"]["privesc"])
                value = known_target_graph(raw)
                reference = bundle["graph_projections" if max_nodes is not None else "graphs"]["privesc"]
                stored = artifacts.get(user.tenant_id, reference) if max_nodes is not None else raw
                if value is raw and known_target_graph(stored) is stored:
                    return signed_download(user.tenant_id, reference)
                if max_nodes is not None:
                    from peaso.storage.reports import privesc_projection
                    return privesc_projection(value, max_nodes)
                return value
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
        from peaso.privesc.queries import GraphIndex, known_target_graph
        return GraphIndex(known_target_graph(artifacts.get(tenant, reference)))

    def privesc_graph(tenant, bundle):
        from peaso.privesc.queries import known_target_graph
        if bundle.get("bundle_version") == 1:
            reference = bundle.get("graphs", {}).get("privesc")
            raw = artifacts.get(tenant, reference) if reference else {"nodes": [], "edges": []}
        else:
            raw = bundle.get("graphs", {}).get("privesc") or {"nodes": [], "edges": []}
        return known_target_graph(raw)

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
    def privesc_admins(ident: str, max_depth: int = Query(default=6, ge=1, le=20), include_unknown: bool = False, offset: int = Query(default=0, ge=0), limit: int = Query(default=500, ge=1, le=500), user=Depends(identity)):
        from peaso.privesc import queries
        row, bundle, index = privesc_index(user.tenant_id, ident)
        return page(queries.reach_admin(index, max_depth=max_depth, include_unknown=include_unknown), offset, limit)

    @app.get("/api/scans/{ident}/privesc/paths")
    def privesc_paths(ident: str, source: str | None = Query(default=None, max_length=2000), source_alias: str | None = Query(default=None, alias="from", max_length=2000),
                      target: str | None = Query(default=None, max_length=2000), target_alias: str | None = Query(default=None, alias="to", max_length=2000),
                      max_depth: int = Query(default=6, ge=1, le=20), limit: int = Query(default=10, ge=1, le=100), include_unknown: bool = False, user=Depends(identity)):
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
        labels, meta = check_labels(bundle), check_fields(bundle)
        findings = [with_labels(with_meta(finding_summary(f), meta, bundle), labels)
                    for f in (with_meta(f, meta, bundle) for f in summaries) if f.get("category") == "privesc"]
        card = queries.principal_card(index, principal_id, findings)
        for key in ("outgoing", "incoming", "findings"):
            card[key + "_total"] = len(card.get(key, []))
            card[key] = card.get(key, [])[:500]
        from peaso.engine import privesc_technique_details
        from peaso.privesc.versioned_catalog import card_technique_ids, lookup_entries
        binding = bundle.get("privesc_catalog")
        if binding is None and isinstance(bundle.get("summary"), dict) and "privesc_catalog" in bundle["summary"]:
            binding = {}  # A missing tenant-bound copy is invalid, not legacy.
        technique_ids = card_technique_ids(card, principal_id)
        _, lookup_status = lookup_entries((), binding, tenant_id=user.tenant_id)
        catalog_details = privesc_technique_details(technique_ids, catalog_binding=binding, tenant_id=user.tenant_id)
        aggregates = set(card.get("member_of_aggregates") or [])
        for key in ("outgoing", "incoming"):
            # Graph edges are cached; check each endpoint before decorating a copy.
            decorated = []
            for edge in card[key]:
                target = edge.get("target")
                belongs = (edge.get("source") == principal_id if key == "outgoing" else
                           target == principal_id or (target in aggregates and edge.get("via_aggregate") == target))
                techniques = [dict((catalog_details.get(t) if belongs else None) or
                                   {"id": t, "unknown": True, "catalog_lookup_status": "edge_target_mismatch"},
                                   edge_confidence=edge.get("confidence"), evidence=edge.get("evidence_refs", []))
                              for t in edge.get("techniques", [])]
                decorated.append(dict(edge, technique_details=techniques))
            card[key] = decorated
        card["technique_details"] = catalog_details
        card["catalog_lookup"] = {"status": lookup_status,
            "manifest_sha256": binding.get("manifest_sha256") if lookup_status in ("exact_bounded_v5", "exact_additive_v4", "exact_legacy") else None}
        return card

    # Bounded graph views. Full graphs are immutable tenant-scoped artifacts; the cache key includes the
    # tenant-checked reference and the cached objects are never mutated by the projection helpers.
    @lru_cache(maxsize=4)
    def graph_views(tenant, reference):
        from peaso.analysis import project_graph
        value = artifacts.get(tenant, reference)
        return value, project_graph(value, 500)

    def full_graph(tenant, bundle, kind):
        if bundle.get("bundle_version") == 1:
            return graph_views(tenant, bundle["graphs"][kind])
        from peaso.analysis import project_graph
        value = bundle.get("graphs", {}).get(kind, {"nodes": [], "edges": []})
        return value, project_graph(value, 500)

    @app.get("/api/scans/{ident}/graphs/{kind}/expand")
    def graph_expand(ident: str, kind: Literal["network", "iam"], node: str = Query(max_length=2000),
                     max_nodes: int = Query(default=500, ge=1, le=5000), max_edges: int = Query(default=2000, ge=1, le=20000), user=Depends(identity)):
        from peaso.analysis import expand_projected_node
        row, bundle = owned_bundle(user.tenant_id, ident)
        value, projected = full_graph(user.tenant_id, bundle, kind)
        try:
            return expand_projected_node(value, node, projected=projected, max_nodes=max_nodes, max_edges=max_edges)
        except KeyError:
            raise HTTPException(404, "Node not found in the 500-node projection") from None

    @app.get("/api/scans/{ident}/graphs/network/page")
    def graph_network_page(ident: str, page: int = Query(default=0, ge=0), page_size: int = Query(default=120, ge=1, le=2000),
                           max_edges: int = Query(default=1000, ge=1, le=20000), user=Depends(identity)):
        from peaso.analysis import page_graph
        row, bundle = owned_bundle(user.tenant_id, ident)
        value, _ = full_graph(user.tenant_id, bundle, "network")
        try:
            return page_graph(value, page, page_size, max_edges=max_edges)
        except ValueError:
            raise HTTPException(404, "Page out of range") from None

    @lru_cache(maxsize=4)
    def network_edge_index(tenant, scan_id, snapshot_id, graph_reference, projection_reference):
        """Index only the immutable, manifest-bound network artifacts for bounded detail reads."""
        from peaso.storage.artifacts import check_reference

        for reference in (graph_reference, projection_reference):
            try:
                check_reference(tenant, reference)
            except (TypeError, ValueError):
                raise HTTPException(409, "Network graph artifact is unavailable") from None
            parts = reference.split("/")
            if parts[1] != scan_id or not parts[2].startswith("graph-network-"):
                raise HTTPException(409, "Network graph artifact is unavailable")
        try:
            graph = artifacts.get(tenant, graph_reference)
            projection = artifacts.get(tenant, projection_reference)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if isinstance(exc, (FileNotFoundError, KeyError)) or code in {"NoSuchKey", "404", "NotFound"}:
                raise HTTPException(409, "Network graph artifact is unavailable") from None
            raise
        if (not isinstance(graph, dict) or not isinstance(projection, dict)
                or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list)
                or not isinstance(projection.get("edges"), list)):
            raise HTTPException(409, "Network graph artifact is unsupported")
        nodes, edges, groups = {}, {}, {}
        for node in graph["nodes"]:
            if not isinstance(node, dict) or not isinstance(node.get("id"), str) or node["id"] in nodes:
                raise HTTPException(409, "Network graph artifact is unsupported")
            nodes[node["id"]] = node
        for edge in graph["edges"]:
            if (not isinstance(edge, dict) or not isinstance(edge.get("id"), str) or edge["id"] in edges
                    or edge.get("source") not in nodes or edge.get("target") not in nodes):
                raise HTTPException(409, "Network graph artifact is unsupported")
            edges[edge["id"]] = edge
        for group in projection["edges"]:
            if not isinstance(group, dict) or not isinstance(group.get("id"), str):
                raise HTTPException(409, "Network graph artifact is unsupported")
            refs = group.get("edge_refs")
            if refs is None:
                continue
            # Expansion boundaries carry a sample only. The stored projection's
            # underlying_count equals its complete list of native references.
            if isinstance(refs, list) and (group.get("boundary") or group.get("underlying_count") != len(refs)):
                continue
            if (not isinstance(refs, list) or group["id"] in groups
                    or any(not isinstance(ref, str) or ref not in edges for ref in refs)
                    or len(set(refs)) != len(refs)):
                raise HTTPException(409, "Network graph artifact is unsupported")
            groups[group["id"]] = tuple(refs)
        return nodes, edges, groups

    def network_edge_fact(edge, nodes):
        def endpoint(node_id):
            node = nodes[node_id]
            return {key: node[key] for key in ("id", "label", "native_id", "resource_id", "type", "provider", "scope")
                    if isinstance(node.get(key), str) and len(node[key]) <= 2000}

        evidence = edge.get("evidence")
        source = evidence.get("source") if isinstance(evidence, dict) else None
        refs = []
        if isinstance(source, dict):
            ref = {key: source[key] for key in ("snapshot_id", "resource_id", "resource_type", "scope", "path", "collection_status")
                   if isinstance(source.get(key), str) and len(source[key]) <= 2000}
            if ref:
                refs.append(ref)
        return {"id": edge["id"],
                "type": edge["type"] if isinstance(edge.get("type"), str) and len(edge["type"]) <= 100 else None,
                "layer": edge["layer"] if isinstance(edge.get("layer"), str) and len(edge["layer"]) <= 100 else None,
                "confidence": edge["confidence"] if isinstance(edge.get("confidence"), str) and edge["confidence"] in {"low", "medium", "high"} else None,
                "source": endpoint(edge["source"]), "target": endpoint(edge["target"]),
                "evidence_refs": refs, "evidence_status": "source_reference" if refs else "unavailable"}

    @app.get("/api/scans/{ident}/graphs/network/edges")
    def graph_network_edges(ident: str, request: Request, user=Depends(identity)):
        # Ownership precedes selector parsing, so foreign scans always remain 404.
        row, bundle = owned_bundle(user.tenant_id, ident)
        params = request.query_params
        ids = params.getlist("ids")
        group_ids, cursors, limits = (params.getlist(name) for name in ("group_id", "cursor", "limit"))
        if (bool(ids) == bool(group_ids) or len(group_ids) > 1 or len(cursors) > 1 or len(limits) > 1
                or ((cursors or limits) and ids) or (cursors and not group_ids)):
            raise HTTPException(422, "Select explicit ids or one listed group_id")
        native_id_pattern = r"analysis:[a-f0-9]{24}"
        if ids and (not 1 <= len(ids) <= 100 or len(set(ids)) != len(ids)
                    or any(re.fullmatch(native_id_pattern, value) is None for value in ids)):
            raise HTTPException(422, "Invalid native edge IDs")
        group_id = group_ids[0] if group_ids else None
        if group_id is not None and re.fullmatch(native_id_pattern, group_id) is None:
            raise HTTPException(422, "Invalid group ID")
        cursor = cursors[0] if cursors else None
        if cursor is not None and re.fullmatch(r"0|[1-9][0-9]{0,18}", cursor) is None:
            raise HTTPException(422, "Invalid cursor")
        limit_text = limits[0] if limits else "100"
        if re.fullmatch(r"[1-9][0-9]{0,2}", limit_text) is None or int(limit_text) > 100:
            raise HTTPException(422, "Invalid limit")
        limit = int(limit_text)
        if (bundle.get("bundle_version") != 1 or not isinstance(bundle.get("graphs"), dict)
                or not isinstance(bundle.get("graph_projections"), dict)):
            raise HTTPException(409, "Full network graph artifact is unavailable for this scan")
        graph_reference = bundle["graphs"].get("network")
        projection_reference = bundle["graph_projections"].get("network")
        if not graph_reference or not projection_reference:
            raise HTTPException(409, "Full network graph artifact is unavailable for this scan")
        summary = bundle.get("summary")
        snapshot_id = summary.get("snapshot_id") if isinstance(summary, dict) else None
        if not isinstance(snapshot_id, str) or not snapshot_id or len(snapshot_id) > 2000:
            raise HTTPException(409, "Network graph snapshot binding is unavailable")
        nodes, edges, groups = network_edge_index(user.tenant_id, row["id"], snapshot_id, graph_reference, projection_reference)
        if ids:
            if any(edge_id not in edges for edge_id in ids):
                raise HTTPException(404, "Native network edge not found in this scan")
            selected, total, next_cursor = ids, len(ids), None
        else:
            refs = groups.get(group_id)
            if refs is None:
                raise HTTPException(404, "Listed network edge group not found in this scan")
            offset = int(cursor or "0")
            if offset > len(refs):
                raise HTTPException(404, "Network edge group cursor out of range")
            selected = refs[offset:offset + limit]
            total = len(refs)
            next_cursor = str(offset + len(selected)) if offset + len(selected) < total else None
        return {"items": [network_edge_fact(edges[edge_id], nodes) for edge_id in selected],
                "total": total, "next_cursor": next_cursor, "group_id": group_id, "snapshot_id": snapshot_id}

    @app.get("/api/scans/{ident}/graphs/privesc/subgraph")
    def privesc_subgraph(ident: str, focus: str | None = Query(default=None, max_length=2000), depth: int = Query(default=2, ge=0, le=6),
                         direction: Literal["both", "out", "in"] = "both", top: int = Query(default=10, ge=1, le=100),
                         max_nodes: int = Query(default=150, ge=1, le=2000), max_edges: int = Query(default=400, ge=1, le=10000),
                         member_cap: int = Query(default=40, ge=0, le=1000), include_unknown: bool = False, user=Depends(identity)):
        from peaso.analysis import subgraph
        row, bundle, index = privesc_index(user.tenant_id, ident)
        if focus is None:
            return subgraph.overview(index, top=top, max_nodes=max_nodes, max_edges=max_edges, member_cap=member_cap, include_unknown=include_unknown)
        try:
            return subgraph.neighbourhood(index, focus, depth=depth, direction=direction, max_nodes=max_nodes, max_edges=max_edges,
                                          member_cap=member_cap, include_unknown=include_unknown)
        except KeyError:
            raise HTTPException(404, "Node not found in the privilege-escalation map") from None

    @app.get("/api/scans/{ident}/graphs/privesc/aggregates/{aggregate_id:path}/members")
    def privesc_aggregate_members(ident: str, aggregate_id: str, offset: int = Query(default=0, ge=0), limit: int = Query(default=200, ge=1, le=1000), user=Depends(identity)):
        from peaso.analysis import subgraph
        row, bundle, index = privesc_index(user.tenant_id, ident)
        try:
            return subgraph.aggregate_members(index, aggregate_id, offset=offset, limit=limit)
        except KeyError:
            raise HTTPException(404, "Aggregate not found in the privilege-escalation map") from None

    @app.get("/api/scans/{ident}/graphs/{kind}/aggregates/{node_id:path}/members")
    def graph_aggregate_members(ident: str, kind: Literal["network", "iam"], node_id: str, offset: int = Query(default=0, ge=0),
                                limit: int = Query(default=200, ge=1, le=1000), user=Depends(identity)):
        from peaso.analysis import stored_aggregate_members
        row, bundle = owned_bundle(user.tenant_id, ident)
        value, _ = full_graph(user.tenant_id, bundle, kind)
        try:
            return stored_aggregate_members(value, node_id, offset=offset, limit=limit)
        except KeyError:
            raise HTTPException(404, "Stored aggregate not found in this graph") from None

    # Report schema 1.1 omits resources[].data; this returns the native item behind a resources[].id
    # (also evidence.native_resource_ref on graph nodes).
    def native_resource(tenant, ident, resource_id):
        """(native item, report provider) for a resources[].id of a completed scan."""
        row, bundle = owned_bundle(tenant, ident)
        if bundle.get("bundle_version") == 1 and "resource_chunks" in bundle:
            for chunk in bundle["resource_chunks"]:
                if chunk["first_id"] <= resource_id <= chunk["last_id"]:
                    for value in artifacts.get(tenant, chunk["reference"])["items"]:
                        if value["id"] == resource_id:
                            return value, bundle.get("summary", {}).get("provider")
            raise HTTPException(404, "Resource not found")
        value = owned_report(tenant, ident)
        for resource in value.get("resources", []):
            if resource.get("id") == resource_id:
                if "data" not in resource:
                    raise HTTPException(409, "Native data was not stored with this report")
                return {key: resource[key] for key in ("id", "native_id", "type", "scope", "data") if key in resource}, value.get("provider")
        raise HTTPException(404, "Resource not found")

    @app.get("/api/scans/{ident}/resources")
    def resource_inventory(ident: str, offset: int = Query(default=0, ge=0),
                           limit: int = Query(default=100, ge=1, le=500), user=Depends(identity)):
        """Bounded inventory metadata; native facts remain available through the detail route."""
        report = owned_report(user.tenant_id, ident)
        resources = report.get("resources", [])
        if not isinstance(resources, list):
            raise HTTPException(409, "Report inventory is unavailable")
        return {"items": [{key: value for key, value in item.items() if key != "data"}
                          for item in resources[offset:offset + limit] if isinstance(item, dict)],
                "total": len(resources), "next_offset": offset + limit if offset + limit < len(resources) else None}

    @app.get("/api/scans/{ident}/resources/{resource_id:path}")
    def resource_detail(ident: str, resource_id: str, user=Depends(identity)):
        return native_resource(user.tenant_id, ident, resource_id)[0]

    # Graph cards carry a bounded, highest-risk grant sample (card.source_grants, grant_count,
    # card.detail_ref.resource_ref); this returns the complete severity-annotated declared grant list.
    @app.get("/api/scans/{ident}/graphs/iam/grants/{resource_id:path}")
    def iam_grants(ident: str, resource_id: str, user=Depends(identity)):
        from peaso.analysis.iam import full_grants, grant_summary
        resource, provider = native_resource(user.tenant_id, ident, resource_id)
        try:
            grants = full_grants(resource, provider)
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            raise HTTPException(422, "Native facts of this resource are malformed; grants cannot be listed") from None
        return {"resource_ref": resource_id, "native_id": resource.get("native_id"), "type": resource.get("type"), "scope": resource.get("scope"),
                "provider": provider, "grant_count": len(grants), "grant_summary": grant_summary(grants), "grants": grants,
                "semantics": "Declared grants with rule-based severity; not effective access."}

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

    catalog_bodies = {}

    def catalog_response(request, key, build):
        """The catalog is immutable for the process: serialize once, then answer with ETag revalidation."""
        if key not in catalog_bodies:
            import hashlib
            body = json.dumps(build(), separators=(",", ":"), ensure_ascii=False).encode()
            catalog_bodies[key] = (body, '"' + hashlib.sha256(body).hexdigest()[:32] + '"')
        body, etag = catalog_bodies[key]
        headers = {"ETag": etag, "Cache-Control": "private, no-cache"}
        if etag in {tag.strip() for tag in request.headers.get("if-none-match", "").split(",")}:
            return Response(status_code=304, headers=headers)
        return Response(body, media_type="application/json", headers=headers)

    @app.get("/api/catalog/frameworks")
    def catalog_frameworks(request: Request, user=Depends(identity)):
        from .catalog_view import frameworks_view
        return catalog_response(request, "frameworks", frameworks_view)

    @app.get("/api/catalog")
    def catalog(request: Request, view: Literal["full", "summary"] = "full", user=Depends(identity)):
        if view == "summary":
            from .catalog_view import summary
            from peaso.privesc.versioned_catalog import current_binding
            return catalog_response(request, "summary", lambda: dict(summary(), privesc_catalog=current_binding()))
        from peaso.engine import get_catalog
        return catalog_response(request, "full", get_catalog)

    # Built frontend is served by the same API origin when available.
    static = Path(__file__).resolve().parents[1] / "frontend_dist"
    if static.is_dir():
        from fastapi.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=static, html=True), name="frontend")
    return app
