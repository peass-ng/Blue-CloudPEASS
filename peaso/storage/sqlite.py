"""Durable tenant-scoped state, atomic quotas, fenced leases and schedules."""
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import time
import uuid
from .cost import runtime_estimate

TERMINAL = {"completed", "failed", "cancelled", "timed_out"}
GENERIC_FAILURE = "Scan processing failed; check connector access and coverage"
# Fifty maximum-length role ARNs with the longest fixed message serialize to <64 KiB.
_MAX_FAILURE_ERROR_BYTES = 128 * 1024
_ROLE_ARN = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}\Z")
_TARGET_MESSAGES = {
    "external_id_not_required_by_trust": "trust policy does not require External ID; add the sts:ExternalId condition shown in onboarding.",
    "external_id_trust_unverified": "the role's External ID boundary could not be verified; require an exact workspace External ID and retry.",
    "platform_owned_account": "this platform account cannot be a customer scan target.",
    "role_target_limit": "the hosted scan limit of 50 role targets was reached.",
}


def curated_failure_reasons(reasons):
    """Accept only generated text derived from allowlisted codes and IAM role ARNs."""
    safe = []
    for item in reasons[:50] if isinstance(reasons, list) else []:
        if not isinstance(item, dict):
            continue
        code, arn = item.get("code"), item.get("role_arn")
        if not isinstance(code, str) or code not in _TARGET_MESSAGES or not isinstance(arn, str) or not _ROLE_ARN.fullmatch(arn):
            continue
        safe.append({"code": code, "role_arn": arn,
                     "message": f"Role {arn} was refused: {_TARGET_MESSAGES[code]}"})
    return safe


def failure_error(reasons):
    safe = curated_failure_reasons(reasons)
    return json.dumps({"failure_reasons": safe}, separators=(",", ":")) if safe else GENERIC_FAILURE


def public_failure(error):
    """Render the existing job error field without exposing arbitrary stored text."""
    if not isinstance(error, str) or not error.startswith('{"failure_reasons":'):
        return error, []
    # Generated envelopes are ASCII; this also bounds encoded bytes before parsing.
    if len(error) > _MAX_FAILURE_ERROR_BYTES or not error.isascii():
        return GENERIC_FAILURE, []
    try:
        decoded = json.loads(error)
    except (RecursionError, TypeError, ValueError):
        return GENERIC_FAILURE, []
    if not isinstance(decoded, dict) or set(decoded) != {"failure_reasons"}:
        return GENERIC_FAILURE, []
    entries = decoded["failure_reasons"]
    if not isinstance(entries, list) or len(entries) > 50:
        return GENERIC_FAILURE, []
    reasons = curated_failure_reasons(entries)
    if len(reasons) != len(entries):
        return GENERIC_FAILURE, []
    return reasons[0]["message"] if reasons else GENERIC_FAILURE, reasons


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def utc(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat()


def week(now):
    date = datetime.fromtimestamp(now, timezone.utc).date()
    return (date - timedelta(days=date.weekday())).isoformat()


def history(row, status, now):
    events = row.get("history", []) if isinstance(row, dict) else row["history"]
    events = json.loads(events) if isinstance(events, str) else list(events or [])
    events.append({"status": status, "at": utc(now)})
    return json.dumps(events)


class StoreError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class SQLiteStore:
    def __init__(self, state_dir: Path):
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = state_dir / "peaso.sqlite3"
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS workspace_external_ids (tenant TEXT PRIMARY KEY, external_id TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS connectors (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, auth TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS connectors_tenant ON connectors(tenant);
            CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, connector_id TEXT NOT NULL, data TEXT NOT NULL, connector TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, deadline REAL NOT NULL, owner TEXT, lease REAL, snapshot TEXT, report TEXT, error TEXT, idem TEXT, digest TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS jobs_idem ON jobs(tenant,idem) WHERE idem IS NOT NULL;
            CREATE INDEX IF NOT EXISTS jobs_tenant ON jobs(tenant,created);
            CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status,lease);
            CREATE TABLE IF NOT EXISTS quota (tenant TEXT NOT NULL, week TEXT NOT NULL, used INTEGER NOT NULL, PRIMARY KEY(tenant,week));
            CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, next_run REAL NOT NULL, enabled INTEGER NOT NULL, last_error TEXT);
            CREATE TABLE IF NOT EXISTS entitlements (tenant TEXT PRIMARY KEY, paid INTEGER NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS admin_qa_grants (tenant TEXT PRIMARY KEY, record TEXT NOT NULL, rev INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS admin_qa_grant_events (audit_id TEXT NOT NULL, event TEXT NOT NULL, tenant TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(audit_id,event));
            CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, secret_sha256 TEXT NOT NULL, name TEXT NOT NULL, prefix TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL, revoked_at REAL, last_used_at REAL, cognito_username TEXT);
            CREATE INDEX IF NOT EXISTS api_keys_tenant ON api_keys(tenant,id);
            CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE, created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS workspaces_owner ON workspaces(owner);
            CREATE TABLE IF NOT EXISTS workspace_members (workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL, joined REAL NOT NULL, PRIMARY KEY(workspace_id,user_id));
            CREATE INDEX IF NOT EXISTS workspace_members_user ON workspace_members(user_id);
            CREATE TABLE IF NOT EXISTS workspace_invites (workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL, invited_by TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(workspace_id,user_id));
            CREATE INDEX IF NOT EXISTS workspace_invites_user ON workspace_invites(user_id);
            """)
            db.execute("BEGIN IMMEDIATE")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(jobs)")}
            for name, definition in (("history", "TEXT NOT NULL DEFAULT '[]'"), ("error_code", "TEXT"), ("error_stage", "TEXT")):
                if name not in columns:
                    db.execute(f"ALTER TABLE jobs ADD COLUMN {name} {definition}")
        os.chmod(self.path, 0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None, factory=ClosingConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def workspaces(self, user_id):
        with self.connect() as db:
            rows = db.execute("SELECT w.id,w.owner,w.name,m.role FROM workspaces w JOIN workspace_members m ON m.workspace_id=w.id WHERE m.user_id=? ORDER BY w.name COLLATE NOCASE", (user_id,)).fetchall()
            return [dict(row) for row in rows]

    def workspace(self, workspace_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
            return dict(row) if row else None

    def workspace_role(self, workspace_id, user_id):
        with self.connect() as db:
            row = db.execute("SELECT role FROM workspace_members WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).fetchone()
            return row["role"] if row else None

    def create_workspace(self, owner, name, name_key, email):
        ident, now = "ws_" + uuid.uuid4().hex, time.time()
        with self.transaction() as db:
            if db.execute("SELECT COUNT(*) FROM workspaces WHERE owner=?", (owner,)).fetchone()[0] >= 5:
                raise StoreError(403, "You can create up to five workspaces")
            try:
                db.execute("INSERT INTO workspaces VALUES(?,?,?,?,?)", (ident, owner, name, name_key, now))
            except sqlite3.IntegrityError:
                raise StoreError(409, "Workspace name is already in use") from None
            db.execute("INSERT INTO workspace_members VALUES(?,?,?,?,?)", (ident, owner, email, "admin", now))
        return {"id": ident, "owner": owner, "name": name, "role": "admin"}

    def workspace_people(self, workspace_id):
        with self.connect() as db:
            members = [dict(row) for row in db.execute("SELECT user_id,email,role,joined FROM workspace_members WHERE workspace_id=? ORDER BY joined", (workspace_id,))]
            invites = [dict(row) for row in db.execute("SELECT user_id,email,role,invited_by,created FROM workspace_invites WHERE workspace_id=? ORDER BY created", (workspace_id,))]
        return members, invites

    def workspace_invitations(self, user_id):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT i.workspace_id,i.email,i.role,i.invited_by,i.created,w.name FROM workspace_invites i JOIN workspaces w ON w.id=i.workspace_id WHERE i.user_id=? ORDER BY i.created DESC", (user_id,))]

    def invite_workspace(self, workspace_id, user_id, email, role, invited_by):
        with self.transaction() as db:
            self._require_workspace_admin(db, workspace_id, invited_by)
            if db.execute("SELECT 1 FROM workspace_members WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).fetchone():
                raise StoreError(409, "This person is already a workspace member")
            if db.execute("SELECT 1 FROM workspace_invites WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).fetchone():
                raise StoreError(409, "An invitation is already pending")
            count = db.execute("SELECT COUNT(*) FROM workspace_members WHERE workspace_id=?", (workspace_id,)).fetchone()[0] - 1
            count += db.execute("SELECT COUNT(*) FROM workspace_invites WHERE workspace_id=?", (workspace_id,)).fetchone()[0]
            if count >= 100:
                raise StoreError(403, "Workspace invitation limit reached")
            db.execute("INSERT INTO workspace_invites VALUES(?,?,?,?,?,?)", (workspace_id, user_id, email, role, invited_by, time.time()))

    def respond_workspace_invitation(self, workspace_id, user_id, accept):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM workspace_invites WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).fetchone()
            if not row:
                raise StoreError(404, "Invitation not found")
            if accept:
                db.execute("INSERT INTO workspace_members VALUES(?,?,?,?,?)", (workspace_id, user_id, row["email"], row["role"], time.time()))
            db.execute("DELETE FROM workspace_invites WHERE workspace_id=? AND user_id=?", (workspace_id, user_id))

    @staticmethod
    def _require_workspace_admin(db, workspace_id, actor):
        if actor is not None:
            row = db.execute("SELECT role FROM workspace_members WHERE workspace_id=? AND user_id=?", (workspace_id, actor)).fetchone()
            if not row or row["role"] != "admin":
                raise StoreError(403, "Workspace admin access required")

    def revoke_workspace_invitation(self, workspace_id, user_id, *, actor=None):
        with self.transaction() as db:
            self._require_workspace_admin(db, workspace_id, actor)
            if db.execute("DELETE FROM workspace_invites WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).rowcount != 1:
                raise StoreError(404, "Invitation not found")

    def set_workspace_role(self, workspace_id, user_id, role, *, actor=None):
        with self.transaction() as db:
            self._require_workspace_admin(db, workspace_id, actor)
            row = db.execute("SELECT owner FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
            if not row or row["owner"] == user_id:
                raise StoreError(403, "The workspace owner's role cannot be changed")
            if db.execute("UPDATE workspace_members SET role=? WHERE workspace_id=? AND user_id=?", (role, workspace_id, user_id)).rowcount != 1:
                raise StoreError(404, "Workspace member not found")

    def remove_workspace_member(self, workspace_id, user_id, *, actor=None):
        with self.transaction() as db:
            self._require_workspace_admin(db, workspace_id, actor)
            row = db.execute("SELECT owner FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
            if not row or row["owner"] == user_id:
                raise StoreError(403, "The workspace owner cannot be removed")
            if db.execute("DELETE FROM workspace_members WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).rowcount != 1:
                raise StoreError(404, "Workspace member not found")

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def create_api_key(self, tenant, record):
        from peaso.auth.api_keys import MAX_UNREVOKED_KEYS
        with self.transaction() as db:
            count = db.execute("SELECT COUNT(*) FROM api_keys WHERE tenant=? AND revoked_at IS NULL", (tenant,)).fetchone()[0]
            if count >= MAX_UNREVOKED_KEYS:
                raise StoreError(429, "Revoke an unused API key before creating another")
            db.execute("INSERT INTO api_keys(id,tenant,secret_sha256,name,prefix,created_at,expires_at,revoked_at,last_used_at,cognito_username) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (record["id"], tenant, record["secret_sha256"], record["name"], record["prefix"], record["created_at"], record.get("expires_at"), None, None, record.get("cognito_username")))
        return dict(record, tenant=tenant, revoked_at=None, last_used_at=None)

    def api_key(self, key_id):
        with self.connect() as db:
            value = db.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
            return dict(value) if value else None

    def api_keys(self, tenant, after=None, limit=50):
        with self.connect() as db:
            rows = [dict(value) for value in db.execute("SELECT * FROM api_keys WHERE tenant=? AND id>? ORDER BY id LIMIT ?", (tenant, after or "", limit + 1))]
        return rows[:limit], rows[limit - 1]["id"] if len(rows) > limit else None

    def revoke_api_key(self, tenant, key_id, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            changed = db.execute("UPDATE api_keys SET revoked_at=? WHERE tenant=? AND id=? AND revoked_at IS NULL", (now, tenant, key_id)).rowcount
        if changed != 1:
            raise StoreError(404, "API key not found")

    def touch_api_key(self, tenant, key_id, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            return db.execute("UPDATE api_keys SET last_used_at=? WHERE tenant=? AND id=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)",
                              (now, tenant, key_id, now)).rowcount == 1

    def workspace_external_id(self, tenant):
        """Allocate once, atomically, without deriving the ID from public names."""
        import secrets
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO workspace_external_ids VALUES(?,?)",
                       (tenant, "hacktricks-cspm-ws-" + secrets.token_urlsafe(48)))
            return db.execute("SELECT external_id FROM workspace_external_ids WHERE tenant=?", (tenant,)).fetchone()["external_id"]

    def ai_state(self, user, name):
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS ai_state (user TEXT, name TEXT, value TEXT, PRIMARY KEY(user,name))")
            row = db.execute("SELECT value FROM ai_state WHERE user=? AND name=?", (user, name)).fetchone()
            return row[0] if row else None

    def set_ai_state(self, user, name, value, expected=None):
        # Compare-and-swap serializes device polling and refresh-token rotation.
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS ai_state (user TEXT, name TEXT, value TEXT, PRIMARY KEY(user,name))")
            row = db.execute("SELECT value FROM ai_state WHERE user=? AND name=?", (user, name)).fetchone()
            if (row[0] if row else None) != expected:
                return False
            if value is None:
                db.execute("DELETE FROM ai_state WHERE user=? AND name=?", (user, name))
            else:
                db.execute("INSERT INTO ai_state VALUES(?,?,?) ON CONFLICT(user,name) DO UPDATE SET value=excluded.value", (user, name, value))
            return True

    def add_connector(self, tenant, data, encrypted_auth):
        value = dict(data, id=uuid.uuid4().hex, created_at=utc())
        with self.transaction() as db:
            db.execute("INSERT INTO connectors VALUES(?,?,?,?)", (value["id"], tenant, json.dumps(value), encrypted_auth))
        return value

    def connector(self, tenant, ident, db=None):
        if db is None:
            with self.connect() as connection:
                return self.connector(tenant, ident, connection)
        row = db.execute("SELECT * FROM connectors WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
        if not row:
            raise StoreError(404, "Connector not found")
        return dict(row)

    def connectors(self, tenant):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM connectors WHERE tenant=? ORDER BY rowid", (tenant,))]

    def update_connector(self, tenant, ident, patch, encrypted_auth=None):
        with self.transaction() as db:
            row = self.connector(tenant, ident, db)
            data = json.loads(row["data"])
            data.update(patch)
            db.execute("UPDATE connectors SET data=?,auth=? WHERE tenant=? AND id=?", (json.dumps(data), encrypted_auth or row["auth"], tenant, ident))

    def delete_connector(self, tenant, ident):
        with self.transaction() as db:
            self.connector(tenant, ident, db)
            db.execute("DELETE FROM connectors WHERE tenant=? AND id=?", (tenant, ident))
            # Retire schedules at deletion, while existing jobs retain their encrypted input.
            for row in db.execute("SELECT * FROM schedules WHERE tenant=?", (tenant,)).fetchall():
                if json.loads(row["data"])["connector_id"] == ident:
                    db.execute("DELETE FROM schedules WHERE id=? AND tenant=?", (row["id"], tenant))

    def _enqueue(self, db, tenant, request, limit, timeout, idem, now):
        digest = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if idem is not None:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND idem=?", (tenant, idem)).fetchone()
            if row:
                if row["digest"] != digest:
                    raise StoreError(409, "Idempotency key already used for a different request")
                return self.public_job(row)
        connector = self.connector(tenant, request["connector_id"], db)
        current = week(now)
        db.execute("INSERT INTO quota VALUES(?,?,0) ON CONFLICT DO NOTHING", (tenant, current))
        if db.execute("UPDATE quota SET used=used+1 WHERE tenant=? AND week=? AND used<?", (tenant, current, limit)).rowcount != 1:
            raise StoreError(429, "Weekly scan quota exhausted")
        ident = uuid.uuid4().hex
        encrypted_input = json.dumps({"data": json.loads(connector["data"]), "auth": connector["auth"]})
        db.execute("INSERT INTO jobs(id,tenant,connector_id,data,connector,status,created,deadline,idem,digest,history) VALUES(?,?,?,?,?,'queued',?,?,?,?,?)",
                   (ident, tenant, request["connector_id"], json.dumps(request), encrypted_input, now, now + timeout, idem, digest, history({}, "queued", now)))
        return self.public_job(db.execute("SELECT * FROM jobs WHERE id=?", (ident,)).fetchone())

    def enqueue(self, tenant, request, limit=1, timeout=900, idem=None, now=None):
        with self.transaction() as db:
            return self._enqueue(db, tenant, request, limit, timeout, idem, time.time() if now is None else now)

    @staticmethod
    def public_job(row):
        value = dict(row)
        events = value.get("history", [])
        events = json.loads(events) if isinstance(events, str) else events
        error, reasons = public_failure(row["error"])
        result = dict(json.loads(row["data"]), id=row["id"], status=row["status"], created_at=utc(row["created"]), deadline_at=utc(row["deadline"]), error=error, error_code=value.get("error_code"), error_stage=value.get("error_stage"), timeline=events, updated_at=events[-1]["at"] if events else utc(row["created"]), input_mode=json.loads(row["connector"])["data"].get("input_mode", "live"), runtime=runtime_estimate(events))
        if reasons:
            result["failure_reasons"] = reasons
        return result

    def job(self, tenant, ident):
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            return dict(row)

    def replace_completed_report(self, tenant, ident, expected_report, report):
        """Operator-only compare-and-swap; keep original runtime and job history."""
        with self.transaction() as db:
            cursor = db.execute("UPDATE jobs SET report=? WHERE tenant=? AND id=? AND status='completed' AND report=?",
                                (report, tenant, ident, expected_report))
            if cursor.rowcount != 1:
                raise StoreError(409, "Completed scan report changed")

    def jobs(self, tenant, transform=None):
        with self.connect() as db:
            return [(transform or self.public_job)(row) for row in db.execute("SELECT * FROM jobs WHERE tenant=? ORDER BY created DESC", (tenant,))]

    def deletion_job(self, tenant, ident):
        return self.job(tenant, ident)

    def deletion_jobs(self, tenant):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT id,status,deadline FROM jobs WHERE tenant=?", (tenant,))]

    def delete_job(self, tenant, ident):
        with self.transaction() as db:
            row = db.execute("SELECT status,deadline FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            if row["status"] not in TERMINAL and row["deadline"] > time.time():
                raise StoreError(409, "Cancel the scan or wait for it to finish before deleting it")
            db.execute("DELETE FROM jobs WHERE tenant=? AND id=?", (tenant, ident))

    def usage(self, tenant, now=None):
        with self.connect() as db:
            row = db.execute("SELECT used FROM quota WHERE tenant=? AND week=?", (tenant, week(time.time() if now is None else now))).fetchone()
            return row["used"] if row else 0

    def get_entitlement(self, tenant):
        with self.connect() as db:
            row = db.execute("SELECT * FROM entitlements WHERE tenant=? AND expires>?", (tenant, time.time())).fetchone()
            return bool(row["paid"]) if row else None

    def set_entitlement(self, tenant, paid, seconds=3600):
        with self.transaction() as db:
            db.execute("INSERT INTO entitlements VALUES(?,?,?) ON CONFLICT(tenant) DO UPDATE SET paid=excluded.paid,expires=excluded.expires", (tenant, bool(paid), time.time() + seconds))

    def get_admin_qa_grant(self, tenant):
        with self.connect() as db:
            row = db.execute("SELECT record,rev FROM admin_qa_grants WHERE tenant=?", (tenant,)).fetchone()
            return dict(json.loads(row["record"]), rev=row["rev"]) if row else None

    def issue_admin_qa_grant(self, tenant, record, now=None, expected_predecessor=None):
        from peaso.auth.admin_qa import valid_issue
        now = time.time() if now is None else now
        if not valid_issue(record, tenant=tenant, now=now):
            raise StoreError(400, "Invalid administrator QA grant")
        if expected_predecessor is not None and (
                not isinstance(expected_predecessor, dict) or
                set(expected_predecessor) != {"audit_id", "rev"} or
                not isinstance(expected_predecessor["audit_id"], str) or
                type(expected_predecessor["rev"]) is not int or expected_predecessor["rev"] < 0):
            raise StoreError(400, "Invalid reviewed predecessor")
        with self.transaction() as db:
            previous = db.execute("SELECT record,rev FROM admin_qa_grants WHERE tenant=?", (tenant,)).fetchone()
            if expected_predecessor is None:
                if previous:
                    raise StoreError(409, "Prior administrator QA grant requires explicit review")
                rev = 0
            else:
                if not previous:
                    raise StoreError(409, "Reviewed predecessor is absent")
                prior = json.loads(previous["record"])
                revoked = type(prior.get("revoked_at")) in (int, float) and prior["revoked_at"] > 0
                expired = type(prior.get("hard_expires_at")) in (int, float) and prior["hard_expires_at"] <= now
                if (prior.get("audit_id") != expected_predecessor["audit_id"] or
                        previous["rev"] != expected_predecessor["rev"] or not (revoked or expired)):
                    raise StoreError(409, "Reviewed predecessor changed or remains active")
                rev = previous["rev"] + 1
            serialized = json.dumps(record, sort_keys=True, separators=(",", ":"))
            db.execute("INSERT INTO admin_qa_grant_events(audit_id,event,tenant,record) VALUES(?,?,?,?)",
                       (record["audit_id"], "issue", tenant, serialized))
            if previous:
                db.execute("UPDATE admin_qa_grants SET record=?,rev=? WHERE tenant=? AND rev=?",
                           (serialized, rev, tenant, previous["rev"]))
            else:
                db.execute("INSERT INTO admin_qa_grants(tenant,record,rev) VALUES(?,?,?)", (tenant, serialized, rev))
        return dict(record, rev=rev)

    def revoke_admin_qa_grant(self, tenant, audit_id, actor, reason, now=None):
        from peaso.auth.admin_qa import valid_actor
        now = time.time() if now is None else now
        if not valid_actor(actor) or not isinstance(reason, str) or not reason.strip():
            raise StoreError(400, "Valid revocation actor and reason required")
        with self.transaction() as db:
            old = db.execute("SELECT record,rev FROM admin_qa_grants WHERE tenant=?", (tenant,)).fetchone()
            if not old:
                raise StoreError(404, "Administrator QA grant not found")
            value = json.loads(old["record"])
            if value.get("audit_id") != audit_id or value.get("revoked_at") is not None:
                raise StoreError(409, "Administrator QA grant changed")
            value.update(revoked_at=now, revoked_by=actor, revoke_reason=reason.strip())
            serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
            next_rev = old["rev"] + 1
            db.execute("UPDATE admin_qa_grants SET record=?,rev=? WHERE tenant=? AND rev=?",
                       (serialized, next_rev, tenant, old["rev"]))
            db.execute("INSERT INTO admin_qa_grant_events(audit_id,event,tenant,record) VALUES(?,?,?,?)",
                       (audit_id, "revoke", tenant, serialized))
        return dict(value, rev=next_rev)

    def cancel(self, tenant, ident):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            if row["status"] not in TERMINAL:
                db.execute("UPDATE jobs SET status='cancelled',owner=NULL,lease=NULL,history=? WHERE tenant=? AND id=?", (history(row, "cancelled", time.time()), tenant, ident))
        return self.public_job(self.job(tenant, ident))

    def expire(self, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            for row in db.execute("SELECT * FROM jobs WHERE deadline<=? AND status NOT IN ('completed','failed','cancelled','timed_out')", (now,)).fetchall():
                stage = "collector" if row["status"] in {"queued", "collecting"} else "analyzer"
                db.execute("UPDATE jobs SET status='timed_out',owner=NULL,lease=NULL,error='Scan deadline exceeded',error_code='deadline_exceeded',error_stage=?,history=? WHERE id=?", (stage, history(row, "timed_out", now), row["id"]))

    def expire_job(self, tenant, ident, now=None):
        """Expire only the addressed job under the same lock as its status read."""
        now = time.time() if now is None else now
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            if row["status"] in TERMINAL or row["deadline"] > now:
                return False
            stage = "collector" if row["status"] in {"queued", "collecting"} else "analyzer"
            return db.execute("UPDATE jobs SET status='timed_out',owner=NULL,lease=NULL,error='Scan deadline exceeded',error_code='deadline_exceeded',error_stage=?,history=? WHERE tenant=? AND id=? AND deadline<=? AND status=?",
                              (stage, history(row, "timed_out", now), tenant, ident, now, row["status"])).rowcount == 1

    def claim(self, role, lease_seconds=30, now=None, tenant=None, ident=None):
        if role not in {"collector", "analyzer"}:
            raise ValueError("Unknown worker role")
        if ident is not None and tenant is None:
            raise ValueError("Tenant required for targeted claim")
        now = time.time() if now is None else now
        ready, active = ("queued", "collecting") if role == "collector" else ("collected", "analyzing")
        if ident is not None:
            self.expire_job(tenant, ident, now)
        else:
            self.expire(now)
        with self.transaction() as db:
            query = "SELECT * FROM jobs WHERE deadline>? AND (status=? OR (status=? AND lease<=?))"
            args = [now, ready, active, now]
            if ident is not None:
                query += " AND tenant=? AND id=?"
                args += [tenant, ident]
            row = db.execute(query + " ORDER BY created LIMIT 1", args).fetchone()
            if not row:
                return None
            owner = uuid.uuid4().hex
            db.execute("UPDATE jobs SET status=?,owner=?,lease=?,history=? WHERE id=?", (active, owner, now + lease_seconds, history(row, active, now), row["id"]))
            return dict(db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())

    def heartbeat(self, ident, owner, lease_seconds=30, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            return db.execute("UPDATE jobs SET lease=? WHERE id=? AND owner=? AND lease>? AND deadline>? AND status IN ('collecting','analyzing')", (now + lease_seconds, ident, owner, now, now)).rowcount == 1

    def finish(self, ident, owner, status, artifact=None, now=None, error_code="processing_failed", failure_reasons=None):
        now = time.time() if now is None else now
        if status not in {"collected", "completed", "failed"}:
            raise ValueError("Invalid worker transition")
        previous = "collecting" if status == "collected" else "analyzing" if status == "completed" else None
        field = "snapshot" if status == "collected" else "report"
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=? AND owner=? AND lease>? AND deadline>?", (ident, owner, now, now)).fetchone()
            if not row or row["status"] not in {"collecting", "analyzing"} or (previous and row["status"] != previous):
                return False
            if status == "failed":
                allowed = {"processing_failed", "invalid_input", "credential_access_denied", "dependency_unavailable", "provider_error", "collector_timeout", "artifact_error", "worker_interrupted"}
                error_code = error_code if error_code in allowed else "processing_failed"
                stage = "collector" if row["status"] == "collecting" else "analyzer"
                db.execute("UPDATE jobs SET status='failed',error=?,error_code=?,error_stage=?,history=?,owner=NULL,lease=NULL WHERE id=? AND owner=?", (failure_error(failure_reasons), error_code, stage, history(row, "failed", now), ident, owner))
            else:
                db.execute(f"UPDATE jobs SET status=?,{field}=?,history=?,owner=NULL,lease=NULL WHERE id=? AND owner=?", (status, artifact, history(row, status, now), ident, owner))
            return True

    @staticmethod
    def public_schedule(row):
        return dict(json.loads(row["data"]), id=row["id"], enabled=bool(row["enabled"]), next_run_at=utc(row["next_run"]), last_error=row["last_error"])

    def schedules(self, tenant):
        with self.connect() as db:
            return [self.public_schedule(row) for row in db.execute("SELECT * FROM schedules WHERE tenant=?", (tenant,))]

    def add_schedule(self, tenant, data, next_run, enabled=True):
        with self.transaction() as db:
            self.connector(tenant, data["connector_id"], db)
            ident = uuid.uuid4().hex
            db.execute("INSERT INTO schedules VALUES(?,?,?,?,?,NULL)", (ident, tenant, json.dumps(data), next_run, enabled))
            return self.public_schedule(db.execute("SELECT * FROM schedules WHERE id=?", (ident,)).fetchone())

    def update_schedule(self, tenant, ident, patch, next_run=None, enabled=None):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM schedules WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Schedule not found")
            data = dict(json.loads(row["data"]), **patch)
            self.connector(tenant, data["connector_id"], db)
            if next_run is None and (set(patch) & {'rules', 'timezone', 'interval_hours'} or enabled is True and not row['enabled']):
                from peaso.scheduling import next_run as following_run
                next_run = following_run(data, time.time())
            db.execute("UPDATE schedules SET data=?,next_run=?,enabled=?,last_error=NULL WHERE tenant=? AND id=?", (json.dumps(data), row["next_run"] if next_run is None else next_run, row["enabled"] if enabled is None else enabled, tenant, ident))
            return self.public_schedule(db.execute("SELECT * FROM schedules WHERE id=?", (ident,)).fetchone())

    def delete_schedule(self, tenant, ident):
        with self.transaction() as db:
            if db.execute("DELETE FROM schedules WHERE tenant=? AND id=?", (tenant, ident)).rowcount != 1:
                raise StoreError(404, "Schedule not found")

    def pause_schedule(self, tenant, ident):
        with self.transaction() as db:
            db.execute("UPDATE schedules SET enabled=0,last_error='Schedule disabled: identity is no longer eligible' WHERE tenant=? AND id=?", (tenant, ident))

    def due_schedules(self, now=None):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (time.time() if now is None else now,))]

    def trigger_schedule(self, row, limit=1, timeout=900, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            current = db.execute("SELECT * FROM schedules WHERE tenant=? AND id=? AND enabled=1 AND next_run=? AND next_run<=?", (row["tenant"], row["id"], row["next_run"], now)).fetchone()
            if not current:
                return None
            data = json.loads(current["data"])
            request = {k: data[k] for k in ("connector_id", "categories", "checks", "frameworks", "ai_enabled", "ai_user_id") if k in data}
            error, result = None, None
            # Savepoint ensures a rejected enqueue never partially reserves quota.
            db.execute("SAVEPOINT scheduled_enqueue")
            try:
                result = self._enqueue(db, row["tenant"], request, limit, timeout, f"schedule:{row['id']}:{row['next_run']}", now)
            except StoreError as exc:
                db.execute("ROLLBACK TO scheduled_enqueue")
                error = exc.message
            db.execute("RELEASE scheduled_enqueue")
            from peaso.scheduling import next_run as following_run
            db.execute("UPDATE schedules SET next_run=?,last_error=? WHERE id=? AND tenant=?", (following_run(data, now), error, row["id"], row["tenant"]))
            return result
