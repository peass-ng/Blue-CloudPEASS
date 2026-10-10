"""Durable tenant-scoped state, atomic quotas, fenced leases and schedules."""
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
from .cost import runtime_estimate

TERMINAL = {"completed", "failed", "cancelled", "timed_out"}


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
            CREATE TABLE IF NOT EXISTS connectors (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, auth TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS connectors_tenant ON connectors(tenant);
            CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, connector_id TEXT NOT NULL, data TEXT NOT NULL, connector TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, deadline REAL NOT NULL, owner TEXT, lease REAL, snapshot TEXT, report TEXT, error TEXT, idem TEXT, digest TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS jobs_idem ON jobs(tenant,idem) WHERE idem IS NOT NULL;
            CREATE INDEX IF NOT EXISTS jobs_tenant ON jobs(tenant,created);
            CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status,lease);
            CREATE TABLE IF NOT EXISTS quota (tenant TEXT NOT NULL, week TEXT NOT NULL, used INTEGER NOT NULL, PRIMARY KEY(tenant,week));
            CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, next_run REAL NOT NULL, enabled INTEGER NOT NULL, last_error TEXT);
            CREATE TABLE IF NOT EXISTS entitlements (tenant TEXT PRIMARY KEY, paid INTEGER NOT NULL, expires REAL NOT NULL);
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
        return dict(json.loads(row["data"]), id=row["id"], status=row["status"], created_at=utc(row["created"]), deadline_at=utc(row["deadline"]), error=row["error"], error_code=value.get("error_code"), error_stage=value.get("error_stage"), timeline=events, updated_at=events[-1]["at"] if events else utc(row["created"]), input_mode=json.loads(row["connector"])["data"].get("input_mode", "live"), runtime=runtime_estimate(events))

    def job(self, tenant, ident):
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            return dict(row)

    def jobs(self, tenant):
        with self.connect() as db:
            return [self.public_job(row) for row in db.execute("SELECT * FROM jobs WHERE tenant=? ORDER BY created DESC", (tenant,))]

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

    def claim(self, role, lease_seconds=30, now=None, tenant=None, ident=None):
        if role not in {"collector", "analyzer"}:
            raise ValueError("Unknown worker role")
        now = time.time() if now is None else now
        ready, active = ("queued", "collecting") if role == "collector" else ("collected", "analyzing")
        self.expire(now)
        with self.transaction() as db:
            query = "SELECT * FROM jobs WHERE deadline>? AND (status=? OR (status=? AND lease<=?))"
            args = [now, ready, active, now]
            if ident is not None:
                if tenant is None:
                    raise ValueError("Tenant required for targeted claim")
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

    def finish(self, ident, owner, status, artifact=None, now=None, error_code="processing_failed"):
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
                db.execute("UPDATE jobs SET status='failed',error='Scan processing failed; check connector access and coverage',error_code=?,error_stage=?,history=?,owner=NULL,lease=NULL WHERE id=? AND owner=?", (error_code, stage, history(row, "failed", now), ident, owner))
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
            request = {k: data[k] for k in ("connector_id", "categories", "checks", "frameworks") if k in data}
            error, result = None, None
            # Savepoint ensures a rejected enqueue never partially reserves quota.
            db.execute("SAVEPOINT scheduled_enqueue")
            try:
                result = self._enqueue(db, row["tenant"], request, limit, timeout, f"schedule:{row['id']}:{row['next_run']}", now)
            except StoreError as exc:
                db.execute("ROLLBACK TO scheduled_enqueue")
                error = exc.message
            db.execute("RELEASE scheduled_enqueue")
            db.execute("UPDATE schedules SET next_run=?,last_error=? WHERE id=? AND tenant=?", (now + data["interval_hours"] * 3600, error, row["id"], row["tenant"]))
            return result
