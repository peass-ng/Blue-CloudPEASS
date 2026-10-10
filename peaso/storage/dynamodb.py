"""Optional hosted tenant repository with transactionally reserved weekly quotas.

Uses only PK/SK, paginated strongly consistent tenant queries and fenced writes.
No live deployment is implied by this adapter; cloud validation is documented.
"""
from decimal import Decimal
import hashlib
import json
import time
import uuid
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
from botocore.exceptions import ClientError
from .sqlite import SQLiteStore, StoreError, TERMINAL, utc, week

SERIALIZER, DESERIALIZER = TypeSerializer(), TypeDeserializer()


def attrs(value):
    value = json.loads(json.dumps(value), parse_float=Decimal)
    return {k: SERIALIZER.serialize(v) for k, v in value.items()}


def plain(value):
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


def row(item):
    return plain({k: DESERIALIZER.deserialize(v) for k, v in item.items()})


class DynamoStore:
    public_job = staticmethod(SQLiteStore.public_job)
    public_schedule = staticmethod(SQLiteStore.public_schedule)

    def __init__(self, table, client=None):
        if client is None:
            import boto3
            client = boto3.client("dynamodb")
        self.table, self.client = table, client
        self.claims = {}
        self.clock = time.time

    def key(self, tenant, kind, ident):
        return {"PK": "tenant/" + tenant, "SK": kind + "/" + ident}

    def _get(self, tenant, kind, ident):
        item = self.client.get_item(TableName=self.table, Key=attrs(self.key(tenant, kind, ident)), ConsistentRead=True).get("Item")
        return row(item) if item else None

    def _put(self, tenant, kind, ident, value, old=None):
        value = dict(value, **self.key(tenant, kind, ident), kind=kind, rev=0 if old is None else old["rev"] + 1)
        item = attrs(value)
        if len(json.dumps(item)) > 380000:
            raise StoreError(413, "Hosted connector input is too large; use a smaller snapshot")
        arguments = {"TableName": self.table, "Item": item, "ConditionExpression": "attribute_not_exists(PK)"}
        if old is not None:
            arguments.update(ConditionExpression="#rev=:rev", ExpressionAttributeNames={"#rev": "rev"}, ExpressionAttributeValues=attrs({":rev": old["rev"]}))
        self.client.put_item(**arguments)

    def _query(self, tenant, kind):
        arguments = {"TableName": self.table, "ConsistentRead": True,
                     "KeyConditionExpression": "PK=:tenant AND begins_with(SK,:kind)",
                     "ExpressionAttributeValues": attrs({":tenant": "tenant/" + tenant, ":kind": kind + "/"})}
        result = []
        while True:
            page = self.client.query(**arguments)
            result += [row(item) for item in page.get("Items", [])]
            if not page.get("LastEvaluatedKey"):
                return result
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def _scan(self, kind):
        arguments = {"TableName": self.table, "ConsistentRead": True, "FilterExpression": "#kind=:kind",
                     "ExpressionAttributeNames": {"#kind": "kind"}, "ExpressionAttributeValues": attrs({":kind": kind})}
        result = []
        while True:
            page = self.client.scan(**arguments)
            result += [row(item) for item in page.get("Items", [])]
            if not page.get("LastEvaluatedKey"):
                return result
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def add_connector(self, tenant, data, encrypted_auth):
        value = dict(data, id=uuid.uuid4().hex, created_at=utc())
        self._put(tenant, "connector", value["id"], {"id": value["id"], "tenant": tenant, "data": json.dumps(value), "auth": encrypted_auth})
        return value

    def connector(self, tenant, ident):
        value = self._get(tenant, "connector", ident)
        if not value:
            raise StoreError(404, "Connector not found")
        return value

    def connectors(self, tenant):
        return self._query(tenant, "connector")

    def update_connector(self, tenant, ident, patch, encrypted_auth=None):
        for _ in range(8):
            old = self.connector(tenant, ident)
            new = dict(old, data=json.dumps(dict(json.loads(old["data"]), **patch)), auth=encrypted_auth or old["auth"])
            try:
                self._put(tenant, "connector", ident, new, old)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
        raise StoreError(409, "Connector changed concurrently; retry")

    def delete_connector(self, tenant, ident):
        self.connector(tenant, ident)
        self.client.delete_item(TableName=self.table, Key=attrs(self.key(tenant, "connector", ident)))
        for schedule in self.schedules(tenant):
            if schedule["connector_id"] == ident:
                try:
                    self.delete_schedule(tenant, schedule["id"])
                except StoreError:
                    pass

    def usage(self, tenant, now=None):
        current = self._get(tenant, "quota", week(time.time() if now is None else now))
        return current.get("used", 0) if current else 0

    def get_entitlement(self, tenant):
        value = self._get(tenant, "entitlement", "stripe")
        return value["paid"] if value and value["expires_at"] > time.time() else None

    def set_entitlement(self, tenant, paid, seconds=3600):
        self.client.put_item(TableName=self.table, Item=attrs(dict(self.key(tenant, "entitlement", "stripe"), kind="entitlement", paid=bool(paid), verified_at=int(time.time()), expires_at=int(time.time() + seconds))))

    def _replay(self, tenant, idem, digest):
        if idem is None:
            return None
        current = self._get(tenant, "idem", hashlib.sha256(idem.encode()).hexdigest())
        if not current or current.get("expires_at", float("inf")) <= self.clock():
            return None
        if current["digest"] != digest:
            raise StoreError(409, "Idempotency key already used for a different request")
        return self.public_job(self.job(tenant, current["id"]))

    def enqueue(self, tenant, request, limit=1, timeout=900, idem=None, now=None, extra=None):
        now = time.time() if now is None else now
        digest = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        replay = self._replay(tenant, idem, digest)
        if replay:
            return replay
        for attempt in range(8):
            connector = self.connector(tenant, request["connector_id"])
            ident = uuid.uuid4().hex
            value = dict(self.key(tenant, "job", ident), kind="job", rev=0, id=ident, tenant=tenant,
                         connector_id=request["connector_id"], data=json.dumps(request), connector=json.dumps({"data": json.loads(connector["data"]), "auth": connector["auth"]}),
                         status="queued", created=now, deadline=now + timeout, expires_at=int(now + max(30 * 86400, timeout + 86400)), owner=None, lease=None, snapshot=None, report=None, error=None, error_code=None, error_stage=None, history=[{"status": "queued", "at": utc(now)}], idem=idem, digest=digest)
            transactions = [
                {"ConditionCheck": {"TableName": self.table, "Key": attrs(self.key(tenant, "connector", connector["id"])), "ConditionExpression": "#rev=:rev", "ExpressionAttributeNames": {"#rev": "rev"}, "ExpressionAttributeValues": attrs({":rev": connector["rev"]})}},
                {"Update": {"TableName": self.table, "Key": attrs(self.key(tenant, "quota", week(now))), "UpdateExpression": "SET #kind=:kind, expires_at=:expires ADD used :one", "ConditionExpression": "attribute_not_exists(used) OR used<:limit", "ExpressionAttributeNames": {"#kind": "kind"}, "ExpressionAttributeValues": attrs({":kind": "quota", ":one": 1, ":limit": limit, ":expires": int(now + 14 * 86400)})}},
                {"Put": {"TableName": self.table, "Item": attrs(value), "ConditionExpression": "attribute_not_exists(PK)"}},
            ]
            if idem is not None:
                transactions.append({"Put": {"TableName": self.table, "Item": attrs(dict(self.key(tenant, "idem", hashlib.sha256(idem.encode()).hexdigest()), kind="idem", id=ident, digest=digest, expires_at=value["expires_at"])), "ConditionExpression": "attribute_not_exists(PK) OR expires_at<=:now", "ExpressionAttributeValues": attrs({":now": now})}})
            if extra:
                transactions.append(extra)
            try:
                self.client.transact_write_items(TransactItems=transactions)
                return self.public_job(value)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "TransactionCanceledException":
                    raise
                replay = self._replay(tenant, idem, digest)
                if replay:
                    return replay
                reasons = exc.response.get("CancellationReasons", [])
                if extra and reasons and reasons[-1].get("Code") == "ConditionalCheckFailed":
                    raise StoreError(409, "Schedule changed concurrently")
                if self.usage(tenant, now) >= limit:
                    raise StoreError(429, "Weekly scan quota exhausted")
                time.sleep(0.01 * (attempt + 1))
        raise StoreError(409, "Concurrent reservation; retry")

    def job(self, tenant, ident):
        value = self._get(tenant, "job", ident)
        if not value or value.get("expires_at", float("inf")) <= self.clock():
            raise StoreError(404, "Scan not found")
        return value

    def jobs(self, tenant):
        return [self.public_job(value) for value in sorted(self._query(tenant, "job"), key=lambda x: x["created"], reverse=True) if value.get("expires_at", float("inf")) > self.clock()]

    def queued_jobs(self):
        return [item for item in self._scan("job") if item["status"] == "queued"]

    def _update_job(self, tenant, ident, expression, names, values, condition):
        new_status = values.get(":status") if "#status=:status" in expression else values.get(":active") if "#status=:active" in expression else values.get(":cancelled") if "#status=:cancelled" in expression else values.get(":timed") if "#status=:timed" in expression else None
        if new_status:
            expression += ", #history=list_append(if_not_exists(#history,:empty),:events)"
            names["#history"] = "history"
            values[":empty"] = []
            values[":events"] = [{"status": new_status, "at": utc(values.get(":now", time.time()))}]
        try:
            self.client.update_item(TableName=self.table, Key=attrs(self.key(tenant, "job", ident)), UpdateExpression=expression, ExpressionAttributeNames=names, ExpressionAttributeValues=attrs(values), ConditionExpression="attribute_exists(PK) AND " + condition)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def cancel(self, tenant, ident):
        self.job(tenant, ident)
        self._update_job(tenant, ident, "SET #status=:cancelled, #owner=:null, lease=:null", {"#status": "status", "#owner": "owner"},
                         {":cancelled": "cancelled", ":null": None, ":done": "completed", ":failed": "failed", ":timed": "timed_out"}, "NOT (#status IN (:done,:failed,:cancelled,:timed))")
        return self.public_job(self.job(tenant, ident))

    def expire(self, now=None):
        now = time.time() if now is None else now
        for job in self._scan("job"):
            if job["status"] in TERMINAL or job["deadline"] > now:
                continue
            self._update_job(job["tenant"], job["id"], "SET #status=:timed, #owner=:null, lease=:null, #error=:error", {"#status": "status", "#owner": "owner", "#error": "error"},
                             {":timed": "timed_out", ":null": None, ":done": "completed", ":failed": "failed", ":cancelled": "cancelled", ":now": now, ":error": "Scan deadline exceeded"},
                             "deadline<=:now AND NOT (#status IN (:done,:failed,:cancelled,:timed))")

    def claim(self, role, lease_seconds=30, now=None, tenant=None, ident=None):
        if role not in {"collector", "analyzer"}:
            raise ValueError("Unknown worker role")
        if ident is not None and tenant is None:
            raise ValueError("Tenant required for targeted claim")
        now = time.time() if now is None else now
        ready, active = ("queued", "collecting") if role == "collector" else ("collected", "analyzing")
        candidates = [self.job(tenant, ident)] if ident else self._scan("job")
        for job in sorted(candidates, key=lambda x: x["created"]):
            if job["deadline"] <= now:
                if job["status"] not in TERMINAL:
                    self.expire(now)
                continue
            if job["status"] != ready and not (job["status"] == active and (job["lease"] or 0) <= now):
                continue
            owner = uuid.uuid4().hex
            success = self._update_job(job["tenant"], job["id"], "SET #status=:active, #owner=:owner, lease=:lease", {"#status": "status", "#owner": "owner"},
                                      {":active": active, ":ready": ready, ":owner": owner, ":lease": now + lease_seconds, ":now": now},
                                      "deadline>:now AND (#status=:ready OR (#status=:active AND lease<=:now))")
            if success:
                self.claims[(job["id"], owner)] = job["tenant"]
                return dict(job, status=active, owner=owner, lease=now + lease_seconds)
        return None

    def heartbeat(self, ident, owner, lease_seconds=30, now=None):
        now = time.time() if now is None else now
        tenant = self.claims.get((ident, owner))
        if tenant is None:
            return False
        return self._update_job(tenant, ident, "SET lease=:lease", {"#owner": "owner", "#status": "status"},
                                {":owner": owner, ":lease": now + lease_seconds, ":now": now, ":collecting": "collecting", ":analyzing": "analyzing"},
                                "#owner=:owner AND lease>:now AND deadline>:now AND #status IN (:collecting,:analyzing)")

    def finish(self, ident, owner, status, artifact=None, now=None, error_code="processing_failed"):
        if status not in {"collected", "completed", "failed"}:
            raise ValueError("Invalid worker transition")
        now = time.time() if now is None else now
        tenant = self.claims.get((ident, owner))
        if tenant is None:
            return False
        names = {"#owner": "owner", "#status": "status", "#artifact": "snapshot" if status == "collected" else "report", "#error": "error"}
        values = {":owner": owner, ":now": now, ":status": status, ":null": None, ":artifact": artifact,
                  ":error": "Scan processing failed; check connector access and coverage" if status == "failed" else None}
        names.update({"#error_code": "error_code", "#error_stage": "error_stage"})
        allowed = {"processing_failed", "invalid_input", "credential_access_denied", "dependency_unavailable", "provider_error", "collector_timeout", "artifact_error", "worker_interrupted"}
        values[":error_code"] = error_code if status == "failed" and error_code in allowed else "processing_failed" if status == "failed" else None
        values[":error_stage"] = ("collector" if self.job(tenant, ident)["status"] == "collecting" else "analyzer") if status == "failed" else None
        if status == "failed":
            values.update({":collecting": "collecting", ":analyzing": "analyzing"})
            previous = "#status IN (:collecting,:analyzing)"
        else:
            values[":previous"] = "collecting" if status == "collected" else "analyzing"
            previous = "#status=:previous"
        return self._update_job(tenant, ident, "SET #status=:status, #owner=:null, lease=:null, #artifact=:artifact, #error=:error, #error_code=:error_code, #error_stage=:error_stage", names, values,
                                "#owner=:owner AND lease>:now AND deadline>:now AND " + previous)

    def schedules(self, tenant):
        return [self.public_schedule(value) for value in self._query(tenant, "schedule")]

    def add_schedule(self, tenant, data, next_run, enabled=True):
        self.connector(tenant, data["connector_id"])
        ident = uuid.uuid4().hex
        value = {"id": ident, "tenant": tenant, "data": json.dumps(data), "next_run": next_run, "enabled": bool(enabled), "last_error": None}
        self._put(tenant, "schedule", ident, value)
        return self.public_schedule(value)

    def update_schedule(self, tenant, ident, patch, next_run=None, enabled=None):
        for _ in range(8):
            old = self._get(tenant, "schedule", ident)
            if old is None:
                raise StoreError(404, "Schedule not found")
            data = dict(json.loads(old["data"]), **patch)
            self.connector(tenant, data["connector_id"])
            new = dict(old, data=json.dumps(data), next_run=old["next_run"] if next_run is None else next_run, enabled=old["enabled"] if enabled is None else enabled, last_error=None)
            try:
                self._put(tenant, "schedule", ident, new, old)
                return self.public_schedule(new)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
        raise StoreError(409, "Schedule changed concurrently; retry")

    def delete_schedule(self, tenant, ident):
        try:
            self.client.delete_item(TableName=self.table, Key=attrs(self.key(tenant, "schedule", ident)), ConditionExpression="attribute_exists(PK)")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise StoreError(404, "Schedule not found") from None
            raise

    def due_schedules(self, now=None):
        now = time.time() if now is None else now
        return [value for value in self._scan("schedule") if value["enabled"] and value["next_run"] <= now]

    def pause_schedule(self, tenant, ident):
        self.client.update_item(TableName=self.table, Key=attrs(self.key(tenant, "schedule", ident)), UpdateExpression="SET #enabled=:false,last_error=:error ADD #rev :one", ConditionExpression="attribute_exists(PK)", ExpressionAttributeNames={"#enabled": "enabled", "#rev": "rev"}, ExpressionAttributeValues=attrs({":false": False, ":error": "Schedule disabled: identity is no longer eligible", ":one": 1}))

    def trigger_schedule(self, current, limit=1, timeout=900, now=None):
        now = time.time() if now is None else now
        data = json.loads(current["data"])
        request = {k: data[k] for k in ("connector_id", "categories", "checks", "frameworks") if k in data}
        update = {"TableName": self.table, "Key": attrs(self.key(current["tenant"], "schedule", current["id"])),
                  "UpdateExpression": "SET next_run=:next, last_error=:null ADD #rev :one", "ConditionExpression": "#enabled=:true AND next_run=:old AND #rev=:rev",
                  "ExpressionAttributeNames": {"#enabled": "enabled", "#rev": "rev"},
                  "ExpressionAttributeValues": attrs({":next": now + data["interval_hours"] * 3600, ":old": current["next_run"], ":rev": current["rev"], ":one": 1, ":true": True, ":null": None})}
        try:
            return self.enqueue(current["tenant"], request, limit, timeout, f"schedule:{current['id']}:{current['next_run']}", now, {"Update": update})
        except StoreError as exc:
            if exc.status == 409:
                return None
            update["ExpressionAttributeValues"] = attrs({":next": now + data["interval_hours"] * 3600, ":old": current["next_run"], ":rev": current["rev"], ":one": 1, ":true": True, ":null": exc.message})
            try:
                self.client.update_item(**update)
            except ClientError as update_error:
                if update_error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
            return None

    def health(self):
        self.client.describe_table(TableName=self.table)
