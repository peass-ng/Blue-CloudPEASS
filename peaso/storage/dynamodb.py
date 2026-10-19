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
from .sqlite import SQLiteStore, StoreError, TERMINAL, failure_error, utc, week

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

    @staticmethod
    def _workspace_key(workspace_id, kind, ident):
        return {"PK": "workspace/" + workspace_id, "SK": kind + "/" + ident}

    @staticmethod
    def _workspace_user_key(user_id, kind, ident):
        return {"PK": "user/" + user_id, "SK": kind + "/" + ident}

    def _workspace_get(self, key):
        item = self.client.get_item(TableName=self.table, Key=attrs(key), ConsistentRead=True).get("Item")
        return row(item) if item else None

    def _workspace_query(self, partition, prefix):
        arguments = {"TableName": self.table, "ConsistentRead": True,
                     "KeyConditionExpression": "PK=:pk AND begins_with(SK,:prefix)",
                     "ExpressionAttributeValues": attrs({":pk": partition, ":prefix": prefix})}
        result = []
        while True:
            page = self.client.query(**arguments)
            result.extend(row(item) for item in page.get("Items", []))
            if not page.get("LastEvaluatedKey"):
                return result
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def workspace(self, workspace_id):
        return self._workspace_get(self._workspace_key(workspace_id, "meta", "current"))

    def workspace_role(self, workspace_id, user_id):
        member = self._workspace_get(self._workspace_key(workspace_id, "member", user_id))
        return member.get("role") if member else None

    def workspaces(self, user_id):
        refs = self._workspace_query("user/" + user_id, "workspace/")
        result = []
        for ref in refs:
            workspace = self.workspace(ref["workspace_id"])
            role = self.workspace_role(ref["workspace_id"], user_id) if workspace else None
            if role:
                result.append({"id": workspace["id"], "name": workspace["name"], "owner": workspace["owner"], "role": role})
        return sorted(result, key=lambda item: item["name"].casefold())

    def create_workspace(self, owner, name, name_key, email):
        ident, now = "ws_" + uuid.uuid4().hex, time.time()
        meta = dict(self._workspace_key(ident, "meta", "current"), id=ident, owner=owner, name=name, name_key=name_key, created=now, occupied=0)
        member = dict(self._workspace_key(ident, "member", owner), workspace_id=ident, user_id=owner, email=email, role="admin", joined=now)
        ref = dict(self._workspace_user_key(owner, "workspace", ident), workspace_id=ident)
        name_lock = {"PK": "workspace-name/" + name_key, "SK": "current", "workspace_id": ident}
        capacity = self._workspace_user_key(owner, "workspace_capacity", "current")
        try:
            self.client.transact_write_items(TransactItems=[
                {"Put": {"TableName": self.table, "Item": attrs(meta), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(member), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(ref), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(name_lock), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Update": {"TableName": self.table, "Key": attrs(capacity), "UpdateExpression": "ADD workspace_count :one",
                            "ConditionExpression": "attribute_not_exists(workspace_count) OR workspace_count<:limit",
                            "ExpressionAttributeValues": attrs({":one": 1, ":limit": 5})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                if self._workspace_get({"PK": "workspace-name/" + name_key, "SK": "current"}):
                    raise StoreError(409, "Workspace name is already in use") from None
                raise StoreError(403, "You can create up to five workspaces") from None
            raise
        return {"id": ident, "owner": owner, "name": name, "role": "admin"}

    def workspace_people(self, workspace_id):
        members = self._workspace_query("workspace/" + workspace_id, "member/")
        invites = self._workspace_query("workspace/" + workspace_id, "invite/")
        return ([{k: item[k] for k in ("user_id", "email", "role", "joined")} for item in members],
                [{k: item[k] for k in ("user_id", "email", "role", "invited_by", "created")} for item in invites])

    def workspace_invitations(self, user_id):
        refs = self._workspace_query("user/" + user_id, "invite/")
        result = []
        for ref in refs:
            workspace = self.workspace(ref["workspace_id"])
            if workspace:
                result.append({k: ref[k] for k in ("workspace_id", "email", "role", "invited_by", "created")} | {"name": workspace["name"]})
        return sorted(result, key=lambda item: item["created"], reverse=True)

    def invite_workspace(self, workspace_id, user_id, email, role, invited_by):
        if self.workspace_role(workspace_id, user_id):
            raise StoreError(409, "This person is already a workspace member")
        now = time.time()
        payload = {"workspace_id": workspace_id, "user_id": user_id, "email": email, "role": role, "invited_by": invited_by, "created": now}
        invite = dict(self._workspace_key(workspace_id, "invite", user_id), **payload)
        pointer = dict(self._workspace_user_key(user_id, "invite", workspace_id), **payload)
        try:
            self.client.transact_write_items(TransactItems=[
                {"ConditionCheck": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "member", user_id)),
                                    "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(invite), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(pointer), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Update": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "meta", "current")),
                            "UpdateExpression": "ADD occupied :one", "ConditionExpression": "attribute_exists(PK) AND occupied<:limit",
                            "ExpressionAttributeValues": attrs({":one": 1, ":limit": 100})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                if self.workspace_role(workspace_id, user_id):
                    raise StoreError(409, "This person is already a workspace member") from None
                if self._workspace_get(self._workspace_key(workspace_id, "invite", user_id)):
                    raise StoreError(409, "An invitation is already pending") from None
                raise StoreError(403, "Workspace invitation limit reached") from None
            raise

    def respond_workspace_invitation(self, workspace_id, user_id, accept):
        invite_key = self._workspace_key(workspace_id, "invite", user_id)
        invite = self._workspace_get(invite_key)
        if not invite:
            raise StoreError(404, "Invitation not found")
        actions = [
            {"Delete": {"TableName": self.table, "Key": attrs(invite_key), "ConditionExpression": "attribute_exists(PK)"}},
            {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_user_key(user_id, "invite", workspace_id))}},
        ]
        if accept:
            member = dict(self._workspace_key(workspace_id, "member", user_id), workspace_id=workspace_id,
                          user_id=user_id, email=invite["email"], role=invite["role"], joined=time.time())
            ref = dict(self._workspace_user_key(user_id, "workspace", workspace_id), workspace_id=workspace_id)
            actions.extend([
                {"Put": {"TableName": self.table, "Item": attrs(member), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(ref), "ConditionExpression": "attribute_not_exists(PK)"}},
            ])
        else:
            actions.append({"Update": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "meta", "current")),
                                      "UpdateExpression": "ADD occupied :minus", "ExpressionAttributeValues": attrs({":minus": -1})}})
        try:
            self.client.transact_write_items(TransactItems=actions)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(409, "Invitation changed; refresh and try again") from None
            raise

    def revoke_workspace_invitation(self, workspace_id, user_id):
        try:
            self.client.transact_write_items(TransactItems=[
                {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "invite", user_id)),
                            "ConditionExpression": "attribute_exists(PK)"}},
                {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_user_key(user_id, "invite", workspace_id))}},
                {"Update": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "meta", "current")),
                            "UpdateExpression": "ADD occupied :minus", "ExpressionAttributeValues": attrs({":minus": -1})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(404, "Invitation not found") from None
            raise

    def set_workspace_role(self, workspace_id, user_id, role):
        workspace = self.workspace(workspace_id)
        if not workspace or workspace["owner"] == user_id:
            raise StoreError(403, "The workspace owner's role cannot be changed")
        try:
            self.client.update_item(TableName=self.table, Key=attrs(self._workspace_key(workspace_id, "member", user_id)),
                                    UpdateExpression="SET #role=:role", ConditionExpression="attribute_exists(PK)",
                                    ExpressionAttributeNames={"#role": "role"}, ExpressionAttributeValues=attrs({":role": role}))
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise StoreError(404, "Workspace member not found") from None
            raise

    def remove_workspace_member(self, workspace_id, user_id):
        workspace = self.workspace(workspace_id)
        if not workspace or workspace["owner"] == user_id:
            raise StoreError(403, "The workspace owner cannot be removed")
        try:
            self.client.transact_write_items(TransactItems=[
                {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "member", user_id)), "ConditionExpression": "attribute_exists(PK)"}},
                {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_user_key(user_id, "workspace", workspace_id))}},
                {"Update": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "meta", "current")),
                            "UpdateExpression": "ADD occupied :minus", "ExpressionAttributeValues": attrs({":minus": -1})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(404, "Workspace member not found") from None
            raise

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

    def create_api_key(self, tenant, record):
        """Store the hash under the tenant and a hash-free random-ID lookup pointer."""
        from peaso.auth.api_keys import MAX_UNREVOKED_KEYS
        value = {key: item for key, item in record.items() if item is not None}
        value.update(self.key(tenant, "api_key", record["id"]), kind="api_key", tenant=tenant)
        pointer = {"PK": "api-key/" + record["id"], "SK": "lookup", "kind": "api_key_lookup", "tenant": tenant}
        capacity = self.key(tenant, "api_key_capacity", "current")
        try:
            self.client.transact_write_items(TransactItems=[
                {"Put": {"TableName": self.table, "Item": attrs(value), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(pointer), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Update": {"TableName": self.table, "Key": attrs(capacity),
                            "UpdateExpression": "SET #kind=:kind ADD active_count :one",
                            "ConditionExpression": "attribute_not_exists(active_count) OR active_count<:limit",
                            "ExpressionAttributeNames": {"#kind": "kind"},
                            "ExpressionAttributeValues": attrs({":kind": "api_key_capacity", ":one": 1, ":limit": MAX_UNREVOKED_KEYS})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(429, "Revoke an unused API key before creating another") from None
            raise
        return dict(value)

    def api_key(self, key_id):
        pointer = self.client.get_item(TableName=self.table,
                                       Key=attrs({"PK": "api-key/" + key_id, "SK": "lookup"}),
                                       ConsistentRead=True).get("Item")
        if not pointer:
            return None
        tenant = row(pointer).get("tenant")
        if not isinstance(tenant, str):
            return None
        value = self._get(tenant, "api_key", key_id)
        return value if value and value.get("tenant") == tenant and value.get("id") == key_id else None

    def api_keys(self, tenant, after=None, limit=50):
        arguments = {"TableName": self.table, "ConsistentRead": True,
                     "KeyConditionExpression": "PK=:tenant AND begins_with(SK,:kind)",
                     "ExpressionAttributeValues": attrs({":tenant": "tenant/" + tenant, ":kind": "api_key/"}),
                     "Limit": limit + 1}
        if after:
            arguments["ExclusiveStartKey"] = attrs(self.key(tenant, "api_key", after))
        values = []
        while len(values) <= limit:
            page = self.client.query(**arguments)
            values.extend(row(item) for item in page.get("Items", ()))
            if not page.get("LastEvaluatedKey") or len(values) > limit:
                break
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]
            arguments["Limit"] = limit + 1 - len(values)
        return values[:limit], values[limit - 1]["id"] if len(values) > limit else None

    def revoke_api_key(self, tenant, key_id, now=None):
        now = time.time() if now is None else now
        try:
            self.client.transact_write_items(TransactItems=[
                {"Update": {"TableName": self.table, "Key": attrs(self.key(tenant, "api_key", key_id)),
                            "UpdateExpression": "SET revoked_at=:now",
                            "ConditionExpression": "attribute_exists(PK) AND attribute_not_exists(revoked_at)",
                            "ExpressionAttributeValues": attrs({":now": now})}},
                {"Update": {"TableName": self.table, "Key": attrs(self.key(tenant, "api_key_capacity", "current")),
                            "UpdateExpression": "ADD active_count :minus",
                            "ConditionExpression": "attribute_exists(active_count) AND active_count>:zero",
                            "ExpressionAttributeValues": attrs({":minus": -1, ":zero": 0})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(404, "API key not found") from None
            raise

    def touch_api_key(self, tenant, key_id, now=None):
        now = time.time() if now is None else now
        try:
            self.client.update_item(TableName=self.table, Key=attrs(self.key(tenant, "api_key", key_id)),
                                    UpdateExpression="SET last_used_at=:now",
                                    ConditionExpression="attribute_exists(PK) AND attribute_not_exists(revoked_at) AND (attribute_not_exists(expires_at) OR expires_at>:now)",
                                    ExpressionAttributeValues=attrs({":now": now}))
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def workspace_external_id(self, tenant):
        import secrets
        existing = self._get(tenant, "aws_external_id", "workspace")
        if existing:
            return existing["external_id"]
        value = "hacktricks-cspm-ws-" + secrets.token_urlsafe(48)
        try:
            self._put(tenant, "aws_external_id", "workspace", {"external_id": value})
            return value
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            existing = self._get(tenant, "aws_external_id", "workspace")
            if not existing:
                raise
            return existing["external_id"]

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

    def get_admin_qa_grant(self, tenant):
        value = self._get(tenant, "entitlement", "admin_qa")
        return value if value and value.get("tenant") == tenant and value.get("kind") == "admin_qa_grant" else None

    def issue_admin_qa_grant(self, tenant, record, now=None, expected_predecessor=None):
        from peaso.auth.admin_qa import valid_issue
        now = self.clock() if now is None else now
        if not valid_issue(record, tenant=tenant, now=now):
            raise StoreError(400, "Invalid administrator QA grant")
        if expected_predecessor is not None and (
                not isinstance(expected_predecessor, dict) or
                set(expected_predecessor) != {"audit_id", "rev"} or
                not isinstance(expected_predecessor["audit_id"], str) or
                type(expected_predecessor["rev"]) is not int or expected_predecessor["rev"] < 0):
            raise StoreError(400, "Invalid reviewed predecessor")
        prior = self.get_admin_qa_grant(tenant)
        if expected_predecessor is None:
            if prior is not None:
                raise StoreError(409, "Prior administrator QA grant requires explicit review")
            revision = 0
            condition = "attribute_not_exists(PK)"
            values = None
        else:
            if (not prior or prior.get("audit_id") != expected_predecessor["audit_id"] or
                    prior.get("rev") != expected_predecessor["rev"]):
                raise StoreError(409, "Reviewed predecessor is absent or changed")
            revoked = type(prior.get("revoked_at")) in (int, float) and prior["revoked_at"] > 0
            expired = type(prior.get("hard_expires_at")) in (int, float) and prior["hard_expires_at"] <= now
            if not (revoked or expired):
                raise StoreError(409, "Reviewed predecessor remains active")
            revision = prior["rev"] + 1
            condition = ("audit_id=:old_audit AND #rev=:old_rev AND "
                         "((attribute_type(revoked_at,:number_type) AND revoked_at>:zero) "
                         "OR hard_expires_at<=:now)")
            values = attrs({":old_audit": expected_predecessor["audit_id"],
                            ":old_rev": expected_predecessor["rev"],
                            ":number_type": "N", ":zero": 0, ":now": now})
        current = dict(self.key(tenant, "entitlement", "admin_qa"), **record,
                       kind="admin_qa_grant", rev=revision)
        event = dict(self.key(tenant, "admin_qa_grant_event", record["audit_id"] + "/issue"),
                     kind="admin_qa_grant_event", tenant=tenant, audit_id=record["audit_id"],
                     event="issue", record=record)
        put = {"TableName": self.table, "Item": attrs(current), "ConditionExpression": condition}
        if values is not None:
            put.update(ExpressionAttributeNames={"#rev": "rev"}, ExpressionAttributeValues=values)
        try:
            self.client.transact_write_items(TransactItems=[
                {"Put": put},
                {"Put": {"TableName": self.table, "Item": attrs(event),
                         "ConditionExpression": "attribute_not_exists(PK)"}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(409, "Administrator QA predecessor or audit ID changed") from None
            raise
        return dict(current)

    def revoke_admin_qa_grant(self, tenant, audit_id, actor, reason, now=None):
        now = self.clock() if now is None else now
        from peaso.auth.admin_qa import valid_actor
        if not valid_actor(actor) or not isinstance(reason, str) or not reason.strip():
            raise StoreError(400, "Valid revocation actor and reason required")
        old = self.get_admin_qa_grant(tenant)
        if not old or old.get("audit_id") != audit_id or old.get("revoked_at") is not None:
            raise StoreError(409, "Administrator QA grant changed or expired")
        updated = dict(old, revoked_at=now, revoked_by=actor, revoke_reason=reason.strip(), rev=old["rev"] + 1)
        event = dict(self.key(tenant, "admin_qa_grant_event", audit_id + "/revoke"),
                     kind="admin_qa_grant_event", tenant=tenant, audit_id=audit_id,
                     event="revoke", record=updated)
        try:
            self.client.transact_write_items(TransactItems=[
                {"Put": {"TableName": self.table, "Item": attrs(updated),
                         "ConditionExpression": "#rev=:rev AND audit_id=:audit AND attribute_not_exists(revoked_at)",
                         "ExpressionAttributeNames": {"#rev": "rev"},
                         "ExpressionAttributeValues": attrs({":rev": old["rev"], ":audit": audit_id})}},
                {"Put": {"TableName": self.table, "Item": attrs(event),
                         "ConditionExpression": "attribute_not_exists(PK)"}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(409, "Administrator QA grant changed or expired") from None
            raise
        return updated

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

    def jobs(self, tenant, transform=None):
        return [(transform or self.public_job)(value) for value in sorted(self._query(tenant, "job"), key=lambda x: x["created"], reverse=True) if value.get("expires_at", float("inf")) > self.clock()]

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
            self._expire_job(job, now)

    def expire_job(self, tenant, ident, now=None):
        """Expire one tenant job without enumerating other jobs or tenants."""
        now = time.time() if now is None else now
        return self._expire_job(self.job(tenant, ident), now)

    def _expire_job(self, job, now):
        if job["status"] in TERMINAL or job["deadline"] > now:
            return False
        stage = "collector" if job["status"] in {"queued", "collecting"} else "analyzer"
        return self._update_job(job["tenant"], job["id"],
                                "SET #status=:timed, #owner=:null, lease=:null, #error=:error, #error_code=:code, #error_stage=:stage",
                                {"#status": "status", "#owner": "owner", "#error": "error", "#error_code": "error_code", "#error_stage": "error_stage"},
                                {":timed": "timed_out", ":null": None, ":previous": job["status"], ":now": now, ":error": "Scan deadline exceeded", ":code": "deadline_exceeded", ":stage": stage},
                                "deadline<=:now AND #status=:previous")

    def claim(self, role, lease_seconds=30, now=None, tenant=None, ident=None):
        if role not in {"collector", "analyzer"}:
            raise ValueError("Unknown worker role")
        if ident is not None and tenant is None:
            raise ValueError("Tenant required for targeted claim")
        now = time.time() if now is None else now
        ready, active = ("queued", "collecting") if role == "collector" else ("collected", "analyzing")
        candidates = [self.job(tenant, ident)] if ident is not None else self._scan("job")
        for job in sorted(candidates, key=lambda x: x["created"]):
            if job["deadline"] <= now:
                self._expire_job(job, now)
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

    def finish(self, ident, owner, status, artifact=None, now=None, error_code="processing_failed", failure_reasons=None):
        if status not in {"collected", "completed", "failed"}:
            raise ValueError("Invalid worker transition")
        now = time.time() if now is None else now
        tenant = self.claims.get((ident, owner))
        if tenant is None:
            return False
        names = {"#owner": "owner", "#status": "status", "#artifact": "snapshot" if status == "collected" else "report", "#error": "error"}
        values = {":owner": owner, ":now": now, ":status": status, ":null": None, ":artifact": artifact,
                  ":error": failure_error(failure_reasons) if status == "failed" else None}
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
        try:
            self.client.update_item(TableName=self.table, Key=attrs(self.key(tenant, "schedule", ident)), UpdateExpression="SET #enabled=:false,last_error=:error ADD #rev :one", ConditionExpression="attribute_exists(PK)", ExpressionAttributeNames={"#enabled": "enabled", "#rev": "rev"}, ExpressionAttributeValues=attrs({":false": False, ":error": "Schedule disabled: identity is no longer eligible", ":one": 1}))
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # A concurrent deletion must not halt other tenants or resurrect a row.
                return False
            raise

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
