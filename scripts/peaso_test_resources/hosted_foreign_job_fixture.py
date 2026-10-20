"""Controlled foreign-tenant metadata fixture for hosted API-key isolation QA.

Preview is offline. Create/verify/delete require the reviewed manifest SHA and
an AWS session for the exact CSPM account. Never runs a scan or creates a
connector, artifact, quota, lock, schedule, workflow, or compute resource.
"""
from peaso import deployment
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import time


ACCOUNT = deployment.value("account_id")
REGION = "us-east-1"
TABLE = "hacktricks-cspm"
OWN_TENANT = "d48824c8-5021-7029-7c47-9c55bf99e58f"
MANIFEST = Path(".cache/hosted-current-rc-guard-api-name/foreign-job-fixture.private.json")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def fixture(now):
    tenant = "qa-foreign-" + secrets.token_hex(12)
    ident = secrets.token_hex(16)
    nonce = secrets.token_hex(16)
    record = {
        "PK": "tenant/" + tenant,
        "SK": "job/" + ident,
        "kind": "job",
        "rev": 0,
        "id": ident,
        "tenant": tenant,
        "connector_id": "qa-no-connector",
        "data": json.dumps({"connector_id": "qa-no-connector"}, separators=(",", ":")),
        "connector": json.dumps({"data": {"input_mode": "fixture"}, "auth": None}, separators=(",", ":")),
        "status": "failed",
        "created": now,
        "deadline": now,
        "expires_at": int(now) + 3600,
        "owner": None,
        "lease": None,
        "snapshot": None,
        "report": None,
        "error": "Controlled QA tenant-isolation fixture; no scan was run",
        "error_code": "QA_FIXTURE_ONLY",
        "error_stage": "preflight",
        "history": [{"status": "failed", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))}],
        "idem": None,
        "digest": digest({"purpose": "tenant-isolation", "nonce": nonce}),
        "qa_provenance": "hosted-current-api-key-isolation",
        "qa_nonce": nonce,
    }
    return {"account": ACCOUNT, "region": REGION, "table": TABLE, "own_tenant": OWN_TENANT,
            "record": record, "record_sha256": digest(record), "created_offline_at": int(now)}


def save_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value) + b"\n")


def load_reviewed(expected_sha, *, allow_expired=False):
    data = MANIFEST.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise SystemExit("Manifest SHA guard failed")
    manifest = json.loads(data)
    item = manifest["record"]
    if manifest["account"] != ACCOUNT or manifest["region"] != REGION or manifest["table"] != TABLE or manifest["own_tenant"] != OWN_TENANT:
        raise SystemExit("Environment guard failed")
    if item["PK"] == "tenant/" + OWN_TENANT or not item["PK"].startswith("tenant/qa-foreign-") or item["SK"] != "job/" + item["id"]:
        raise SystemExit("Synthetic identity guard failed")
    if item["kind"] != "job" or item["status"] != "failed" or item["qa_provenance"] != "hosted-current-api-key-isolation" or item["rev"] != 0:
        raise SystemExit("Inactive fixture guard failed")
    if manifest["record_sha256"] != digest(item) or not 0 < item["expires_at"] - manifest["created_offline_at"] <= 3600:
        raise SystemExit("Record or expiry guard failed")
    if not allow_expired and int(time.time()) >= item["expires_at"]:
        raise SystemExit("Fixture expired before use")
    return manifest


def client():
    import boto3
    if boto3.client("sts", region_name=REGION).get_caller_identity().get("Account") != ACCOUNT:
        raise SystemExit("Account guard failed")
    return boto3.client("dynamodb", region_name=REGION)


def encoded(item):
    from peaso.storage.dynamodb import attrs
    return attrs(item)


def decoded(item):
    from peaso.storage.dynamodb import row
    return row(item)


def get_exact(api, item):
    return api.get_item(TableName=TABLE, Key=encoded({"PK": item["PK"], "SK": item["SK"]}), ConsistentRead=True).get("Item")


def active_jobs(api):
    """Require complete bounded metadata inventory, never inspect job contents."""
    kwargs = dict(TableName=TABLE, Limit=100, ConsistentRead=True,
                  ProjectionExpression="PK, SK, #status",
                  ExpressionAttributeNames={"#status": "status"},
                  FilterExpression="begins_with(PK,:tenant) AND begins_with(SK,:job)",
                  ExpressionAttributeValues=encoded({":tenant": "tenant/", ":job": "job/"}))
    active = 0
    for _ in range(20):
        page = api.scan(**kwargs)
        for item in page.get("Items", []):
            status = item.get("status", {}).get("S")
            if status not in {"completed", "failed", "cancelled", "timed_out"}:
                active += 1
        last = page.get("LastEvaluatedKey")
        if not last:
            return active
        kwargs["ExclusiveStartKey"] = last
    raise SystemExit("Active-work inventory exceeded the bounded page limit")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preview", "create", "verify", "delete"))
    parser.add_argument("--manifest-sha256", help="Exact coordinator-reviewed private manifest SHA")
    args = parser.parse_args()
    if args.action == "preview":
        save_private(MANIFEST, fixture(time.time()))
        print(json.dumps({"action": "preview", "manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
                          "record_sha256": json.loads(MANIFEST.read_text())["record_sha256"], "ttl_seconds": 3600}))
        return
    if not args.manifest_sha256:
        raise SystemExit("Exact manifest SHA is required")
    manifest = load_reviewed(args.manifest_sha256, allow_expired=args.action == "delete")
    item = manifest["record"]
    api = client()
    if args.action == "create":
        if active_jobs(api):
            raise SystemExit("Active jobs present before fixture creation")
        if get_exact(api, item):
            raise SystemExit("Fixture key already exists")
        api.put_item(TableName=TABLE, Item=encoded(item),
                     ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)")
        if decoded(get_exact(api, item)) != item:
            raise SystemExit("Postcreate fixture mismatch; manually inspect before cleanup")
        if active_jobs(api):
            raise SystemExit("Active jobs present after fixture creation")
        print(json.dumps({"action": "create", "verified": True, "record_sha256": manifest["record_sha256"]}))
    elif args.action == "verify":
        found = get_exact(api, item)
        if not found or decoded(found) != item:
            raise SystemExit("Fixture absent or changed")
        print(json.dumps({"action": "verify", "verified": True, "record_sha256": manifest["record_sha256"]}))
    else:
        if active_jobs(api):
            raise SystemExit("Active jobs present before fixture deletion")
        found = get_exact(api, item)
        if not found or decoded(found) != item:
            raise SystemExit("Exact-owned fixture absent or changed; refusing delete")
        api.delete_item(TableName=TABLE, Key=encoded({"PK": item["PK"], "SK": item["SK"]}),
                        ConditionExpression="qa_nonce=:nonce AND #status=:failed AND #rev=:zero AND expires_at=:expiry",
                        ExpressionAttributeNames={"#status": "status", "#rev": "rev"},
                        ExpressionAttributeValues=encoded({":nonce": item["qa_nonce"], ":failed": "failed", ":zero": 0,
                                                           ":expiry": item["expires_at"]}))
        if get_exact(api, item):
            raise SystemExit("Postdelete fixture still exists")
        if active_jobs(api):
            raise SystemExit("Active jobs present after fixture deletion")
        print(json.dumps({"action": "delete", "verified_absent": True, "record_sha256": manifest["record_sha256"]}))


if __name__ == "__main__":
    main()
