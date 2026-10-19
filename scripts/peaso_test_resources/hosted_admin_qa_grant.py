"""Operator-only candidate for a reviewed, short-lived CSPM QA entitlement.

No public API route calls this command. Its private manifest is pre-reviewed;
issue/revoke must each have a separate exact coordinator cloud-write grant.
"""
from __future__ import annotations

from peaso import deployment
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import sys
import time

import boto3

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from peaso.auth.admin_qa import AUTHORITY, MAX_LIFETIME_SECONDS, valid_issue
from peaso.storage.dynamodb import DynamoStore

ACCOUNT = deployment.value("account_id")
REGION = "us-east-1"
TABLE = "hacktricks-cspm"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def private_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        raise RuntimeError("Private audit receipt already exists")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, sort_keys=True, indent=2)
        out.write("\n")


def load_manifest(path, expected_sha):
    if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError("Manifest must be a private non-symlink file")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise RuntimeError("Reviewed private manifest changed")
    value = json.loads(raw)
    required = {"account", "region", "table", "pool_id", "client_id", "cognito_username",
                "subject", "verified_email", "reason", "audit_id", "issued_at", "hard_expires_at",
                "operator_role_prefix", "ledger_dir"}
    if not isinstance(value, dict) or set(value) != required:
        raise RuntimeError("Private manifest fields are incomplete or excessive")
    if (value["account"], value["region"], value["table"]) != (ACCOUNT, REGION, TABLE):
        raise RuntimeError("Wrong deployment account, region or table")
    if not re.fullmatch(((r"arn:aws:sts::DEPLOYMENT_ACCOUNT_ID:assumed-role/[A-Za-z0-9+=,.@_-]+/").replace("DEPLOYMENT_ACCOUNT_ID", deployment.value("account_id"))),
                        value["operator_role_prefix"]):
        raise RuntimeError("Reviewed operator role prefix is invalid")
    return value


def live_identity(session, value):
    caller = session.client("sts").get_caller_identity()
    arn = caller["Arn"]
    if caller["Account"] != ACCOUNT or not arn.startswith(value["operator_role_prefix"]):
        raise RuntimeError("Operator identity differs from reviewed role")
    cognito = session.client("cognito-idp")
    user = cognito.admin_get_user(UserPoolId=value["pool_id"], Username=value["cognito_username"])
    attrs = {entry["Name"]: entry["Value"] for entry in user.get("UserAttributes", [])}
    if (user.get("Enabled") is not True or attrs.get("sub") != value["subject"] or
            attrs.get("email") != value["verified_email"] or attrs.get("email_verified") != "true"):
        raise RuntimeError("Live enabled verified Cognito identity differs from reviewed tenant")
    client = cognito.describe_user_pool_client(UserPoolId=value["pool_id"], ClientId=value["client_id"])["UserPoolClient"]
    if client.get("UserPoolId") != value["pool_id"] or client.get("ClientId") != value["client_id"]:
        raise RuntimeError("Current Cognito client differs from reviewed app")
    return arn


def record(value, actor):
    return {"tenant": value["subject"], "cognito_subject": value["subject"],
            "cognito_pool_id": value["pool_id"], "cognito_client_id": value["client_id"],
            "verified_email": value["verified_email"], "authority": AUTHORITY,
            "actor": actor, "reason": value["reason"], "audit_id": value["audit_id"],
            "issued_at": value["issued_at"], "hard_expires_at": value["hard_expires_at"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("issue", "revoke"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--expected-row-sha256", help="Exact separately reviewed active grant preimage for revoke")
    args = parser.parse_args()
    value = load_manifest(args.manifest, args.manifest_sha256)
    session = boto3.Session(region_name=REGION)
    actor = live_identity(session, value)
    now = time.time()
    store = DynamoStore(TABLE, session.client("dynamodb"))
    previous = store.get_admin_qa_grant(value["subject"])
    if args.action == "issue":
        if args.expected_row_sha256 is not None:
            raise RuntimeError("Issue requires an absent row, not a predecessor hash")
        wanted = record(value, actor)
        if not valid_issue(wanted, tenant=value["subject"], now=now):
            raise RuntimeError("Grant shape or <=24-hour deadline is invalid")
        if previous is not None:
            raise RuntimeError("An existing QA grant requires separately reviewed predecessor authorization")
        action_hash = digest(wanted)
    else:
        if (not previous or previous.get("audit_id") != value["audit_id"] or
                previous.get("revoked_at") is not None or
                digest(previous) != args.expected_row_sha256):
            raise RuntimeError("Exact reviewed active grant preimage is missing or changed")
        action_hash = digest(previous)
    ledger_dir = Path(value["ledger_dir"])
    if ledger_dir.is_symlink() or not ledger_dir.resolve().is_relative_to((ROOT / ".cache").resolve()):
        raise RuntimeError("Private ledger path escapes cache")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ledger = ledger_dir / f"admin-qa-{args.action}-{stamp}-{value['audit_id']}.private.json"
    private_json(ledger, {"phase": "planned", "action": args.action,
                          "manifest_sha256": args.manifest_sha256, "before_sha256": digest(previous),
                          "requested_sha256": action_hash, "account": ACCOUNT, "region": REGION,
                          "audit_id": value["audit_id"], "actor": actor, "at": now})
    if args.action == "issue":
        store.issue_admin_qa_grant(value["subject"], wanted, now=now)
        after = store.get_admin_qa_grant(value["subject"])
        if not after or any(after.get(k) != v for k, v in wanted.items()):
            raise RuntimeError("Issued grant did not match reviewed row; inspect private ledger")
    else:
        store.revoke_admin_qa_grant(value["subject"], value["audit_id"], actor,
                                    "QA acceptance complete; operator revoked temporary grant", now=now)
        after = store.get_admin_qa_grant(value["subject"])
        if not after or after.get("audit_id") != value["audit_id"] or after.get("revoked_at") is None:
            raise RuntimeError("Revocation was not verified; inspect private ledger")
    # A separate immutable receipt records the postwrite state and prior ledger;
    # the planned receipt itself is never rewritten after the mutation.
    private_json(ledger.with_name(ledger.stem + ".verified.json"),
                 {"phase": "verified", "action": args.action, "before_ledger_sha256": hashlib.sha256(ledger.read_bytes()).hexdigest(),
                  "after_sha256": digest(after), "audit_id": value["audit_id"], "at": time.time()})
    print(json.dumps({"action": args.action, "verified": True,
                      "after_sha256": digest(after), "ledger": str(ledger)}))


if __name__ == "__main__":
    main()
