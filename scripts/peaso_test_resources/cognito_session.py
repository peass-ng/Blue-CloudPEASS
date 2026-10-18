"""Own short-lived free Cognito test identities, private tokens and finally teardown.

Invoke only inside `assume wiki --exec` after its authorized short-lived login.
Does not modify the existing pool, client, plan attributes or other users.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import signal
import time
import uuid

import boto3

ACCOUNT = "202533532952"
POOL = "us-east-1_7rbhezdKX"
CLIENT = "3g2u5ilb7kbte92lra40ji2ht0"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--count", type=int, default=2, choices=(1, 2, 3))
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    root = Path(args.directory).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    ledger = root / "cognito-ledger.json"
    credentials = root / "hosted-test-identities.json"
    data = json.loads(ledger.read_text()) if ledger.exists() else {"schema_version": 1, "task_id": "task_02a312b5ac1f", "resources": []}
    if data["task_id"] != "task_02a312b5ac1f":
        raise RuntimeError("Wrong ledger task")
    sts = boto3.client("sts", region_name="us-east-1")
    client = boto3.client("cognito-idp", region_name="us-east-1")
    def save():
        ledger.write_text(json.dumps(data, indent=2) + "\n")
        os.chmod(ledger, 0o600)
    def identity():
        actual = sts.get_caller_identity()
        if actual["Account"] != ACCOUNT:
            raise RuntimeError("Wiki account mismatch; refusing write")
        return {"account": actual["Account"], "arn": actual["Arn"]}
    def write(method, row, **kwargs):
        row["identity_before_write"] = identity()
        save()
        return getattr(client, method)(**kwargs)
    def cleanup():
        credentials.unlink(missing_ok=True)
        for row in reversed(data["resources"]):
            if row["creation_status"] == "deleted":
                continue
            if row["account"] != ACCOUNT or row["pool_id"] != POOL or not row["name"].startswith("peaso-test-") or not row["name"].endswith("@example.invalid"):
                raise RuntimeError("User ledger ownership mismatch")
            try:
                user = client.admin_get_user(UserPoolId=POOL, Username=row["id"])
            except client.exceptions.UserNotFoundException:
                row.update(creation_status="deleted", verification="not_found")
                save()
                continue
            attrs = {a["Name"]: a["Value"] for a in user["UserAttributes"]}
            if attrs.get("email") != row["name"] or attrs.get("sub") != row.get("sub") or user["Username"] != row["id"]:
                raise RuntimeError("Native user sub/email mismatch; refusing deletion")
            write("admin_user_global_sign_out", row, UserPoolId=POOL, Username=row["id"])
            write("admin_delete_user", row, UserPoolId=POOL, Username=row["id"])
            try:
                client.admin_get_user(UserPoolId=POOL, Username=row["id"])
            except client.exceptions.UserNotFoundException:
                row.update(creation_status="deleted", verification="not_found", credentials_removed=True)
                save()
            else:
                raise RuntimeError("Cognito user still exists")
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    save()
    if args.cleanup:
        cleanup()
        return
    try:
        users = []
        for index in range(args.count):
            email = "peaso-test-" + uuid.uuid4().hex + "@example.invalid"
            password = secrets.token_urlsafe(28) + "aA1!"
            row = {"provider": "cognito", "account": ACCOUNT, "project": None, "subscription": None, "region": "us-east-1",
                   "name": email, "id": email, "pool_id": POOL, "client_id": CLIENT, "creation_status": "planned", "verification": "pending",
                   "delete_operation": "admin global signout then admin delete exact username after email/sub check",
                   "cleanup_deadline": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(), "plan": "free", "purpose": "hosted-integration-qa"}
            data["resources"].append(row)
            save()
            created = write("admin_create_user", row, UserPoolId=POOL, Username=email, MessageAction="SUPPRESS",
                            UserAttributes=[{"Name": "email", "Value": email}])
            native = created["User"]
            attrs = {a["Name"]: a["Value"] for a in native["Attributes"]}
            row.update(id=native["Username"], sub=attrs["sub"], creation_status="created")
            save()
            write("admin_set_user_password", row, UserPoolId=POOL, Username=row["id"], Password=password, Permanent=True)
            # Actual shared app client login; credentials never enter the ledger.
            result = write("initiate_auth", row, ClientId=CLIENT, AuthFlow="USER_PASSWORD_AUTH", AuthParameters={"USERNAME": email, "PASSWORD": password})
            auth = result["AuthenticationResult"]
            users.append({"email": email, "username": row["id"], "sub": row["sub"], "password": password,
                          "id_token": auth["IdToken"], "refresh_token": auth["RefreshToken"], "expires_seconds": auth["ExpiresIn"]})
        fd = os.open(credentials, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump({"pool_id": POOL, "client_id": CLIENT, "users": users}, output)
        print(json.dumps({"created_free_users": len(users), "login_flow": "USER_PASSWORD_AUTH", "credentials_file": str(credentials), "secret_values": "omitted"}))
        deadline = time.monotonic() + 2400
        while not (root / "release-cognito").exists() and time.monotonic() < deadline:
            time.sleep(2)
    finally:
        cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("Cognito fixture session failed:", type(exc).__name__)
        raise SystemExit(1)
