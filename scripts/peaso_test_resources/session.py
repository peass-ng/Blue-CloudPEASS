"""Disposable benign fixture session with a private ledger and finally cleanup.

Usage: python scripts/peaso_test_resources/session.py aws --ledger PATH -- COMMAND
Run cleanup again safely: python .../session.py cleanup --ledger PATH
Only this tool's ledger records authorize deletion; no wildcard deletion exists.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import uuid

TASK = "task_02a312b5ac1f"
AWS_ACCOUNT = "947247140022"
AZ_SUBSCRIPTION = "cfbcdcf4-cb4f-4e4e-9f3e-a6b3b3abadfc"
AZ_TENANT = "fdd066e1-ee37-49bc-b08f-d0e152119b04"


def now():
    return datetime.now(timezone.utc).isoformat()


class OperationError(RuntimeError):
    pass


def call(args, *, absent=()):
    result = subprocess.run(args, capture_output=True, text=True, timeout=180)
    if result.returncode:
        if any(code in result.stderr for code in absent):
            return None
        # Do not persist raw cloud errors, which can contain auth/request material.
        raise OperationError(f"{args[0]} {args[1]} failed (exit {result.returncode})")
    return json.loads(result.stdout) if result.stdout.strip() else {}


class Session:
    def __init__(self, path):
        self.path = Path(path)
        self.data = json.loads(self.path.read_text())
        if self.data.get("task_id") != TASK or self.data.get("schema_version") != 1:
            raise OperationError("Wrong ledger ownership/schema")
        self.owner = self.data.setdefault("owner_token", uuid.uuid4().hex)
        self.save()

    def save(self):
        if self.path.is_symlink():
            raise OperationError("Ledger cannot be a symlink")
        temporary = self.path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(self.data, output, indent=2)
            output.write("\n")
        os.replace(temporary, self.path)
        os.chmod(self.path, 0o600)

    def aws(self, *args, absent=()):
        return call(["aws", "--profile", "naxusai-admin", "--region", "us-east-1", *args, "--output", "json"], absent=absent)

    def az(self, *args, absent=()):
        return call(["az", *args, "--subscription", AZ_SUBSCRIPTION, "--output", "json"], absent=absent)

    def identity(self, provider):
        if provider == "aws":
            actual = self.aws("sts", "get-caller-identity")
            if actual["Account"] != AWS_ACCOUNT:
                raise OperationError("AWS account mismatch; refusing write")
            return {"account": actual["Account"], "principal": actual["Arn"]}
        actual = call(["az", "account", "show", "--subscription", AZ_SUBSCRIPTION, "-o", "json"])
        if actual["id"] != AZ_SUBSCRIPTION or actual["tenantId"] != AZ_TENANT:
            raise OperationError("Azure subscription/tenant mismatch; refusing write")
        return {"subscription": actual["id"], "tenant": actual["tenantId"]}

    def record(self, provider, kind, name, delete_operation, **extra):
        identity = self.identity(provider)
        item = {"provider": provider, "kind": kind, "name": name, "id": name,
                "account": identity.get("account"), "project": None,
                "subscription": identity.get("subscription"), "region": "us-east-1" if provider == "aws" else "westeurope",
                "creation_status": "planned", "delete_operation": delete_operation,
                "verification": "pending", "owner_token": self.owner,
                "created_at": now(), "identity_before_write": identity, **extra}
        self.data["resources"].append(item)
        self.save()  # Record exact target before creation, including failed creations.
        return item

    def write(self, provider, args, row=None):
        self.identity(provider)  # Verify immediately before EVERY cloud mutation.
        result = self.aws(*args) if provider == "aws" else self.az(*args)
        if row is not None:
            row["creation_status"] = "created"
            self.save()
        return result

    def create_aws(self):
        name = "peaso-test-" + uuid.uuid4().hex[:16]
        tags = [{"Key": "peaso-test-owner", "Value": self.owner}, {"Key": "peaso-test-task", "Value": TASK}, {"Key": "Name", "Value": name}]
        bucket = self.record("aws", "bucket", name, "s3api delete-bucket with expected-bucket-owner")
        self.write("aws", ["s3api", "create-bucket", "--bucket", name], bucket)
        self.write("aws", ["s3api", "put-bucket-tagging", "--bucket", name, "--expected-bucket-owner", AWS_ACCOUNT, "--tagging", json.dumps({"TagSet": tags})])
        self.write("aws", ["s3api", "put-public-access-block", "--bucket", name, "--expected-bucket-owner", AWS_ACCOUNT,
                           "--public-access-block-configuration", "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"])
        self.write("aws", ["s3api", "put-bucket-encryption", "--bucket", name, "--expected-bucket-owner", AWS_ACCOUNT,
                           "--server-side-encryption-configuration", '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'])
        vpc = self.record("aws", "vpc", name, "ec2 delete-vpc")
        result = self.write("aws", ["ec2", "create-vpc", "--cidr-block", "10.247.0.0/24", "--tag-specifications", json.dumps([{"ResourceType": "vpc", "Tags": tags}])], vpc)
        vpc["id"] = result["Vpc"]["VpcId"]
        self.save()
        group = self.record("aws", "security_group", name, "ec2 delete-security-group", vpc_id=vpc["id"])
        result = self.write("aws", ["ec2", "create-security-group", "--vpc-id", vpc["id"], "--group-name", name,
                                   "--description", "Inert private peaso QA fixture; no ingress", "--tag-specifications", json.dumps([{"ResourceType": "security-group", "Tags": tags}])], group)
        group["id"] = result["GroupId"]
        self.save()
        return {"PEASO_TEST_BUCKET": name, "PEASO_TEST_VPC": vpc["id"], "PEASO_TEST_SECURITY_GROUP": group["id"]}

    def create_azure(self):
        name = "peaso-test-" + uuid.uuid4().hex[:16]
        group = self.record("azure", "resource_group", name, "az group delete exact group; no force dependencies")
        result = self.write("azure", ["group", "create", "--name", name, "--location", "westeurope", "--tags", "peaso-test-owner=" + self.owner, "peaso-test-task=" + TASK], group)
        group["id"] = result["id"]
        self.save()
        nsg = self.record("azure", "nsg", name, "az network nsg delete exact tagged NSG", resource_group=name)
        nsg["id"] = group["id"] + "/providers/Microsoft.Network/networkSecurityGroups/" + name
        self.save()
        self.write("azure", ["network", "nsg", "create", "--resource-group", name, "--name", name, "--location", "westeurope", "--tags", "peaso-test-owner=" + self.owner, "peaso-test-task=" + TASK], nsg)
        vnet = self.record("azure", "vnet", name, "az network vnet delete exact tagged VNet including recorded subnet", resource_group=name)
        vnet["id"] = group["id"] + "/providers/Microsoft.Network/virtualNetworks/" + name
        vnet["owned_children"] = [vnet["id"] + "/subnets/" + name]
        self.save()
        self.write("azure", ["network", "vnet", "create", "--resource-group", name, "--name", name, "--location", "westeurope", "--address-prefixes", "10.248.0.0/24",
                              "--subnet-name", name, "--subnet-prefixes", "10.248.0.0/27", "--tags", "peaso-test-owner=" + self.owner, "peaso-test-task=" + TASK], vnet)
        return {"PEASO_TEST_RESOURCE_GROUP": name, "PEASO_TEST_NSG": nsg["id"], "PEASO_TEST_VNET": vnet["id"]}

    def create_audit_role(self):
        name = "peaso-test-" + uuid.uuid4().hex[:16]
        external_id = "peaso-" + uuid.uuid4().hex
        collector = "arn:aws:iam::202533532952:role/hacktricks-cspm-collector"
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
            "Principal": {"AWS": "arn:aws:iam::202533532952:root"},
            "Condition": {"ArnEquals": {"aws:PrincipalArn": collector}, "StringEquals": {"sts:ExternalId": external_id}}}]}
        policy = "arn:aws:iam::aws:policy/SecurityAudit"
        row = self.record("aws", "iam_role", name, "detach exact SecurityAudit managed policy then delete exact role",
                          policy_arn=policy, external_id=external_id, trusted_collector=collector,
                          cleanup_deadline=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
        tags = [{"Key": "peaso-test-owner", "Value": self.owner}, {"Key": "peaso-test-task", "Value": TASK}]
        result = self.write("aws", ["iam", "create-role", "--role-name", name, "--assume-role-policy-document", json.dumps(trust),
                                    "--description", "Disposable read-only CSPM integration QA role", "--max-session-duration", "3600", "--tags", json.dumps(tags)], row)
        row["id"] = result["Role"]["Arn"]
        self.save()
        self.write("aws", ["iam", "attach-role-policy", "--role-name", name, "--policy-arn", policy])
        return {"PEASO_TEST_ROLE_ARN": row["id"], "PEASO_TEST_EXTERNAL_ID": external_id}

    def cleanup(self):
        errors = []
        for row in reversed(self.data["resources"]):
            if row["creation_status"] == "deleted":
                continue
            try:
                self.remove(row)
            except Exception as exc:
                row["verification"] = "cleanup_failed: " + str(exc)
                errors.append(str(exc))
            self.save()
        if errors:
            raise OperationError("; ".join(errors))

    def remove(self, row):
        if row["owner_token"] != self.owner or not row["name"].startswith("peaso-test-"):
            raise OperationError("Ownership/name mismatch")
        provider, kind = row["provider"], row["kind"]
        if provider == "aws":
            if row["account"] != AWS_ACCOUNT:
                raise OperationError("Ledger AWS account mismatch")
            if kind == "bucket":
                exists = self.aws("s3api", "head-bucket", "--bucket", row["id"], "--expected-bucket-owner", AWS_ACCOUNT, absent=("404", "NoSuchBucket"))
                if exists is not None:
                    tagged = self.aws("s3api", "get-bucket-tagging", "--bucket", row["id"], "--expected-bucket-owner", AWS_ACCOUNT, absent=("NoSuchTagSet",))
                    tags = {x["Key"]: x["Value"] for x in (tagged or {}).get("TagSet", [])}
                    # Before successful creation a collision never authorizes deletion.
                    if tags.get("peaso-test-owner") != self.owner and not (not tags and row["creation_status"] == "created"):
                        raise OperationError("Bucket ownership tag mismatch")
                    contents = self.aws("s3api", "list-objects-v2", "--bucket", row["id"], "--expected-bucket-owner", AWS_ACCOUNT, "--max-keys", "1")
                    if contents.get("KeyCount", 0):
                        raise OperationError("Bucket is not empty; refusing unexpected object deletion")
                    self.write("aws", ["s3api", "delete-bucket", "--bucket", row["id"], "--expected-bucket-owner", AWS_ACCOUNT])
                    if self.aws("s3api", "head-bucket", "--bucket", row["id"], "--expected-bucket-owner", AWS_ACCOUNT, absent=("404", "NoSuchBucket")) is not None:
                        raise OperationError("Bucket still exists")
            elif kind == "iam_role":
                role = self.aws("iam", "get-role", "--role-name", row["name"], absent=("NoSuchEntity",))
                if role is not None:
                    tags = {x["Key"]: x["Value"] for x in role["Role"].get("Tags", [])}
                    if tags.get("peaso-test-owner") != self.owner or tags.get("peaso-test-task") != TASK:
                        raise OperationError("Role ownership tag mismatch")
                    policies = self.aws("iam", "list-attached-role-policies", "--role-name", row["name"])["AttachedPolicies"]
                    if any(p["PolicyArn"] != row["policy_arn"] for p in policies):
                        raise OperationError("Unexpected role policy; refusing deletion")
                    inline = self.aws("iam", "list-role-policies", "--role-name", row["name"])["PolicyNames"]
                    profiles = self.aws("iam", "list-instance-profiles-for-role", "--role-name", row["name"])["InstanceProfiles"]
                    if inline or profiles:
                        raise OperationError("Unexpected inline policy or instance profile; refusing deletion")
                    for policy in policies:
                        self.write("aws", ["iam", "detach-role-policy", "--role-name", row["name"], "--policy-arn", policy["PolicyArn"]])
                    self.write("aws", ["iam", "delete-role", "--role-name", row["name"]])
                    if self.aws("iam", "get-role", "--role-name", row["name"], absent=("NoSuchEntity",)) is not None:
                        raise OperationError("Role still exists")
            elif kind in ("vpc", "security_group"):
                describe, field, idarg, missing = (("describe-vpcs", "Vpcs", "--vpc-ids", "InvalidVpcID.NotFound") if kind == "vpc" else ("describe-security-groups", "SecurityGroups", "--group-ids", "InvalidGroup.NotFound"))
                if not row["id"].startswith("vpc-" if kind == "vpc" else "sg-"):
                    if row["creation_status"] == "planned":
                        row["verification"] = "creation_not_confirmed_no_deletion"
                        return
                    raise OperationError("Invalid resource ID")
                result = self.aws("ec2", describe, idarg, row["id"], absent=(missing,))
                if result is not None:
                    tags = {x["Key"]: x["Value"] for x in result[field][0].get("Tags", [])}
                    if tags.get("peaso-test-owner") != self.owner or tags.get("peaso-test-task") != TASK:
                        raise OperationError("EC2 ownership tag mismatch")
                    self.write("aws", ["ec2", "delete-vpc" if kind == "vpc" else "delete-security-group", "--vpc-id" if kind == "vpc" else "--group-id", row["id"]])
                    if self.aws("ec2", describe, idarg, row["id"], absent=(missing,)) is not None:
                        raise OperationError("EC2 resource still exists")
            else:
                raise OperationError("Unknown ledger resource kind")
        elif provider == "azure" and kind in ("vnet", "nsg"):
            if row["subscription"] != AZ_SUBSCRIPTION or row["id"].lower() != ("/subscriptions/" + AZ_SUBSCRIPTION + "/resourceGroups/" + row["resource_group"] + "/providers/Microsoft.Network/" + ("virtualNetworks/" if kind == "vnet" else "networkSecurityGroups/") + row["name"]).lower():
                raise OperationError("Azure exact resource ID mismatch")
            result = self.az("network", kind, "show", "--resource-group", row["resource_group"], "--name", row["name"], absent=("ResourceNotFound", "ResourceGroupNotFound"))
            if result is not None:
                if result.get("tags", {}).get("peaso-test-owner") != self.owner:
                    raise OperationError("Azure network ownership tag mismatch")
                if kind == "vnet":
                    actual = {item["id"].lower() for item in result.get("subnets", [])}
                    if not actual.issubset({item.lower() for item in row["owned_children"]}):
                        raise OperationError("Unledgered subnet; refusing deletion")
                self.write("azure", ["network", kind, "delete", "--resource-group", row["resource_group"], "--name", row["name"]])
                if self.az("network", kind, "show", "--resource-group", row["resource_group"], "--name", row["name"], absent=("ResourceNotFound", "ResourceGroupNotFound")) is not None:
                    raise OperationError("Azure network resource still exists")
        elif provider == "azure" and kind == "resource_group":
            if row["subscription"] != AZ_SUBSCRIPTION:
                raise OperationError("Ledger subscription mismatch")
            result = self.az("group", "show", "--name", row["name"], absent=("ResourceGroupNotFound",))
            if result is not None:
                if result.get("tags", {}).get("peaso-test-owner") != self.owner:
                    raise OperationError("Azure ownership tag mismatch")
                # No recursive deletion of unledgered objects in a group.
                resources = self.az("resource", "list", "--resource-group", row["name"])
                if resources:
                    raise OperationError("Unledgered group contents; refusing recursive deletion")
                self.write("azure", ["group", "delete", "--name", row["name"], "--yes"])
                if self.az("group", "exists", "--name", row["name"]) is not False:
                    raise OperationError("Azure group still exists")
        else:
            raise OperationError("Unsupported ledger provider/kind")
        row.update(creation_status="deleted", verification="not_found", verified_at=now())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=("aws", "azure", "audit-role", "cleanup"))
    parser.add_argument("--ledger", required=True)
    options, command = parser.parse_known_args()
    if command[:1] == ["--"]:
        command = command[1:]
    session = Session(options.ledger)
    if options.provider == "cleanup":
        session.cleanup()
        return 0
    if not command:
        parser.error("Fixture creation requires an in-session command")
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, terminate)
    try:
        environment = session.create_aws() if options.provider == "aws" else session.create_audit_role() if options.provider == "audit-role" else session.create_azure()
        return subprocess.run(command, env={**os.environ, **environment}, timeout=3600 if options.provider == "audit-role" else 900).returncode
    finally:
        session.cleanup()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"Fixture session failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
