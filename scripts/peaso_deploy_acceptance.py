#!/usr/bin/env python3
"""Ledgered disposable free identity and bounded three-policy hosted scan acceptance."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import secrets
import time

import boto3
from botocore.exceptions import ClientError
import requests

from peaso_deploy import ACCOUNT, ROOT

DIRECTORY = ROOT / ".cache/hosted-deploy/acceptance"
LEDGER = DIRECTORY / "ledger.json"
SESSION = DIRECTORY / "private-session.json"
POOL = "us-east-1_7rbhezdKX"
CLIENT = "3g2u5ilb7kbte92lra40ji2ht0"
HOST = "https://cspm.hacktricks.wiki"


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    # Create with restrictive permissions before writing any credential material.
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    path.chmod(0o600)


def aws():
    session = boto3.Session(region_name="us-east-1")
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != ACCOUNT:
        raise RuntimeError("Acceptance requires wiki account 202533532952")
    return session, identity


def prepare(session, identity, preview=False):
    if LEDGER.exists() and not preview:
        raise RuntimeError("Existing fixture ledger must be inspected/cleaned before creation")
    suffix = secrets.token_hex(6)
    ledger = {"account": ACCOUNT, "created_at": datetime.now(timezone.utc).isoformat(),
              "username": f"peaso-hosted-{suffix}@example.invalid", "user_state": "planned",
              "stack": f"peaso-hosted-{suffix}", "stack_state": "planned"}
    private = {"password": "Peaso!Aa9" + secrets.token_urlsafe(30), "external_id": "peaso-" + secrets.token_urlsafe(32)}
    if not preview:
        save(LEDGER, ledger)
        save(SESSION, private)
    customer_source = (ROOT / "infra/aws/customer-role.json").read_bytes()
    template = json.loads(customer_source)
    role = template["Resources"]["AuditRole"]["Properties"]
    # The disposable source identity supplies explicit temporary credentials to
    # hosted collection, so no permanent platform role allow-list update is needed.
    source_role = identity["Arn"].replace("arn:aws:sts::", "arn:aws:iam::").replace(":assumed-role/", ":role/").rsplit("/", 1)[0]
    role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] = {"AWS": source_role}
    role["PermissionsBoundary"] = {"Ref": "FixtureBoundary"}
    role["Tags"] = [{"Key": "FixtureOwner", "Value": "peaso-hosted-acceptance"}]
    resources = template["Resources"]
    resources["FixtureBoundary"] = {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
        "Description": "Disposable acceptance boundary: only two regional metadata inventories",
        "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:DescribeVpcs", "ec2:DescribeSecurityGroups"], "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}}]}}}
    resources["FixtureVpc"] = {"Type": "AWS::EC2::VPC", "Properties": {
        "CidrBlock": "10.252.240.0/28", "Tags": [{"Key": "FixtureOwner", "Value": "peaso-hosted-acceptance"}]}}
    resources["FixtureSecurityGroup"] = {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "GroupDescription": "Disposable hosted scan fixture; no ingress or instances",
        "VpcId": {"Ref": "FixtureVpc"}, "SecurityGroupIngress": [],
        "Tags": [{"Key": "FixtureOwner", "Value": "peaso-hosted-acceptance"}]}}
    template.setdefault("Outputs", {}).update({
        "FixtureVpcId": {"Value": {"Ref": "FixtureVpc"}},
        "FixtureSecurityGroupId": {"Value": {"Ref": "FixtureSecurityGroup"}}})
    ledger["customer_template_sha256"] = hashlib.sha256(customer_source).hexdigest()
    ledger["fixture_template_sha256"] = hashlib.sha256(json.dumps(template, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if not preview:
        save(LEDGER, ledger)
    save(DIRECTORY / "fixture-template.json", template)
    cloudformation = session.client("cloudformation")
    cloudformation.validate_template(TemplateBody=json.dumps(template))
    if preview:
        print(json.dumps({"template_validation": "passed", "resource_count": len(resources),
                          "attached_managed_policy_count": 3,
                          "boundary": "EC2 VPC/security-group metadata in us-east-1 only",
                          "cloud_mutations": 0}))
        return
    created = cloudformation.create_stack(StackName=ledger["stack"], TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": "ExternalId", "ParameterValue": private["external_id"]}],
        Capabilities=["CAPABILITY_NAMED_IAM"], Tags=[{"Key": "FixtureOwner", "Value": "peaso-hosted-acceptance"}])
    ledger.update(stack_id=created["StackId"], stack_state="creating")
    save(LEDGER, ledger)
    cloudformation.get_waiter("stack_create_complete").wait(StackName=ledger["stack_id"])
    stack = cloudformation.describe_stacks(StackName=ledger["stack_id"])["Stacks"][0]
    outputs = {r["OutputKey"]: r["OutputValue"] for r in stack.get("Outputs", [])}
    details = cloudformation.list_stack_resources(StackName=ledger["stack_id"])["StackResourceSummaries"]
    ledger.update(stack_state="created", resources=[{k: r[k] for k in ("LogicalResourceId", "PhysicalResourceId", "ResourceType")} for r in details],
                  outputs=outputs)
    role_name = next(r["PhysicalResourceId"] for r in details if r["LogicalResourceId"] == "AuditRole")
    role_arn = session.client("iam").get_role(RoleName=role_name)["Role"]["Arn"]
    ledger.update(role_name=role_name, role_arn=role_arn)
    attached = session.client("iam").list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    assert len(attached) == 3, "Customer role must have exactly three attached managed policies"
    assert not session.client("iam").list_role_policies(RoleName=role_name)["PolicyNames"], "No inline role policies expected"
    ledger["attached_managed_policy_count"] = len(attached)
    save(LEDGER, ledger)
    cognito = session.client("cognito-idp")
    cognito.admin_create_user(UserPoolId=POOL, Username=ledger["username"], MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": ledger["username"]}, {"Name": "email_verified", "Value": "true"}])
    ledger["user_state"] = "created"
    save(LEDGER, ledger)
    cognito.admin_set_user_password(UserPoolId=POOL, Username=ledger["username"], Password=private["password"], Permanent=True)
    result = cognito.initiate_auth(ClientId=CLIENT, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": ledger["username"], "PASSWORD": private["password"]})["AuthenticationResult"]
    private.update(id_token=result["IdToken"], refresh_token=result["RefreshToken"])
    save(SESSION, private)
    print(json.dumps({"stack": ledger["stack"], "customer_role": role_arn, "attached_managed_policies": 3,
                      "boundary": "EC2 VPC/security-group metadata in us-east-1 only", "auth": "disposable free direct-Cognito test identity"}))


def request(client, path, method="GET", body=None, expected=200):
    response = client.request(method, HOST + "/api" + path, json=body, timeout=60)
    if response.status_code != expected:
        raise RuntimeError(f"Hosted {method} {path}: HTTP {response.status_code}, expected {expected}")
    return response.json() if response.content else None


def verify_fixtures(session):
    ledger = json.loads(LEDGER.read_text())
    assert ledger.get("customer_template_sha256") == hashlib.sha256((ROOT / "infra/aws/customer-role.json").read_bytes()).hexdigest(), "Customer fixture template is stale"
    private = json.loads(SESSION.read_text())
    iam = session.client("iam")
    attached = iam.list_attached_role_policies(RoleName=ledger["role_name"])["AttachedPolicies"]
    assert len(attached) == 3
    assert iam.get_role(RoleName=ledger["role_name"])["Role"]["PermissionsBoundary"]
    temporary = session.client("sts").assume_role(RoleArn=ledger["role_arn"],
        RoleSessionName="peaso-fixture-read-verification", ExternalId=private["external_id"], DurationSeconds=900)["Credentials"]
    ec2 = boto3.client("ec2", region_name="us-east-1", aws_access_key_id=temporary["AccessKeyId"],
        aws_secret_access_key=temporary["SecretAccessKey"], aws_session_token=temporary["SessionToken"])
    assert ec2.describe_vpcs(VpcIds=[ledger["outputs"]["FixtureVpcId"]])["Vpcs"]
    assert ec2.describe_security_groups(GroupIds=[ledger["outputs"]["FixtureSecurityGroupId"]])["SecurityGroups"]
    simulation = iam.simulate_principal_policy(PolicySourceArn=ledger["role_arn"],
        ActionNames=["ec2:DescribeVpcs", "ec2:DescribeSecurityGroups", "iam:CreateRole", "s3:GetObject", "secretsmanager:GetSecretValue"],
        ContextEntries=[{"ContextKeyName": "aws:RequestedRegion", "ContextKeyValues": ["us-east-1"], "ContextKeyType": "string"}])
    decisions = {value["EvalActionName"]: value["EvalDecision"] for value in simulation["EvaluationResults"]}
    assert decisions["ec2:DescribeVpcs"] == decisions["ec2:DescribeSecurityGroups"] == "allowed"
    assert all(decisions[action] != "allowed" for action in ("iam:CreateRole", "s3:GetObject", "secretsmanager:GetSecretValue"))
    tools = requests.Session()
    tools.cookies.set("__Secure-ht_refresh", private["refresh_token"], domain="hacktricks.wiki", path="/", secure=True)
    response = tools.get("https://tools.hacktricks.wiki/api/auth/me", timeout=60)
    assert response.status_code == 200 and ledger["username"] in json.dumps(response.json()), "Shared tools auth failed"
    summary = {"three_attached_managed_policies": True, "exact_fixture_metadata_reads": "passed",
               "permissions_boundary_decisions": decisions, "tools_auth_me_http": response.status_code,
               "auth": "direct disposable Cognito identity with shared refresh cookie; public signup not tested"}
    save(DIRECTORY / "fixture-summary.json", summary)
    print(json.dumps(summary, indent=2))


def scan(session):
    ledger = json.loads(LEDGER.read_text())
    assert ledger.get("customer_template_sha256") == hashlib.sha256((ROOT / "infra/aws/customer-role.json").read_bytes()).hexdigest(), "Customer fixture template is stale"
    private = json.loads(SESSION.read_text())
    client = requests.Session()
    client.headers["Origin"] = HOST
    client.cookies.set("__Secure-ht_refresh", private["refresh_token"], domain="hacktricks.wiki", path="/", secure=True)
    shared = client.get("https://tools.hacktricks.wiki/api/auth/me", timeout=60)
    if shared.status_code != 200 or ledger["username"] not in json.dumps(shared.json()):
        raise RuntimeError("Existing tools service did not recognize the shared refresh-cookie identity")
    me = request(client, "/me")
    assert me["plan"] == "free" and me["weekly_limit"] == 1 and me["weekly_used"] == 0
    ledger["tenant_id"] = me["tenant_id"]
    save(LEDGER, ledger)
    temporary = session.client("sts").assume_role(RoleArn=ledger["role_arn"],
        RoleSessionName="peaso-hosted-acceptance", ExternalId=private["external_id"], DurationSeconds=3600)["Credentials"]
    connector = request(client, "/connectors", "POST", {
        "name": "Disposable three-policy VPC/SG acceptance", "provider": "aws", "scopes": [ACCOUNT + "/us-east-1"],
        "auth": {"method": "access_keys", "aws_access_key_id": temporary["AccessKeyId"],
                 "aws_secret_access_key": temporary["SecretAccessKey"], "aws_session_token": temporary["SessionToken"]},
        "options": {"inventories": ["vpc", "security_group"], "regions": ["us-east-1"],
                    "max_calls": 30, "max_pages": 5, "max_resources": 100, "service_concurrency": 1}}, expected=201)
    ledger["connector_id"] = connector["id"]
    save(LEDGER, ledger)
    job = request(client, "/scans", "POST", {"connector_id": connector["id"]}, expected=201)
    ledger["scan_id"] = job["id"]
    save(LEDGER, ledger)
    request(client, "/scans", "POST", {"connector_id": connector["id"]}, expected=429)
    schedule = request(client, "/schedules", "POST", {"connector_id": connector["id"],
        "interval_hours": 168,
        "next_run_at": datetime.now(timezone.utc).isoformat()}, expected=201)
    ledger["schedule_id"] = schedule["id"]
    save(LEDGER, ledger)
    tick = session.client("lambda").invoke(FunctionName="hacktricks-cspm-scheduler", InvocationType="RequestResponse", Payload=b"{}")
    with tick["Payload"] as payload:
        tick_result = json.loads(payload.read())
    if tick.get("FunctionError"):
        raise RuntimeError("Hosted scheduler invocation failed")
    assert tick_result["scheduled"] == 0, "Scheduled job bypassed exhausted free quota"
    schedules = request(client, "/schedules")["items"]
    scheduled = next(value for value in schedules if value["id"] == ledger["schedule_id"])
    assert "limit" in str(scheduled.get("last_error", "")).lower(), "Scheduled quota error missing"
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        job = request(client, "/scans/" + ledger["scan_id"])
        if job["status"] in {"completed", "failed", "cancelled"}:
            break
        print("Hosted scan status:", job["status"], flush=True)
        time.sleep(20)
    if job["status"] != "completed":
        raise RuntimeError(f"Hosted scan did not complete: {job['status']}; code={job.get('error_code')}")
    envelope = request(client, "/scans/" + ledger["scan_id"] + "/report")
    if "download_url" in envelope:
        response = requests.get(envelope["download_url"], timeout=60)
        response.raise_for_status()
        content = response.content
        if content.startswith(b"\x1f\x8b"):
            content = gzip.decompress(content)
        report = json.loads(content)
    else:
        report = envelope
    serialized = json.dumps(report)
    for name in ("FixtureVpcId", "FixtureSecurityGroupId"):
        assert ledger["outputs"][name] in serialized, f"Hosted report omits {name}"
    summary = {"host": HOST, "scan_id": ledger["scan_id"], "status": job["status"],
               "auth": "shared refresh-cookie direct-Cognito fixture (not public Turnstile/signup)",
               "shared_tools_auth_me_http": shared.status_code,
               "quota": {"free_limit": 1, "second_scan_http": 429, "used": request(client, "/me")["weekly_used"]},
               "scheduled_quota": {"new_scans": tick_result["scheduled"], "error_recorded": True},
               "fixture_vpc_present": True, "fixture_security_group_present": True,
               "managed_policy_count": ledger["attached_managed_policy_count"], "paid_live": "pending real identity"}
    save(DIRECTORY / "hosted-summary.json", summary)
    print(json.dumps(summary, indent=2))


def cleanup(session):
    ledger = json.loads(LEDGER.read_text())
    if ledger.get("scan_id"):
        states = session.client("stepfunctions")
        arn = f"arn:aws:states:us-east-1:{ACCOUNT}:execution:hacktricks-cspm:scan-{ledger['scan_id']}"
        try:
            execution = states.describe_execution(executionArn=arn)
            if execution["status"] == "RUNNING":
                states.stop_execution(executionArn=arn, error="DisposableFixtureCleanup", cause="Owner teardown of disposable acceptance fixture")
                # ECS .sync cancellation is asynchronous. Do not remove the
                # tenant partition while a task can still republish it.
                deadline = time.monotonic() + 180
                ecs = session.client("ecs")
                while time.monotonic() < deadline:
                    tasks = ecs.list_tasks(cluster="hacktricks-cspm", desiredStatus="RUNNING")["taskArns"]
                    if not tasks:
                        break
                    time.sleep(10)
                else:
                    raise RuntimeError("CSPM task still running; defer fixture data teardown")
        except states.exceptions.ExecutionDoesNotExist:
            pass
    if ledger.get("tenant_id"):
        # Delete only the disposable tenant's partition and artifact prefix.
        # Never scan the entire metadata table or touch another tenant's records.
        tenant = ledger["tenant_id"]
        from boto3.dynamodb.conditions import Key
        table = session.resource("dynamodb").Table("hacktricks-cspm")
        arguments = {"KeyConditionExpression": Key("PK").eq("tenant/" + tenant), "ProjectionExpression": "PK,SK", "ConsistentRead": True}
        deleted_rows = 0
        while True:
            page = table.query(**arguments)
            with table.batch_writer() as batch:
                for row in page.get("Items", []):
                    batch.delete_item(Key=row)
                    deleted_rows += 1
            if not page.get("LastEvaluatedKey"):
                break
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]
        assert table.query(KeyConditionExpression=Key("PK").eq("tenant/" + tenant), Select="COUNT", ConsistentRead=True)["Count"] == 0
        s3 = session.client("s3")
        bucket = f"hacktricks-cspm-artifacts-{ACCOUNT}"
        tenant_hash = hashlib.sha256(tenant.encode()).hexdigest()
        deleted_objects = 0
        for prefix in ("artifacts/" + tenant_hash + "/", "inputs/" + tenant_hash + "/"):
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
                keys = [{"Key": value["Key"]} for value in page.get("Contents", [])]
                if keys:
                    response = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys, "Quiet": True})
                    if response.get("Errors"):
                        raise RuntimeError("Disposable tenant artifact deletion failed")
                    deleted_objects += len(keys)
            assert s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=1).get("KeyCount", 0) == 0
        ledger["tenant_data"] = {"state": "verified_deleted", "metadata_rows": deleted_rows, "artifact_objects": deleted_objects}
        save(LEDGER, ledger)
    cognito = session.client("cognito-idp")
    if ledger["user_state"] in {"planned", "created"}:
        try:
            cognito.admin_user_global_sign_out(UserPoolId=POOL, Username=ledger["username"])
            cognito.admin_delete_user(UserPoolId=POOL, Username=ledger["username"])
        except cognito.exceptions.UserNotFoundException:
            pass
        try:
            cognito.admin_get_user(UserPoolId=POOL, Username=ledger["username"])
        except cognito.exceptions.UserNotFoundException:
            ledger["user_state"] = "verified_deleted"
            save(LEDGER, ledger)
        else:
            raise RuntimeError("Disposable Cognito user still exists")
    if ledger.get("stack_id"):
        cfn = session.client("cloudformation")
        cfn.delete_stack(StackName=ledger["stack_id"])
        cfn.get_waiter("stack_delete_complete").wait(StackName=ledger["stack_id"])
        for resource in ledger.get("resources", []):
            physical = resource["PhysicalResourceId"]
            try:
                if resource["ResourceType"] == "AWS::IAM::Role":
                    session.client("iam").get_role(RoleName=physical)
                elif resource["ResourceType"] == "AWS::IAM::ManagedPolicy":
                    session.client("iam").get_policy(PolicyArn=physical)
                elif resource["ResourceType"] == "AWS::EC2::VPC":
                    session.client("ec2").describe_vpcs(VpcIds=[physical])
                elif resource["ResourceType"] == "AWS::EC2::SecurityGroup":
                    session.client("ec2").describe_security_groups(GroupIds=[physical])
                else:
                    continue
            except ClientError as error:
                if error.response["Error"]["Code"] not in {"NoSuchEntity", "InvalidVpcID.NotFound", "InvalidGroup.NotFound"}:
                    raise
            else:
                raise RuntimeError("Disposable fixture resource still exists: " + resource["LogicalResourceId"])
        ledger["stack_state"] = "verified_deleted"
        save(LEDGER, ledger)
    SESSION.unlink(missing_ok=True)
    print("Disposable cloud identity and three-policy fixture teardown verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan-fixture", "prepare", "verify-fixtures", "scan", "cleanup"])
    args = parser.parse_args()
    session, identity = aws()
    if args.command == "plan-fixture":
        prepare(session, identity, preview=True)
    elif args.command == "prepare":
        prepare(session, identity)
    elif args.command == "verify-fixtures":
        verify_fixtures(session)
    elif args.command == "scan":
        scan(session)
    else:
        cleanup(session)


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as error:
        raise SystemExit("Hosted HTTP transport failed: " + type(error).__name__) from None
    except ClientError as error:
        raise SystemExit("AWS acceptance failed: " + error.response.get("Error", {}).get("Code", "ClientError")) from None
