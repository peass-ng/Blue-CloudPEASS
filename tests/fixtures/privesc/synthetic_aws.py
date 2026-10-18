"""Deterministic synthetic AWS snapshot shaped like a mid-size estate, for privesc scaling benchmarks.

scale=1 has 321 principals (the shape of the audit's real 1x snapshot: shared AWS-managed and customer policies,
resource-scoped PassRole/AssumeRole statements, conditional statements, service-trusting roles with instance
profiles, a few admins and service-linked roles); scale=10 has 3,156 (the audit's 10x target is 3,130) and scale=100 31,506.
"""
from __future__ import annotations

ACCOUNTS = ("111111111111", "222222222222", "333333333333")
SERVICES = ("ec2.amazonaws.com", "lambda.amazonaws.com", "ecs-tasks.amazonaws.com", "glue.amazonaws.com",
            "codebuild.amazonaws.com", "sagemaker.amazonaws.com")


def _policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _managed(account):
    """Customer-managed policies shared by many principals (the dominant real-world pattern)."""
    arn = f"arn:aws:iam::{account}:policy"
    return [
        {"Arn": f"{arn}/dev-passrole", "PolicyName": "dev-passrole", "Document": _policy(
            {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": f"arn:aws:iam::{account}:role/app-*"},
            {"Effect": "Allow", "Action": ["ec2:RunInstances", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"})},
        {"Arn": f"{arn}/ops-assume", "PolicyName": "ops-assume", "Document": _policy(
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{account}:role/ops-*"})},
        {"Arn": f"{arn}/tagged-passrole", "PolicyName": "tagged-passrole", "Document": _policy(
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
             "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}},
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"})},
        {"Arn": f"{arn}/readonly", "PolicyName": "readonly", "Document": _policy(
            {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "ec2:Describe*", "iam:Get*", "iam:List*"], "Resource": "*"})},
        {"Arn": f"{arn}/mfa-admin", "PolicyName": "mfa-admin", "Document": _policy(
            {"Effect": "Allow", "Action": "iam:*", "Resource": "*",
             "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}})},
    ]


def _attached(policies, *names):
    return [{"PolicyArn": p["Arn"], "PolicyName": p["PolicyName"]} for p in policies if p["PolicyName"] in names]


def snapshot(scale=1):
    users, roles, policies, scp = [], [], [], []
    for account in ACCOUNTS:
        managed = _managed(account)
        policies.extend({"Arn": p["Arn"], "PolicyName": p["PolicyName"], "IsAttachable": True,
                         "PolicyVersionList": [{"IsDefaultVersion": True, "Document": p["Document"]}]} for p in managed)
        for copy in range(scale):
            suffix = f"-{copy}"
            for i in range(45):
                name = f"user{i}{suffix}"
                kind = ("dev-passrole", "ops-assume", "readonly", "tagged-passrole", "mfa-admin")[i % 5]
                inline = []
                if i % 9 == 0:
                    inline = [{"PolicyName": "own", "PolicyDocument": _policy(
                        {"Effect": "Allow", "Action": ["iam:CreateAccessKey", "iam:UpdateLoginProfile"],
                         "Resource": "arn:aws:iam::" + account + ":user/${aws:username}"})}]
                if i == 0 and copy == 0:
                    inline = [{"PolicyName": "admin", "PolicyDocument": _policy({"Effect": "Allow", "Action": "*", "Resource": "*"})}]
                users.append({"UserName": name, "Arn": f"arn:aws:iam::{account}:user/{name}", "Path": "/", "GroupList": [],
                              "UserPolicyList": inline, "AttachedManagedPolicies": _attached(managed, kind),
                              "Tags": [{"Key": "team", "Value": ("a", "b", "c")[i % 3]}]})
            for i in range(60):
                service = SERVICES[i % len(SERVICES)]
                prefix = ("app", "ops", "data")[i % 3]
                name = f"{prefix}-role{i}{suffix}"
                trust = {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
                if prefix == "ops":
                    trust = {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}
                roles.append({"RoleName": name, "Arn": f"arn:aws:iam::{account}:role/{name}", "Path": "/",
                              "AssumeRolePolicyDocument": _policy(trust),
                              "RolePolicyList": [{"PolicyName": "work", "PolicyDocument": _policy(
                                  {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
                                   "Resource": f"arn:aws:s3:::bucket-{i % 7}/*"})}],
                              "AttachedManagedPolicies": _attached(managed, "dev-passrole") if i % 10 == 0 else [],
                              "InstanceProfileList": [{"Arn": f"arn:aws:iam::{account}:instance-profile/{name}"}]
                              if service == "ec2.amazonaws.com" else [],
                              "Tags": []})
            for i in range(2 if copy == 0 else 0):
                name = f"AWSServiceRoleForX{i}"
                roles.append({"RoleName": name, "Arn": f"arn:aws:iam::{account}:role/aws-service-role/x.amazonaws.com/{name}",
                              "Path": "/aws-service-role/x.amazonaws.com/",
                              "AssumeRolePolicyDocument": _policy({"Effect": "Allow", "Principal": {"Service": "x.amazonaws.com"},
                                                                   "Action": "sts:AssumeRole"}),
                              "RolePolicyList": [{"PolicyName": "slr", "PolicyDocument": _policy(
                                  {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"})}],
                              "AttachedManagedPolicies": [], "InstanceProfileList": []})
    cols = []
    for ctype, items in (("iam_user", users), ("iam_role", roles), ("iam_policy", policies)):
        for account in ACCOUNTS:
            mine = [it for it in items if f":{account}:" in it["Arn"]]
            cols.append({"type": ctype, "scope": f"{account}/global", "service": "iam", "status": "collected",
                         "items": mine, "error": None})
    for account in ACCOUNTS:
        cols.append({"type": "iam_group", "scope": f"{account}/global", "service": "iam", "status": "empty", "items": [], "error": None})
        cols.append({"type": "scp_policy", "scope": f"{account}/global", "service": "organizations", "status": "empty",
                     "items": scp, "error": None})
    return {"schema_version": 1, "provider": "aws", "scopes": [f"{a}/global" for a in ACCOUNTS], "collections": cols,
            "metadata": {}}


def principals(snap):
    return sum(len(c["items"]) for c in snap["collections"] if c["type"] in ("iam_user", "iam_role"))
