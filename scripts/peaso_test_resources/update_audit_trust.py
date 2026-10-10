"""Bind the exact temporary audit role to the server-generated connector ID."""
import argparse
import copy
import re

from scripts.peaso_test_resources.session import Session, TASK, now


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--external-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"peaso-[A-Za-z0-9_-]{16,200}", args.external_id):
        parser.error("Expected server generated peaso- external ID")
    session = Session(args.ledger)
    rows = [r for r in session.data["resources"] if r["kind"] == "iam_role" and r["creation_status"] == "created"]
    if len(rows) != 1:
        raise RuntimeError("Expected one exact active ledger-owned audit role")
    row = rows[0]
    role = session.aws("iam", "get-role", "--role-name", row["name"])["Role"]
    tags = {item["Key"]: item["Value"] for item in role["Tags"]}
    if role["Arn"] != row["id"] or tags.get("peaso-test-owner") != session.owner or tags.get("peaso-test-task") != TASK:
        raise RuntimeError("Audit role ownership mismatch")
    trust = copy.deepcopy(role["AssumeRolePolicyDocument"])
    statements = trust["Statement"]
    if len(statements) != 1:
        raise RuntimeError("Unexpected trust statement")
    stmt = statements[0]
    if stmt.get("Effect") != "Allow" or stmt.get("Action") != "sts:AssumeRole" or stmt.get("Principal") != {"AWS": "arn:aws:iam::202533532952:root"}:
        raise RuntimeError("Unexpected trust principal/action")
    expected = {"ArnEquals": {"aws:PrincipalArn": row["trusted_collector"]}, "StringEquals": {"sts:ExternalId": row["external_id"]}}
    if stmt.get("Condition") != expected:
        raise RuntimeError("Trust condition differs from owned ledger")
    stmt["Condition"]["StringEquals"]["sts:ExternalId"] = args.external_id
    import json
    session.write("aws", ["iam", "update-assume-role-policy", "--role-name", row["name"], "--policy-document", json.dumps(trust)])
    actual = session.aws("iam", "get-role", "--role-name", row["name"])["Role"]["AssumeRolePolicyDocument"]
    if actual != trust:
        raise RuntimeError("Trust update not verified")
    row.update(external_id=args.external_id, trust_verified_at=now())
    session.save()
    print("Exact owned role trust updated and verified; principal restriction retained")


if __name__ == "__main__":
    main()
