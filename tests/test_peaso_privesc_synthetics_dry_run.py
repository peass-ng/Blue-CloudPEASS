"""Inline Synthetics dry-run code must join one canary to its execution role."""

from pathlib import Path

import yaml

from peaso import privesc
from test_peaso_privesc_aws_followups import ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, reached, role, role_arn, user


TECHNIQUE = "aws-synthetics-startcanarydryrun-replacement-code"
CANARY_ARN = f"arn:aws:synthetics:{REGION}:{ACCOUNT}:canary:prod"
ROLE_ARN = role_arn("canary")
CATALOG = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/synthetics.yaml"


def _run(*, runtime="syn-nodejs-puppeteer-10.0", action="synthetics:StartCanaryDryRun",
         canary_resource=CANARY_ARN, passrole=True, status="collected", role_name="canary"):
    entry = next(row for row in yaml.safe_load(CATALOG.read_text()) if row["id"] == TECHNIQUE)
    grants = [allow(action, resource=canary_resource)]
    if passrole:
        grants.append(allow("iam:PassRole", resource=ROLE_ARN))
    canary = {"Name": "prod", "RuntimeVersion": runtime, "ExecutionRoleArn": ROLE_ARN}
    snap = aws_snap([user("alice", *grants)], roles=[role(role_name, "lambda.amazonaws.com")],
                    extra=[col("synthetics_canary", [canary], status=status)])
    return privesc.analyze(snap, entries=[entry], include_unknown=True)


def test_supported_canary_exact_grants_reach_its_role():
    assert reached(_run(), ALICE, TECHNIQUE) == {ROLE_ARN: "conditional"}


def test_wrong_canary_grant_runtime_role_or_passrole_does_not_reach():
    assert not reached(_run(action="synthetics:StartCanary"), ALICE, TECHNIQUE)
    assert not reached(_run(canary_resource=CANARY_ARN + "-other"), ALICE, TECHNIQUE)
    assert not reached(_run(passrole=False), ALICE, TECHNIQUE)
    assert not reached(_run(runtime="syn-nodejs-puppeteer-9.9"), ALICE, TECHNIQUE)
    assert not reached(_run(role_name="other"), ALICE, TECHNIQUE)


def test_missing_inventory_or_runtime_is_unresolved():
    assert not reached(_run(status="denied"), ALICE, TECHNIQUE)
    assert not reached(_run(runtime="unrecognized"), ALICE, TECHNIQUE)
    assert edges(_run(runtime="unrecognized"), ALICE, TECHNIQUE)
