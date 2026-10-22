"""Braket role execution requires an available device, script and output path."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, REGION, ALICE, aws_snap, col, user, role, allow, real, reached, policy,
)

TECHNIQUE = "aws-braket-passrole-createjob"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/job"
DEVICE = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"
JOB = f"arn:aws:braket:{REGION}:{ACCOUNT}:job/*"
CODE = "arn:aws:s3:::braket-code/peaso-braket-*/code.tar.gz"
OUTPUT = "arn:aws:s3:::braket-output/results/*"
ONLINE = {"deviceArn": DEVICE, "deviceType": "SIMULATOR", "deviceStatus": "ONLINE"}


def _bucket(name, region=REGION, policy_doc=None, kms=False):
    return {"Name": name,
            "Location": {"collection_status": "collected", "LocationConstraint": region},
            "Policy": ({"collection_status": "collected", "Policy": policy_doc} if policy_doc else
                       {"collection_status": "empty", "absent": True}),
            "Encryption": ({"collection_status": "collected",
                            "ServerSideEncryptionConfiguration": {"Rules": [
                                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}} if kms else
                           {"collection_status": "empty", "absent": True})}


def _evaluate(*, grants=None, role_item=None, device=ONLINE, device_status="collected",
              buckets=None, bucket_status="collected", device_scope=f"{ACCOUNT}/{REGION}"):
    if grants is None:
        grants = (allow("iam:PassRole", resource=ROLE_ARN),
                  allow("braket:CreateJob", resource=DEVICE),
                  allow("braket:CreateJob", resource=JOB),
                  allow("s3:PutObject", resource=CODE))
    if role_item is None:
        role_item = role("job", "braket.amazonaws.com",
                         allow("s3:GetObject", resource=CODE),
                         allow("s3:PutObject", resource=OUTPUT))
    if buckets is None:
        buckets = (_bucket("braket-code"), _bucket("braket-output"))
    snap = aws_snap([user("alice", *grants)], [role_item], [
        col("braket_device", [device] if device is not None else [], device_status, scope=device_scope),
        col("bucket", buckets, bucket_status, scope=f"{ACCOUNT}/global")])
    return reached(real(snap, TECHNIQUE, include_unknown=True), ALICE, TECHNIQUE)


def test_braket_script_route():
    assert _evaluate() == {ROLE_ARN: "conditional"}
    grants = (allow("iam:PassRole", resource=ROLE_ARN),
              allow("braket:CreateJob", resource=DEVICE),
              allow("braket:CreateJob", resource=JOB),
              allow("s3:PutObject", resource=CODE))
    assert ROLE_ARN not in _evaluate(grants=grants[:-1])
    assert ROLE_ARN not in _evaluate(grants=(grants[0], grants[2], grants[3]))
    assert ROLE_ARN not in _evaluate(grants=(grants[0], grants[1], grants[3]))
    assert ROLE_ARN not in _evaluate(grants=(grants[0], grants[1],
        allow("braket:CreateJob", resource=f"arn:aws:braket:us-west-2:{ACCOUNT}:job/*"), grants[3]))
    wrong_pass = {"Effect": "Allow", "Action": "iam:PassRole", "Resource": ROLE_ARN,
                  "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}}
    assert ROLE_ARN not in _evaluate(grants=(wrong_pass, *grants[1:]))
    assert ROLE_ARN not in _evaluate(device={**ONLINE, "deviceStatus": "OFFLINE"})
    assert ROLE_ARN not in _evaluate(device=None, device_status="empty")
    assert ROLE_ARN not in _evaluate(device_status="denied")
    assert ROLE_ARN not in _evaluate(device_scope=f"{ACCOUNT}/us-west-2")
    assert ROLE_ARN not in _evaluate(role_item=role("job", "lambda.amazonaws.com",
        allow("s3:GetObject", resource=CODE), allow("s3:PutObject", resource=OUTPUT)))
    assert ROLE_ARN not in _evaluate(role_item=role("job", "braket.amazonaws.com",
        allow("s3:PutObject", resource=OUTPUT)))
    assert ROLE_ARN not in _evaluate(role_item=role("job", "braket.amazonaws.com",
        allow("s3:GetObject", resource=CODE)))
    assert ROLE_ARN not in _evaluate(buckets=(_bucket("braket-code"), _bucket("braket-output", kms=True)))
    deny = policy({"Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
                   "Resource": "arn:aws:s3:::braket-output/*"})
    assert ROLE_ARN not in _evaluate(buckets=(_bucket("braket-code"),
        _bucket("braket-output", policy_doc=deny)))
    assert ROLE_ARN not in _evaluate(buckets=(_bucket("braket-code", region="eu-west-1"),
        _bucket("braket-output")))
    custom = "arn:aws:s3:::braket-code/custom/input.tar.gz"
    custom_role = role("job", "braket.amazonaws.com",
                       allow("s3:GetObject", resource=custom),
                       allow("s3:PutObject", resource=OUTPUT))
    assert _evaluate(grants=(grants[0], grants[1], grants[2],
        allow("s3:PutObject", resource=custom)), role_item=custom_role) == {ROLE_ARN: "conditional"}


def test_braket_permission_template_includes_device_read():
    import json
    from pathlib import Path
    template = json.loads((Path(__file__).resolve().parents[1] / "infra/aws/customer-role.json").read_text())
    actions = []
    for resource in template["Resources"].values():
        if resource.get("Type") == "AWS::IAM::ManagedPolicy":
            document = resource["Properties"]["PolicyDocument"]
            assert len(json.dumps(document, separators=(",", ":"))) <= 6144
            for statement in document["Statement"]:
                actions.extend(statement.get("Action", []))
    assert actions.count("braket:SearchDevices") == 1


def test_braket_device_read_uses_required_exact_arn_filter():
    import importlib.util
    from pathlib import Path
    from types import SimpleNamespace
    source = Path(__file__).resolve().parents[1] / "peaso/collectors/aws_facts_cb_ca.py"
    spec = importlib.util.spec_from_file_location("braket_facts_test", source)
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    facts._result = lambda items, status=None, error=None: SimpleNamespace(
        items=items, status=status or ("collected" if items else "empty"), error=error)

    class Requests:
        def pages(self, session, service, region, operation, expression, **kwargs):
            assert (service, region, operation, expression) == ("braket", REGION, "search_devices", "devices")
            assert kwargs["filters"] == [{"name": "deviceArn", "values": [DEVICE]}]
            return SimpleNamespace(status="collected", items=[ONLINE], error=None)

    result = facts._braket_devices(Requests(), object(), REGION, ACCOUNT)
    assert result.status == "collected"
    assert result.items[0]["deviceArn"] == DEVICE
