"""Offline regression for the ECS tag read in each reviewed update route."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("public_peaso_deploy", HERE.parent / "scripts/peaso_deploy.py")
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


@pytest.mark.parametrize("route", ["artifact", "current", "successor"])
@pytest.mark.parametrize("tag_mismatch", [False, True])
def test_resolved_ecs_tags_requested_and_checked(route, tag_mismatch, tmp_path):
    folder = tmp_path
    plan = Path(folder) / "offline.tfplan"
    plan.write_bytes(b"offline plan only")
    digest = hashlib.sha256(plan.read_bytes()).hexdigest()
    account = deploy.ACCOUNT
    workflow = f"arn:aws:states:us-east-1:{account}:stateMachine:hacktricks-cspm"
    secret = f"arn:aws:secretsmanager:us-east-1:{account}:secret:hacktricks-cspm-credential-key-Ab1234"
    bucket = f"hacktricks-cspm-artifacts-{account}"
    image = deploy.REPOSITORY + "@sha256:" + "a" * 64
    sizes = {"collector": {"cpu": 1024, "memory": 6144},
             "analyzer": {"cpu": 512, "memory": 4096}}
    contract = {
        "source_version": "a" * 64,
        "api_code_sha256": "reviewed-api-code",
        "api_environment": {"PEASO_CREDENTIAL_SECRET_ARN": {"arn_pattern":
            rf"arn:aws:secretsmanager:us-east-1:{account}:secret:hacktricks-cspm-credential-key-[A-Za-z0-9]+"},
            "PEASO_ARTIFACT_BUCKET": bucket},
        "worker_image": image,
        "worker_resources": sizes,
        "worker_environments": {"collector": {}, "analyzer": {}},
        "current_ecs_defaults": ["collector", "analyzer"],
    }
    lambda_review = {name: {"function_name": f"hacktricks-cspm-{name}",
        "source_code_hash": "reviewed-api-code", "memory_size": 256,
        "timeout": 60, "runtime": "python3.12", "handler": "handler.handler",
        "architectures": ["x86_64"]} for name in ("api", "scheduler")}
    review = {"resources": [{"address": address} for address in (
        'aws_ecs_task_definition.tasks["collector"]',
        'aws_ecs_task_definition.tasks["analyzer"]',
        "aws_lambda_function.api", "aws_lambda_function.scheduler")],
        "resolved_validation_required": True, "resolved_contract": contract,
        "lambda_configuration": lambda_review, "json_sha256": "offline-json"}
    plan.with_suffix(".review.json").write_text(json.dumps(review))

    output = {key: {"value": value} for key, value in {
        "workflow_arn": workflow, "credential_secret_arn": secret,
        "artifact_bucket": bucket, "metadata_table": "hacktricks-cspm",
        "api_function": "hacktricks-cspm-api"}.items()}
    states, tasks = {}, {}
    for stage, state in (("collector", "Collect"), ("analyzer", "Analyze")):
        arn = f"arn:aws:ecs:us-east-1:{account}:task-definition/hacktricks-cspm-{stage}:8"
        states[state] = {"Parameters": {"TaskDefinition": arn,
            "Overrides": {"ContainerOverrides": [{"Name": stage,
                "Command.$": f"States.Array('{stage}', '--once', '--tenant-id', $.tenant_id, '--scan-id', $.scan_id)"}]}}}
        env = dict(contract["worker_environments"][stage],
                   PEASO_ARTIFACT_BUCKET=bucket, PEASO_DYNAMODB_TABLE="hacktricks-cspm")
        if stage == "collector":
            env["PEASO_CREDENTIAL_SECRET_ARN"] = secret
        tasks[arn] = dict(sizes[stage], taskDefinitionArn=arn, status="ACTIVE",
            family=f"hacktricks-cspm-{stage}", volumes=[{"name": "scratch", "host": {}}],
            containerDefinitions=[{"name": stage, "image": image,
                "environment": [{"name": key, "value": value} for key, value in env.items()]}])

    expected_tags = [{"key": "Application", "value": "hacktricks-cspm"},
                     {"key": "ManagedBy", "value": "Terraform"}]
    calls = []
    def describe_task_definition(**kwargs):
        calls.append(kwargs)
        response = {"taskDefinition": tasks[kwargs["taskDefinition"]]}
        # ECS returns top-level tags only when the caller includes TAGS.
        if kwargs.get("include") == ["TAGS"]:
            response["tags"] = [dict(item) for item in expected_tags]
            if tag_mismatch and kwargs["taskDefinition"].endswith("collector:8"):
                response["tags"][1]["value"] = "Manual"
        return response

    clients = {service: Mock() for service in ("sts", "stepfunctions", "ecs", "lambda")}
    session = Mock()
    session.client.side_effect = clients.__getitem__
    clients["sts"].get_caller_identity.return_value = {"Account": account}
    clients["stepfunctions"].describe_state_machine.return_value = {
        "definition": json.dumps({"States": states})}
    clients["ecs"].describe_task_definition.side_effect = describe_task_definition
    def lambda_configuration(FunctionName):
        name = FunctionName.removeprefix("hacktricks-cspm-")
        reviewed = lambda_review[name]
        environment = dict(contract["api_environment"],
            PEASO_CREDENTIAL_SECRET_ARN=secret, PEASO_ARTIFACT_BUCKET=bucket,
            PEASO_DYNAMODB_TABLE="hacktricks-cspm", PEASO_WORKFLOW_ARN=workflow)
        return {"FunctionName": FunctionName, "CodeSha256": reviewed["source_code_hash"],
            "MemorySize": reviewed["memory_size"], "Timeout": reviewed["timeout"],
            "Runtime": reviewed["runtime"], "Handler": reviewed["handler"],
            "Architectures": reviewed["architectures"], "State": "Active",
            "LastUpdateStatus": "Successful", "Environment": {"Variables": environment}}
    clients["lambda"].get_function_configuration.side_effect = lambda_configuration
    options = {f"{route}_update_contract": "/private/reviewed-contract.json",
               f"{route}_update_sha256": "b" * 64}
    with patch.object(deploy, "verify_backend"), \
         patch.object(deploy, "plan_summary", return_value=digest), \
         patch.object(deploy, "terraform", return_value=SimpleNamespace(stdout=json.dumps(output))), \
         patch.object(deploy, "verify_current_update_resolved") as update_guard, \
         contextlib.redirect_stdout(io.StringIO()):
        if tag_mismatch:
            with pytest.raises(RuntimeError, match="ECS tags differ"):
                deploy.verify_resolved_deployment(session, plan, digest, **options)
            assert not plan.with_suffix(".resolved.json").exists()
            update_guard.assert_not_called()
        else:
            receipt = deploy.verify_resolved_deployment(session, plan, digest, **options)
            assert receipt["status"] == "passed"
            update_guard.assert_called_once()
    assert calls == ([{"taskDefinition": next(iter(tasks)), "include": ["TAGS"]}]
                     if tag_mismatch else
                     [{"taskDefinition": arn, "include": ["TAGS"]} for arn in tasks])
