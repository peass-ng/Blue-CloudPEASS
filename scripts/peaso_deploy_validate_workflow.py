"""Compile the actual workflow expression with stand-in IDs, then ask AWS to validate ASL."""
import json
from pathlib import Path
import re
import subprocess
import tempfile


def balanced(text, opening, close):
    start = text.index(opening)
    depth = 0
    quoted = escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == opening:
            depth += 1
        elif char == close:
            depth -= 1
            if depth == 0:
                return start, index + 1
    raise ValueError("Unbalanced workflow HCL")


def compile_definition(root: Path, terraform: str):
    text = (root / "infra/aws/workflow.tf").read_text()
    definitions, removals = [], []
    for match in re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', text):
        start, stop = balanced(text[match.end():], "{", "}")
        begin, end = match.end() + start, match.end() + stop
        block = text[begin:end]
        if match.group(1) == "aws_sfn_state_machine":
            assignment = re.search(r"definition\s*=\s*jsonencode", block)
            if not assignment:
                raise ValueError("Workflow definition expression missing")
            left, right = balanced(block[assignment.end():], "(", ")")
            definitions.append("jsonencode" + block[assignment.end() + left:assignment.end() + right])
        removals.append((match.start(), end))
    if len(definitions) != 1:
        raise ValueError("Expected one actual state-machine definition")
    for begin, end in reversed(removals):
        text = text[:begin] + text[end:]
    text += "\nlocals { validation_definition = " + definitions[0] + " }\n"
    prefix = "arn:aws:ecs:us-east-1:202533532952:"
    values = {
        "aws_ecs_task_definition.tasks[stage].arn": '"' + prefix + 'task-definition/hacktricks-cspm-${stage}:1"',
        "aws_ecs_cluster.cspm.arn": json.dumps(prefix + "cluster/hacktricks-cspm"),
        "aws_subnet.tasks.id": '"subnet-0123456789abcdef0"',
        "aws_security_group.tasks.id": '"sg-0123456789abcdef0"',
        "aws_s3_bucket.artifacts.id": '"hacktricks-cspm-artifacts-202533532952"',
        "aws_dynamodb_table.metadata.name": '"hacktricks-cspm"',
        "aws_cloudwatch_log_group.tasks.name": '"/ecs/hacktricks-cspm"',
        "aws_secretsmanager_secret.credentials.arn": '"arn:aws:secretsmanager:us-east-1:202533532952:secret:hacktricks-cspm-validation-abcdef"',
        "var.region": '"us-east-1"', "var.source_version": '"validation"',
        "local.issuer": '"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_7rbhezdKX"',
        "local.client_id": '"3g2u5ilb7kbte92lra40ji2ht0"',
    }
    # Resolve sizing/time limits from the actual dedicated configuration, rather
    # than validating a second, stale hard-coded workflow definition.
    variables_text = (root / "infra/aws/variables.tf").read_text()
    variable_file = root / "infra/aws/deployment.auto.tfvars.json"
    overrides = json.loads(variable_file.read_text()) if variable_file.is_file() else {}
    for name in ["worker_resources", "scan_runtime_limits"]:
        if name in overrides:
            expression = json.dumps(overrides[name])
        else:
            match = re.search(r'variable\s+"' + name + r'"', variables_text)
            if not match:
                raise ValueError("Workflow sizing/time input missing")
            start, stop = balanced(variables_text[match.end():], "{", "}")
            block = variables_text[match.end() + start:match.end() + stop]
            default = re.search(r"default\s*=", block)
            if not default:
                raise ValueError("Workflow sizing/time default missing")
            left, right = balanced(block[default.end():], "{", "}")
            expression = block[default.end() + left:default.end() + right]
        values["var." + name] = "(" + expression + ")"
    for role in ["collector", "analyzer"]:
        values[f"aws_iam_role.{role}.arn"] = json.dumps(f"arn:aws:iam::202533532952:role/hacktricks-cspm-{role}")
    for reference, value in values.items():
        text = text.replace(reference, value)
    if re.search(r"\b(?:aws_[a-z_]+\.[a-z_]+|var\.|data\.)", text):
        raise ValueError("Unresolved workflow reference; update stand-in ID mapping")
    with tempfile.TemporaryDirectory(prefix="peaso-asl-") as folder:
        Path(folder, "main.tf").write_text(text)
        result = subprocess.run([terraform, f"-chdir={folder}", "console", "-no-color"],
                                input="local.validation_definition\n", capture_output=True, text=True, check=True)
        definition = json.loads(result.stdout.strip())
    compiled = json.loads(definition)
    workflow_seconds = compiled["TimeoutSeconds"]
    stage_seconds = compiled["States"]["Collect"]["TimeoutSeconds"]
    lease_expression = compiled["States"]["AcquireSlot"]["Arguments"]["Item"]["expires_at"]["N"]
    lease_match = re.search(r"\+\s*([0-9]+)", lease_expression)
    if not lease_match or not 0 < stage_seconds <= workflow_seconds < int(lease_match[1]):
        raise ValueError("Workflow stage/deadline/lease invariant violated")
    if compiled["States"]["Analyze"]["TimeoutSeconds"] != stage_seconds:
        raise ValueError("Expected matching bounded collector/analyzer stage limits")
    lock = compiled["States"]["ReleaseSucceeded"]["Parameters"]
    if lock.get("ConditionExpression") != "#owner = :owner":
        raise ValueError("Workflow lock release must remain owner-conditional")
    validate_failure_paths(compiled)
    return definition, {"workflow_seconds": workflow_seconds, "stage_seconds": stage_seconds,
                        "lease_seconds": int(lease_match[1])}


def validate_failure_paths(definition):
    """Check the compiled deployed path, including uncatchable worker death."""
    states = definition["States"]
    for stage, task, failed, status in [
        ("collector", "Collect", "CollectorTaskFailed", "CollectedStatus"),
        ("analyzer", "Analyze", "AnalyzerTaskFailed", "CompletedStatus"),
    ]:
        if states[task]["Resource"] != "arn:aws:states:::ecs:runTask.sync":
            raise ValueError("Worker failure detection requires ECS synchronous tasks")
        catch = states[task].get("Catch", [])
        if not any(item["ErrorEquals"] == ["States.ALL"] and item["Next"] == failed for item in catch):
            raise ValueError("ECS worker failures must enter the persisted failure path")
        if states[status]["Default"] != failed:
            raise ValueError("Stopped tasks without a completed job must fail the scan")
        if states[failed].get("Result") != {"code": "worker_task_failed", "stage": stage} or states[failed]["Next"] != "ReleaseFailed":
            raise ValueError("Task failures require a safe code and owned lock release")
    release = states["ReleaseFailed"]
    if release["Parameters"].get("ConditionExpression") != "#owner = :owner" or release["Next"] != "ReadFailureStatus":
        raise ValueError("Failed task lock release must remain owner-conditional")
    if not any(item["ErrorEquals"] == ["States.ALL"] and item["Next"] == "ReadFailureStatus" for item in release.get("Catch", [])):
        raise ValueError("Lock release errors must not prevent job failure reconciliation")
    read = states["ReadFailureStatus"]
    if (read["Resource"] != "arn:aws:states:::dynamodb:getItem" or
            read["Parameters"].get("ConsistentRead") is not True or read["Next"] != "FailureStatus"):
        raise ValueError("Failure reconciliation must read the authoritative terminal status")
    choices = states["FailureStatus"]
    expected = [{"Variable": "$.job_status.Item.status.S", "IsPresent": False, "Next": "Failed"}]
    expected += [{"Variable": "$.job_status.Item.status.S", "StringEquals": status, "Next": target}
                 for status, target in [("cancelled", "Cancelled"), ("completed", "Succeeded"),
                                        ("failed", "Failed"), ("timed_out", "Failed")]]
    if choices.get("Choices") != expected or choices.get("Default") != "MarkFailed" or states["Cancelled"] != {"Type": "Succeed"}:
        raise ValueError("Failure reconciliation must distinguish cancellation from failed scans")
    catch = states["MarkFailed"].get("Catch", [])
    if catch != [{"ErrorEquals": ["DynamoDB.ConditionalCheckFailedException"],
                  "Output": "{% $states.input %}", "Next": "ReadFailureStatus"}]:
        raise ValueError("A terminal-state race must preserve inputs and re-read the job")
    mark = states["MarkFailed"]["Arguments"]
    if mark.get("ConditionExpression") != "attribute_exists(PK) AND #status IN (:queued,:collecting,:collected,:analyzing)":
        raise ValueError("Workflow failure must preserve terminal scan states")
    for assignment in ["#owner=:null", "lease=:null", "error_code=:code", "error_stage=:stage"]:
        if assignment not in mark["UpdateExpression"]:
            raise ValueError("Workflow failure must clear job ownership and persist diagnostics")


def validate(root: Path, terraform: str, session):
    definition, bounds = compile_definition(root, terraform)
    result = session.client("stepfunctions").validate_state_machine_definition(
        definition=definition, type="STANDARD", severity="WARNING", maxResults=100)
    report = {"result": result["result"], "diagnostics": result.get("diagnostics", []),
              "truncated": result.get("truncated", False), "stand_in_resource_ids": True,
              "bounds": bounds, "lock_release": "owner_conditional"}
    output = root / "infra/aws/build/workflow-validation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if report["result"] != "OK":
        raise RuntimeError("AWS rejected the actual workflow expression")
    return report
