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


def validate(root: Path, terraform: str, session):
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
        "var.region": '"us-east-1"', "var.source_version": '"validation"', "var.customer_role_arns": "[]",
    }
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
    json.loads(definition)
    result = session.client("stepfunctions").validate_state_machine_definition(
        definition=definition, type="STANDARD", severity="WARNING", maxResults=100)
    report = {"result": result["result"], "diagnostics": result.get("diagnostics", []),
              "truncated": result.get("truncated", False), "stand_in_resource_ids": True}
    output = root / "infra/aws/build/workflow-validation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if report["result"] != "OK":
        raise RuntimeError("AWS rejected the actual workflow expression")
    return report
