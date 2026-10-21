"""Pipeline override and retry signals retain no parameter values or ARNs."""

from copy import deepcopy
from pathlib import Path

from peaso.attack_detection.aws_sagemaker_pipeline_execution_next import normalize
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
PIPELINE = f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:pipeline/synthetic-pipeline"
EXECUTION = PIPELINE + "/execution/synthetic-run"


def event(name, request):
    return {
        "eventSource": "sagemaker.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-event", "eventTime": "2026-10-21T12:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": request,
    }


def start():
    return event("StartPipelineExecution", {
        "pipelineName": "synthetic-pipeline",
        "pipelineParameters": [{"name": "InputText", "value": "private-synthetic-override"}],
    })


def retry():
    return event("RetryPipelineExecution", {"pipelineExecutionArn": EXECUTION})


def test_two_valid_routes_only_expose_opaque_targets(tmp_path: Path):
    for suffix, synthetic, marker in (
        ("start", "SageMakerPipelineParametersOverridden", "request.sagemaker_pipeline_parameter_override"),
        ("retry", "SageMakerPipelineExecutionRetried", "request.sagemaker_pipeline_execution_retried"),
    ):
        (tmp_path / f"{suffix}.yml").write_text(f"""title: Synthetic {suffix}
id: 14900000-0000-4000-8000-00000000000{1 if suffix == 'start' else 2}
status: experimental
description: Synthetic pipeline signal.
references: [https://example.test/source]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: sagemaker.amazonaws.com
    event.name: {synthetic}
    event.outcome: success
    {marker}: true
  condition: selection
falsepositives: [Approved operation]
level: low
tags: [attack.execution]
x_hacktricks_technique_id: synthetic-{suffix}
""", encoding="utf-8")
    hits = detect_aws_events([start(), retry()], load_rules(tmp_path, product="aws"))
    assert {hit.technique_id for hit in hits} == {"synthetic-start", "synthetic-retry"}
    assert all(hit.target_id.startswith("sha256:") for hit in hits)
    assert PIPELINE not in str(hits)
    assert "private-synthetic-override" not in str(hits)


def test_empty_denied_foreign_and_malformed_requests_do_not_match():
    empty = deepcopy(start()); empty["requestParameters"]["pipelineParameters"] = []
    denied = deepcopy(start()); denied["errorCode"] = "AccessDeniedException"
    foreign_start = deepcopy(start()); foreign_start["requestParameters"]["pipelineName"] = (
        PIPELINE.replace(ACCOUNT, "111111111111")
    )
    foreign_retry = deepcopy(retry()); foreign_retry["requestParameters"]["pipelineExecutionArn"] = (
        EXECUTION.replace(ACCOUNT, "111111111111")
    )
    malformed = deepcopy(retry()); malformed["requestParameters"]["pipelineExecutionArn"] = PIPELINE
    read_only = deepcopy(retry()); read_only["readOnly"] = True
    assert normalize(start()) is not None
    assert normalize(retry()) is not None
    assert all(normalize(item) is None for item in (
        empty, denied, foreign_start, foreign_retry, malformed, read_only,
    ))
