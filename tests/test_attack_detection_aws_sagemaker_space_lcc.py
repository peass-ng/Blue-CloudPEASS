"""Studio lifecycle storage and space attachment require accepted writes."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection.aws_sagemaker_space_lcc import normalize_aws_sagemaker_space_lcc
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-2"
DOMAIN = "d-synthetic123"
NAME = "synthetic-lcc"
ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:studio-lifecycle-config/{NAME}"


def event(action="UpdateSpace"):
    request = ({"domainId": DOMAIN, "spaceName": "synthetic-space",
                "spaceSettings": {"jupyterLabAppSettings": {
                    "defaultResourceSpec": {"lifecycleConfigArn": ARN}}}}
               if action == "UpdateSpace" else
               {"studioLifecycleConfigName": NAME, "studioLifecycleConfigAppType": "JupyterLab",
                "studioLifecycleConfigContent": "IyEvYmluL2Jhc2gK"})
    response = ({"spaceArn": f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:space/{DOMAIN}/synthetic-space"}
                if action == "UpdateSpace" else {"studioLifecycleConfigArn": ARN})
    return {
        "eventSource": "sagemaker.amazonaws.com", "eventName": action,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": "synthetic-event", "eventTime": "2026-10-23T12:00:00Z",
        "userIdentity": {"accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def rules(tmp_path):
    for action, flag, index in (
        ("CreateStudioLifecycleConfig", "sagemaker_studio_lcc_code_created", 1),
        ("UpdateSpace", "sagemaker_space_lcc_attached", 2),
    ):
        (tmp_path / f"{index}.yml").write_text(f"""title: Synthetic SageMaker lifecycle {index}
id: b3830000-0000-4000-8000-00000000000{index}
status: experimental
description: Synthetic test rule.
references: [https://example.test/sagemaker]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: sagemaker.amazonaws.com
    event.name: {action}
    event.outcome: success
    request.{flag}: true
  condition: selection
falsepositives: [Approved lifecycle setup]
level: high
x_hacktricks_technique_id: synthetic-sagemaker-{index}
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_created_and_attached_events_match_without_script_or_arn(tmp_path):
    hits = detect_aws_events([event("CreateStudioLifecycleConfig"), event()], rules(tmp_path))
    assert {hit.technique_id for hit in hits} == {"synthetic-sagemaker-1", "synthetic-sagemaker-2"}
    assert all(hit.target_id.startswith("sha256:") for hit in hits)
    assert ARN not in str(hits)
    assert "IyEvYmluL2Jhc2gK" not in str(hits)


def test_failed_foreign_or_unconfirmed_space_attachments_fail_closed(tmp_path):
    base = event()
    variants = []
    changes = (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x.update(eventCategory="Data"),
        lambda x: x["userIdentity"].update(accountId="111111111111"),
        lambda x: x["requestParameters"]["spaceSettings"]["jupyterLabAppSettings"]["defaultResourceSpec"].update(
            lifecycleConfigArn=ARN.replace(ACCOUNT, "111111111111")),
        lambda x: x["requestParameters"]["spaceSettings"].update(jupyterLabAppSettings={}),
        lambda x: x["responseElements"].update(spaceArn="other"),
        lambda x: x["requestParameters"].update(domainId="wrong"),
    )
    for change in changes:
        variant = deepcopy(base)
        change(variant)
        variants.append(variant)
    assert detect_aws_events(variants, rules(tmp_path)) == []


def test_classic_lcc_creation_is_outside_current_studio_rule():
    value = event("CreateStudioLifecycleConfig")
    value["requestParameters"]["studioLifecycleConfigAppType"] = "JupyterServer"
    assert normalize_aws_sagemaker_space_lcc(value) is None


def test_code_editor_space_attachment_is_recognized():
    value = event()
    settings = value["requestParameters"]["spaceSettings"]
    settings["codeEditorAppSettings"] = settings.pop("jupyterLabAppSettings")
    assert normalize_aws_sagemaker_space_lcc(value)["request.sagemaker_space_lcc_attached"] is True
