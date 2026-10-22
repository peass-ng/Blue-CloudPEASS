"""EMR Serverless image updates require a confirmed same-Region ECR image."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection.aws_emr_serverless_custom_image import normalize_aws_emr_custom_image
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-2"
APP_ID = "syntheticapp123"
APP_ARN = f"arn:aws:emr-serverless:{REGION}:{ACCOUNT}:/applications/{APP_ID}"
IMAGE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/synthetic-repo:lab"


def event(*, worker=False):
    request = {"applicationId": APP_ID}
    application = {"applicationId": APP_ID, "arn": APP_ARN, "type": "Spark"}
    if worker:
        request["workerTypeSpecifications"] = {"Driver": {"imageConfiguration": {"imageUri": IMAGE}}}
        application["workerTypeSpecifications"] = deepcopy(request["workerTypeSpecifications"])
    else:
        request["imageConfiguration"] = {"imageUri": IMAGE}
        application["imageConfiguration"] = deepcopy(request["imageConfiguration"])
    return {"eventSource": "emr-serverless.amazonaws.com", "eventName": "UpdateApplication",
            "eventType": "AwsApiCall", "eventCategory": "Management",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": REGION,
            "eventID": "synthetic-event", "eventTime": "2026-10-22T12:00:00Z",
            "userIdentity": {"accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
            "requestParameters": request, "responseElements": {"application": application}}


def rules(tmp_path):
    (tmp_path / "emr.yml").write_text("""title: Synthetic EMR image update
id: b3770000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/emr-image]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: emr-serverless.amazonaws.com
    event.name: UpdateApplication
    event.outcome: success
    request.emr_custom_image_update_requested: true
  condition: selection
falsepositives: [Approved image update]
level: high
x_hacktricks_technique_id: synthetic-emr-image-update
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_application_and_worker_images_match_without_uri(tmp_path):
    hits = detect_aws_events([event(), event(worker=True)], rules(tmp_path))
    assert len(hits) == 2
    assert all(h.technique_id == "synthetic-emr-image-update" for h in hits)
    assert all(h.target_id.startswith("sha256:") for h in hits)
    assert IMAGE not in str(hits)
    assert APP_ARN not in str(hits)


def test_denials_foreign_images_and_unconfirmed_response_fail_closed(tmp_path):
    base = event()
    variants = []
    for change in (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x["userIdentity"].update(accountId="111111111111"),
        lambda x: x["requestParameters"]["imageConfiguration"].update(
            imageUri=IMAGE.replace(ACCOUNT, "111111111111")),
        lambda x: x["requestParameters"]["imageConfiguration"].update(
            imageUri=IMAGE.replace(REGION, "us-west-2")),
        lambda x: x["requestParameters"]["imageConfiguration"].update(imageUri="public.ecr.aws/example"),
        lambda x: x["responseElements"]["application"].update(imageConfiguration={}),
        lambda x: x["responseElements"]["application"].update(arn="other"),
        lambda x: x["responseElements"]["application"].update(type="Other"),
        lambda x: x["requestParameters"].update(applicationId="different"),
    ):
        item = deepcopy(base)
        change(item)
        variants.append(item)
    assert detect_aws_events(variants, rules(tmp_path)) == []


def test_mixed_and_invalid_worker_images_are_excluded():
    mixed = event(worker=True)
    mixed["requestParameters"]["imageConfiguration"] = {"imageUri": IMAGE}
    assert normalize_aws_emr_custom_image(mixed) is None
    foreign_worker = event(worker=True)
    foreign_worker["requestParameters"]["workerTypeSpecifications"]["Driver"]["imageConfiguration"]["imageUri"] = (
        IMAGE.replace(ACCOUNT, "111111111111"))
    assert normalize_aws_emr_custom_image(foreign_worker) is None
