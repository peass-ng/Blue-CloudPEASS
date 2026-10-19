"""Exercise the native projection through the registered high-confidence check."""
import base64
import json

import pytest

from peaso.checks import evaluate_check
from peaso.collectors.aws import ReadFailure, _project_user_data_indicators

INSTANCE = "i-0123456789abcdef0"
SCOPE = "123456789012/us-east-1"


def observed(text):
    response = _project_user_data_indicators({"InstanceId": INSTANCE, "UserData": {
        "Value": base64.b64encode(text.encode()).decode()}}, INSTANCE)
    return {"InstanceId": INSTANCE, "UserDataSecretIndicators": response["UserDataSecretIndicators"]}, response


def index(item):
    return {"context": {"provider": "aws", "scope": SCOPE, "metadata": {}},
            "collections": {"instance": [{"type": "instance", "scope": SCOPE, "status": "collected", "items": [item]}]},
            "instance": [{"type": "instance", "scope": SCOPE, "data": item}]}


@pytest.mark.parametrize("text,category", [
    ("-----BEGIN PRIVATE KEY-----\nAAECAwQ=\n-----END PRIVATE KEY-----", "private_key"),
    ("AWS_ACCESS_KEY_ID=AKIA" + "Z" * 16 + "\naws_secret_access_key=" + "x" * 40, "cloud_credential"),
    ('DB_PASSWORD="synthetic-password-529!"', "password_assignment"),
])
def test_native_projection_drives_failure_without_retaining_secret(text, category):
    item, response = observed(text)
    status, evidence = evaluate_check("aws_cis_ec2_userdata_embedded_secrets", item, index(item))
    assert status == "FAIL"
    assert evidence["matched_categories"] == [category]
    serialized = json.dumps(response)
    assert text not in serialized
    assert "Value" not in serialized and "UserData\"" not in serialized


@pytest.mark.parametrize("text", ["", "#!/bin/sh\necho SafeConfiguration123!", 'DB_PASSWORD="${DATABASE_PASSWORD}"',
                                         'password="example-password-123"', "AKIA" + "Z" * 16])
def test_complete_bounded_inspection_without_indicator_passes(text):
    item, _ = observed(text)
    assert evaluate_check("aws_cis_ec2_userdata_embedded_secrets", item, index(item))[0] == "PASS"


def test_denied_malformed_and_foreign_evidence_cannot_pass():
    item = {"InstanceId": INSTANCE, "UserDataSecretIndicators": {"collection_status": "denied"}}
    assert evaluate_check("aws_cis_ec2_userdata_embedded_secrets", item, index(item))[0] == "UNKNOWN"
    item, _ = observed("")
    item["UserDataSecretIndicators"]["InstanceId"] = "i-foreign"
    assert evaluate_check("aws_cis_ec2_userdata_embedded_secrets", item, index(item))[0] == "UNKNOWN"
    with pytest.raises(ReadFailure):
        _project_user_data_indicators({"InstanceId": INSTANCE, "UserData": {"Value": "malformed"}}, INSTANCE)


def test_documented_absent_user_data_is_inspected_empty():
    response = _project_user_data_indicators({"InstanceId": INSTANCE}, INSTANCE)
    assert response["UserDataSecretIndicators"]["Present"] is False
    assert response["UserDataSecretIndicators"]["HighConfidenceSecretPresent"] is False


@pytest.mark.parametrize("mode,status", [("literal", "FAIL"), ("empty", "PASS"), ("denied", "UNKNOWN")])
def test_real_sdk_cache_enrichment_and_snapshot_chain(mode, status):
    import boto3
    from botocore.stub import Stubber
    from peaso.collectors.aws import Requests, _enrich
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot

    session = boto3.Session(aws_access_key_id="fixture", aws_secret_access_key="fixture", region_name="us-east-1")
    client = session.client("ec2")
    requests = Requests({"retry_attempts": 1})
    requests._clients[(id(session), "ec2", "us-east-1")] = client
    literal = 'DB_PASSWORD="synthetic-password-529!"'
    with Stubber(client) as stub:
        params = {"InstanceId": INSTANCE, "Attribute": "userData"}
        if mode == "denied":
            stub.add_client_error("describe_instance_attribute", "UnauthorizedOperation", expected_params=params)
        else:
            text = literal if mode == "literal" else ""
            stub.add_response("describe_instance_attribute", {"InstanceId": INSTANCE, "UserData": {
                "Value": base64.b64encode(text.encode()).decode()}}, params)
        stub.add_response("describe_instance_attribute", {"InstanceId": INSTANCE, "DisableApiTermination": {"Value": True}},
                          {"InstanceId": INSTANCE, "Attribute": "disableApiTermination"})
        row = _enrich(requests, session, "us-east-1", "instance", [{"InstanceId": INSTANCE}],
                      account="123456789012", partition="aws")[0]
        snap = make_snapshot("aws", [SCOPE], [{"type": "instance", "scope": SCOPE, "service": "ec2",
                                              "status": "collected", "items": [row]}])
        result = evaluate_snapshot(snap, checks=["aws_cis_ec2_userdata_embedded_secrets"])
        assert result["findings"][0]["status"] == status
        stub.assert_no_pending_responses()
    for future in requests._cache.values():
        if future.exception() is None:
            assert literal not in json.dumps(future.result(), default=str)
    assert literal not in json.dumps(snap, default=str)
    assert literal not in json.dumps(result, default=str)
