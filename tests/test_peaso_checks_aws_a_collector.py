"""AWS-A collector boundary regressions use inert metadata, never real values."""
import copy
import json

import pytest

from peaso.collectors.aws import _safe

MARKER = "INERT_AWS_A_CREDENTIAL_MARKER"


@pytest.mark.parametrize("key", ["api_token", "apiKey", "PASSWORD", "client_secret", "Authorization", "aws_access_key_id", "aws_secret_access_key", "ssh_private_key", "mfa_secret"])
def test_credential_shaped_tag_values_are_redacted_and_keys_preserved(key):
    payload = {"Tags": [{"Key": key, "Value": MARKER}, {"Key": "Name", "Value": "benign-resource"}, {"Key": "project", "Value": "blue"}], "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}}
    before = copy.deepcopy(payload)
    safe = _safe(payload)
    assert MARKER not in json.dumps(safe)
    assert safe["Tags"][0]["Key"] == key
    assert safe["Tags"][0]["_coverage"]["Value"]["status"] == "not_collected"
    assert safe["Tags"][1:] == payload["Tags"][1:]
    assert safe["MetadataOptions"] == payload["MetadataOptions"]
    assert payload == before


def test_flat_label_maps_and_header_credentials_do_not_leak():
    safe = _safe({"tags": {"api_token": MARKER, "Name": "benign"}, "Origins": [{"HeaderName": "Authorization", "HeaderValue": MARKER}, {"HeaderName": "Strict-Transport-Security", "HeaderValue": "max-age=31536000"}]})
    assert MARKER not in json.dumps(safe)
    assert safe["tags"]["Name"] == "benign"
    assert safe["Origins"][1]["HeaderValue"] == "max-age=31536000"


def test_environment_records_never_retain_values_even_under_benign_variable_names():
    safe = _safe({"containerDefinitions": [{"environment": [{"name": "CONFIG", "value": MARKER}]}], "enabled": True, "tokenRequired": False})
    assert MARKER not in json.dumps(safe)
    assert safe["containerDefinitions"][0]["environment"][0]["name"] == "CONFIG"
    assert safe["enabled"] is True
    assert safe["tokenRequired"] is False


def test_tag_boolean_security_flags_remain_evidence():
    safe = _safe({"Tags": [{"Key": "token_required", "Value": True}], "HttpTokens": "required", "secretRotationEnabled": True})
    assert safe["Tags"][0]["Value"] is True
    assert safe["HttpTokens"] == "required"
    assert safe["secretRotationEnabled"] is True


def test_numeric_credential_label_values_are_redacted_without_losing_boolean_flags():
    safe = _safe({"Tags": [{"Key": "db_password", "Value": 123456}, {"Key": "token_required", "Value": True}]})
    assert safe["Tags"][0]["Value"] == "[redacted]"
    assert safe["Tags"][1]["Value"] is True


@pytest.mark.parametrize("container", ["TagSet", "TagList", "customTagEnvelope"])
def test_sdk_tag_record_shapes_and_credential_values_are_scrubbed_in_any_envelope(container):
    safe = _safe({container: [{"Key": "api_token", "Value": MARKER}, {"Key": "Name", "Value": "benign"}]})
    assert MARKER not in json.dumps(safe)
    assert safe[container][1]["Value"] == "benign"
