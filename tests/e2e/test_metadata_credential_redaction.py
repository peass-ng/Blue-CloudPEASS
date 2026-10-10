"""Credential-shaped metadata uses inert values; no real secrets are read."""
import json

import pytest

from peaso.collectors.aws import _safe
from peaso.collectors.azure import _metadata_only
from peaso.collectors.gcp import sanitize
from peaso.collectors.k8s import _sanitize
from peaso.auth.secrets import redact

MARKER = "INERT_QA_MARKER_NOT_A_REAL_SECRET"


@pytest.mark.parametrize("provider,scrub,payload", [
    ("aws", _safe, {"Tags": [{"Key": "api_token", "Value": MARKER}, {"Key": "Name", "Value": "peaso-test"}], "MetadataOptions": {"HttpTokens": "required"}}),
    ("azure", _metadata_only, {"tags": {"api_token": MARKER, "Name": "peaso-test"}}),
    ("gcp", sanitize, {"labels": {"api_token": MARKER, "name": "peaso-test"}}),
    ("k8s", _sanitize, {"metadata": {"annotations": {"api_token": MARKER}, "labels": {"app": "peaso-test"}}}),
])
def test_credential_shaped_metadata_does_not_enter_cli_snapshot(provider, scrub, payload):
    result = scrub(payload)
    assert MARKER not in json.dumps(result)
    assert "peaso-test" in json.dumps(result)
    if provider == "aws":
        assert result["MetadataOptions"]["HttpTokens"] == "required"


def test_worker_redacts_aws_key_value_credential_tag_without_auth_match():
    result = redact({"Tags": [{"Key": "api_token", "Value": MARKER}, {"Key": "Name", "Value": "peaso-test"}], "MetadataOptions": {"HttpTokens": "required"}})
    assert MARKER not in json.dumps(result)
    assert "peaso-test" in json.dumps(result)
    assert result["MetadataOptions"]["HttpTokens"] == "required"
