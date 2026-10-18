"""Worker redaction preserves security facts while removing actual credentials."""
import json

import pytest

from peaso.auth.secrets import credential_values, redact
from peaso.engine import evaluate_snapshot, catalog
from peaso.snapshot import make_snapshot, seal


@pytest.mark.parametrize("tokens,expected", [("required", "PASS"), ("optional", "FAIL")])
def test_imds_fact_survives_worker_redaction(tokens, expected):
    sentinel = "INERT_QA_CREDENTIAL_SENTINEL_38ef014a"
    snapshot = make_snapshot("aws", ["test-account/us-east-1"], [{"type": "instance", "scope": "test-account/us-east-1", "service": "ec2", "status": "collected",
        "items": [{"InstanceId": "peaso-test-instance", "MetadataOptions": {"HttpTokens": tokens, "HttpEndpoint": "enabled"}, "SecretAccessKey": sentinel}]}])
    auth = {"method": "profile", "profile": "peaso-test-profile", "region_name": "us-east-1", "aws_secret_access_key": sentinel}
    scrubbed = seal(redact(snapshot, tuple(credential_values(auth))))
    assert sentinel not in json.dumps(scrubbed)
    assert scrubbed["provider"] == "aws"
    assert scrubbed["collections"][0]["items"][0]["MetadataOptions"]["HttpTokens"] == tokens
    checks = [c["id"] for c in catalog()["checks"] if c["provider"] == "aws" and ("imds" in c["id"].lower() or "metadata" in c["title"].lower())]
    assert checks, "IMDS security predicate must be present"
    report = evaluate_snapshot(scrubbed, checks=checks)
    outcomes = [f["status"] for f in report["findings"] if f["resource_id"] != "inventory:instance"]
    assert expected in outcomes


def test_identity_and_routing_metadata_are_not_credential_values():
    auth = {"method": "profile", "profile": "peaso-test-profile", "provider": "aws", "context": "peaso-test-context", "region_name": "us-east-1",
            "tenant_id": "peaso-test-tenant", "client_id": "peaso-test-client", "client_secret": "INERT_QA_CREDENTIAL_SENTINEL"}
    values = tuple(credential_values(auth))
    assert "profile" not in values
    assert "peaso-test-profile" not in values
    assert "aws" not in values
    assert "peaso-test-tenant" not in values
    assert "INERT_QA_CREDENTIAL_SENTINEL" in values
