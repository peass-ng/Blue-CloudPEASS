"""Signer profile inventory for the Lambda signing route."""

from peaso.collectors import aws, aws_facts_swc
from peaso.collectors.aws import ReadResult


def test_signer_profile_inventory_keeps_version_status_without_signing_material():
    assert "signer_profile" in aws.AWS_TYPES
    assert ("signer", "list_signing_profiles") in aws.READ_ACTIONS
    calls = []
    class Requests:
        def pages(self, session, service, region, operation, field, **arguments):
            calls.append((service, region, operation, field, arguments))
            return ReadResult([{"profileName": "release", "profileVersion": "1",
                "profileVersionArn": "arn:aws:signer:us-east-1:111111111111:/signing-profiles/release/1",
                "arn": "arn:aws:signer:us-east-1:111111111111:/signing-profiles/release",
                "platformId": "AWSLambda-SHA384-ECDSA", "status": "ACTIVE",
                "signingMaterial": {"certificateArn": "arn:aws:acm:us-east-1:111111111111:certificate/private"}}],
                "collected", None)

    result = aws_facts_swc._signer_profiles(Requests(), None, "us-east-1", "111111111111")
    assert result.status == "collected"
    assert result.items[0]["status"] == "ACTIVE"
    assert "signingMaterial" not in result.items[0]
    assert calls == [("signer", "us-east-1", "list_signing_profiles", "profiles", {"includeCanceled": True})]
