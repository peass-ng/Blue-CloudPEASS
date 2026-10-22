"""Synthetic CloudTrail derivative of a disposable Redshift password reset."""

from copy import deepcopy

from peaso.attack_detection.aws_redshift_password_reset import normalize_aws_redshift_password_reset


def event():
    return {"eventSource": "redshift.amazonaws.com", "eventName": "ModifyCluster",
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": "999999999999", "awsRegion": "us-east-2",
            "eventTime": "2026-10-22T00:00:00Z", "eventID": "synthetic-password-reset",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::999999999999:user/synthetic"},
            "requestParameters": {"clusterIdentifier": "synthetic-cluster",
                                  "masterUserPassword": "HIDDEN_DUE_TO_SECURITY_REASONS"},
            "responseElements": {"clusterIdentifier": "synthetic-cluster",
                                 "pendingModifiedValues": {"masterUserPassword": "HIDDEN_DUE_TO_SECURITY_REASONS"}}}


def test_accepted_password_change_emits_only_opaque_signal():
    result = normalize_aws_redshift_password_reset(event())
    assert result["request.redshift_master_password_reset"] is True
    assert result["resource.type"] == "CloudTrail::UnscopedEvent"
    assert "synthetic-cluster" not in str(result)
    assert "HIDDEN_DUE_TO_SECURITY_REASONS" not in str(result)


def test_other_cluster_changes_and_failed_requests_do_not_match():
    base = event()
    for mutation in (
        lambda x: x["requestParameters"].pop("masterUserPassword"),
        lambda x: x["responseElements"]["pendingModifiedValues"].pop("masterUserPassword"),
        lambda x: x["responseElements"].update(clusterIdentifier="different-cluster"),
        lambda x: x.update(errorCode="InvalidClusterState"),
        lambda x: x.update(eventName="DescribeClusters"),
        lambda x: x.update(readOnly=True),
    ):
        changed = deepcopy(base)
        mutation(changed)
        assert normalize_aws_redshift_password_reset(changed) is None
