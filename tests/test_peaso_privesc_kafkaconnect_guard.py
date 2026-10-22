"""MSK Connect grants alone do not prove controlled plugin code can run."""

from tests.test_peaso_privesc_aws_followups import (
    ALICE, aws_snap, user, role, allow, real, reached, assert_unresolved,
)


def test_connector_without_plugin_and_cluster_evidence_stays_unresolved():
    technique = "aws-kafkaconnect-passrole-createconnector"
    target = role("connector", "kafkaconnect.amazonaws.com")
    caller = user("alice", allow("iam:PassRole", resource=target["Arn"]),
                  allow("kafkaconnect:CreateCustomPlugin"),
                  allow("kafkaconnect:CreateConnector"))
    snap = aws_snap([caller], [target])
    result = real(snap, technique, include_unknown=True)
    assert target["Arn"] not in reached(result, ALICE, technique)
    assert_unresolved(result, ALICE, technique)
