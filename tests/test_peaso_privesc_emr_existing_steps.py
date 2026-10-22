"""An EMR command step reaches only the role of its recorded instance profile."""

import pytest

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, profile_arn, real, reached, role, role_arn, user,
)


TECHNIQUE = "aws-emr-addjobflowsteps"
CLUSTER = f"arn:aws:elasticmapreduce:{REGION}:{ACCOUNT}:cluster/j-123"
OTHER_CLUSTER = f"arn:aws:elasticmapreduce:{REGION}:{ACCOUNT}:cluster/j-456"


def evidence(*, cluster_id="j-123", permitted_arn=CLUSTER, profile="emr-ec2", state="WAITING",
             detail_status="collected", inventory_status="collected"):
    target = role("target", "ec2.amazonaws.com", profiles=[profile_arn("emr-ec2")])
    other = role("other", "ec2.amazonaws.com", profiles=[profile_arn("other")])
    cluster = {"Id": cluster_id, "ClusterArn": f"arn:aws:elasticmapreduce:{REGION}:{ACCOUNT}:cluster/{cluster_id}",
               "Status": {"State": state}, "Ec2InstanceAttributes": {"IamInstanceProfile": profile}}
    record = {"Id": cluster_id, "Cluster": {"collection_status": detail_status, "Cluster": cluster}}
    snap = aws_snap([user("alice", allow("elasticmapreduce:AddJobFlowSteps", resource=permitted_arn))],
                    roles=[target, other], extra=[col("emr_cluster", [record], inventory_status)])
    return snap


def test_active_cluster_step_reaches_only_instance_profile_role():
    assert reached(real(evidence(), TECHNIQUE), ALICE, TECHNIQUE) == {role_arn("target"): "conditional"}
    assert reached(real(evidence(profile="other"), TECHNIQUE), ALICE, TECHNIQUE) == \
        {role_arn("other"): "conditional"}


@pytest.mark.parametrize("change", (
    {"cluster_id": "j-456"}, {"permitted_arn": OTHER_CLUSTER}, {"state": "TERMINATED"},
    {"detail_status": "access_denied"}, {"inventory_status": "access_denied"},
))
def test_wrong_or_unavailable_cluster_does_not_reach_role(change):
    assert reached(real(evidence(**change), TECHNIQUE), ALICE, TECHNIQUE) == {}
