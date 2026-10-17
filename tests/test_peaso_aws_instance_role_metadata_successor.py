"""Review metadata for the twenty corrected EC2 instance-role controls."""

import json
from pathlib import Path

from peaso.checks import aws_gap_ec2

REVIEW = Path(__file__).resolve().parents[1] / "peaso" / "rulepacks" / "reviewed_aws_gap.json"


def test_instance_role_review_reason_preserves_requirement_and_evidence_boundary():
    rows = json.loads(REVIEW.read_text())
    expected = {"aws-compliance.control." + query for query in aws_gap_ec2.STEAMPIPE_NATIVES}
    actual = {key for key in rows if key.startswith("aws-compliance.control.ec2_instance_no_iam_")}
    assert actual == expected
    assert len(actual) == 20
    for key in expected:
        row = rows[key]
        assert row["native_checks"] == [aws_gap_ec2.STEAMPIPE_NATIVES[key.removeprefix("aws-compliance.control.")]]
        reason = row["reason"]
        assert "not allow the listed sensitive actions" in reason
        assert "full combination requirement" in reason
        assert "unconditional identity-policy grant on Resource * is a configuration finding" in reason
        assert "not proof that a live API call would succeed" in reason
        assert "SCPs, session policies" in reason
        assert "scoped or conditional policy term whose effect cannot be established, yields UNKNOWN" in reason
        assert "an Allow with a condition still counts as a grant" not in reason
