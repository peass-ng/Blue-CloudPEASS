"""Keep EMR's Custom-only policy guidance distinct from valid AWS KMS encryption."""

from __future__ import annotations

import json
from pathlib import Path

from peaso.checks import CHECKS


ROOT = Path(__file__).resolve().parents[1]
CHECK_ID = "aws.c2b.emr.cluster_local_disk_cmk"


def test_custom_provider_guidance_preserves_kms_exception():
    check = next(check for check in CHECKS if check.id == CHECK_ID)
    structured = json.loads((ROOT / "peaso/rulepacks/remediation_aws_reviewed.json").read_text())[CHECK_ID]

    assert "Custom" in check.remediation
    assert "AwsKms with EBS encryption" in check.remediation
    assert "owner-reviewed policy exception" in check.remediation
    assert "solely to clear this finding" in check.remediation
    assert "AwsKms does not satisfy this pinned predicate" in structured["iac"]["code"]
    assert "using EncryptionKeyProviderType=Custom" in structured["iac"]["code"]
    assert "with Select" not in structured["iac"]["code"]
    assert any("approved secure design" in caveat for caveat in structured["caveats"])
