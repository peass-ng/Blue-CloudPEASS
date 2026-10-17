"""Cross-region replication must not select the last conflicting bucket identity."""
from copy import deepcopy
import pytest
from peaso.checks import claude_aws_a_s3 as s3
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot
CID="aws.claude_a.s3.prowler_cross_region_replication"

@pytest.mark.parametrize("reverse",[False,True])
def test_duplicate_destination_identity_cannot_prove_cross_region(reverse):
    source=deepcopy(s3.B)
    destinations=[s3.w(s3.B2,Location__LocationConstraint=None),deepcopy(s3.B2)]
    if reverse:destinations.reverse()
    scope=s3.ACCOUNT+"/us-east-1"
    snap=make_snapshot("aws",[scope],[{"type":"bucket","scope":scope,"status":"collected","items":[source,*destinations]}],created_at="2026-10-17T00:00:00Z")
    rows=[f for f in evaluate_snapshot(snap,checks=[CID])["findings"] if f["check_id"]==CID and f.get("native_resource_id")=="b1"]
    assert len(rows)==1 and rows[0]["status"]=="UNKNOWN"
