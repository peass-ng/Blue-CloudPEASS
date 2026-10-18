"""A bucket detail is absent only with readable source absence evidence."""
from copy import deepcopy
import pytest
from test_peaso_s3_lifecycle_notification_authority import verdict
from peaso.checks import claude_aws_a_s3 as s3

CASES=[("aws.claude_a.s3.lifecycle_rule_enabled","Lifecycle","FAIL"),
       ("aws.claude_a.s3.object_lock_configured","ObjectLock","FAIL"),
       ("aws.claude_a.s3.static_website_disabled","Website","PASS"),
       ("aws.claude_a.s3.bucket_public_access_block_all","PublicAccessBlock","FAIL"),
       ("aws.claude_a.s3.prowler_kms_encryption","Encryption","FAIL")]

@pytest.mark.parametrize("cid,key,expected",CASES)
@pytest.mark.parametrize("field",["absent","collection_status"])
def test_unavailable_absence_receipt_cannot_prove_configuration_state(cid,key,expected,field):
    item=deepcopy(s3.B);item[key]={**s3.ABSENT,"_coverage":{field:{"status":"denied"}}}
    assert verdict(cid,item)=="UNKNOWN"

@pytest.mark.parametrize("cid,key,expected",CASES)
def test_authoritative_absence_keeps_source_outcome(cid,key,expected):
    item=deepcopy(s3.B);item[key]=deepcopy(s3.ABSENT)
    assert verdict(cid,item)==expected
