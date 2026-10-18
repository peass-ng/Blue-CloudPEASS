"""Mirror S3 controls must use readable scoped account block identity."""
from copy import deepcopy
import pytest
from peaso.checks import claude_aws_a_s3 as s3
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot

@pytest.mark.parametrize("cid",["aws.claude_a.s3.account_public_access_block_all","aws.claude_a.s3.prowler_account_ignore_restrict","aws.claude_a.s3.prowler_bucket_level_public_access_block"])
def test_unreadable_global_account_identity_cannot_supply_block_proof(cid):
    scope=s3.ACCOUNT+"/us-east-1"
    row={"AccountId":s3.ACCOUNT,"PublicAccessBlockConfiguration":deepcopy(s3.ACCT_OK["PublicAccessBlockConfiguration"]),"_coverage":{"AccountId":{"status":"denied"}}}
    bucket=s3.w(s3.B,PublicAccessBlock=s3.OPEN_BLOCK)
    snap=make_snapshot("aws",[scope],[{"type":"bucket","scope":scope,"status":"collected","items":[bucket]},{"type":"s3_account_public_access_block","scope":s3.ACCOUNT+"/global","global":True,"account_id":s3.ACCOUNT,"status":"collected","items":[row]}],created_at="2026-10-17T00:00:00Z")
    findings=[f for f in evaluate_snapshot(snap,checks=[cid])["findings"] if f["check_id"]==cid]
    assert findings and all(f["status"]=="UNKNOWN" for f in findings)

@pytest.mark.parametrize("error,expected",[(None,"FAIL"),({"code":"NoSuchPublicAccessBlockConfiguration"},"FAIL"),({"code":"AccessDenied"},"UNKNOWN"),({"code":"WrongError"},"UNKNOWN")])
def test_empty_inventory_rejects_explicit_contradictory_error(error,expected):
    scope=s3.ACCOUNT+"/us-east-1"
    collection={"type":"s3_account_public_access_block","scope":scope,"status":"empty","items":[]}
    if error is not None:collection["error"]=error
    snap=make_snapshot("aws",[scope],[collection],created_at="2026-10-17T00:00:00Z")
    cid="aws.claude_a.s3.account_public_access_block_all"
    rows=[f for f in evaluate_snapshot(snap,checks=[cid])["findings"] if f["check_id"]==cid]
    assert rows and all(f["status"]==expected for f in rows)
