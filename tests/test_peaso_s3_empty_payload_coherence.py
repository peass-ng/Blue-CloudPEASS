"""Native detail absence cannot contradict a retained configuration payload."""
from copy import deepcopy
import pytest
from peaso.checks import claude_aws_a_s3 as s3
from peaso.checks.facts import Unavailable
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
SCOPE="123456789012/us-east-1"
PREFIX="aws.claude_a.s3."
PUBLIC=PREFIX+"prowler_public_access"
READ=PREFIX+"restrict_public_read"
CASES=[("PublicAccessBlock","bucket_public_access_block_all","FAIL"),
       ("Policy","policy_restrict_public_access","NOT_APPLICABLE"),
       ("Encryption","prowler_kms_encryption","FAIL"),
       ("Lifecycle","lifecycle_rule_enabled","FAIL"),
       ("Replication","replication_rule_enabled","FAIL"),
       ("ObjectLock","object_lock_configured","FAIL"),
       ("OwnershipControls","prowler_acl_disabled","FAIL"),
       ("PolicyStatus","restrict_public_read","PASS"),
       ("Website","static_website_disabled","PASS")]

def verdict(cid,item,account=None):
    snapshot=make_snapshot("aws",[SCOPE],[{"type":"bucket","scope":SCOPE,"status":"collected","items":[deepcopy(item)]},{"type":"s3_account_public_access_block","scope":SCOPE,"status":"collected","items":[deepcopy(s3.ACCT_OPEN if account is None else account)]}],created_at="2026-10-17T00:00:00Z")
    before=deepcopy(snapshot);rows=[f for f in evaluate_snapshot(snapshot,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snapshot==before and len(rows)==1
    return rows[0]

def public_bucket():
    item=deepcopy(s3.B);item["Acl"]=s3.acl_with(s3.ALL_USERS,"FULL_CONTROL")
    item["PublicAccessBlock"]={**deepcopy(s3.ABSENT),"PublicAccessBlockConfiguration":{key:True for key in s3.BLOCKS}}
    return item

def test_contradictory_bucket_block_cannot_prove_unmitigated_public_access():
    for suffix in ("prowler_public_access","prowler_public_list_acl","prowler_public_write_acl"):
        assert verdict(PREFIX+suffix,public_bucket())["status"]=="UNKNOWN"

def test_stored_public_acl_remains_independent_with_unknown_mitigation_labels():
    finding=verdict(READ,public_bucket())
    assert finding["status"]=="FAIL"
    assert finding["evidence"]["bucket_public_access_block"] is None
    assert finding["evidence"]["runtime_acl_ignored"] is None

def test_independent_complete_account_block_still_settles_prowler_safety():
    account={"PublicAccessBlockConfiguration":{key:True for key in s3.BLOCKS}}
    assert verdict(PUBLIC,public_bucket(),account)["status"]=="PASS"

def test_retained_native_payload_is_not_absence_across_actual_consumers():
    for key,cid,_ in CASES:
        item=deepcopy(s3.B)
        payload=deepcopy(s3.B[key])
        if key=="Policy":payload={"Policy":{"Statement":[]}}
        if key=="Website":payload={"IndexDocument":{"Suffix":"index.html"}}
        item[key]={**payload,**deepcopy(s3.ABSENT)}
        assert verdict(PREFIX+cid,item)["status"]=="UNKNOWN",key

def test_coherent_absence_with_legitimate_receipt_metadata_preserves_outcomes():
    codes={"PublicAccessBlock":"NoSuchPublicAccessBlockConfiguration","Policy":"NoSuchBucketPolicy","PolicyStatus":"NoSuchBucketPolicy","Encryption":"ServerSideEncryptionConfigurationNotFoundError","Lifecycle":"NoSuchLifecycleConfiguration","Replication":"ReplicationConfigurationNotFoundError","ObjectLock":"ObjectLockConfigurationNotFoundError","OwnershipControls":"OwnershipControlsNotFoundError","Website":"NoSuchWebsiteConfiguration"}
    for key,cid,expected in CASES:
        item=deepcopy(s3.B)
        item[key]={**deepcopy(s3.ABSENT),"_coverage":{"collection_status":{"status":"collected"},"absent":{"status":"collected"}},"_provenance":{"source":"synthetic archived fixture"},"error":{"code":codes[key]},"ResponseMetadata":{"RequestId":"synthetic-request","HTTPStatusCode":404}}
        assert verdict(PREFIX+cid,item)["status"]==expected,key

def test_retained_null_or_empty_payload_is_also_contradictory():
    for payload in (None,{},[]):
        item=public_bucket();item["PublicAccessBlock"]["PublicAccessBlockConfiguration"]=payload
        assert verdict(PUBLIC,item)["status"]=="UNKNOWN"

def test_all_native_website_payload_members_conflict_with_absence():
    for field,value in (("IndexDocument",{"Suffix":"index.html"}),("ErrorDocument",{"Key":"error.html"}),("RedirectAllRequestsTo",{"HostName":"example.com"}),("RoutingRules",[])):
        item=deepcopy(s3.B);item["Website"]={**deepcopy(s3.ABSENT),field:value}
        assert verdict(PREFIX+"static_website_disabled",item)["status"]=="UNKNOWN"

def test_tagset_decoder_and_unreadable_absence_authority():
    with pytest.raises(Unavailable):s3.section({"Tags":{**deepcopy(s3.ABSENT),"TagSet":[]}},"Tags")
    for field in ("collection_status","absent"):
        item=deepcopy(s3.B);item["Website"]={**deepcopy(s3.ABSENT),"_coverage":{field:{"status":"denied"}}}
        assert verdict(PREFIX+"static_website_disabled",item)["status"]=="UNKNOWN"
