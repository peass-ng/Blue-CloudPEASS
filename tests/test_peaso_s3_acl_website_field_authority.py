"""Selected native ACL/ownership/website fields, through inert registered snapshots."""
from copy import deepcopy
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks.claude_aws_a_s3 import B, ABSENT, OWNER_GRANT, OWNER, ALL_USERS, AUTH_USERS, ACCT_OPEN
ACL="aws.claude_a.s3.acls_prohibit_user_access"
AUTH="aws.claude_a.s3.no_authenticated_users_acl"
LIST="aws.claude_a.s3.prowler_public_list_acl"
PUBLIC="aws.claude_a.s3.prowler_public_access"
WRITE="aws.claude_a.s3.prowler_public_write_acl"
WEB="aws.claude_a.s3.static_website_disabled"
SCOPE="123456789012/us-east-1"

def deny(row,key):row.setdefault("_coverage",{})[key]={"status":"denied"}
def grant(uri=AUTH_USERS,permission="READ"):
    return {"Grantee":{"Type":"Group","URI":uri},"Permission":permission}
def bucket(*rows):
    item=deepcopy(B);item["OwnershipControls"]=deepcopy(ABSENT);item["PublicAccessBlock"]=deepcopy(ABSENT)
    item["Acl"]["Grants"]=[deepcopy(OWNER_GRANT),*deepcopy(rows)]
    return item

def verdict(cid,item,account=None):
    snap=make_snapshot("aws",[SCOPE],[{"type":"bucket","scope":SCOPE,"status":"collected","items":[deepcopy(item)]},{"type":"s3_account_public_access_block","scope":SCOPE,"status":"collected","items":[deepcopy(ACCT_OPEN if account is None else account)]}],created_at="2026-10-17T00:00:00Z")
    before=deepcopy(snap);rows=[f for f in evaluate_snapshot(snap,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snap==before and len(rows)==1
    return rows[0]["status"]

def test_denied_ownership_cannot_disable_observed_acl():
    item=bucket({"Grantee":{"ID":"b"*64,"Type":"CanonicalUser"},"Permission":"READ"})
    item["OwnershipControls"]=deepcopy(B["OwnershipControls"])
    deny(item["OwnershipControls"]["OwnershipControls"]["Rules"][0],"ObjectOwnership")
    assert verdict(ACL,item)=="UNKNOWN"

def test_denied_grantee_id_cannot_prove_safe_or_other_user():
    for identity in (OWNER,"b"*64):
        row={"Grantee":{"Type":"CanonicalUser","ID":identity},"Permission":"READ"};deny(row["Grantee"],"ID")
        assert verdict(ACL,bucket(row))=="UNKNOWN"

def test_denied_group_uri_cannot_prove_public_or_private():
    for uri in (AUTH_USERS,"private"):
        row=grant(uri);deny(row["Grantee"],"URI")
        assert verdict(AUTH,bucket(row))=="UNKNOWN"

def test_selected_group_type_and_permission_must_be_available():
    for field,container in (("Type","Grantee"),("Permission",None)):
        row=grant();deny(row[container] if container else row,field)
        assert verdict(LIST,bucket(row))=="UNKNOWN"

def test_website_suffix_authority_and_shape():
    for value in ("index.html",None,23,""):
        item=deepcopy(B);item["Website"]={"collection_status":"collected","IndexDocument":{"Suffix":value}}
        if value=="index.html":deny(item["Website"]["IndexDocument"],"Suffix")
        assert verdict(WEB,item)=="UNKNOWN"

def test_independent_acl_violations_survive_unknown_peers():
    unknown=grant();deny(unknown["Grantee"],"URI")
    for rows in ((unknown,grant()),(grant(),unknown)):
        assert verdict(AUTH,bucket(*rows))=="FAIL"
        assert verdict(LIST,bucket(*rows))=="FAIL"
    unknown_id={"Grantee":{"Type":"CanonicalUser","ID":OWNER},"Permission":"READ"};deny(unknown_id["Grantee"],"ID")
    other={"Grantee":{"Type":"CanonicalUser","ID":"b"*64},"Permission":"READ"}
    assert verdict(ACL,bucket(unknown_id,other))=="FAIL"

def test_known_enforced_ownership_is_sufficient_and_owner_only_safe():
    item=deepcopy(B);item["OwnershipControls"]["OwnershipControls"]["Rules"].append({"collection_status":"denied"})
    deny(item,"Acl")
    assert verdict(ACL,item)=="PASS"
    assert verdict(ACL,bucket())=="PASS"

def test_unused_permission_and_other_grantee_fields_do_not_poison_proof():
    row=grant("private");deny(row,"Permission")
    assert verdict(LIST,bucket(row))=="PASS"
    row=grant();deny(row,"Permission");deny(row["Grantee"],"ID")
    assert verdict(AUTH,bucket(row))=="FAIL"
    assert verdict(PUBLIC,bucket(row))=="FAIL"
    row=grant(permission="WRITE");deny(row["Grantee"],"URI")
    assert verdict(LIST,bucket(row))=="PASS"
    row=deepcopy(OWNER_GRANT);deny(row["Grantee"],"URI")
    assert verdict(LIST,bucket(row))=="PASS"

def test_omitted_optional_grantee_fields_and_website_configuration():
    row=grant();row.pop("Permission")
    assert verdict(LIST,bucket(row))=="PASS"
    assert verdict(AUTH,bucket(row))=="FAIL"
    assert verdict(PUBLIC,bucket(row))=="FAIL"
    assert verdict(AUTH,bucket())=="PASS"
    assert verdict(LIST,bucket())=="PASS"
    assert verdict(ACL,bucket(grant()))=="PASS"
    assert verdict(WEB,deepcopy(B))=="PASS"
    item=deepcopy(B);item["Website"]={"collection_status":"collected","RedirectAllRequestsTo":{"HostName":"example.com"}}
    assert verdict(WEB,item)=="PASS"
    item["Website"]={"collection_status":"collected","IndexDocument":{"Suffix":"index.html"}}
    assert verdict(WEB,item)=="FAIL"

def test_malformed_selected_native_fields_are_unknown():
    for key,value in (("Type",1),("Type","G"),("URI",23)):
        row=grant();row["Grantee"][key]=value
        assert verdict(LIST,bucket(row))=="UNKNOWN"
    for value in (None,23,"future"):
        row=grant();row["Permission"]=value
        assert verdict(LIST,bucket(row))=="UNKNOWN"
    item=deepcopy(B);item["Website"]={"IndexDocument":{}}
    assert verdict(WEB,item)=="UNKNOWN"

def test_write_permission_predicate_and_omitted_denied_uri():
    row=grant(ALL_USERS,"WRITE");deny(row,"Permission")
    assert verdict(WRITE,bucket(row))=="UNKNOWN"
    row={"Grantee":{"Type":"Group"},"Permission":"READ"};deny(row["Grantee"],"URI")
    assert verdict(LIST,bucket(row))=="UNKNOWN"

READ="aws.claude_a.s3.restrict_public_read"

def test_public_read_acl_reduction_preserves_independent_known_violation():
    bad=grant(ALL_USERS,"READ");unavailable=grant("private");deny(unavailable["Grantee"],"URI")
    for peer in (unavailable,None):
        for rows in ((peer,bad),(bad,peer)):
            assert verdict(READ,bucket(*rows))=="FAIL"
    item=bucket(bad);deny(item,"Policy")
    assert verdict(READ,item)=="FAIL"

def test_public_read_selected_authority_and_independent_policy():
    row=grant("private");deny(row,"Permission")
    assert verdict(READ,bucket(row))=="PASS"
    for selected in ("URI","Permission"):
        row=grant(ALL_USERS,"READ");deny(row["Grantee"] if selected=="URI" else row,selected)
        assert verdict(READ,bucket(row))=="UNKNOWN"
        item=bucket(row)
        item["Policy"]={"collection_status":"collected","Policy":{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b1/*"}]}}
        assert verdict(READ,item)=="FAIL"
    row=grant(ALL_USERS,"WRITE");deny(row["Grantee"],"URI")
    assert verdict(READ,bucket(row))=="PASS"
    row=grant(ALL_USERS);row.pop("Permission");deny(row["Grantee"],"URI")
    assert verdict(READ,bucket(row))=="PASS"


def test_prowler_public_acl_and_policy_are_independent_alternatives():
    from peaso.checks.claude_aws_a_s3 import PUBLIC_POLICY
    unknown=grant("private");deny(unknown["Grantee"],"URI")
    item=bucket(unknown);item["Policy"]=deepcopy(PUBLIC_POLICY)
    assert verdict(PUBLIC,item)=="FAIL"
    item=bucket(grant(ALL_USERS));deny(item,"Policy")
    assert verdict(PUBLIC,item)=="FAIL"
    item=bucket(unknown)
    assert verdict(PUBLIC,item)=="UNKNOWN"


def test_independently_known_account_block_survives_unavailable_finder():
    from peaso.checks.claude_aws_a_s3 import BLOCKS
    row=grant(permission="FULL_CONTROL");deny(row["Grantee"],"URI")
    safe={"PublicAccessBlockConfiguration":{key:True for key in BLOCKS}}
    for cid in (PUBLIC,LIST,WRITE):
        assert verdict(cid,bucket(row),account=safe)=="PASS"
        assert verdict(cid,bucket(row))=="UNKNOWN"
        denied_account=deepcopy(safe);deny(denied_account["PublicAccessBlockConfiguration"],"IgnorePublicAcls")
        assert verdict(cid,bucket(row),account=denied_account)=="UNKNOWN"
