"""S3 declaration predicates retain uncertainty of selected native fields."""
from copy import deepcopy
import pytest
from peaso.checks import claude_aws_a_s3 as s3
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot

LIFECYCLE="aws.claude_a.s3.lifecycle_rule_enabled"
VERSIONED="aws.claude_a.s3.versioning_and_lifecycle"
NOTIFICATIONS="aws.claude_a.s3.event_notifications"

def verdict(cid,item):
    scope=s3.ACCOUNT+"/us-east-1"
    snap=make_snapshot("aws",[scope],[{"type":"bucket","scope":scope,"status":"collected","items":[item]}],created_at="2026-10-17T00:00:00Z")
    before=deepcopy(snap)
    rows=[f for f in evaluate_snapshot(snap,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snap==before and len(rows)==1
    return rows[0]["status"]

@pytest.mark.parametrize("cid",[LIFECYCLE,VERSIONED])
@pytest.mark.parametrize("status",["denied","malformed"])
def test_unavailable_enabled_status_cannot_prove_lifecycle(cid,status):
    item=deepcopy(s3.B);item["Lifecycle"]["Rules"][0]["_coverage"]={"Status":{"status":status}}
    assert verdict(cid,item)=="UNKNOWN"

@pytest.mark.parametrize("cid",[LIFECYCLE,VERSIONED])
@pytest.mark.parametrize("status",[None,"nonsense",1])
def test_invalid_status_cannot_prove_absence(cid,status):
    item=deepcopy(s3.B);item["Lifecycle"]["Rules"][0]["Status"]=status
    assert verdict(cid,item)=="UNKNOWN"

@pytest.mark.parametrize("cid",[LIFECYCLE,VERSIONED])
def test_independent_enabled_rule_is_sufficient(cid):
    item=deepcopy(s3.B);item["Lifecycle"]["Rules"]=[{"Status":"Enabled","_coverage":{"Status":{"status":"denied"}}},{"Status":"Enabled"}]
    assert verdict(cid,item)=="PASS"

@pytest.mark.parametrize("status",["Enabled","Suspended",None])
def test_unavailable_versioning_cannot_prove_applicability(status):
    item=deepcopy(s3.B);item["Versioning"]["Status"]=status
    item["Versioning"]["_coverage"]={"Status":{"status":"denied"}}
    assert verdict(VERSIONED,item)=="UNKNOWN"

@pytest.mark.parametrize("key",["EventBridgeConfiguration","TopicConfigurations","QueueConfigurations","LambdaFunctionConfigurations"])
def test_unavailable_notification_selector_cannot_prove_configuration(key):
    item=deepcopy(s3.B);item["Notifications"]={key:{} if key=="EventBridgeConfiguration" else [{"Id":"existing"}],"_coverage":{key:{"status":"denied"}}}
    assert verdict(NOTIFICATIONS,item)=="UNKNOWN"

@pytest.mark.parametrize("key",["TopicConfigurations","QueueConfigurations","LambdaFunctionConfigurations"])
def test_unavailable_omitted_notification_selector_cannot_prove_absence(key):
    item=deepcopy(s3.B);item["Notifications"]={"_coverage":{key:{"status":"denied"}}}
    assert verdict(NOTIFICATIONS,item)=="UNKNOWN"

def test_independent_notification_selector_is_sufficient():
    item=deepcopy(s3.B);item["Notifications"]={"EventBridgeConfiguration":{},"_coverage":{"TopicConfigurations":{"status":"denied"}}}
    assert verdict(NOTIFICATIONS,item)=="PASS"

def test_native_omissions_remain_valid():
    item=deepcopy(s3.B);item["Notifications"]={}
    assert verdict(NOTIFICATIONS,item)=="FAIL"
    item["Versioning"]={}
    assert verdict(VERSIONED,item)=="NOT_APPLICABLE"

@pytest.mark.parametrize("key",["EventBridgeConfiguration","TopicConfigurations","QueueConfigurations","LambdaFunctionConfigurations"])
def test_explicit_null_selectors_are_unavailable(key):
    item=deepcopy(s3.B);item["Notifications"]={key:None}
    assert verdict(NOTIFICATIONS,item)=="UNKNOWN"

def test_explicit_null_versioning_status_is_unavailable():
    item=deepcopy(s3.B);item["Versioning"]={"Status":None}
    assert verdict(VERSIONED,item)=="UNKNOWN"

def test_explicit_null_source_collection_status_is_unavailable():
    item=deepcopy(s3.B);item["Lifecycle"]["collection_status"]=None
    assert verdict(LIFECYCLE,item)=="UNKNOWN"
