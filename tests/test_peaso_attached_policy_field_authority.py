"""Declared-policy checks require available selected policy fields."""
from copy import deepcopy
from urllib.parse import quote
import json
import pytest
from peaso.checks.aws_a_iam_policies import BAD
from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

CID="aws.a.iam.attached_policy_no_star_star"
SCOPE="123456789012/global"


def assessed(item):
    snap=make_snapshot("aws",[SCOPE],[{"type":"iam_policy","scope":SCOPE,"status":"collected","items":[item]}])
    before=deepcopy(snap)
    captured=collect_snapshot({"connector":{"provider":"aws","scopes":[SCOPE],"options":{"snapshot":snap}},"checks":[CID]})
    rows=[f for f in evaluate_snapshot(captured,checks=[CID])["findings"] if f["check_id"]==CID]
    assert len(rows)==1 and captured==before and snap==before
    return rows[0]["status"]


@pytest.mark.parametrize("field",["Statement","Action","Resource"])
def test_unreadable_selected_policy_field_is_not_a_declared_grant(field):
    item=deepcopy(BAD)
    document=item["PolicyVersionList"][0]["Document"]
    target=document if field=="Statement" else document["Statement"][0]
    target["_coverage"]={field:{"status":"denied"}}
    assert assessed(item)=="UNKNOWN"


@pytest.mark.parametrize("encode",[json.dumps,lambda doc:quote(json.dumps(doc))])
def test_encoded_document_preserves_statement_authority(encode):
    item=deepcopy(BAD)
    item["PolicyVersionList"][0]["Document"]["_coverage"]={"Statement":{"status":"denied"}}
    item["PolicyVersionList"][0]["Document"]=encode(item["PolicyVersionList"][0]["Document"])
    assert assessed(item)=="UNKNOWN"


@pytest.mark.parametrize("first",[False,True])
def test_known_wildcard_violation_survives_unreadable_peer(first):
    item=deepcopy(BAD)
    bad=item["PolicyVersionList"][0]["Document"]["Statement"][0]
    unavailable={"Effect":"Allow","Action":"s3:GetObject","Resource":"*","_coverage":{"Action":{"status":"denied"}}}
    item["PolicyVersionList"][0]["Document"]["Statement"]=[bad,unavailable] if first else [unavailable,bad]
    assert assessed(item)=="FAIL"


def test_irrelevant_deny_does_not_require_its_action_resource():
    item=deepcopy(BAD)
    row=item["PolicyVersionList"][0]["Document"]["Statement"][0]
    row["Effect"]="Deny";row["_coverage"]={"Action":{"status":"denied"},"Resource":{"status":"denied"}}
    assert assessed(item)=="PASS"


def test_declared_notaction_remains_outside_literal_source_check():
    item=deepcopy(BAD)
    row=item["PolicyVersionList"][0]["Document"]["Statement"][0]
    row.pop("Action");row["NotAction"]="iam:GetRole"
    assert assessed(item)=="PASS"
