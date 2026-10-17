"""Public snapshot checks for document-level IAM administrator precedence."""
from copy import deepcopy
from urllib.parse import quote
import json

import pytest

from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "aws.iam.no_full_admin"
SCOPE = "123456789012/global"
BAD = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
SAFE = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}


def assessed(item):
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "iam_policy", "scope": SCOPE,
                                               "status": "collected", "items": [item]}])
    before = deepcopy(snapshot)
    imported = collect_snapshot({"connector": {"provider": "aws", "scopes": [SCOPE],
                                                 "options": {"snapshot": snapshot}}, "checks": [CID]})
    findings = [row for row in evaluate_snapshot(imported, checks=[CID])["findings"]
                if row["check_id"] == CID]
    assert len(findings) == 1 and snapshot == before and imported == before
    return findings[0]["status"]


@pytest.mark.parametrize("document", [BAD, SAFE])
def test_unreadable_peer_inline_inventory_preserves_known_result_only(document):
    item = {"PolicyDocument": deepcopy(document),
            "_coverage": {"RolePolicyList": {"status": "denied"}}}
    assert assessed(item) == ("FAIL" if document == BAD else "UNKNOWN")


@pytest.mark.parametrize("document", [BAD, SAFE])
def test_unreadable_peer_default_selector_preserves_known_result_only(document):
    item = {"PolicyVersionList": [
        {"IsDefaultVersion": True, "Document": deepcopy(document)},
        {"IsDefaultVersion": False, "_coverage": {"IsDefaultVersion": {"status": "denied"}}},
    ]}
    assert assessed(item) == ("FAIL" if document == BAD else "UNKNOWN")


@pytest.mark.parametrize("document", [BAD, SAFE])
def test_unreadable_peer_statement_preserves_known_result_only(document):
    peer = {"Statement": [], "_coverage": {"Statement": {"status": "denied"}}}
    item = {"PolicyDocument": deepcopy(document),
            "RolePolicyList": [{"PolicyDocument": peer}]}
    assert assessed(item) == ("FAIL" if document == BAD else "UNKNOWN")


def test_unreadable_direct_document_does_not_hide_known_default_version():
    item = {"PolicyDocument": deepcopy(SAFE),
            "_coverage": {"PolicyDocument": {"status": "denied"}},
            "PolicyVersionList": [{"IsDefaultVersion": True, "Document": deepcopy(BAD)}]}
    assert assessed(item) == "FAIL"


@pytest.mark.parametrize("encode", [json.dumps, lambda document: quote(json.dumps(document))])
def test_encoded_known_document_survives_unreadable_peer(encode):
    item = {"PolicyDocument": encode(BAD),
            "_coverage": {"GroupPolicyList": {"status": "denied"}}}
    assert assessed(item) == "FAIL"


def test_conditional_only_document_remains_manual():
    item = {"PolicyDocument": deepcopy(BAD)}
    item["PolicyDocument"]["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
    assert assessed(item) == "MANUAL"


def test_unreadable_peer_prevents_conditional_only_manual():
    item = {"PolicyDocument": deepcopy(BAD),
            "_coverage": {"RolePolicyList": {"status": "denied"}}}
    item["PolicyDocument"]["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
    assert assessed(item) == "UNKNOWN"
