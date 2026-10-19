"""Mapping audit detects missing, foreign and overstated checklist membership."""
from copy import deepcopy

import pytest

from scripts.audit_aws_framework_mappings import HACKTRICKS, audit


@pytest.fixture
def documents():
    tag = {"framework_id": "cis.aws", "requirement_id": "1.2", "decision": "PARTIAL", "runtime_status": "partial"}
    native = {"checks": [{"id": "aws.iam.root_mfa", "provider": "aws", "type": "account", "title": "Root MFA",
                         "frameworks": [HACKTRICKS, "CIS AWS"], "framework_ids": ["cis.aws"],
                         "requirement_controls": [deepcopy(tag)],
                         "mapping": {HACKTRICKS: {"reference": "https://cloud.hacktricks.wiki/"},
                                     "CIS AWS": {"controls": [{"framework_id": "cis.aws", "control_id": "1.2", "decision": "PARTIAL", "runtime_status": "partial"}]}}}]}
    requirements = {"frameworks": [{"id": "cis.aws", "provider": "aws", "requirements": [
        {"requirement_id": "1.2", "native_checks": ["aws.iam.root_mfa"], "decision": "PARTIAL", "runtime_status": "partial"}]}],
        "by_check": {"aws.iam.root_mfa": [tag]}}
    return native, requirements, {"checks": []}


def test_preserves_partial_assurance_and_visits_every_check(documents):
    result = audit(*documents)
    assert not result["issues"]
    assert result["summary"]["checks"] == result["summary"]["mapping_pass"] == 1
    assert result["checks"][0]["requirement_statuses"] == {"partial": 1}


def test_excluded_observability_check_preserves_other_requirements(documents):
    import json
    native, requirements, source = json.loads(json.dumps(documents).replace("aws.iam.root_mfa", "aws.a.cloudwatch.alarm_actions_enabled"))
    check = native["checks"][0]
    check["frameworks"].remove(HACKTRICKS)
    check["mapping"].pop(HACKTRICKS)
    result = audit(native, requirements, source)
    assert result["issues"] == [] and result["summary"]["hacktricks_mapped"] == 0
    check["frameworks"].append(HACKTRICKS)
    assert any(row["issue"] == "unexpected_hacktricks_security_mapping" for row in audit(native, requirements, source)["issues"])


@pytest.mark.parametrize("mutation,issue", [
    ("hacktricks", "missing_hacktricks_security_mapping"),
    ("foreign", "foreign_or_missing_framework"),
    ("assurance", "requirement_assurance_mismatch"),
    ("forward", "missing_forward_requirement"),
    ("reverse", "missing_reverse_requirement"),
    ("public", "requirement_absent_from_public_mapping"),
])
def test_detects_broken_membership(documents, mutation, issue):
    native, requirements, _ = documents
    check = native["checks"][0]
    if mutation == "hacktricks":
        check["frameworks"] = []
    elif mutation == "foreign":
        requirements["frameworks"][0]["provider"] = "azure"
    elif mutation == "assurance":
        requirements["frameworks"][0]["requirements"][0]["runtime_status"] = "automated"
    elif mutation == "forward":
        requirements["frameworks"][0]["requirements"][0]["native_checks"] = []
    elif mutation == "reverse":
        requirements["by_check"] = {}
    else:
        check["mapping"]["CIS AWS"]["controls"] = []
    assert any(issue in row["issue"] for row in audit(*documents)["issues"])


def test_does_not_invent_compliance_membership_for_hacktricks_only_check(documents):
    native, requirements, _ = documents
    check = native["checks"][0]
    check["framework_ids"] = []
    check["requirement_controls"] = []
    check["mapping"].pop("CIS AWS")
    requirements["by_check"] = {}
    requirements["frameworks"] = []
    report = audit(*documents)
    assert not report["issues"]
    assert report["summary"]["hacktricks_only"] == 1


def test_public_mapping_cannot_advertise_unreviewed_numbered_control(documents):
    documents[0]['checks'][0]['mapping']['CIS AWS']['controls'].append(
        {'framework_id': 'cis.aws', 'control_id': '9.9'})
    assert any(r['issue'] == 'unreviewed_public_requirement_mapping' for r in audit(*documents)['issues'])


def test_public_partial_mapping_cannot_claim_full_automation(documents):
    documents[0]['checks'][0]['mapping']['CIS AWS']['controls'][0]['runtime_status'] = 'automated'
    assert any(r['issue'] == 'public_requirement_assurance_mismatch' for r in audit(*documents)['issues'])


@pytest.mark.parametrize('reference', ['https://example.com/', 'https://cloud.hacktricks.wiki.evil.test/',
                                       'https://github.com/other/repo/', 'http://cloud.hacktricks.wiki/'])
def test_hacktricks_mapping_requires_real_source_host(documents, reference):
    documents[0]['checks'][0]['mapping'][HACKTRICKS]['reference'] = reference
    assert any(r['issue'] == 'missing_hacktricks_security_mapping' for r in audit(*documents)['issues'])
