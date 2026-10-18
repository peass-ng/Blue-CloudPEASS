"""Scoped AWS grants require an exact reviewed permission differential."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import ACCOUNT, ALICE, allow, aws_snap, reached, user


ENTRIES = {entry["id"]: entry for entry in yaml.safe_load(
    (Path(__file__).parents[1] / "peaso/privesc/catalog/aws/scoped_grants.yaml").read_text())}
REGION = "us-east-1"
CONFIG = {
    "aws-secretsmanager-putresourcepolicy-self-grant": (
        "aws_secretsmanager_policy_self_grant_evidence", "secretsmanager:PutResourcePolicy",
        f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:reviewed-ABC", "secretsmanager:GetSecretValue",
        {"PolicyPrincipalArn": ALICE, "PolicyResourceArn": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:reviewed-ABC",
         "PolicyAccepted": True, "KmsDecryptAfterAllowed": True}),
    "aws-efs-putfilesystempolicy-self-grant": (
        "aws_efs_policy_self_grant_evidence", "elasticfilesystem:PutFileSystemPolicy",
        f"arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:file-system/fs-01234567", "elasticfilesystem:ClientMount",
        {"PolicyPrincipalArn": ALICE, "PolicyResourceArn": f"arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:file-system/fs-01234567",
         "PolicyAccepted": True}),
    "aws-cases-tagresource-domain-event-self-grant": (
        "aws_cases_tag_self_grant_evidence", "cases:TagResource",
        f"arn:aws:cases:{REGION}:{ACCOUNT}:domain/domain1", "cases:PutCaseEventConfiguration",
        {"TagKey": "Access", "TagValue": "Operator", "IAMConditionKey": "aws:ResourceTag/Access",
         "IAMConditionValue": "Operator", "TagWriteAccepted": True, "AllEvaluatedResourcesCovered": True}),
    "aws-sitewise-createaccesspolicy-portal-self-grant": (
        "aws_sitewise_portal_self_grant_evidence", "iotsitewise:CreateAccessPolicy",
        f"arn:aws:iotsitewise:{REGION}:{ACCOUNT}:portal/portal1", "iotsitewise:MonitorPortalAdministrator",
        {"TargetIdentityArn": ALICE, "AccessPolicyIdentityArn": ALICE,
         "AccessPolicyResourceArn": f"arn:aws:iotsitewise:{REGION}:{ACCOUNT}:portal/portal1",
         "AccessPolicyPermission": "ADMINISTRATOR", "AccessPolicyAccepted": True, "MonitorAvailable": True}),
}


def proof(technique):
    _, _, resource, gained, fields = CONFIG[technique]
    return {"TechniqueId": technique, "Status": "verified", "SourceArn": ALICE,
            "ResourceArn": resource, "SourceAccount": ACCOUNT, "GrantedPermission": gained,
            "PriorAccessDenied": True, "EffectiveAccessAfterAllowed": True,
            "GuardrailsReviewed": True, "EvidenceRef": f"reviewed-{technique}", **fields}


def case(technique, records=None, *, writer=True, status="collected"):
    collection, action, resource, _, _ = CONFIG[technique]
    alice = user("alice", allow(action if writer else "iam:GetUser", resource))
    snap = aws_snap([alice])
    snap["collections"].append({"type": collection, "scope": f"{ACCOUNT}/{REGION}",
                                "service": action.split(":")[0], "status": status,
                                "items": [proof(technique)] if records is None else records, "error": None})
    return snap


@pytest.mark.parametrize("technique", CONFIG)
def test_reviewed_scoped_grant_yields_only_its_bounded_target(technique):
    entry = ENTRIES[technique]
    assert validate_entry(entry)[0] == []
    snap = case(technique)
    before = copy.deepcopy(snap)
    result = privesc.analyze(snap, entries=[entry])
    reached_targets = reached(result, ALICE, technique)
    assert len(reached_targets) == 1
    assert set(reached_targets.values()) == {"conditional"}
    assert next(iter(reached_targets)).startswith("aws_verified_authority:")
    assert result["graph"]["edges"][0]["technique_details"][0]["grants"] == entry["target"]["grants"]
    assert snap == before


@pytest.mark.parametrize("technique", CONFIG)
def test_missing_duplicate_partial_or_nonwriter_has_no_path(technique):
    entry = ENTRIES[technique]
    cases = (case(technique, []), case(technique, [proof(technique), proof(technique)]),
             case(technique, status="partial"), case(technique, status="empty"),
             case(technique, status="access_denied"),
             case(technique, writer=False))
    for snap in cases:
        assert reached(privesc.analyze(snap, entries=[entry]), ALICE, technique) == {}


@pytest.mark.parametrize("technique", CONFIG)
def test_every_review_field_is_required(technique):
    entry = ENTRIES[technique]
    for field in proof(technique):
        record = proof(technique)
        record.pop(field)
        assert reached(privesc.analyze(case(technique, [record]), entries=[entry]), ALICE, technique) == {}, field


@pytest.mark.parametrize("technique", CONFIG)
def test_wrong_resource_or_technique_cannot_satisfy_the_source_action(technique):
    entry = ENTRIES[technique]
    for field, value in (("ResourceArn", CONFIG[technique][2] + "-other"),
                         ("TechniqueId", "aws-another-technique")):
        record = proof(technique)
        record[field] = value
        assert reached(privesc.analyze(case(technique, [record]), entries=[entry]), ALICE, technique) == {}


@pytest.mark.parametrize("technique", CONFIG)
@pytest.mark.parametrize("field,value", [
    ("SourceArn", f"arn:aws:iam::{ACCOUNT}:user/bob"),
    ("SourceAccount", "222222222222"),
    ("GrantedPermission", "iam:CreateUser"),
    ("PriorAccessDenied", False),
    ("EffectiveAccessAfterAllowed", False),
    ("GuardrailsReviewed", False),
    ("Status", "unreviewed"),
    ("EvidenceRef", ""),
])
def test_mismatched_or_unreviewed_grant_has_no_path(technique, field, value):
    record = proof(technique)
    record[field] = value
    assert reached(privesc.analyze(case(technique, [record]), entries=[ENTRIES[technique]]), ALICE, technique) == {}


@pytest.mark.parametrize("technique,field,value", [
    ("aws-secretsmanager-putresourcepolicy-self-grant", "PolicyPrincipalArn", f"arn:aws:iam::{ACCOUNT}:user/bob"),
    ("aws-secretsmanager-putresourcepolicy-self-grant", "PolicyResourceArn", f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:other-XYZ"),
    ("aws-secretsmanager-putresourcepolicy-self-grant", "KmsDecryptAfterAllowed", False),
    ("aws-secretsmanager-putresourcepolicy-self-grant", "PolicyAccepted", False),
    ("aws-efs-putfilesystempolicy-self-grant", "PolicyResourceArn", f"arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:file-system/fs-other"),
    ("aws-efs-putfilesystempolicy-self-grant", "PolicyAccepted", False),
    ("aws-cases-tagresource-domain-event-self-grant", "TagValue", "Viewer"),
    ("aws-cases-tagresource-domain-event-self-grant", "TagWriteAccepted", False),
    ("aws-cases-tagresource-domain-event-self-grant", "AllEvaluatedResourcesCovered", False),
    ("aws-sitewise-createaccesspolicy-portal-self-grant", "TargetIdentityArn", f"arn:aws:iam::{ACCOUNT}:user/bob"),
    ("aws-sitewise-createaccesspolicy-portal-self-grant", "AccessPolicyResourceArn", f"arn:aws:iotsitewise:{REGION}:{ACCOUNT}:portal/other"),
    ("aws-sitewise-createaccesspolicy-portal-self-grant", "MonitorAvailable", False),
    ("aws-sitewise-createaccesspolicy-portal-self-grant", "AccessPolicyPermission", "VIEWER"),
])
def test_service_specific_subject_or_effect_mismatch_has_no_path(technique, field, value):
    record = proof(technique)
    record[field] = value
    assert reached(privesc.analyze(case(technique, [record]), entries=[ENTRIES[technique]]), ALICE, technique) == {}


def test_reviewed_authority_selector_must_be_exclusive():
    entry = copy.deepcopy(ENTRIES["aws-efs-putfilesystempolicy-self-grant"])
    entry["target"]["selector"]["aws_cases_tag_self_grant"] = True
    assert any("exactly one reviewed authority selector" in error for error in validate_entry(entry)[0])
