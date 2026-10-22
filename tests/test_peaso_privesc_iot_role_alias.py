"""The two self-contained IoT certificate routes need their own permission proof."""
from __future__ import annotations

import pytest
import json
from pathlib import Path
import runpy

from peaso import privesc
from peaso.privesc import versioned_catalog as catalog
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-iot-passrole-rolealias-certificate"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
COMMON = ["iam:PassRole", "iot:CreateRoleAlias", "iot:CreatePolicy", "iot:AttachPolicy"]
CERTIFICATE_ACTIONS = ["iot:CreateKeysAndCertificate", "iot:RegisterCertificateWithoutCA"]
EXISTING_ID = "aws-iot-update-existing-alias-new-certificate"
EXISTING_ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == EXISTING_ID)
ALIAS_ARN = "arn:aws:iot:us-east-1:111111111111:rolealias/known"


def _case(actions, *, passed_to="iot.amazonaws.com", trust="credentials.iot.amazonaws.com"):
    snapshot = _snapshot(ENTRY)
    user = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": actions, "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": TARGET,
         "Condition": {"StringEquals": {"iam:PassedToService": passed_to}}},
    ]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]["Action"] = [
        action for action in actions if action != "iam:PassRole"
    ]
    role = next(c for c in snapshot["collections"] if c["type"] == "iam_role")["items"][0]
    role["AssumeRolePolicyDocument"] = {
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust},
                       "Action": "sts:AssumeRole"}]}
    return snapshot


@pytest.mark.parametrize("certificate_action", CERTIFICATE_ACTIONS)
def test_fresh_alias_and_either_fresh_certificate_route(certificate_action):
    snapshot = _case(COMMON + [certificate_action])
    assert reached(privesc.analyze(snapshot, entries=[ENTRY]), SOURCE, ID) == {TARGET: "conditional"}


@pytest.mark.parametrize("omitted", COMMON[1:] + CERTIFICATE_ACTIONS)
def test_each_setup_permission_is_required(omitted):
    actions = COMMON + CERTIFICATE_ACTIONS
    if omitted in CERTIFICATE_ACTIONS:
        actions = COMMON + [omitted]
    actions = [action for action in actions if action != omitted]
    snapshot = _case(actions)
    assert not reached(privesc.analyze(snapshot, entries=[ENTRY]), SOURCE, ID)


def test_wrong_passrole_service_or_role_trust_does_not_reach_target():
    for kwargs in ({"passed_to": "ec2.amazonaws.com"}, {"trust": "iot.amazonaws.com"}):
        snapshot = _case(COMMON + [CERTIFICATE_ACTIONS[0]], **kwargs)
        assert not reached(privesc.analyze(snapshot, entries=[ENTRY]), SOURCE, ID)


def test_alias_policy_and_certificate_permissions_need_one_region():
    for policy_region, expected in (("us-east-1", {TARGET: "conditional"}),
                                    ("eu-west-1", {})):
        snapshot = _case(COMMON + [CERTIFICATE_ACTIONS[0]])
        statements = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0][
            "UserPolicyList"][0]["PolicyDocument"]["Statement"]
        statements[0:1] = [
            {"Effect": "Allow", "Action": "iot:CreateRoleAlias",
             "Resource": "arn:aws:iot:us-east-1:111111111111:rolealias/audit-*"},
            {"Effect": "Allow", "Action": "iot:CreatePolicy",
             "Resource": f"arn:aws:iot:{policy_region}:111111111111:policy/audit-*"},
            {"Effect": "Allow", "Action": "iot:AttachPolicy",
             "Resource": "arn:aws:iot:us-east-1:111111111111:cert/*"},
            {"Effect": "Allow", "Action": CERTIFICATE_ACTIONS[0], "Resource": "*"},
        ]
        assert reached(privesc.analyze(snapshot, entries=[ENTRY]), SOURCE, ID) == expected


def test_one_existing_certificate_grant_cannot_authorize_new_random_certificate():
    snapshot = _case(COMMON + [CERTIFICATE_ACTIONS[0]])
    statement = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0][
        "UserPolicyList"][0]["PolicyDocument"]["Statement"][0]
    statement["Action"] = ["iot:CreateRoleAlias", "iot:CreatePolicy", CERTIFICATE_ACTIONS[0]]
    snapshot_user = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    snapshot_user["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
        {"Effect": "Allow", "Action": "iot:AttachPolicy",
         "Resource": "arn:aws:iot:us-east-1:111111111111:cert/existing"})
    assert not reached(privesc.analyze(snapshot, entries=[ENTRY]), SOURCE, ID)


def test_previous_iot_binding_preserves_exact_old_route():
    binding = {"schema": catalog.BINDING_SCHEMA,
               "manifest_sha256": catalog.IOT_V1_CURRENT_MANIFEST,
               "effective_tree_sha256": catalog.IOT_V1_CURRENT_TREE,
               "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ID], binding)
    assert status == "exact_previous_current"
    assert set(previous) == {ID}
    assert len(catalog._verified_iot_v1_current()) == 667
    assert "any_of" not in previous[ID]["requires"]
    current, current_status = catalog.lookup_entries([ID], catalog.current_binding())
    assert current_status == "exact_strict_privesc"
    assert "any_of" in current[ID]["requires"]


def test_pre_region_iot_binding_preserves_earlier_certificate_alternatives():
    binding = {"schema": catalog.BINDING_SCHEMA,
               "manifest_sha256": catalog.IOT_V2_CURRENT_MANIFEST,
               "effective_tree_sha256": catalog.IOT_V2_CURRENT_TREE,
               "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ID], binding)
    assert status == "exact_previous_current"
    assert set(previous) == {ID}
    assert len(catalog._verified_iot_v2_current()) == 667
    assert "any_of" in previous[ID]["requires"]
    assert "preconditions" not in previous[ID]


def _existing_alias_case(*, alias_status="collected", alias_arn=ALIAS_ARN,
                         update_resource=ALIAS_ARN, policy_region="us-east-1",
                         certificate_action="iot:CreateKeysAndCertificate"):
    snapshot = _case(["iot:UpdateRoleAlias", "iot:CreatePolicy", "iot:AttachPolicy", certificate_action])
    user = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    statements = user["UserPolicyList"][0]["PolicyDocument"]["Statement"]
    statements[0:1] = [
        {"Effect": "Allow", "Action": "iot:UpdateRoleAlias", "Resource": update_resource},
        {"Effect": "Allow", "Action": "iot:CreatePolicy",
         "Resource": f"arn:aws:iot:{policy_region}:111111111111:policy/*"},
        {"Effect": "Allow", "Action": "iot:AttachPolicy",
         "Resource": "arn:aws:iot:us-east-1:111111111111:cert/*"},
        {"Effect": "Allow", "Action": certificate_action, "Resource": "*"},
    ]
    if alias_status is not None:
        snapshot["collections"].append({"type": "iot_role_alias", "scope": "111111111111/us-east-1",
            "service": "iot", "status": alias_status,
            "items": [{"RoleAlias": "known", "RoleAliasArn": alias_arn, "id": alias_arn}]
                     if alias_status == "collected" else [], "error": None})
    return snapshot


@pytest.mark.parametrize("certificate_action", CERTIFICATE_ACTIONS)
def test_existing_alias_exact_permission_and_new_certificate_reach_role(certificate_action):
    snapshot = _existing_alias_case(certificate_action=certificate_action)
    assert reached(privesc.analyze(snapshot, entries=[EXISTING_ENTRY]), SOURCE, EXISTING_ID) == {
        TARGET: "conditional"}


def test_other_alias_or_other_region_does_not_reach_role():
    for snapshot in (
        _existing_alias_case(update_resource=ALIAS_ARN + "-other"),
        _existing_alias_case(policy_region="eu-west-1"),
        _existing_alias_case(alias_arn=ALIAS_ARN + "-other"),
    ):
        assert not reached(privesc.analyze(snapshot, entries=[EXISTING_ENTRY]), SOURCE, EXISTING_ID)


def test_missing_or_denied_alias_inventory_never_yields_definite_role_edge():
    for status in (None, "access_denied", "empty"):
        snapshot = _existing_alias_case(alias_status=status)
        assert not reached(privesc.analyze(snapshot, entries=[EXISTING_ENTRY],
                                           include_unknown=False), SOURCE, EXISTING_ID)


def test_existing_alias_collector_keeps_only_valid_names_and_generated_arns():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "peaso/collectors/aws_facts_ext.py"))

    class ReadResult:
        def __init__(self, items, status="collected", error=None):
            self.items, self.status, self.error = items, status, error

    module["_iot_role_aliases"].__globals__["_aws"] = lambda: type("Aws", (), {"ReadResult": ReadResult})

    class Requests:
        def pages(self, _session, service, region, operation, key, **kwargs):
            assert (service, region, operation, key) == ("iot", "us-east-1", "list_role_aliases", "roleAliases")
            assert kwargs == {"_tokens": ("marker", "nextMarker")}
            return ReadResult(["known"])

        def detail(self, _session, service, region, operation, **kwargs):
            assert (service, region, operation, kwargs) == (
                "iot", "us-east-1", "describe_role_alias", {"roleAlias": "known"})
            return {"collection_status": "collected", "roleAliasDescription": {
                "roleAlias": "known", "roleAliasArn": ALIAS_ARN, "roleArn": TARGET}}

    result = module["_iot_role_aliases"](Requests(), object(), "us-east-1", "111111111111")
    assert result.status == "collected" and result.items == [{
        "RoleAlias": "known", "RoleAliasArn": ALIAS_ARN, "RoleArn": TARGET, "id": ALIAS_ARN}]


def test_existing_alias_collector_denied_detail_is_incomplete():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "peaso/collectors/aws_facts_ext.py"))

    class ReadResult:
        def __init__(self, items, status="collected", error=None):
            self.items, self.status, self.error = items, status, error

    module["_iot_role_aliases"].__globals__["_aws"] = lambda: type("Aws", (), {"ReadResult": ReadResult})

    class Requests:
        def pages(self, *_args, **_kwargs):
            return ReadResult(["known"])

        def detail(self, *_args, **_kwargs):
            return {"collection_status": "access_denied", "error": {"code": "AccessDeniedException"}}

    result = module["_iot_role_aliases"](Requests(), object(), "us-east-1", "111111111111")
    assert result.status == "access_denied" and result.items == []


def test_previous_binding_does_not_reinterpret_new_alias_route():
    old = dict(catalog.current_binding(), manifest_sha256=catalog.IOT_EXISTING_689_PREVIOUS_MANIFEST,
               effective_tree_sha256=catalog.IOT_EXISTING_689_PREVIOUS_TREE)
    entries, state = catalog.lookup_entries([EXISTING_ID], old)
    assert state == "exact_previous_current" and EXISTING_ID not in entries


def test_customer_setup_includes_iot_alias_inventory_read():
    from scripts.peaso_deploy_customer_policy import build_policy
    generated = build_policy({("iot", "list_role_aliases"), ("iot", "describe_role_alias")},
                             include_credential_report_generation=False)
    assert "iot:ListRoleAliases" in generated["Statement"][0]["Action"]
    assert "iot:DescribeRoleAlias" in generated["Statement"][0]["Action"]
    static = json.loads((Path(__file__).resolve().parents[1] / "infra/aws/customer-role.json").read_text())
    documents = [resource["Properties"]["PolicyDocument"] for resource in static["Resources"].values()
                 if resource["Type"] == "AWS::IAM::ManagedPolicy"]
    assert all(len(json.dumps(document, separators=(",", ":"))) <= 6144 for document in documents)
    assert any("iot:ListRoleAliases" in statement.get("Action", [])
               for document in documents for statement in document["Statement"])
    assert any("iot:DescribeRoleAlias" in statement.get("Action", [])
               for document in documents for statement in document["Statement"])
