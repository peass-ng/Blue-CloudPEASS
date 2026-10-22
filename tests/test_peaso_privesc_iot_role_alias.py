"""The two self-contained IoT certificate routes need their own permission proof."""
from __future__ import annotations

import pytest

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
