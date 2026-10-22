"""Hybrid SSM shells must bind the same online node and its recorded role."""

from peaso.privesc import schema, versioned_catalog
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_followups import ACCOUNT, ALICE, aws_snap, role, trust_service, user


REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
INSTANCE_ID = "mi-" + "1" * 17
NODE = f"arn:aws:ssm:{REGION}:{ACCOUNT}:managed-instance/{INSTANCE_ID}"
RUN_DOC = f"arn:aws:ssm:{REGION}::document/AWS-RunShellScript"
SESSION_DOC = f"arn:aws:ssm:{REGION}:{ACCOUNT}:document/SSM-SessionManagerRunShell"
CHANNEL = f"arn:aws:ssm:{REGION}:{ACCOUNT}:session/*"
TARGET = f"arn:aws:iam::{ACCOUNT}:role/hybrid-exec"
ENTRIES = {row["id"]: row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"]}


def _model(*, session=False, node=NODE, document=None, channel=CHANNEL,
           iam_role="hybrid-exec", ping="Online", platform="Linux", status="collected"):
    document = document or (SESSION_DOC if session else RUN_DOC)
    action = "ssm:StartSession" if session else "ssm:SendCommand"
    statements = [{"Effect": "Allow", "Action": action, "Resource": [node, document]}]
    if session and channel:
        statements.append({"Effect": "Allow", "Action": "ssmmessages:OpenDataChannel",
                           "Resource": channel})
    actor = user("alice", *statements)
    execution = role("hybrid-exec", trust_service("ssm.amazonaws.com"),
                     {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"})
    managed = {"InstanceId": INSTANCE_ID, "IamRole": iam_role, "PingStatus": ping,
               "PlatformType": platform, "ResourceType": "ManagedInstance"}
    return AwsModel(aws_snap([actor], [execution],
                             [("ssm_managed_instance", SCOPE, [managed], status)]))


def _verdict(model, *, session=False):
    name = "ssm_hybrid_startsession_role" if session else "ssm_hybrid_sendcommand_role"
    return model.precondition(name, {TARGET: model.principals[TARGET]},
                              model.principals[ALICE]).get(TARGET)


def test_run_command_reaches_only_recorded_hybrid_role():
    model = _model()
    assert _verdict(model) == ("conditional", "ssm_hybrid_online_node_role_and_shell_bound")
    edges = Evaluator(model, [ENTRIES["aws-ssm-sendcommand-hybrid-role"]], include_unknown=False).run()
    assert {target for edge in edges if edge.source.id == ALICE for target in edge.targets} == {TARGET}


def test_windows_node_uses_powershell_document():
    powershell = f"arn:aws:ssm:{REGION}::document/AWS-RunPowerShellScript"
    assert _verdict(_model(platform="Windows", document=powershell)) == (
        "conditional", "ssm_hybrid_online_node_role_and_shell_bound")


def test_start_session_requires_default_shell_and_future_data_channel():
    model = _model(session=True)
    assert _verdict(model, session=True) == (
        "conditional", "ssm_hybrid_online_node_role_and_shell_bound")
    edges = Evaluator(model, [ENTRIES["aws-ssm-startsession-hybrid-role"]],
                      include_unknown=False).run()
    assert {target for edge in edges if edge.source.id == ALICE for target in edge.targets} == {TARGET}
    for change in ({"channel": None},
                   {"channel": f"arn:aws:ssm:{REGION}:{ACCOUNT}:session/old-session"},
                   {"document": f"arn:aws:ssm:{REGION}:{ACCOUNT}:document/AWS-StartPortForwardingSession"},
                   {"node": NODE + "-other"}):
        assert _verdict(_model(session=True, **change), session=True) != (
            "conditional", "ssm_hybrid_online_node_role_and_shell_bound"), change


def test_other_role_platform_node_or_denied_inventory_cannot_bind():
    for change in ({"iam_role": "another-role"}, {"platform": "Windows"},
                   {"ping": "ConnectionLost"}, {"status": "access_denied"},
                   {"node": NODE + "-other"},
                   {"document": f"arn:aws:ssm:{REGION}::document/AWS-RunPowerShellScript"}):
        assert _verdict(_model(**change)) != (
            "conditional", "ssm_hybrid_online_node_role_and_shell_bound"), change


def test_catalog_bindings_preserve_previous_meanings():
    current = versioned_catalog.current_binding()
    ids = ["aws-ssm-sendcommand-hybrid-role", "aws-ssm-startsession-hybrid-role"]
    entries, state = versioned_catalog.lookup_entries(ids, current)
    assert state == "exact_strict_privesc" and set(entries) == set(ids)
    previous = dict(current,
                    manifest_sha256=versioned_catalog.SSM_HYBRID_PREVIOUS_MANIFEST,
                    effective_tree_sha256=versioned_catalog.SSM_HYBRID_PREVIOUS_TREE)
    entries, state = versioned_catalog.lookup_entries(
        [*ids, "aws-ssm-sendcommand"], previous)
    assert state == "exact_previous_current"
    assert not set(ids).intersection(entries) and "aws-ssm-sendcommand" in entries
