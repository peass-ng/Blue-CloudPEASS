"""New Glue sessions and SageMaker notebooks need one bound workload path."""

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
SCOPE = "111111111111/us-east-1"


def _entry(ident):
    return next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ident)


def _case(ident, service, actions, *, occupied=False, missing=(), trust=None):
    entry = _entry(ident)
    snap = _snapshot(entry)
    source = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    role["AssumeRolePolicyDocument"]["Statement"] = [{
        "Effect": "Allow", "Principal": {"Service": trust or service + ".amazonaws.com"},
        "Action": "sts:AssumeRole"}]
    source["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": TARGET,
         "Condition": {"StringEquals": {"iam:PassedToService": service + ".amazonaws.com"}}},
        *({"Effect": "Allow", "Action": action, "Resource": "*"}
          for action in actions if action not in missing),
    ]
    kind = "glue_session" if service == "glue" else "sagemaker_notebook_instance"
    item = ({"Id": "PeasoBoundOccupied"} if service == "glue" else
            {"NotebookInstanceName": "PeasoBoundOccupied",
             "NotebookInstanceArn":
                 "arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/PeasoBoundOccupied"})
    snap["collections"].append({"type": kind, "scope": SCOPE, "service": service,
                                "status": "collected" if occupied else "empty",
                                "error": None, "items": [item] if occupied else []})
    return entry, snap


def _reached(entry, snap):
    return reached(privesc.analyze(snap, entries=[entry], include_unknown=False), SOURCE, entry["id"])


def test_glue_new_session_requires_creation_and_statement_on_same_unused_session():
    ident = "aws-glue-passrole-createsession"
    actions = ("glue:CreateSession", "glue:RunStatement")
    entry, snap = _case(ident, "glue", actions)
    assert _reached(entry, snap) == {TARGET: "conditional"}
    for missing in actions:
        entry, snap = _case(ident, "glue", actions, missing=(missing,))
        assert TARGET not in _reached(entry, snap)
    entry, snap = _case(ident, "glue", actions, trust="lambda.amazonaws.com")
    assert TARGET not in _reached(entry, snap)


def test_sagemaker_new_notebook_requires_creation_and_url_for_one_notebook():
    ident = "aws-sagemaker-passrole-createnotebookinstance"
    actions = ("sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl")
    entry, snap = _case(ident, "sagemaker", actions)
    assert _reached(entry, snap) == {TARGET: "conditional"}
    for missing in actions:
        entry, snap = _case(ident, "sagemaker", actions, missing=(missing,))
        assert TARGET not in _reached(entry, snap)
    entry, snap = _case(ident, "sagemaker", actions, trust="lambda.amazonaws.com")
    assert TARGET not in _reached(entry, snap)
