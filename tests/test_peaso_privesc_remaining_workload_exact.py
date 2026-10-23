"""Exact graph cases for existing workload and hybrid activation routes."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, real, reached,
    role, role_arn, user,
)


GLUE_ROLE = role_arn("glue")
SESSION = f"arn:aws:glue:{REGION}:{ACCOUNT}:session/interactive"
ENDPOINT = f"arn:aws:glue:{REGION}:{ACCOUNT}:devEndpoint/legacy"
NOTEBOOK_ROLE = role_arn("notebook")
NOTEBOOK = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:notebook-instance/research"
HYBRID_ROLE = role_arn("hybrid")


def _session_snapshot(*, writer=SESSION, status="READY"):
    actor = user("alice", allow("glue:RunStatement", resource=writer))
    session = {"Id": "interactive", "Role": GLUE_ROLE, "Status": status}
    return aws_snap([actor], [role("glue", "glue.amazonaws.com")], [col("glue_session", [session])])


def test_glue_run_statement_requires_ready_session_and_exact_session_arn():
    tid = "aws-glue-runstatement-interactive-session"
    assert GLUE_ROLE in reached(real(_session_snapshot(), tid), ALICE, tid)
    assert GLUE_ROLE not in reached(real(_session_snapshot(writer=ENDPOINT), tid), ALICE, tid)
    assert GLUE_ROLE not in reached(real(_session_snapshot(status="STOPPED"), tid), ALICE, tid)


def _endpoint_snapshot(*, writer=ENDPOINT, public=True, state="READY"):
    actor = user("alice", allow("glue:UpdateDevEndpoint", resource=writer))
    endpoint = {"EndpointName": "legacy", "RoleArn": GLUE_ROLE, "Status": state,
                "ManagedPublicKeyCount": 0, "LegacyPublicKeyPresent": False}
    if public:
        endpoint["PublicAddress"] = "203.0.113.10"
    return aws_snap([actor], [role("glue", "glue.amazonaws.com")], [col("glue_dev_endpoint", [endpoint])])


def test_glue_dev_endpoint_requires_ready_public_endpoint_with_exact_update_grant():
    tid = "aws-glue-updatedevendpoint"
    assert GLUE_ROLE in reached(real(_endpoint_snapshot(), tid), ALICE, tid)
    assert GLUE_ROLE not in reached(real(_endpoint_snapshot(writer=SESSION), tid), ALICE, tid)
    assert GLUE_ROLE not in reached(real(_endpoint_snapshot(public=False), tid), ALICE, tid)
    assert GLUE_ROLE not in reached(real(_endpoint_snapshot(state="STOPPED"), tid), ALICE, tid)


def _notebook_snapshot(*, writer=NOTEBOOK, state="InService"):
    actor = user("alice", allow("sagemaker:CreatePresignedNotebookInstanceUrl", resource=writer))
    notebook = {"NotebookInstanceArn": NOTEBOOK, "RoleArn": NOTEBOOK_ROLE,
                "NotebookInstanceStatus": state}
    return aws_snap([actor], [role("notebook", "sagemaker.amazonaws.com")],
                    [col("sagemaker_notebook_instance", [notebook])])


def test_presigned_notebook_url_requires_existing_in_service_notebook_and_exact_arn():
    tid = "aws-sagemaker-createpresignednotebookinstanceurl"
    assert NOTEBOOK_ROLE in reached(real(_notebook_snapshot(), tid), ALICE, tid)
    assert NOTEBOOK_ROLE not in reached(real(_notebook_snapshot(writer=NOTEBOOK.replace("research", "other")), tid), ALICE, tid)
    assert NOTEBOOK_ROLE not in reached(real(_notebook_snapshot(state="Failed"), tid), ALICE, tid)


def _activation_snapshot(*, passed=HYBRID_ROLE, create=True, trust="ssm.amazonaws.com"):
    grants = [allow("iam:PassRole", resource=passed)]
    if create:
        grants.append(allow("ssm:CreateActivation"))
    return aws_snap([user("alice", *grants)], [role("hybrid", trust)])


def test_create_activation_requires_passable_role_trusting_ssm_service():
    tid = "aws-ssm-passrole-createactivation"
    assert HYBRID_ROLE in reached(real(_activation_snapshot(), tid), ALICE, tid)
    assert HYBRID_ROLE not in reached(real(_activation_snapshot(passed=NOTEBOOK_ROLE), tid), ALICE, tid)
    assert HYBRID_ROLE not in reached(real(_activation_snapshot(create=False), tid), ALICE, tid)
    assert HYBRID_ROLE not in reached(real(_activation_snapshot(trust="ec2.amazonaws.com"), tid), ALICE, tid)
