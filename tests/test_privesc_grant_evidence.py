"""Every administrative classification names the actual authorization it matched."""
import copy

from peaso.privesc import analyze
from peaso.privesc.effective_permissions import Grant, combine, permission_match
from peaso.snapshot import make_snapshot
from tests.test_peaso_privesc import gcp_snapshot, azure_snapshot, SUB, WRITER_ROLE
from tests.test_principal_exposure import kube

ACCOUNT = "555566667777"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/AWSReservedSSO_AdministratorAccess_example"
POLICY = f"arn:aws:iam::{ACCOUNT}:policy/AdministratorAccess"


def aws_admin_snapshot():
    statement = {"Sid": "AdministrativeAccess", "Effect": "Allow", "Action": "*", "Resource": "*",
                 "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    role = {"Arn": ROLE, "RoleName": ROLE.rsplit("/", 1)[1], "AttachedManagedPolicies": [{"PolicyArn": POLICY}],
            "AssumeRolePolicyDocument": {"Statement": []}}
    policy = {"Arn": POLICY, "PolicyName": "AdministratorAccess", "PolicyVersionList": [
        {"IsDefaultVersion": True, "Document": {"Statement": [statement]}}]}
    scope = ACCOUNT + "/us-east-1"
    return make_snapshot("aws", [scope], [{"type": kind, "scope": scope, "service": "iam", "status": "collected" if rows else "empty", "items": rows}
        for kind, rows in {"iam_role": [role], "iam_policy": [policy], "iam_user": [], "iam_group": []}.items()])


def test_aws_admin_names_policy_wildcard_resource_and_condition_in_finding_and_edge():
    snap = aws_admin_snapshot()
    original = copy.deepcopy(snap)
    result = analyze(snap, entries=[])
    finding = next(f for f in result["findings"] if f["check_id"] == "admin-equivalent")
    permissions = finding["evidence"]["granting_permissions"]
    assert len(permissions) == 1
    match = permissions[0]
    assert match["permission"] == "*"
    assert match["grant"]["policy"] == POLICY
    assert match["grant"]["policy_name"] == "AdministratorAccess"
    assert match["grant"]["statement"] == 0
    assert match["grant"]["statement_document"] == {"Sid": "AdministrativeAccess", "Effect": "Allow", "Action": ["*"], "Resource": ["*"],
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    detail = result["graph"]["edges"][0]["technique_details"][0]
    assert detail["granting_permissions"] == permissions
    assert finding["status"] == "MANUAL"
    assert POLICY in finding["evidence"]["technique"]["summary"]
    assert 'Action: ["*"] on Resource: ["*"]' in finding["evidence"]["technique"]["summary"]
    assert snap == original


def test_gcp_admin_records_set_iam_policy_permission_role_and_scope():
    snap = gcp_snapshot([{"role": "roles/owner", "members": ["user:admin@example.test"]}], [])
    finding = next(f for f in analyze(snap, entries=[])["findings"] if f["check_id"] == "admin-equivalent")
    matched = finding["evidence"]["granting_permissions"][0]
    assert matched["permission"] == "resourcemanager.projects.setIamPolicy"
    assert matched["grant"]["role"] == "roles/owner"
    assert matched["grant"]["policy"] == "projects/p1"
    assert matched["grant"]["matched_role_permissions"] == ["*"]


def test_azure_admin_records_actual_role_assignment_action_and_definition():
    snap = azure_snapshot([("u-alice", SUB, WRITER_ROLE)])
    finding = next(f for f in analyze(snap, entries=[])["findings"] if f["check_id"] == "admin-equivalent")
    match = finding["evidence"]["granting_permissions"][0]
    assert match["permission"] == "microsoft.authorization/roleassignments/write"
    assert match["grant"]["assignment"]
    assert match["grant"]["role"] == "RA writer"
    assert match["grant"]["scope"] == SUB.lower()
    assert match["grant"]["role_permissions"]["actions"] == ["microsoft.authorization/roleassignments/write"]


def test_kubernetes_admin_records_exact_binding_and_wildcard_rule():
    finding = next(f for f in analyze(kube(), entries=[])["findings"] if f["check_id"] == "admin-equivalent")
    match = finding["evidence"]["granting_permissions"][0]
    assert match["permission"] == "* *"
    assert match["grant"]["binding"] == "clusterrolebinding/admin"
    assert match["grant"]["role"] == "ClusterRole/admin"
    assert match["grant"]["rule"] == {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}


def test_permission_matches_are_complete_beyond_native_reference_sample_limit():
    grants = [permission_match(Grant(refs=[{"policy": f"policy-{i}", "effect": "Allow"}]), {"action": f"service:Action{i}"}, f"resource-{i}") for i in range(24)]
    grant = combine(*grants)
    assert len(grant.refs) == 12  # Existing native-reference sampling is retained.
    assert len(grant.permission_refs) == 24
    assert grant.permission_refs[-1]["evaluated_resource"] == "resource-23"


def test_supporting_context_and_denies_are_never_labelled_as_granting_permissions():
    grant = permission_match(Grant(refs=[{"policy": "allow", "effect": "Allow"}, {"policy": "deny", "effect": "Deny"},
        {"deny_policy": "deny"}, {"bound_resource": "resource"}]), {"action": "service:Action"})
    assert [p["grant"].get("policy") for p in grant.permission_refs] == ["allow"]
