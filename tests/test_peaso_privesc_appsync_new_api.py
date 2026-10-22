"""A new AppSync API needs every setup action and a passable exact role."""

from peaso import privesc
from peaso.privesc.schema import load_catalog
from peaso.privesc import versioned_catalog


ACCOUNT = "111111111111"
USER = f"arn:aws:iam::{ACCOUNT}:user/alice"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/appsync-role"
ENTRY = next(row for row in load_catalog()["entries"] if row["id"] == "aws-appsync-passrole-new-api-sigv4")
ACTIONS = ("CreateGraphqlApi", "StartSchemaCreation", "CreateDataSource", "CreateResolver", "CreateApiKey")


def _snapshot(*, missing=None, passed_to="appsync.amazonaws.com", trust="appsync.amazonaws.com", api_resource="*"):
    statements = [{"Effect": "Allow", "Action": f"appsync:{action}", "Resource": api_resource}
                  for action in ACTIONS if action != missing]
    statements.append({"Effect": "Allow", "Action": "iam:PassRole", "Resource": ROLE,
                       "Condition": {"StringEquals": {"iam:PassedToService": passed_to}}})
    alice = {"UserName": "alice", "Arn": USER, "GroupList": [], "AttachedManagedPolicies": [],
             "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": statements}}]}
    role = {"RoleName": "appsync-role", "Arn": ROLE, "Path": "/", "RolePolicyList": [], "AttachedManagedPolicies": [],
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": trust}}]}}
    collections = [("iam_user", [alice]), ("iam_role", [role]), ("iam_group", []), ("iam_policy", []), ("scp_policy", [])]
    return {"schema_version": 1, "provider": "aws", "scopes": [f"{ACCOUNT}/us-east-1"], "metadata": {},
            "collections": [{"type": kind, "service": kind, "scope": f"{ACCOUNT}/us-east-1", "status": "collected" if rows else "empty", "items": rows, "error": None}
                            for kind, rows in collections]}


def _edges(snapshot):
    graph = privesc.analyze(snapshot, entries=[ENTRY])["graph"]
    return {edge["target"]: edge["confidence"] for edge in graph["edges"] if edge["source"] == USER}


def test_complete_self_contained_appsync_route_is_conditional():
    assert _edges(_snapshot()) == {ROLE: "conditional"}


def test_missing_setup_action_or_wrong_role_context_does_not_reach_role():
    for action in ACTIONS:
        assert _edges(_snapshot(missing=action)) == {}, action
    assert _edges(_snapshot(passed_to="lambda.amazonaws.com")) == {}
    assert _edges(_snapshot(trust="lambda.amazonaws.com")) == {}
    assert _edges(_snapshot(api_resource=f"arn:aws:appsync:us-east-1:{ACCOUNT}:apis/existing")) == {}
    assert _edges(_snapshot(api_resource="peaso-global-appsync-operation")) == {}


def test_new_appsync_route_keeps_prior_catalog_binding_exact():
    binding = versioned_catalog.current_binding()
    entries, status = versioned_catalog.lookup_entries([ENTRY["id"]], binding)
    assert status == "exact_strict_privesc" and set(entries) == {ENTRY["id"]}
    prior = {"schema": versioned_catalog.BINDING_SCHEMA,
             "manifest_sha256": versioned_catalog.APPRUNNER_CURRENT_MANIFEST,
             "effective_tree_sha256": versioned_catalog.APPRUNNER_CURRENT_TREE,
             "source_revision": versioned_catalog.V4_REVISION}
    entries, status = versioned_catalog.lookup_entries([ENTRY["id"]], prior)
    assert status == "exact_previous_current" and entries == {}
    assert len(versioned_catalog._verified_apprunner_current()) == 666
