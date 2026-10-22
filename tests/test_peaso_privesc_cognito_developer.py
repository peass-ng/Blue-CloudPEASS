"""A developer token reaches only the exact pool's authenticated IAM role."""
from peaso.privesc import schema
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_followups import ACCOUNT, ALICE, aws_snap, pol, role, user


SCOPE = f"{ACCOUNT}/us-east-1"
POOL_ID = "us-east-1:12345678-1234-1234-1234-123456789abc"
POOL_ARN = f"arn:aws:cognito-identity:us-east-1:{ACCOUNT}:identitypool/{POOL_ID}"
ENTRY_ID = "aws-cognito-getopenidtokenfordeveloperidentity"


def _entry():
    return next(row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"] if row["id"] == ENTRY_ID)


def _trust(audience=POOL_ID, method="authenticated", extra=()):
    return pol({"Effect": "Allow", "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": audience},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": method}}}, *extra)


def _pool(*, developer=True, roles_status="collected", authenticated=True):
    roles = {"unauthenticated": f"arn:aws:iam::{ACCOUNT}:role/guest"}
    if authenticated:
        roles["authenticated"] = f"arn:aws:iam::{ACCOUNT}:role/authenticated"
    config = {"collection_status": "collected"}
    if developer:
        config["DeveloperProviderName"] = "login.example.app"
    return ("cognito_identity_pool", SCOPE, [{"IdentityPoolId": POOL_ID, "Configuration": config,
        "Roles": {"collection_status": roles_status, "Roles": roles}}])


def _result(*, permission=POOL_ARN, developer=True, roles_status="collected", authenticated=True,
            audience=POOL_ID, method="authenticated", extra_trust=()):
    actors = [user("alice", {"Effect": "Allow", "Action": "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
                              "Resource": permission})]
    targets = [role("authenticated", _trust(audience, method, extra_trust)), role("guest", _trust())]
    snap = aws_snap(actors, targets, [_pool(developer=developer, roles_status=roles_status,
                                            authenticated=authenticated)])
    model = AwsModel(snap)
    source = model.principals[ALICE]
    selected = model.selector("cognito_developer_authenticated_role", True,
        {arn: node for arn, node in model.principals.items() if node.kind == "aws_role"}, source)
    return model, selected


def test_developer_token_targets_only_exact_authenticated_role():
    assert not schema.validate_entry({key: value for key, value in _entry().items() if key != "_file"})[0]
    model, selected = _result()
    assert selected == {f"arn:aws:iam::{ACCOUNT}:role/authenticated": None}
    assert model._check_action(model.principals[ALICE],
        "cognito-identity:GetOpenIdTokenForDeveloperIdentity", POOL_ARN) is not None
    reaches = Evaluator(model, [_entry()], include_unknown=False).run()
    assert len(reaches) == 1
    assert reaches[0].source.id == ALICE
    assert set(reaches[0].targets) == {f"arn:aws:iam::{ACCOUNT}:role/authenticated"}


def test_developer_token_requires_exact_pool_permission_and_provider():
    model, selected = _result(permission=POOL_ARN + "-other")
    assert selected == {f"arn:aws:iam::{ACCOUNT}:role/authenticated": None}
    assert model._check_action(model.principals[ALICE],
        "cognito-identity:GetOpenIdTokenForDeveloperIdentity", POOL_ARN) is None
    for _, selected in (_result(developer=False), _result(authenticated=False)):
        assert f"arn:aws:iam::{ACCOUNT}:role/authenticated" not in selected


def test_developer_token_requires_matching_role_trust():
    for _, selected in (_result(audience="us-east-1:different"), _result(method="unauthenticated")):
        assert f"arn:aws:iam::{ACCOUNT}:role/authenticated" not in selected


def test_developer_token_honors_trust_deny_and_uncertain_notprincipal():
    deny = {"Effect": "Deny", "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": POOL_ID}}}
    _, selected = _result(extra_trust=(deny,))
    assert f"arn:aws:iam::{ACCOUNT}:role/authenticated" not in selected
    not_principal = {"Effect": "Deny", "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                     "Action": "sts:AssumeRoleWithWebIdentity"}
    _, selected = _result(extra_trust=(not_principal,))
    assert selected[f"arn:aws:iam::{ACCOUNT}:role/authenticated"][0] == "unknown"


def test_missing_role_inventory_does_not_claim_authenticated_role():
    _, selected = _result(roles_status="denied")
    assert selected[f"arn:aws:iam::{ACCOUNT}:role/authenticated"][0] == "unknown"
