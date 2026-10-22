"""A developer token reaches only the exact pool's authenticated IAM role."""
from peaso.privesc import schema
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_followups import ACCOUNT, ALICE, OTHER, aws_snap, pol, role, user


SCOPE = f"{ACCOUNT}/us-east-1"
POOL_ID = "us-east-1:12345678-1234-1234-1234-123456789abc"
POOL_ARN = f"arn:aws:cognito-identity:us-east-1:{ACCOUNT}:identitypool/{POOL_ID}"
ENTRY_ID = "aws-cognito-getopenidtokenfordeveloperidentity"
CLASSIC_ID = "aws-cognito-getopenidtokenfordeveloperidentity-classic"
SETROLES_ID = "aws-cognito-setidentitypoolroles-developer-token"


def _entry():
    return next(row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"] if row["id"] == ENTRY_ID)


def _classic_entry():
    return next(row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"] if row["id"] == CLASSIC_ID)


def _setroles_entry():
    return next(row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"] if row["id"] == SETROLES_ID)


def _trust(audience=POOL_ID, method="authenticated", extra=()):
    return pol({"Effect": "Allow", "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": audience},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": method}}}, *extra)


def _pool(*, developer=True, roles_status="collected", authenticated=True, classic=False):
    roles = {"unauthenticated": f"arn:aws:iam::{ACCOUNT}:role/guest"}
    if authenticated:
        roles["authenticated"] = f"arn:aws:iam::{ACCOUNT}:role/authenticated"
    config = {"collection_status": "collected"}
    if developer:
        config["DeveloperProviderName"] = "login.example.app"
    config["AllowClassicFlow"] = classic
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
    assert selected == {}
    assert model._check_action(model.principals[ALICE],
        "cognito-identity:GetOpenIdTokenForDeveloperIdentity", POOL_ARN) is None
    for _, selected in (_result(developer=False), _result(authenticated=False)):
        assert f"arn:aws:iam::{ACCOUNT}:role/authenticated" not in selected


def test_developer_token_does_not_mix_permission_and_trust_from_different_pools():
    second_id = "us-east-1:87654321-4321-4321-4321-cba987654321"
    second_arn = f"arn:aws:cognito-identity:us-east-1:{ACCOUNT}:identitypool/{second_id}"
    target = f"arn:aws:iam::{ACCOUNT}:role/authenticated"
    first = _pool()[2][0]
    second = {**first, "IdentityPoolId": second_id}
    actor = user("alice", {"Effect": "Allow", "Action": "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
                            "Resource": second_arn})
    snap = aws_snap([actor], [role("authenticated", _trust())],
                    [("cognito_identity_pool", SCOPE, [first, second])])
    model = AwsModel(snap)
    selected = model.selector("cognito_developer_authenticated_role", True, {target: model.principals[target]},
                              model.principals[ALICE])
    assert selected == {}
    assert Evaluator(model, [_entry()], include_unknown=False).run() == []


def test_developer_token_requires_matching_role_trust():
    _, selected = _result(method="login.example.app")
    assert selected == {f"arn:aws:iam::{ACCOUNT}:role/authenticated": None}
    for _, selected in (_result(audience="us-east-1:different"), _result(method="unauthenticated"),
                        _result(method="cognito-identity.amazonaws.com")):
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


def test_classic_flow_reaches_nondefault_role_only_when_enabled():
    special = f"arn:aws:iam::{ACCOUNT}:role/special"
    actor = user("alice", {"Effect": "Allow", "Action": "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
                           "Resource": POOL_ARN})
    target = role("special", _trust(method="login.example.app"))
    for enabled in (False, True):
        snap = aws_snap([actor], [target], [_pool(classic=enabled, authenticated=False)])
        model = AwsModel(snap)
        reaches = Evaluator(model, [_classic_entry()], include_unknown=False).run()
        assert ({r.source.id: set(r.targets) for r in reaches} == {ALICE: {special}}) is enabled


def test_classic_flow_matches_token_permission_and_cross_account_trust():
    external = f"arn:aws:iam::{OTHER}:role/external"
    target = role("external", _trust(method="login.example.app"), account=OTHER)
    for resource, allowed in ((POOL_ARN, True), (POOL_ARN + "-other", False)):
        actor = user("alice", {"Effect": "Allow", "Action": "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
                               "Resource": resource})
        snap = aws_snap([actor], [target], [_pool(classic=True, authenticated=False)])
        model = AwsModel(snap)
        reaches = Evaluator(model, [_classic_entry()], include_unknown=False).run()
        assert ({r.source.id: set(r.targets) for r in reaches} == {ALICE: {external}}) is allowed
    unrestricted = pol({"Effect": "Allow", "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                        "Action": "sts:AssumeRoleWithWebIdentity"})
    snap = aws_snap([actor], [role("external", unrestricted, account=OTHER)],
                    [_pool(classic=True, authenticated=False)])
    assert Evaluator(AwsModel(snap), [_classic_entry()], include_unknown=False).run() == []


def test_classic_flow_uses_china_partition_principal_and_condition_keys():
    region = "cn-north-1"
    pool_id = region + ":12345678-1234-1234-1234-123456789abc"
    pool_arn = f"arn:aws-cn:cognito-identity:{region}:{ACCOUNT}:identitypool/{pool_id}"
    actor = user("alice", {"Effect": "Allow", "Action": "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
                           "Resource": pool_arn})
    actor["Arn"] = f"arn:aws-cn:iam::{ACCOUNT}:user/alice"
    target = role("special", pol({"Effect": "Allow", "Principal": {
        "Federated": "cognito-identity.cn-north-1.amazonaws.com.cn"},
        "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {
            "StringEquals": {"cognito-identity.amazonaws.com.cn:aud": pool_id},
            "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com.cn:amr": "login.example.app"}}}))
    target["Arn"] = f"arn:aws-cn:iam::{ACCOUNT}:role/special"
    pool = {"IdentityPoolId": pool_id, "Configuration": {"collection_status": "collected",
            "DeveloperProviderName": "login.example.app", "AllowClassicFlow": True}}
    snap = aws_snap([actor], [target], [("cognito_identity_pool", f"{ACCOUNT}/{region}", [pool])])
    model = AwsModel(snap)
    reaches = Evaluator(model, [_classic_entry()], include_unknown=False).run()
    assert {r.source.id: set(r.targets) for r in reaches} == {actor["Arn"]: {target["Arn"]}}
    actor["Arn"] = f"arn:aws:iam::{ACCOUNT}:user/alice"
    assert Evaluator(AwsModel(aws_snap([actor], [target], [(
        "cognito_identity_pool", f"{ACCOUNT}/{region}", [pool])])),
        [_classic_entry()], include_unknown=False).run() == []


def test_setroles_with_developer_token_reaches_exact_passed_role():
    target_arn = f"arn:aws:iam::{ACCOUNT}:role/special"
    actions = [
        {"Effect": "Allow", "Action": "cognito-identity:SetIdentityPoolRoles", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": target_arn,
         "Condition": {"StringEquals": {"iam:PassedToService": "cognito-identity.amazonaws.com"}}},
        {"Effect": "Allow", "Action": "cognito-identity:GetOpenIdTokenForDeveloperIdentity", "Resource": POOL_ARN},
    ]
    target = role("special", _trust(method="login.example.app"))
    def reaches(statements, *, developer=True, audience=POOL_ID):
        role_target = target if audience == POOL_ID else role("special", _trust(audience=audience))
        snap = aws_snap([user("alice", *statements)], [role_target],
                        [_pool(developer=developer, authenticated=False)])
        return Evaluator(AwsModel(snap), [_setroles_entry()], include_unknown=False).run()
    assert {r.source.id: set(r.targets) for r in reaches(actions)} == {ALICE: {target_arn}}
    for omitted in range(len(actions)):
        assert reaches(actions[:omitted] + actions[omitted + 1:]) == []
    assert reaches(actions, developer=False) == []
    assert reaches(actions, audience="us-east-1:different") == []
    other_pool = POOL_ARN + "-other"
    wrong_token = [{**actions[2], "Resource": other_pool}, *actions[:2]]
    assert reaches(wrong_token) == []
    wrong_service = [{**actions[1], "Condition": {
        "StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}}, actions[0], actions[2]]
    assert reaches(wrong_service) == []
