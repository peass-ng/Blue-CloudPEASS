"""Updating a pool can expose only roles that trust its guest Basic-flow token."""
from peaso.privesc import schema
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_followups import ACCOUNT, OTHER, ALICE, aws_snap, pol, role, user


POOL_ID = "us-east-1:12345678-1234-1234-1234-123456789abc"
POOL_ARN = f"arn:aws:cognito-identity:us-east-1:{ACCOUNT}:identitypool/{POOL_ID}"
TECHNIQUE = "aws-cognito-updateidentitypool-enable-guest-classic-role"
UPDATE = {"Effect": "Allow", "Action": "cognito-identity:UpdateIdentityPool", "Resource": POOL_ARN}


def entry():
    return next(row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"] if row["id"] == TECHNIQUE)


def trust(*, audience=POOL_ID, method="unauthenticated", extra=()):
    return pol({"Effect": "Allow", "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": audience},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": method}}}, *extra)


def pool(*, mappings=None, config_status="collected", roles_status="collected", name="test-pool",
         guest=False, classic=False):
    return ("cognito_identity_pool", f"{ACCOUNT}/us-east-1", [{
        "IdentityPoolId": POOL_ID,
        "Configuration": {"collection_status": config_status, "IdentityPoolName": name,
                          "AllowUnauthenticatedIdentities": guest, "AllowClassicFlow": classic},
        "Roles": {"collection_status": roles_status, "Roles": {}, "RoleMappings": mappings or {}}}])


def reaches(*, actions=(UPDATE,), audience=POOL_ID, method="unauthenticated",
            mappings=None, config_status="collected", roles_status="collected", name="test-pool",
            target_account=ACCOUNT, extra_trust=(), guest=False, classic=False):
    target = role("target", trust(audience=audience, method=method, extra=extra_trust), account=target_account)
    model = AwsModel(aws_snap([user("alice", *actions)], [target], [
        pool(mappings=mappings, config_status=config_status, roles_status=roles_status, name=name,
             guest=guest, classic=classic)]))
    return Evaluator(model, [entry()], include_unknown=False).run()


def test_guest_basic_update_reaches_exact_trusted_role_without_assigned_pool_role():
    assert not schema.validate_entry({key: value for key, value in entry().items() if key != "_file"})[0]
    found = reaches()
    assert {r.source.id: set(r.targets) for r in found} == {
        ALICE: {f"arn:aws:iam::{ACCOUNT}:role/target"}}
    assert {r.source.id: set(r.targets) for r in reaches(target_account=OTHER)} == {
        ALICE: {f"arn:aws:iam::{OTHER}:role/target"}}


def test_guest_basic_update_requires_permission_on_the_same_pool():
    assert reaches(actions=()) == []
    assert reaches(actions=({**UPDATE, "Resource": POOL_ARN + "-other"},)) == []


def test_guest_basic_update_requires_guest_trust_and_no_role_mappings():
    assert reaches(audience="us-east-1:different") == []
    assert reaches(method="authenticated") == []
    assert reaches(mappings={"provider": {"Type": "Token"}}) == []
    assert reaches(name="") == []
    assert reaches(guest=True, classic=True) == []  # Already public; this update causes no new access.
    assert reaches(guest=True, classic=False)
    assert reaches(guest=False, classic=True)


def test_guest_basic_update_does_not_claim_incomplete_pool_facts():
    assert reaches(config_status="access_denied") == []
    assert reaches(roles_status="access_denied") == []


def test_guest_basic_update_respects_explicit_trust_deny():
    deny = {"Effect": "Deny", "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": POOL_ID}}}
    assert reaches(extra_trust=(deny,)) == []
