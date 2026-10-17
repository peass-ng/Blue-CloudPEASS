from unittest.mock import Mock

from peaso.auth.billing import ProtectedToolsPlan


POOL = "existing_pool"


def client(ident, writes):
    return {"UserPoolClient": {"UserPoolId": POOL, "ClientId": ident, "WriteAttributes": writes}}


def listed(ident, next_token=None):
    result = {"UserPoolClients": [{"UserPoolId": POOL, "ClientId": ident}]}
    if next_token is not None:
        result["NextToken"] = next_token
    return result


def test_protected_tools_plan_reads_every_client_and_caches_briefly():
    clock = [100.0]
    cognito = Mock()
    cognito.list_user_pool_clients.side_effect = [listed("one", "page-two"), listed("two")]
    cognito.describe_user_pool_client.side_effect = lambda **kwargs: client(kwargs["ClientId"], ["email"])
    authority = ProtectedToolsPlan(cognito, POOL, "one", clock=lambda: clock[0])
    assert authority.plan({"custom:plan": " Pentester "}) == "pentester"
    assert authority.plan({"custom:plan": "free"}) == "free"
    assert cognito.list_user_pool_clients.call_count == 2
    assert cognito.describe_user_pool_client.call_count == 2
    clock[0] += 31
    cognito.list_user_pool_clients.side_effect = [listed("one"), listed("two")]
    cognito.describe_user_pool_client.side_effect = lambda **kwargs: client(kwargs["ClientId"], ["custom:plan"])
    assert authority.plan({"custom:plan": "pentester"}) is None


def test_unsafe_or_incomplete_client_inventory_cannot_authorize_plan():
    for writes in (None, [], ["custom:plan"], ["custom:*"], ["*"], ["email", "Custom:Plan"]):
        cognito = Mock()
        cognito.list_user_pool_clients.return_value = listed("one")
        cognito.describe_user_pool_client.return_value = client("one", writes)
        assert ProtectedToolsPlan(cognito, POOL, "one").plan({"custom:plan": "pentester"}) is None
    cognito = Mock()
    cognito.list_user_pool_clients.return_value = {"UserPoolClients": []}
    assert ProtectedToolsPlan(cognito, POOL, "one").plan({"custom:plan": "pentester"}) is None
    cognito.list_user_pool_clients.return_value = listed("other")
    cognito.describe_user_pool_client.return_value = client("other", ["email"])
    assert ProtectedToolsPlan(cognito, POOL, "one").plan({"custom:plan": "pentester"}) is None
    cognito.list_user_pool_clients.return_value = listed("one", "next")
    assert ProtectedToolsPlan(cognito, POOL, "one").plan({"custom:plan": "pentester"}) is None
    cognito.list_user_pool_clients.side_effect = PermissionError("read denied")
    assert ProtectedToolsPlan(cognito, POOL, "one").plan({"custom:plan": "pentester"}) is None


def test_foreign_or_malformed_client_proof_and_unknown_plan_fail_closed():
    cognito = Mock()
    cognito.list_user_pool_clients.return_value = listed("one")
    cognito.describe_user_pool_client.return_value = client("foreign", ["email"])
    assert ProtectedToolsPlan(cognito, POOL, "one").plan({"custom:plan": "pentester"}) is None
    cognito.describe_user_pool_client.return_value = client("one", ["email"])
    authority = ProtectedToolsPlan(cognito, POOL, "one")
    assert authority.plan({"custom:plan": "enterprise"}) is None
    assert authority.plan({"custom:plan": 1}) is None
