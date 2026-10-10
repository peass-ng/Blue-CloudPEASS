import copy
import time
from types import SimpleNamespace
from unittest.mock import Mock
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient
from peaso.auth import Authenticator
from peaso.auth.billing import StripeEntitlements
from peaso.server import create_app
from peaso.server.config import Settings


@pytest.fixture
def cognito_settings(tmp_path):
    return Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", auth_mode="cognito", issuer="https://cognito-idp.us-east-1.amazonaws.com/existing_pool", audience="existing_client", origins=("https://cspm.hacktricks.wiki",))


def jwt_auth(settings):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = Mock()
    jwks.get_signing_key_from_jwt.return_value = SimpleNamespace(key=key.public_key())
    cognito = Mock()
    cognito.admin_get_user.return_value = {"Enabled": True, "UserAttributes": [{"Name": "sub", "Value": "alice"}, {"Name": "custom:plan", "Value": "pentester"}]}
    entitlements = Mock()
    entitlements.paid.return_value = False
    auth = Authenticator(settings, cognito=cognito, jwks=jwks, entitlements=entitlements)
    claims = {"iss": settings.issuer, "aud": settings.audience, "sub": "alice", "token_use": "id", "iat": int(time.time()), "exp": int(time.time()) + 600, "custom:plan": "pentester", "paid": True}
    return auth, key, claims


def test_cognito_claims_cannot_self_grant_paid(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    user = auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256"))
    assert user.tenant_id == "alice" and user.weekly_limit == 1
    auth.entitlements.paid.return_value = True
    assert auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256")).weekly_limit == 10
    auth.cognito.admin_get_user.return_value["UserAttributes"][0]["Value"] = "bob"
    assert auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256")).weekly_limit == 1


@pytest.mark.parametrize("change", [{"iss": "https://evil.invalid"}, {"aud": "other-client"}, {"exp": 1}, {"token_use": "access"}, {"iat": int(time.time()) + 3600}])
def test_cognito_invalid_issuer_audience_expiry_use(cognito_settings, change):
    auth, key, claims = jwt_auth(cognito_settings)
    claims.update(change)
    with pytest.raises(HTTPException) as error:
        auth.authenticate("Bearer " + jwt.encode(claims, key, algorithm="RS256"))
    assert error.value.status_code == 401


def test_cognito_signature_and_unsigned_token(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for token in (jwt.encode(claims, other, algorithm="RS256"), jwt.encode(claims, "", algorithm="none")):
        with pytest.raises(HTTPException):
            auth.authenticate("Bearer " + token)


def test_existing_refresh_cookie_and_origin_csrf(cognito_settings):
    auth, key, claims = jwt_auth(cognito_settings)
    auth.cognito.initiate_auth.return_value = {"AuthenticationResult": {"IdToken": jwt.encode(claims, key, algorithm="RS256")}}
    with TestClient(create_app(cognito_settings, authenticator=auth), base_url="https://cspm.hacktricks.wiki") as client:
        client.cookies.set("__Secure-ht_refresh", "refresh-fixture")
        assert client.get("/api/me").status_code == 200
        assert client.post("/api/connectors", json={"name": "x", "provider": "aws", "auth": {}}).status_code == 403
        auth.cognito.initiate_auth.assert_called_with(ClientId=cognito_settings.audience, AuthFlow="REFRESH_TOKEN_AUTH", AuthParameters={"REFRESH_TOKEN": "refresh-fixture"})


def billing_fixture():
    attributes = {"email": "alice@example.com", "email_verified": "true", "custom:stripe_customer_id": "cus_fixture", "custom:plan": "pentester"}
    customer = {"id": "cus_fixture", "email": "alice@example.com", "metadata": {"source": "hacktricks-tools", "user_email": "alice@example.com"}}
    subscription = {"id": "sub_fixture", "customer": "cus_fixture", "status": "active", "metadata": {"source": "hacktricks-tools"}, "items": {"data": [{"price": {"id": "price_verified"}}]}}
    session = Mock()
    replies = [Mock(), Mock()]
    replies[0].json.return_value = customer
    replies[1].json.return_value = {"data": [subscription], "has_more": False}
    session.get.side_effect = replies
    return attributes, customer, subscription, StripeEntitlements(secret="stripe-fixture", price="price_verified", session=session)


def test_stripe_live_verified_entitlement():
    attributes, _, _, billing = billing_fixture()
    assert billing.paid(attributes)
    assert billing.session.get.call_count == 2


@pytest.mark.parametrize("change", ["unverified", "customer_email", "customer_metadata_email", "customer_source", "subscription_source", "subscription_customer", "subscription_status", "subscription_price"])
def test_stripe_flags_and_customer_links_cannot_forge_paid(change):
    attributes, customer, subscription, billing = billing_fixture()
    if change == "unverified": attributes["email_verified"] = "false"
    if change == "customer_email": customer["email"] = "bob@example.com"
    if change == "customer_metadata_email": customer["metadata"]["user_email"] = "bob@example.com"
    if change == "customer_source": customer["metadata"]["source"] = "other"
    if change == "subscription_source": subscription["metadata"]["source"] = "other"
    if change == "subscription_customer": subscription["customer"] = "cus_other"
    if change == "subscription_status": subscription["status"] = "cancelled"
    if change == "subscription_price": subscription["items"]["data"][0]["price"]["id"] = "price_other"
    assert not billing.paid(attributes)


@pytest.mark.parametrize("provider,auth,options", [
    ("aws", {"method": "profile", "profile": "/etc/passwd"}, {}),
    ("aws", {"method": "container"}, {}),
    ("aws", {"method": "access_keys", "aws_access_key_id": "fixture", "aws_secret_access_key": "fixture"}, {"endpoint_url": "http://169.254.169.254"}),
    ("gcp", {"method": "service-account", "service_account_file": "/etc/passwd"}, {}),
    ("gcp", {"sa_json": {"type": "service_account", "token_uri": "http://169.254.169.254"}}, {}),
    ("azure", {"method": "workload-identity", "token_file": "/etc/passwd"}, {}),
    ("k8s", {"kubeconfig": "/etc/passwd"}, {}),
    ("k8s", {"server": "https://127.0.0.1", "token": "secret-fixture"}, {}),
    ("aws", {}, {"demo": True}),
    ("aws", {}, {"snapshot": {}}),
])
def test_hosted_unsafe_fields_rejected_before_persistence_and_quota(cognito_settings, provider, auth, options):
    authenticator, key, claims = jwt_auth(cognito_settings)
    with TestClient(create_app(cognito_settings, authenticator=authenticator), base_url="https://cspm.hacktricks.wiki") as client:
        client.headers["Authorization"] = "Bearer " + jwt.encode(claims, key, algorithm="RS256")
        value = client.post("/api/connectors", json={"name": "hostile", "provider": provider, "auth": auth, "options": options})
        assert value.status_code == 422, value.text
        assert client.get("/api/connectors").json() == {"items": []}
        assert client.get("/api/me").json()["weekly_used"] == 0


def test_hosted_external_id_is_server_generated_and_unique(cognito_settings, monkeypatch):
    role = "arn:aws:iam::123456789012:role/Audit"
    monkeypatch.setenv("PEASO_CUSTOMER_ROLE_ARNS", '["' + role + '"]')
    auth, key, claims = jwt_auth(cognito_settings)
    with TestClient(create_app(cognito_settings, authenticator=auth), base_url="https://cspm.hacktricks.wiki") as client:
        client.headers["Authorization"] = "Bearer " + jwt.encode(claims, key, algorithm="RS256")
        body = {"name": "Role", "provider": "aws", "auth": {"method": "assume_role", "role_arn": role}}
        first = client.post("/api/connectors", json=body)
        second = client.post("/api/connectors", json=body)
        assert first.status_code == second.status_code == 201
        assert first.json()["onboarding"]["external_id"].startswith("peaso-")
        assert first.json()["onboarding"] != second.json()["onboarding"]
        assert client.patch("/api/connectors/" + first.json()["id"], json={"name": "updated"}).status_code == 200
        body["auth"]["external_id"] = "attacker-controlled"
        assert client.post("/api/connectors", json=body).status_code == 422
