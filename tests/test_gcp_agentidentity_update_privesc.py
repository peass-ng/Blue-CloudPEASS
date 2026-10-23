"""Token endpoint changes need an exact Google OAuth provider and authorization."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
PROVIDER = PROJECT + "/locations/us-central1/authProviders/google"
AUTH = PROVIDER + "/authorizations/a1"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-agentidentity-update-token-url"
TARGET = "gcp_verified_authority:agentidentity_authorization:" + AUTH


def snapshot(*, permission=True, state="ACTIVE", provider_state="ENABLED",
             auth_host="accounts.google.com", scope="https://www.googleapis.com/auth/gmail.readonly",
             provider_name=PROVIDER, auth_status="collected"):
    def row(kind, value, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": value, "error": None}
    role = PROJECT + "/roles/editor"
    binding = {"role": role, "members": [SOURCE]}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"name": "projects/111", "projectId": "p1"}]),
                row("iam_role", [{"name": role, "includedPermissions":
                    ["agentidentity.authProviders.update"] if permission else []}]),
                row("iam_policy", [{"name": PROJECT, "bindings": []}]),
                row("agentidentity_auth_provider", [{"name": provider_name,
                    "state": provider_state,
                    "authProviderTypeParams": {"threeLeggedOauth": {
                        "authorizationUrl": "https://" + auth_host + "/o/oauth2/v2/auth",
                        "tokenUrl": "https://oauth2.googleapis.com/token"}},
                    "iamPolicy": {"bindings": [binding]},
                    "_coverage": {"iamPolicy": {"status": "collected"}}}]),
                row("agentidentity_authorization", [{"name": AUTH,
                    "authProvider": PROVIDER, "clientUserId": "alice@example.com",
                    "scopes": [scope], "state": state}], auth_status),
                row("iam_deny_policy", [], "empty"),
            ]}


def result(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()}


def test_exact_active_google_authorization_and_provider_update_is_conditional():
    assert result(snapshot())[TARGET] == "conditional"


def test_missing_update_permission_or_wrong_provider_has_no_named_path():
    assert TARGET not in result(snapshot(permission=False))
    assert TARGET not in result(snapshot(provider_name=PROJECT + "/locations/us-central1/authProviders/other"))


def test_disabled_or_suspended_authorization_cannot_refresh_through_provider():
    assert TARGET not in result(snapshot(state="SUSPENDED"))
    assert TARGET not in result(snapshot(provider_state="DISABLED"))


def test_non_google_or_identity_only_scope_has_no_named_path():
    assert TARGET not in result(snapshot(auth_host="auth.example.com"))
    assert TARGET not in result(snapshot(scope="openid"))


def test_denied_authorization_list_is_unresolved():
    snap = snapshot(auth_status="denied")
    next(row for row in snap["collections"] if row["type"] == "agentidentity_authorization")["items"] = []
    assert any(target.startswith("unresolved:") for target in result(snap))


def test_archived_user_wide_contract_is_held():
    from peaso.privesc.versioned_catalog import _verified_prior
    prior, _ = _verified_prior()
    model = GcpModel(snapshot())
    assert Evaluator(model, [prior[TECHNIQUE]]).run() == []
    assert any(TECHNIQUE in row["reason"] for row in model.coverage)
