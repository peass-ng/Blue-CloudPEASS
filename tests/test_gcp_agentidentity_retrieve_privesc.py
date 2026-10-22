"""Agent Identity retrieval is bound to a real, active Google OAuth authorization."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
PROVIDER = PROJECT + "/locations/us-central1/authProviders/google"
AUTH = PROVIDER + "/authorizations/a1"
SOURCE = "user:reader@example.com"
TECHNIQUE = "gcp-agentidentity-retrieve-credentials"
TARGET = "gcp_verified_authority:agentidentity_authorization:" + AUTH


def snapshot(*, permission=True, provider_state="ENABLED", auth_state="ACTIVE",
             provider_type="threeLeggedOauth", auth_host="accounts.google.com",
             scopes=None, provider_name=PROVIDER, provider_status="collected",
             authorization_status="collected"):
    if scopes is None:
        scopes = ["https://www.googleapis.com/auth/drive.readonly"]
    def row(kind, value, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": value, "error": None}
    role = PROJECT + "/roles/reader"
    binding = {"role": role, "members": [SOURCE]}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": role, "includedPermissions":
                    ["agentidentity.authProviders.retrieveCredentials"] if permission else []}]),
                row("iam_policy", [{"name": PROJECT, "bindings": []}]),
                row("agentidentity_auth_provider", [{"name": provider_name,
                    "state": provider_state,
                    "authProviderTypeParams": {provider_type: {
                        "authorizationUrl": "https://" + auth_host + "/o/oauth2/v2/auth",
                        "tokenUrl": "https://oauth2.googleapis.com/token"}},
                    "iamPolicy": {"bindings": [binding]},
                    "_coverage": {"iamPolicy": {"status": "collected"}}}], provider_status),
                row("agentidentity_authorization", [{"name": AUTH,
                    "authProvider": PROVIDER, "clientUserId": "alice@example.com",
                    "scopes": scopes, "state": auth_state}], authorization_status),
                row("iam_deny_policy", [], "empty"),
            ]}


def result(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()}


def test_exact_active_google_authorization_is_conditional():
    assert result(snapshot())[TARGET] == "conditional"
    assert result(snapshot(scopes=["https://mail.google.com/"]))[TARGET] == "conditional"
    assert result(snapshot(provider_status="partial", authorization_status="partial"))[TARGET] == "conditional"


def test_numeric_project_alias_joins_the_same_provider_and_authorization():
    snap = snapshot()
    for row in snap["collections"]:
        if row["type"] == "agentidentity_auth_provider":
            row["items"][0]["name"] = PROVIDER.replace("projects/p1", "projects/111")
        if row["type"] == "agentidentity_authorization":
            row["items"][0]["name"] = AUTH.replace("projects/p1", "projects/111")
            row["items"][0]["authProvider"] = PROVIDER.replace("projects/p1", "projects/111")
    assert result(snap)[TARGET] == "conditional"


def test_missing_permission_and_wrong_provider_do_not_reach_authorization():
    assert TARGET not in result(snapshot(permission=False))
    assert TARGET not in result(snapshot(provider_name=PROJECT + "/locations/us-central1/authProviders/other"))


def test_disabled_or_suspended_auth_does_not_reach_authorization():
    assert TARGET not in result(snapshot(provider_state="DISABLED"))
    assert TARGET not in result(snapshot(auth_state="SUSPENDED"))


def test_non_google_or_non_user_oauth_does_not_claim_workspace_authority():
    assert TARGET not in result(snapshot(auth_host="auth.example.com"))
    assert TARGET not in result(snapshot(provider_type="apiKey"))
    assert TARGET not in result(snapshot(scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"]))


def test_granted_scope_blocked_after_consent_stays_unresolved():
    snap = snapshot()
    provider = next(row for row in snap["collections"] if row["type"] == "agentidentity_auth_provider")["items"][0]
    provider["blockedScopes"] = ["https://www.googleapis.com/auth/drive.readonly"]
    assert TARGET not in {key for key, value in result(snap).items() if value == "conditional"}


def test_malformed_oauth_endpoint_cannot_create_a_path():
    snap = snapshot()
    provider = next(row for row in snap["collections"] if row["type"] == "agentidentity_auth_provider")["items"][0]
    provider["authProviderTypeParams"]["threeLeggedOauth"]["authorizationUrl"] = "https://accounts.google.com:bad/o/oauth2/v2/auth"
    assert TARGET not in result(snap)


def test_incomplete_provider_or_authorization_is_unknown():
    assert TARGET not in {key for key, value in result(snapshot(provider_status="denied")).items()
                          if value == "conditional"}
    assert TARGET not in {key for key, value in result(snapshot(authorization_status="denied")).items()
                          if value == "conditional"}


def test_conflicting_authorization_rows_cannot_create_a_path():
    snap = snapshot()
    row = next(row for row in snap["collections"] if row["type"] == "agentidentity_authorization")
    row["items"].append({**row["items"][0], "state": "SUSPENDED"})
    assert TARGET not in {key for key, value in result(snap).items() if value == "conditional"}


def test_denied_authorization_list_is_unresolved():
    snap = snapshot()
    row = next(row for row in snap["collections"] if row["type"] == "agentidentity_authorization")
    row.update(items=[], status="denied")
    assert any(key.startswith("unresolved:") for key in result(snap))


def test_archived_generic_workspace_user_contract_is_held():
    from peaso.privesc.versioned_catalog import _verified_prior
    prior, _ = _verified_prior()
    model = GcpModel(snapshot())
    assert Evaluator(model, [prior[TECHNIQUE]]).run() == []
    assert any(TECHNIQUE in row["reason"] for row in model.coverage)
