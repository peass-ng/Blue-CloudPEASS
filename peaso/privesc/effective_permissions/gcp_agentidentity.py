"""Bound an Agent Identity credential pivot to an existing authorization."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import Node, inventory_status, items


PROVIDER = re.compile(r"projects/[^/]+/locations/[^/]+/authProviders/[^/]+")
IDENTITY_ONLY = frozenset({
    "openid", "email", "profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
})
GOOGLE_AUTH_PATHS = frozenset({
    ("accounts.google.com", "/o/oauth2/v2/auth"),
    ("accounts.google.com", "/o/oauth2/auth"),
})
GOOGLE_TOKEN_PATHS = frozenset({
    ("oauth2.googleapis.com", "/token"),
    ("www.googleapis.com", "/oauth2/v4/token"),
    ("accounts.google.com", "/o/oauth2/token"),
})


def _google_endpoint(value, paths):
    if not isinstance(value, str):
        return False
    try:
        url = urlsplit(value)
        return (url.scheme == "https" and (url.hostname, url.path) in paths
                and url.port in (None, 443) and url.username is None
                and url.password is None and not url.query and not url.fragment)
    except ValueError:
        return False


def _useful_google_scope(value):
    return (isinstance(value, str) and value not in IDENTITY_ONLY
            and ((value.startswith("https://www.googleapis.com/auth/")
                  and len(value) > len("https://www.googleapis.com/auth/"))
                 or value in {"https://mail.google.com/", "https://www.google.com/m8/feeds/"}))


def targets(model):
    providers = {}
    duplicate_providers = set()
    provider_status = {model._norm_scope(scope): status for scope, status in
                       inventory_status(model.snapshot, "agentidentity_auth_provider").items()}
    authorization_status = {model._norm_scope(scope): status for scope, status in
                            inventory_status(model.snapshot, "agentidentity_authorization").items()}
    for project in sorted(scope for scope in model.scopes if str(scope).startswith("projects/")):
        for kind, status in (("agentidentity_auth_provider", provider_status.get(project)),
                             ("agentidentity_authorization", authorization_status.get(project))):
            if status not in ("collected", "empty"):
                model.add_coverage("collection", project, status or "not_collected",
                                   f"{kind} inventory incomplete",
                                   "Google OAuth credential paths in this project remain unresolved")
    for scope, item in items(model.snapshot, "agentidentity_auth_provider"):
        project = model._norm_scope(scope)
        raw_name = item.get("name")
        name = model._norm_scope(raw_name) if isinstance(raw_name, str) else None
        if (isinstance(name, str) and PROVIDER.fullmatch(name)
                and name.startswith(project + "/")):
            if name in providers:
                duplicate_providers.add(name)
            providers[name] = item
    out = {}
    duplicate_authorizations = set()
    for scope, item in items(model.snapshot, "agentidentity_authorization"):
        project = model._norm_scope(scope)
        raw_name, raw_provider, user_id = (item.get(k) for k in ("name", "authProvider", "clientUserId"))
        name = model._norm_scope(raw_name) if isinstance(raw_name, str) else None
        provider = model._norm_scope(raw_provider) if isinstance(raw_provider, str) else None
        if (not isinstance(provider, str) or not PROVIDER.fullmatch(provider)
                or not provider.startswith(project + "/")
                or not isinstance(name, str) or not name.startswith(provider + "/authorizations/")
                or "/" in name[len(provider + "/authorizations/"):]
                or not isinstance(user_id, str) or not user_id.strip()):
            continue
        ident = "gcp_verified_authority:agentidentity_authorization:" + name
        conflicting = ident in out or ident in duplicate_authorizations
        if conflicting:
            duplicate_authorizations.add(ident)
        out[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                          f"OAuth authorization {name} for client ID {user_id}",
                          attrs={"scope": project, "project": project, "resource": name,
                                 "policy_resource": provider, "client_user_id": user_id,
                                 "authorization": item, "conflicting_authorization": conflicting,
                                 "provider": None if provider in duplicate_providers else providers.get(provider)},
                          entity=True)
    for provider in providers:
        project = provider.split("/locations/", 1)[0]
        if authorization_status.get(project) in ("collected", "empty"):
            continue
        ident = "gcp_verified_authority:agentidentity_authorizations_unresolved:" + provider
        out[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                          f"Unresolved authorizations for {provider}",
                          attrs={"scope": project, "project": project, "resource": provider,
                                 "policy_resource": provider, "unresolved_authorizations": True}, entity=True)
    for project in sorted(scope for scope in model.scopes if str(scope).startswith("projects/")):
        if provider_status.get(project) in ("collected", "empty"):
            continue
        ident = "gcp_verified_authority:agentidentity_providers_unresolved:" + project
        out[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                          f"Unresolved Agent Identity providers in {project}",
                          attrs={"scope": project, "project": project, "resource": project,
                                 "policy_resource": project, "unresolved_authorizations": True}, entity=True)
    return out


def select(model, candidates, *, mode="retrieve"):
    out = {}
    provider_status = {model._norm_scope(scope): status for scope, status in
                       inventory_status(model.snapshot, "agentidentity_auth_provider").items()}
    authorization_status = {model._norm_scope(scope): status for scope, status in
                            inventory_status(model.snapshot, "agentidentity_authorization").items()}
    for ident, node in candidates.items():
        if node.attrs.get("unresolved_authorizations"):
            out[ident] = ("unknown", "agentidentity_inventory_incomplete")
            continue
        auth, provider = node.attrs.get("authorization"), node.attrs.get("provider")
        if not isinstance(auth, dict):
            continue
        if node.attrs.get("conflicting_authorization"):
            out[ident] = ("unknown", "authorization_rows_conflict")
            continue
        if auth.get("state") == "SUSPENDED" or (provider and
                (provider.get("state") == "DISABLED" or provider.get("deleted") is True)):
            continue
        scopes = auth.get("scopes")
        if not isinstance(scopes, list) or not scopes:
            out[ident] = ("unknown", "authorization_scopes_missing")
            continue
        if not any(_useful_google_scope(scope) for scope in scopes):
            continue
        if (auth.get("state") != "ACTIVE" or provider is None
                or provider_status.get(node.scope) not in ("collected", "partial")
                or authorization_status.get(node.scope) not in ("collected", "partial")
                or provider.get("state") != "ENABLED"):
            out[ident] = ("unknown", "provider_or_authorization_incomplete")
            continue
        params = provider.get("authProviderTypeParams")
        if not isinstance(params, dict):
            out[ident] = ("unknown", "provider_type_missing")
            continue
        oauth = params.get("threeLeggedOauth")
        if not isinstance(oauth, dict):
            continue
        if (not _google_endpoint(oauth.get("authorizationUrl"), GOOGLE_AUTH_PATHS)
                or not _google_endpoint(oauth.get("tokenUrl"), GOOGLE_TOKEN_PATHS)):
            continue
        allowed, blocked = provider.get("allowedScopes"), provider.get("blockedScopes")
        if (allowed is not None and not isinstance(allowed, list)) or (blocked is not None and not isinstance(blocked, list)):
            out[ident] = ("unknown", "provider_scope_policy_incomplete")
            continue
        eligible = [scope for scope in scopes if _useful_google_scope(scope)
                    and scope not in (blocked or []) and (not allowed or scope in allowed)]
        if not eligible:
            out[ident] = ("unknown", "granted_scopes_blocked_by_current_provider_policy")
            continue
        out[ident] = ("conditional", "active_google_oauth_authorization_with_useful_scopes"
                      if mode == "retrieve" else
                      "active_google_oauth_authorization_may_refresh_through_changed_endpoint")
    return out
