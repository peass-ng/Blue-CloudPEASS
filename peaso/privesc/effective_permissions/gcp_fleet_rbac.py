"""Fleet RBAC reaches only members with an observed admin-equivalent ClusterRole."""
from __future__ import annotations

import re
from collections import Counter

from . import ANY, inventory_status, items
from .gcp_config_connector import _same_cluster
from .gcp_config_delivery import _canonical_membership, _member_cluster


def _status(model, kind, host):
    states = {model._norm_scope(scope): state for scope, state in inventory_status(model.snapshot, kind).items()}
    return states.get(host, "not_collected")


def _grant(model, source, action, resource):
    grant = model.check(source, {"action": action}, ANY if resource == "*" else resource)
    return None if grant is None else grant.confidence


def _admin_roles(model, cluster):
    if cluster in model.__dict__.get("_ambiguous_k8s", ()):
        return None
    joined = (model.related_k8s or {}).get(cluster)
    if not joined:
        return None
    cluster_id, snapshot = joined
    states = inventory_status(snapshot, "clusterrole")
    if not states or any(state not in ("collected", "empty") for state in states.values()):
        return None
    rows = [row for _, row in items(snapshot, "clusterrole") if _same_cluster(row, cluster_id, snapshot)]
    counts = Counter((row.get("metadata") or {}).get("name") for row in rows)
    names = set()
    for row in rows:
        name = (row.get("metadata") or {}).get("name")
        rules = row.get("rules")
        if not isinstance(name, str) or not name or counts[name] != 1 or not isinstance(rules, list):
            continue
        if any(isinstance(rule, dict) and "*" in (rule.get("apiGroups") or []) and
               "*" in (rule.get("resources") or []) and "*" in (rule.get("verbs") or []) and
               not rule.get("resourceNames") for rule in rules):
            names.add(name)
    return names


def _prior_admin(model, source, cluster, roles):
    joined = (model.related_k8s or {}).get(cluster)
    if not joined:
        return None
    cluster_id, snapshot = joined
    states = inventory_status(snapshot, "clusterrolebinding")
    if not states or any(state not in ("collected", "empty") for state in states.values()):
        return None
    email = source.attrs.get("email")
    if not isinstance(email, str) or not email:
        return None
    for _, row in items(snapshot, "clusterrolebinding"):
        if not _same_cluster(row, cluster_id, snapshot):
            continue
        ref = row.get("roleRef") or {}
        if ref.get("kind") != "ClusterRole" or ref.get("name") not in roles:
            continue
        if any(isinstance(subject, dict) and (
                subject.get("kind") == "User" and subject.get("name") == email or
                subject.get("kind") == "Group" and
                subject.get("name") == "system:authenticated")
               for subject in row.get("subjects") or []):
            return True
    return False


def _gateway(model, source, membership, cluster):
    credentials = _grant(model, source, "gkehub.gateway.generateCredentials", membership)
    read = _grant(model, source, "gkehub.gateway.get", membership)
    writes = [_grant(model, source, action, membership) for action in (
        "gkehub.gateway.post", "gkehub.gateway.put", "gkehub.gateway.patch",
        "gkehub.gateway.delete")]
    if credentials and read and any(writes):
        return "conditional" if credentials == read == "derived" and "derived" in writes else "unknown"
    # A membership IAM policy writer can grant itself Gateway Admin, but the
    # policy and role must be readable to avoid inferring access from a denial.
    self_grant = _grant(model, source, "gkehub.memberships.setIamPolicy", membership)
    if self_grant:
        role = model.roles.get("roles/gkehub.gatewayAdmin")
        policy = model.resource_policy_status.get("fleet_membership", {}).get(membership)
        if (self_grant == "derived" and policy == "collected" and role is not None and
                role.confidence == "derived" and role.has("gkehub.gateway.post") and
                role.has("gkehub.gateway.generatecredentials")):
            return "conditional"
        return "unknown"
    # Direct GKE access is usable only when the recorded public endpoint has
    # no master-authorized-network restriction. Other network paths stay open.
    direct = _grant(model, source, "container.clusters.get", cluster)
    if direct:
        target = model.gke.get(cluster) or {}
        private = (target.get("privateClusterConfig") or {}).get("enablePrivateEndpoint")
        networks = (target.get("masterAuthorizedNetworksConfig") or {}).get("enabled")
        if (direct == "derived" and isinstance(target.get("endpoint"), str) and target["endpoint"] and
                private is False and networks is False):
            return "conditional"
        return "unknown"
    return None


def _bindings(model, host, kind, parent):
    rows = []
    for scope, row in items(model.snapshot, kind):
        if model._norm_scope(scope) != host:
            continue
        name = model._norm_scope(row.get("name"))
        if re.fullmatch(re.escape(parent) + r"/rbacrolebindings/[^/]+", name):
            rows.append((name, row))
    return rows


def _route(model, source, host, parent, kind):
    create = _grant(model, source, "gkehub.rbacrolebindings.create", parent)
    if create == "derived":
        return "conditional"
    possible = "unknown" if create else None
    state = _status(model, kind, host)
    if state not in ("collected", "empty"):
        return possible or ("unknown" if _grant(model, source, "gkehub.rbacrolebindings.update", "*") else None)
    for name, row in _bindings(model, host, kind, parent):
        update = _grant(model, source, "gkehub.rbacrolebindings.update", name)
        if update == "derived" and (row.get("state") or {}).get("code") == "READY":
            return "conditional"
        if update:
            possible = "unknown"
    return possible


def unknown_scopes(model):
    return {scope: "gke_cluster_inventory_" + state for scope, state in model.gke_status.items()
            if state not in ("collected", "empty")}


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    if not any(_grant(model, source, action, "*") for action in (
            "gkehub.rbacrolebindings.create", "gkehub.rbacrolebindings.update")):
        return {}
    members = [(model._norm_scope(scope), row) for scope, row in items(model.snapshot, "fleet_membership")]
    out = {}
    for ident, target in candidates.items():
        cluster = target.attrs.get("cluster")
        if target.kind != "k8s_cluster_admin" or cluster not in model.gke:
            continue
        cluster_state = (model.gke.get(cluster) or {}).get("status")
        if cluster_state != "RUNNING":
            if cluster_state not in ("DELETING", "STOPPING"):
                out[ident] = ("unknown", "gke_cluster_readiness_unverified")
            continue
        joined = [(host, _canonical_membership(model, row.get("name")), row) for host, row in members
                  if _member_cluster(model, row) == cluster]
        if len(joined) != 1:
            if len(joined) > 1 or any(_status(model, "fleet_membership", host) not in ("collected", "empty")
                                        for host in {model._norm_scope(s) for s in model.scopes
                                                     if str(s).startswith("projects/") and str(s).count("/") == 1}):
                out[ident] = ("unknown", "fleet_membership_join_unverified")
            continue
        host, membership, member_row = joined[0]
        if (not membership or not membership.startswith(host + "/") or
                _status(model, "fleet_membership", host) not in ("collected", "empty")):
            out[ident] = ("unknown", "fleet_membership_identity_or_inventory_unverified")
            continue
        state = (member_row.get("state") or {}).get("code")
        if state != "READY":
            if state != "DELETING":
                out[ident] = ("unknown", "fleet_membership_readiness_unverified")
            continue
        can_create = _grant(model, source, "gkehub.rbacrolebindings.create", membership)
        can_update = _grant(model, source, "gkehub.rbacrolebindings.update", "*")
        can_scope_create = _grant(model, source, "gkehub.rbacrolebindings.create", "*")
        if not can_create and not can_update and not can_scope_create:
            continue
        roles = _admin_roles(model, cluster)
        if roles is None:
            out[ident] = ("unknown", "joined_cluster_role_inventory_incomplete")
            continue
        if not roles or roles == {"cluster-admin"}:
            if roles:
                out[ident] = ("unknown", "fleet_custom_cluster_role_eligibility_unverified")
            continue
        prior = _prior_admin(model, source, cluster, roles)
        if prior is None:
            out[ident] = ("unknown", "joined_cluster_binding_inventory_incomplete")
            continue
        if prior:
            continue
        transport = _gateway(model, source, membership, cluster)
        if transport is None:
            out[ident] = ("unknown", "cluster_api_access_path_unverified")
            continue
        routes = [_route(model, source, host, membership, "fleet_member_rbac_binding")]
        scope_state = _status(model, "fleet_scope", host)
        links_state = _status(model, "fleet_scope_member", host)
        if scope_state in ("collected", "empty") and links_state in ("collected", "empty"):
            scope_items = [(model._norm_scope(row.get("name")), row)
                           for scope, row in items(model.snapshot, "fleet_scope")
                           if model._norm_scope(scope) == host]
            scope_counts = Counter(name for name, _ in scope_items)
            scope_rows = dict(scope_items)
            for scope, link in items(model.snapshot, "fleet_scope_member"):
                if (model._norm_scope(scope) != host or
                        _canonical_membership(model, link.get("membership")) != membership):
                    continue
                name = model._norm_scope(link.get("scope"))
                if (name.startswith(host + "/locations/global/scopes/") and
                        scope_counts[name] == 1 and
                        (scope_rows.get(name, {}).get("state") or {}).get("code") == "READY"):
                    routes.append(_route(model, source, host, name, "fleet_scope_rbac_binding"))
                elif name.startswith(host + "/locations/global/scopes/") and scope_counts[name] != 1:
                    routes.append("unknown")
        elif can_scope_create:
            routes.append("unknown")
        if "conditional" in routes and transport == "conditional":
            out[ident] = ("conditional", f"fleet_member:{membership};custom_cluster_role_and_rbac_actuation_conditional")
        elif any(routes):
            out[ident] = ("unknown", "fleet_rbac_route_or_access_conditional")
    return out
