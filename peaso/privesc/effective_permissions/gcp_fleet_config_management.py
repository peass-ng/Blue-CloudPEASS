"""Bind Config Management edits to one fleet member and its GKE cluster."""
from __future__ import annotations

from . import inventory_status, items
from .gcp_config_delivery import _canonical_membership, _member_cluster, _root_sync

FEATURE_ID = "/locations/global/features/configmanagement"
MEMBER_FEATURE_ID = "/features/configmanagement"


def _status(model, kind, host):
    states = {model._norm_scope(scope): state for scope, state in inventory_status(model.snapshot, kind).items()}
    return states.get(host, "not_collected")


def _feature(model, host):
    rows = [row for scope, row in items(model.snapshot, "fleet_feature")
            if model._norm_scope(scope) == host and
            model._norm_scope(row.get("name")) == host + FEATURE_ID]
    if len(rows) > 1:
        return "unknown"
    if not rows:
        return "absent"
    state = (rows[0].get("resourceState") or {}).get("state")
    return "active" if state == "ACTIVE" else "unknown"


def _membership_feature(model, host, member):
    rows = [row for scope, row in items(model.snapshot, "fleet_membership_feature")
            if model._norm_scope(scope) == host and
            _canonical_membership(model, str(row.get("name", "")).removesuffix(MEMBER_FEATURE_ID)) == member and
            str(row.get("name", "")).endswith(MEMBER_FEATURE_ID)]
    if len(rows) > 1:
        return "unknown"
    if not rows:
        return "absent"
    state = (rows[0].get("lifecycleState") or {}).get("state")
    return "active" if state == "ACTIVE" else "unknown"


def _route(model, source, action, resource):
    grant = model.check(source, {"action": action}, resource)
    if grant is None:
        return None
    return "conditional" if grant.confidence == "derived" else "unknown"


def unknown_scopes(model):
    return {scope: "gke_cluster_inventory_" + state for scope, state in model.gke_status.items()
            if state not in ("collected", "empty")}


def select(model, candidates, source):
    if source is None:
        return {}
    out = {}
    memberships = [(model._norm_scope(scope), row) for scope, row in items(model.snapshot, "fleet_membership")]
    for ident, target in candidates.items():
        cluster = target.attrs.get("cluster")
        if target.kind != "k8s_cluster_admin" or cluster not in model.gke:
            continue
        joined = [(host, member, _canonical_membership(model, member.get("name")))
                  for host, member in memberships if _member_cluster(model, member) == cluster]
        if len(joined) != 1:
            if len(joined) > 1:
                out[ident] = ("unknown", "multiple_fleet_memberships_for_cluster")
            elif any(_status(model, "fleet_membership", host) not in ("collected", "empty")
                     for host in {model._norm_scope(s) for s in model.scopes if str(s).startswith("projects/")}):
                out[ident] = ("unknown", "fleet_membership_inventory_incomplete")
            continue
        host, member, membership = joined[0]
        if (membership is None or not membership.startswith(host + "/") or
                _status(model, "fleet_membership", host) not in ("collected", "empty")):
            out[ident] = ("unknown", "fleet_membership_identity_or_inventory_unverified")
            continue
        possible_actions = (("gkehub.features.create", host + "/locations/global"),
                            ("gkehub.features.update", host + FEATURE_ID),
                            ("gkehub.membershipfeatures.create", membership),
                            ("gkehub.membershipfeatures.update", membership + MEMBER_FEATURE_ID))
        if not any(model.check(source, {"action": action}, resource) is not None
                   for action, resource in possible_actions):
            continue
        if _status(model, "fleet_feature", host) not in ("collected", "empty"):
            out[ident] = ("unknown", "fleet_feature_inventory_incomplete")
            continue
        if _status(model, "fleet_membership_feature", host) not in ("collected", "empty"):
            out[ident] = ("unknown", "membership_feature_inventory_incomplete")
            continue
        feature = _feature(model, host)
        member_feature = _membership_feature(model, host, membership)
        if "unknown" in (feature, member_feature):
            out[ident] = ("unknown", "config_management_feature_lifecycle_unverified")
            continue
        if feature == "absent" and member_feature != "absent":
            out[ident] = ("unknown", "membership_feature_without_fleet_feature")
            continue
        if feature == "absent" and not model.check(source, {"action": "gkehub.features.create"},
                                                    host + "/locations/global"):
            # The API documentation does not establish whether a standalone
            # MembershipFeature create can enable an absent fleet Feature.
            if model.check(source, {"action": "gkehub.membershipfeatures.create"}, membership):
                out[ident] = ("unknown", "fleet_feature_enablement_prerequisite_unverified")
            continue
        root = _root_sync(model, cluster, "root-sync")
        if root is None or root == "restricted":
            out[ident] = ("unknown", "config_sync_root_authority_unverified")
            continue
        # v1 Feature mutation and v2 MembershipFeature mutation are separate
        # API routes. Each route checks only the permission that API requires.
        routes = []
        if feature == "absent":
            routes.append(("gkehub.features.create", host + "/locations/global"))
        else:
            routes.append(("gkehub.features.update", host + FEATURE_ID))
            if member_feature == "absent":
                routes.append(("gkehub.membershipfeatures.create", membership))
            else:
                routes.append(("gkehub.membershipfeatures.update", membership + MEMBER_FEATURE_ID))
        outcomes = [_route(model, source, action, resource) for action, resource in routes]
        if "conditional" in outcomes:
            out[ident] = ("conditional", f"fleet_member:{membership};config_sync_source_reconciliation_and_admission_conditional")
        elif "unknown" in outcomes:
            out[ident] = ("unknown", "config_management_permission_conditional")
    return out
