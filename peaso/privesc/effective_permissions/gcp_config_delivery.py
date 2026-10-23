"""Bind Config Delivery to an observed fleet member and Config Sync reconciler."""
from __future__ import annotations

import re

from . import inventory_status, items
from .gcp_config_connector import _same_cluster

TECHNIQUE = "gcp-configdelivery-fleetpackage-publish"
AUTHORING = (
    "configdelivery.resourceBundles.create",
    "configdelivery.releases.create",
    "configdelivery.variants.create",
    "configdelivery.releases.update",
)


def _canonical_membership(model, name):
    if not isinstance(name, str):
        return None
    parts = name.split("/")
    if len(parts) != 6 or parts[0] != "projects" or parts[2] != "locations" or parts[4] != "memberships":
        return None
    project = model._norm_scope("/".join(parts[:2]))
    return project + "/" + "/".join(parts[2:]) if project.startswith("projects/") else None


def _cluster_link(link):
    if not isinstance(link, str) or not link.startswith("//container.googleapis.com/projects/"):
        return None
    cluster = link.removeprefix("//container.googleapis.com/")
    parts = cluster.split("/")
    return cluster if (len(parts) == 6 and parts[0] == "projects" and parts[2] == "locations"
                       and parts[4] == "clusters" and all(parts)) else None


def _feature(model, host, membership):
    rows = [item for scope, item in items(model.snapshot, "fleet_feature")
            if model._norm_scope(scope) == host and
            model._norm_scope(item.get("name")) == host + "/locations/global/features/configmanagement"]
    if len(rows) != 1:
        return None
    row = rows[0]
    specs = row.get("membershipSpecs", {})
    states = row.get("membershipStates")
    if not isinstance(specs, dict) or not isinstance(states, dict):
        return None
    matching_specs = [value for key, value in specs.items() if _canonical_membership(model, key) == membership]
    matching_states = [value for key, value in states.items() if _canonical_membership(model, key) == membership]
    if len(matching_specs) > 1 or len(matching_states) != 1:
        return None
    configured = (matching_specs[0] if matching_specs else row.get("fleetDefaultMemberConfig")) or {}
    if not isinstance(configured, dict) or not isinstance(matching_states[0], dict):
        return None
    management = configured.get("configmanagement") or {}
    state_row = matching_states[0].get("state") or {}
    if not isinstance(management, dict) or not isinstance(state_row, dict):
        return None
    sync = management.get("configSync") or {}
    if not isinstance(sync, dict):
        return None
    state = state_row.get("code")
    if sync.get("enabled") is False or sync.get("stopSyncing") is True or state == "ERROR":
        return False
    if (sync.get("enabled") is True or
            "enabled" not in sync and any(name in sync for name in ("git", "oci"))) and state == "OK":
        return True
    return None


def _api_enabled(model, host):
    states = {model._norm_scope(scope): state for scope, state in
              inventory_status(model.snapshot, "service_usage").items()}
    if states.get(host) not in ("collected", "empty"):
        return None
    rows = [item for scope, item in items(model.snapshot, "service_usage")
            if model._norm_scope(scope) == host and
            model._norm_scope(item.get("name")) == host + "/services/configdelivery.googleapis.com"]
    return rows[0].get("state") == "ENABLED" if len(rows) == 1 and rows[0].get("state") in ("ENABLED", "DISABLED") else None


def _root_sync(model, cluster, package_name):
    if cluster in model.__dict__.get("_ambiguous_k8s", ()):
        return None
    joined = (model.related_k8s or {}).get(cluster)
    if not joined:
        return None
    cluster_id, snapshot = joined
    status = inventory_status(snapshot, "configsync_rootsync")
    if not status or any(state not in ("collected", "empty") for state in status.values()):
        return None
    roots = [item for _, item in items(snapshot, "configsync_rootsync")
             if _same_cluster(item, cluster_id, snapshot) and
             (item.get("metadata") or {}).get("namespace") == "config-management-system" and
             (item.get("metadata") or {}).get("name") == package_name]
    if not roots:
        return "absent"
    if len(roots) != 1 or not isinstance(roots[0].get("spec"), dict):
        return None
    override = roots[0]["spec"].get("override")
    if override is not None and not isinstance(override, dict):
        return None
    role_refs = (override or {}).get("roleRefs")
    if role_refs is None:
        return "default"
    if not isinstance(role_refs, list):
        return None
    if any(isinstance(ref, dict) and ref.get("kind") == "ClusterRole" and
           ref.get("name") == "cluster-admin" and not ref.get("namespace") for ref in role_refs):
        return "default"
    return "restricted"


def _package_name(model, host, package):
    name = package.get("name")
    if not isinstance(name, str) or not re.fullmatch(
            r"projects/[^/]+/locations/us-central1/fleetPackages/[a-z][a-z0-9-]{0,62}", name):
        return None
    return name.rsplit("/", 1)[-1] if model._norm_scope(name.split("/locations/", 1)[0]) == host else None


def _package_selects(model, host, package, member):
    target = package.get("target")
    if not isinstance(target, dict) or not isinstance(target.get("fleet"), dict):
        return None
    fleet = target["fleet"]
    if model._norm_scope(fleet.get("project")) != host:
        return False
    selector = fleet.get("selector")
    if selector is None:
        return True
    if not isinstance(selector, dict):
        return None
    labels = selector.get("matchLabels", {})
    current = member.get("labels") or {}
    if not isinstance(labels, dict) or not isinstance(current, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()):
        return None
    return all(current.get(key) == value for key, value in labels.items())


def _member_cluster(model, member):
    endpoint = member.get("endpoint")
    if not isinstance(endpoint, dict):
        return None
    gke = endpoint.get("gkeCluster")
    if not isinstance(gke, dict) or gke.get("clusterMissing") is True:
        return None
    link = _cluster_link(gke.get("resourceLink"))
    return model._norm_scope(link) if link else None


def unknown_scopes(model):
    projects = {scope for scope in model.scopes if scope.startswith("projects/") and scope.count("/") == 1}
    out = {}
    # Package inventory is needed only for update; create can reach a new
    # package without an existing object. The selector reports update gaps.
    for kind in ("fleet_membership", "fleet_feature"):
        states = {model._norm_scope(scope): state for scope, state in inventory_status(model.snapshot, kind).items()}
        for project in projects:
            if states.get(project) not in ("collected", "empty"):
                out[project] = kind + "_" + states.get(project, "not_collected")
    for scope, state in model.gke_status.items():
        if state not in ("collected", "empty"):
            out[scope] = "gke_cluster_inventory_" + state
    return out


def select(model, candidates, source):
    if source is None:
        return {}
    membership_status = {model._norm_scope(scope): state for scope, state in
                         inventory_status(model.snapshot, "fleet_membership").items()}
    feature_status = {model._norm_scope(scope): state for scope, state in
                      inventory_status(model.snapshot, "fleet_feature").items()}
    package_status = {model._norm_scope(scope): state for scope, state in
                      inventory_status(model.snapshot, "config_delivery_fleet_package").items()}
    out = {}
    for ident, target in candidates.items():
        cluster = target.attrs.get("cluster")
        if target.kind != "k8s_cluster_admin" or cluster not in model.gke:
            continue
        possible = []
        for host, member in items(model.snapshot, "fleet_membership"):
            host = model._norm_scope(host)
            if (membership_status.get(host) not in ("collected", "empty") or
                    feature_status.get(host) not in ("collected", "empty") or
                    _member_cluster(model, member) != cluster):
                continue
            membership = _canonical_membership(model, member.get("name"))
            if not membership or not membership.startswith(host + "/"):
                continue
            grants = [model.check(source, {"action": action}, host) for action in AUTHORING]
            if any(grant is None for grant in grants):
                continue
            create = model.check(source, {"action": "configdelivery.fleetPackages.create"}, host)
            update = model.check(source, {"action": "configdelivery.fleetPackages.update"}, host)
            host_packages = [row for scope, row in items(model.snapshot, "config_delivery_fleet_package")
                             if model._norm_scope(scope) == host]
            packages = [(name, row) for row in host_packages
                        if (name := _package_name(model, host, row)) is not None]
            update_possible = update is not None and bool(packages)
            if create is None and not update_possible:
                if update is not None and package_status.get(host) not in ("collected", "empty"):
                    possible.append(("unknown", "fleet_package_inventory_incomplete"))
                elif update is not None and host_packages:
                    possible.append(("unknown", "fleet_package_identity_unverified"))
                continue
            api_enabled = _api_enabled(model, host)
            if api_enabled is False:
                if model.check(source, {"action": "serviceusage.services.enable"}, host):
                    possible.append(("unknown", "config_delivery_api_must_be_enabled"))
                continue
            if api_enabled is None:
                possible.append(("unknown", "config_delivery_api_state_unverified"))
                continue
            feature = _feature(model, host, membership)
            if feature is False:
                continue
            if feature is None:
                possible.append(("unknown", "config_sync_state_unverified"))
                continue
            if create is not None and create.confidence == "derived" and all(
                    grant.confidence == "derived" for grant in grants):
                # A fresh package receives its own RootSync. An unrelated
                # existing RootSync cannot reduce this new reconciler's RBAC.
                possible.append(("conditional", f"fleet_member:{membership};new_package_reconciliation_and_admission_unobserved"))
                continue
            if create is not None and create.confidence != "derived":
                possible.append(("unknown", "config_delivery_permission_conditional"))
            if update is None:
                continue
            if package_status.get(host) not in ("collected", "empty"):
                possible.append(("unknown", "fleet_package_inventory_incomplete"))
                continue
            for package_name, package in packages:
                selection = _package_selects(model, host, package, member)
                # Patch accepts an update mask for target and source. Retargeting
                # an existing package within this fleet can include this member.
                if selection is None or model._norm_scope(
                        ((package.get("target") or {}).get("fleet") or {}).get("project")) != host:
                    possible.append(("unknown", "fleet_package_retargeting_unverified"))
                    continue
                root = _root_sync(model, cluster, package_name)
                if root is None or root == "restricted" or root == "absent" and selection is True:
                    possible.append(("unknown", "package_root_sync_authority_unverified"))
                elif update.confidence != "derived" or any(grant.confidence != "derived" for grant in grants):
                    possible.append(("unknown", "config_delivery_permission_conditional"))
                else:
                    possible.append(("conditional", f"fleet_member:{membership};package:{package_name};reconciliation_and_admission_unobserved"))
        if possible:
            out[ident] = next((result for result in possible if result[0] == "conditional"), possible[0])
    return out
