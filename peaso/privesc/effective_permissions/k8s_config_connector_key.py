"""Exact in-cluster Config Connector key route to a Google service account."""

from __future__ import annotations

from . import inventory_status, items
from .gcp_config_connector import _configuration_mode, _health, _identities, _same_cluster


def _rbac(model, source, namespace, verb, resource, group=""):
    return model.check(
        source, {"verb": verb, "api_group": group, "resource": resource,
                 "_rbac_only": True}, (namespace, None, ""))


def select(model, candidates, source):
    if source is None or source.kind != "k8s_service_account":
        return {}
    cluster = source.attrs.get("cluster")
    if not isinstance(cluster, str):
        return {}
    controllers = [cloud for cloud in model.related.models["gcp"] if cluster in cloud.gke]
    if len(controllers) != 1:
        return {tid: ("unknown", "gke_cloud_snapshot_join_unresolved") for tid in candidates}
    cloud = controllers[0]
    mode = _configuration_mode(model.snapshot, cluster)
    needed = ("configconnector", "api_discovery") + (
        ("configconnectorcontext",) if mode == "namespaced" else
        ("namespace",) if mode == "cluster" else ())
    if any(not (status := inventory_status(model.snapshot, kind)) or
           any(state not in ("collected", "empty") for state in status.values())
           for kind in needed):
        return {tid: ("unknown", "kcc_configuration_inventory_incomplete") for tid in candidates}
    discoveries = [row for _, row in items(model.snapshot, "api_discovery")
                   if _same_cluster(row, cluster, model.snapshot)]
    if len(discoveries) != 1 or discoveries[0].get("kccIAMServiceAccountKeyAdvertised") is not True:
        return {tid: ("unknown", "kcc_key_resource_discovery_unresolved") for tid in candidates} if (
            len(discoveries) != 1 or discoveries[0].get("kccIAMServiceAccountKeyAdvertised") is not False) else {}
    routes = []
    for namespace, email, configuration, config in _identities(model.snapshot, cluster):
        create = _rbac(model, source, namespace, "create", "iamserviceaccountkeys",
                       "iam.cnrm.cloud.google.com")
        if create is None:
            continue
        controller = cloud.sas.get("serviceAccount:" + email)
        if controller is None or controller.attrs.get("disabled"):
            continue
        health = _health(configuration, config)
        if health is False:
            continue
        reads = [
            ("generated_secret", _rbac(model, source, namespace, "get", "secrets")),
            ("key_resource_status", _rbac(model, source, namespace, "get",
                                          "iamserviceaccountkeys", "iam.cnrm.cloud.google.com")),
            ("provided_public_key", None),
        ]
        for route, read in reads:
            if route == "provided_public_key" or read is not None:
                routes.append((namespace, controller, health, route, create, read))
    out = {}
    for tid, target in candidates.items():
        if target.attrs.get("disabled") or not target.attrs.get("resource"):
            continue
        if tid not in cloud.sas:
            continue
        annotation = (source.attrs.get("annotations") or {}).get("iam.gke.io/gcp-service-account")
        if annotation == target.attrs.get("email"):
            already = model.related.gcp_wi_grant(target.attrs["email"],
                                                 source.attrs["namespace"], source.attrs["name"])
            if already is not None and already is not False and already.confidence == "derived":
                continue
        best = None
        for namespace, controller, health, route, create, read in routes:
            resource = target.attrs["resource"]
            delegated = cloud.check(controller, {"action": "iam.serviceAccountKeys.create"}, resource)
            if delegated is None:
                continue
            policy_kind = "Upload" if route == "provided_public_key" else "Creation"
            policy = cloud._sa_key_policy(
                target.attrs.get("project") or target.scope,
                "iam.managed.disableServiceAccountKey" + policy_kind,
                "iam.disableServiceAccountKey" + policy_kind)
            if policy is True:
                continue
            lifecycle = [cloud.check(controller, {"action": "iam.serviceAccountKeys." + action}, resource)
                         for action in ("get", "list", "delete")]
            if policy is None:
                verdict = ("unknown", "effective_key_policy_unverified")
            elif any(grant is None or grant.confidence != "derived" for grant in lifecycle):
                verdict = ("unknown", "controller_key_lifecycle_unverified")
            elif (create.confidence != "derived" or delegated.confidence != "derived"
                  or (read is not None and read.confidence != "derived")):
                verdict = ("unknown", "source_or_controller_permission_conditional")
            else:
                reason = f"kcc_{route}:{cluster}:{namespace};key_reconciliation_not_observed"
                if health is not True:
                    reason += ";kcc_controller_health_unverified"
                verdict = ("conditional", reason)
            if best is None or (best[0] == "unknown" and verdict[0] == "conditional"):
                best = verdict
                if verdict[0] == "conditional":
                    break
        if best is not None:
            out[tid] = best
    return out
