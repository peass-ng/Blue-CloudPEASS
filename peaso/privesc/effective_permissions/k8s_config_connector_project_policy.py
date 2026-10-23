"""Project IAM grants through an in-cluster Config Connector policy write."""

from __future__ import annotations

from collections import Counter
import re

from . import Node, inventory_status
from .gcp_config_connector import candidates as cloud_candidates


def targets(model):
    """Reuse the verified cloud target, adding only the K8s object coordinates."""
    cached = model.__dict__.get("_kcc_project_policy_targets")
    if cached is not None:
        return cached
    possible = []
    for cloud in model.related.models["gcp"]:
        cloud.set_related([model.snapshot])
        for target in cloud_candidates(cloud).values():
            attrs = {**target.attrs, "cluster": target.attrs["host_resource"],
                     "namespace": target.attrs["kcc_namespace"],
                     "name": target.attrs.get("kcc_resource_name")}
            possible.append(Node(target.id, target.kind, target.provider, target.scope,
                                 target.label, attrs=attrs, entity=True))
    count = Counter(target.id for target in possible)
    result = {target.id: target for target in possible if count[target.id] == 1}
    model.__dict__["_kcc_project_policy_ambiguous"] = {
        target.scope for target in possible if count[target.id] > 1}
    model.__dict__["_kcc_project_policy_targets"] = result
    return result


def unknown_scopes(model):
    from .gcp_config_connector import unresolved_scopes
    out = {}
    if not model.related.models["gcp"]:
        for cluster in model.clusters:
            if re.fullmatch(r"projects/[^/]+/locations/[^/]+/clusters/[^/]+", cluster):
                out[cluster.split("/locations/", 1)[0]] = "related_gcp_snapshot_missing"
        return out
    for cloud in model.related.models["gcp"]:
        cloud.set_related([model.snapshot])
        out.update(unresolved_scopes(cloud))
    targets(model)
    out.update({scope: "related_gcp_snapshot_join_ambiguous"
                for scope in model.__dict__.get("_kcc_project_policy_ambiguous", ())})
    return out


def _route_grant(model, source, target):
    namespace = target.attrs["namespace"]
    operation = target.attrs["kcc_operation"]
    resource_kind = target.attrs["kcc_resource_kind"]
    resource = {"IAMPolicyMember": "iampolicymembers",
                "kcc_iampolicy": "iampolicies",
                "kcc_iampartialpolicy": "iampartialpolicies"}[resource_kind]
    name = target.attrs.get("name") if operation == "update" else None
    grants = [model.check(source, {"verb": verb, "api_group": "iam.cnrm.cloud.google.com",
                                   "resource": resource, "_rbac_only": True},
                          (namespace, name, ""))
              for verb in (("update", "patch") if operation == "update" else ("create",))]
    return next((grant for grant in grants if grant is not None and grant.confidence == "derived"),
                next((grant for grant in grants if grant is not None), None))


def _existing_cloud_control(model, source, project, cluster):
    annotation = (source.attrs.get("annotations") or {}).get("iam.gke.io/gcp-service-account")
    if not isinstance(annotation, str):
        return None
    clouds = [cloud for cloud in model.related.models["gcp"] if cluster in cloud.gke]
    if len(clouds) != 1:
        return "unknown"
    states = inventory_status(clouds[0].snapshot, "iam_policy")
    if not states or any(state not in ("collected", "empty") for state in states.values()):
        return "unknown"
    wi = model.related.gcp_wi_grant(annotation, source.attrs["namespace"], source.attrs["name"])
    if wi is None:
        return "unknown"
    if wi is False:
        return None
    sa = clouds[0].sas.get("serviceAccount:" + annotation)
    if sa is None:
        return "unknown"
    control = clouds[0].check(sa, {"action": "resourcemanager.projects.setIamPolicy"}, project)
    if control is None:
        return None
    return "derived" if wi.confidence == control.confidence == "derived" else "unknown"


def select(model, candidates, source):
    if source is None or source.kind != "k8s_service_account":
        return {}
    cluster = source.attrs.get("cluster")
    if not isinstance(cluster, str):
        return {}
    out = {}
    ready = all((status := inventory_status(model.snapshot, kind)) and
                all(state in ("collected", "empty") for state in status.values())
                for kind in ("role", "clusterrole", "rolebinding", "clusterrolebinding"))
    for ident, target in candidates.items():
        if target.attrs.get("cluster") != cluster:
            continue
        if target.attrs.get("kcc_configuration_healthy") is False:
            continue
        if not ready:
            out[ident] = ("unknown", "namespace_rbac_inventory_incomplete")
            continue
        grant = _route_grant(model, source, target)
        if grant is None:
            continue
        prior = _existing_cloud_control(model, source, target.scope, cluster)
        if prior == "derived":
            continue
        if prior == "unknown":
            out[ident] = ("unknown", "existing_workload_identity_project_control_unresolved")
        elif (grant.confidence != "derived" or target.attrs["kcc_get_confidence"] != "derived"
              or target.attrs["kcc_set_confidence"] != "derived"):
            out[ident] = ("unknown", "source_or_controller_permission_conditional")
        else:
            reason = "kcc_reconciliation_and_admission_not_observed"
            if target.attrs.get("kcc_configuration_healthy") is not True:
                reason += ";kcc_controller_health_unverified"
            out[ident] = ("conditional", reason)
    return out
