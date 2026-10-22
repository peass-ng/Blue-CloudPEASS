"""Bounded Config Connector project IAM grant paths from joined GKE/K8s evidence."""
from __future__ import annotations

import re
from collections import Counter

from . import Node, inventory_status, items

TECHNIQUE = "gcp-configcontroller-kcc-resource-write"
EMAIL = re.compile(r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.gserviceaccount\.com\Z")
CONFIG_NAME = "configconnector.core.cnrm.cloud.google.com"
CONTEXT_NAME = "configconnectorcontext.core.cnrm.cloud.google.com"


def _same_cluster(item, cluster_id, snapshot):
    return str((item.get("provenance") or {}).get("cluster_id") or
               (item.get("metadata") or {}).get("cluster_id") or
               (snapshot.get("metadata") or {}).get("cluster_id") or "") == cluster_id


def _project_ref(item, model, snapshot, cluster_id):
    spec = item.get("spec")
    ref = spec.get("resourceRef") if isinstance(spec, dict) else None
    if not isinstance(ref, dict) or ref.get("kind") != "Project":
        return None
    external = ref.get("external")
    if isinstance(external, str):
        return model._norm_scope(external) if re.fullmatch(
            r"projects/[a-z][a-z0-9-]{4,61}[a-z0-9]", external) else None
    name = ref.get("name")
    namespace = ref.get("namespace") or (item.get("metadata") or {}).get("namespace")
    if not isinstance(name, str) or not isinstance(namespace, str):
        return None
    matches = [project for _, project in items(snapshot, "kcc_project")
               if _same_cluster(project, cluster_id, snapshot) and
               (project.get("metadata") or {}).get("name") == name and
               (project.get("metadata") or {}).get("namespace") == namespace]
    if len(matches) != 1:
        return None
    project = matches[0]
    meta, status = project.get("metadata") or {}, project.get("status") or {}
    project_id = (project.get("spec") or {}).get("resourceID") or name
    if (not isinstance(project_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", project_id)
            or not str(status.get("number") or "").isdigit()
            or not any(condition.get("type") == "Ready" and condition.get("status") in ("True", True)
                       for condition in status.get("conditions") or () if isinstance(condition, dict))):
        return None
    if (meta.get("generation") is not None and status.get("observedGeneration") is not None and
            meta["generation"] != status["observedGeneration"]):
        return None
    return model._norm_scope("projects/" + project_id)


def _identities(snapshot, cluster_id):
    """Return only uniquely configured KCC identities in watched namespaces."""
    configs = [item for _, item in items(snapshot, "configconnector")
               if _same_cluster(item, cluster_id, snapshot) and
               (item.get("metadata") or {}).get("name") == CONFIG_NAME]
    if len(configs) != 1:
        return []
    config = configs[0]
    if (config.get("status") or {}).get("healthy") is False:
        return []
    mode = (config.get("spec") or {}).get("mode")
    if mode == "cluster":
        email = (config.get("spec") or {}).get("googleServiceAccount")
        if not isinstance(email, str) or not EMAIL.fullmatch(email):
            return []
        namespaces = {(item.get("metadata") or {}).get("name") for _, item in items(snapshot, "namespace")
                      if _same_cluster(item, cluster_id, snapshot)}
        return [(namespace, email, config, config) for namespace in sorted(namespaces)
                if isinstance(namespace, str) and namespace]
    if mode != "namespaced":
        return []
    contexts = [item for _, item in items(snapshot, "configconnectorcontext")
                if _same_cluster(item, cluster_id, snapshot) and
                (item.get("metadata") or {}).get("name") == CONTEXT_NAME]
    counts = Counter((item.get("metadata") or {}).get("namespace") for item in contexts)
    found = []
    for context in contexts:
        namespace = (context.get("metadata") or {}).get("namespace")
        email = (context.get("spec") or {}).get("googleServiceAccount")
        if (isinstance(namespace, str) and namespace and counts[namespace] == 1 and
                isinstance(email, str) and EMAIL.fullmatch(email)):
            found.append((namespace, email, context, config))
    return found


def _configuration_mode(snapshot, cluster_id):
    configs = [item for _, item in items(snapshot, "configconnector")
               if _same_cluster(item, cluster_id, snapshot) and
               (item.get("metadata") or {}).get("name") == CONFIG_NAME]
    return (configs[0].get("spec") or {}).get("mode") if len(configs) == 1 else None


def _policy_updates(snapshot, cluster_id, namespace, project, model):
    found = []
    for kind, field in (("kcc_iampolicy", "kccIAMPolicyAdvertised"),
                        ("kcc_iampartialpolicy", "kccIAMPartialPolicyAdvertised")):
        for _, item in items(snapshot, kind):
            meta = item.get("metadata") or {}
            if (_same_cluster(item, cluster_id, snapshot) and meta.get("namespace") == namespace and
                    isinstance(meta.get("name"), str) and meta["name"] and
                    _project_ref(item, model, snapshot, cluster_id) == project):
                found.append((kind, meta["name"], field))
    return found


def _health(*objects):
    values = [(obj.get("status") or {}).get("healthy") for obj in objects]
    return False if False in values else True if all(value is True for value in values) else None


def unresolved_scopes(model):
    """Keep missing cross-cloud evidence visible without naming an unproven target."""
    out = {scope: "gke_cluster_inventory_" + status for scope, status in model.gke_status.items()
           if status not in ("collected", "empty")}
    if not model.gke_status:
        out.update({scope: "gke_cluster_inventory_missing" for scope in model.scopes
                    if scope.startswith("projects/") and scope.count("/") == 1})
    for cluster in model.gke:
        project = cluster.split("/locations/", 1)[0]
        joined = (model.related_k8s or {}).get(cluster)
        if cluster in model.__dict__.get("_ambiguous_k8s", ()) or joined is None:
            out[project] = "k8s_snapshot_not_uniquely_joined"
            continue
        cluster_id, snapshot = joined
        mode = _configuration_mode(snapshot, cluster_id)
        kinds = ("configconnector", "api_discovery") + (("configconnectorcontext",) if mode == "namespaced"
                    else ("namespace",) if mode == "cluster" else ())
        for kind in kinds:
            status = inventory_status(snapshot, kind)
            if not status or any(state not in ("collected", "empty") for state in status.values()):
                out[project] = "kcc_configuration_inventory_incomplete"
                break
        else:
            identities = _identities(snapshot, cluster_id)
            discoveries = [item for _, item in items(snapshot, "api_discovery")
                           if _same_cluster(item, cluster_id, snapshot)]
            if len(discoveries) != 1 or any(not isinstance(discoveries[0].get(field), bool) for field in
                    ("kccIAMPolicyMemberAdvertised", "kccIAMPolicyAdvertised", "kccIAMPartialPolicyAdvertised")):
                out[project] = "kcc_iam_resource_discovery_incomplete"
            elif any(discoveries[0].get(field) is True and
                    (not (status := inventory_status(snapshot, kind)) or
                     any(state not in ("collected", "empty") for state in status.values()))
                    for kind, field in (("kcc_iampolicy", "kccIAMPolicyAdvertised"),
                                        ("kcc_iampartialpolicy", "kccIAMPartialPolicyAdvertised"))):
                out[project] = "kcc_existing_policy_inventory_incomplete"
            elif any(_same_cluster(item, cluster_id, snapshot) and
                     isinstance(item.get("spec"), dict) and
                     isinstance(item["spec"].get("resourceRef"), dict) and
                     item["spec"]["resourceRef"].get("kind") == "Project" and
                     item["spec"]["resourceRef"].get("name") and
                     _project_ref(item, model, snapshot, cluster_id) is None
                     for kind in ("kcc_iampolicy", "kcc_iampartialpolicy")
                     for _, item in items(snapshot, kind)):
                out[project] = "kcc_project_reference_unresolved"
            elif any("serviceAccount:" + email not in model.sas for _, email, _, _ in identities):
                out[project] = "kcc_service_account_inventory_incomplete"
            elif identities and (not inventory_status(model.snapshot, "iam_policy") or
                    any(state not in ("collected", "empty") for state in
                        inventory_status(model.snapshot, "iam_policy").values())):
                out[project] = "project_iam_policy_inventory_missing"
    return out


def candidates(model):
    out = {}
    projects = {model._norm_scope(scope) for scope in model.scopes if
                model._norm_scope(scope).startswith("projects/") and model._norm_scope(scope).count("/") == 1}
    for scope, item in items(model.snapshot, "project"):
        project = model._norm_scope(item.get("name") or scope)
        if project.startswith("projects/") and project.count("/") == 1:
            projects.add(project)
    for cluster in sorted(model.gke):
        if cluster in model.__dict__.get("_ambiguous_k8s", ()):
            continue
        joined = (model.related_k8s or {}).get(cluster)
        if not joined:
            continue
        cluster_id, snapshot = joined
        gke = model.gke[cluster]
        private = gke.get("privateClusterConfig") or {}
        authorized = gke.get("masterAuthorizedNetworksConfig") or {}
        api_access = ("public" if isinstance(gke.get("endpoint"), str) and gke["endpoint"] and
                      private.get("enablePrivateEndpoint") is not True and authorized.get("enabled") is not True
                      else "unverified")
        mode = _configuration_mode(snapshot, cluster_id)
        needed = ("configconnector", "api_discovery") + (("configconnectorcontext",) if mode == "namespaced"
                    else ("namespace",) if mode == "cluster" else ())
        statuses = tuple(inventory_status(snapshot, kind) for kind in needed)
        if any(not status or any(state not in ("collected", "empty") for state in status.values())
               for status in statuses):
            continue
        discoveries = [item for _, item in items(snapshot, "api_discovery")
                       if _same_cluster(item, cluster_id, snapshot)]
        if len(discoveries) != 1:
            continue
        discovery = discoveries[0]
        kcc_member = discovery.get("kccIAMPolicyMemberAdvertised") is True
        for namespace, email, configuration, config in _identities(snapshot, cluster_id):
            sa = model.sas.get("serviceAccount:" + email)
            if sa is None or sa.attrs.get("disabled"):
                continue
            for project in sorted(projects):
                get_grant = model.check(sa, {"action": "resourcemanager.projects.getIamPolicy"}, project)
                set_grant = model.check(sa, {"action": "resourcemanager.projects.setIamPolicy"}, project)
                if get_grant is None or set_grant is None:
                    continue
                routes = []
                if kcc_member:
                    routes.append(("create", "IAMPolicyMember", None))
                routes.extend(("update", kind, name) for kind, name, field in
                              _policy_updates(snapshot, cluster_id, namespace, project, model)
                              if discovery.get(field) is True)
                for operation, resource_kind, resource_name in routes:
                    ident = (f"gcp_verified_authority:kcc-project-iam:{cluster}:{namespace}:"
                             f"{project}:{operation}:{resource_kind}:{resource_name or '*'}")
                    out[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                        f"Project IAM grant on {project} through Config Connector in {namespace}",
                        attrs={"resource": project, "policy_resource": project, "host_resource": cluster,
                               "kcc_namespace": namespace, "kcc_service_account": email,
                               "kcc_operation": operation, "kcc_resource_kind": resource_kind,
                               "kcc_resource_name": resource_name,
                               "kcc_configuration_healthy": _health(configuration, config),
                               "kcc_api_access": api_access,
                               "kcc_get_confidence": get_grant.confidence,
                               "kcc_set_confidence": set_grant.confidence}, entity=True)
    return out


def select(model, candidates, source):
    if source is None:
        return {}
    out = {}
    rbac_cache = {}
    for ident, target in candidates.items():
        if target.attrs.get("kcc_service_account") == source.attrs.get("email"):
            continue
        project = target.scope
        # An existing direct project-policy write means this route does not add
        # project IAM control to the source.
        direct = model.check(source, {"action": "resourcemanager.projects.setIamPolicy"}, project)
        if direct is not None and direct.confidence == "derived":
            continue
        if direct is not None:
            out[ident] = ("unknown", "existing_project_iam_control_uncertain")
            continue
        action = "container.thirdPartyObjects." + target.attrs["kcc_operation"]
        write = model.check(source, {"action": action}, target.attrs["host_resource"])
        authenticate = model.check(source, {"action": "container.clusters.get"},
                                   target.attrs["host_resource"])
        cluster = target.attrs["host_resource"]
        joined = (model.related_k8s or {}).get(cluster)
        rbac_uncertain = False
        rbac_write = None
        if joined is not None and cluster not in model.__dict__.get("_ambiguous_k8s", ()):
            cluster_id, snapshot = joined
            ready = all(
                (status := inventory_status(snapshot, kind)) and
                all(state in ("collected", "empty") for state in status.values())
                for kind in ("role", "clusterrole", "rolebinding", "clusterrolebinding"))
            if ready:
                from .k8s import K8sModel
                if cluster not in rbac_cache:
                    rbac_cache[cluster] = K8sModel(snapshot)
                rbac = rbac_cache[cluster]
                if source.id.startswith("user:"):
                    user_name = source.id.split(":", 1)[1]
                elif source.id.startswith("serviceAccount:") and source.attrs.get("unique_id"):
                    user_name = str(source.attrs["unique_id"])
                else:
                    user_name = None
                if user_name:
                    principal = rbac.external_user(cluster_id, user_name)
                    resource_kind = target.attrs["kcc_resource_kind"]
                    resource = {"IAMPolicyMember": "iampolicymembers",
                                "kcc_iampolicy": "iampolicies",
                                "kcc_iampartialpolicy": "iampartialpolicies"}[resource_kind]
                    verb = target.attrs["kcc_operation"]
                    ref = (target.attrs["kcc_namespace"],
                           target.attrs["kcc_resource_name"] if verb == "update" else None, "")
                    requirements = [{"verb": candidate, "api_group": "iam.cnrm.cloud.google.com",
                                     "resource": resource, "_rbac_only": True}
                                    for candidate in (("update", "patch") if verb == "update" else ("create",))]
                    options = [rbac.check(principal, req, ref) for req in requirements]
                    rbac_write = next((grant for grant in options
                                       if grant is not None and grant.confidence == "derived"), None)
                    if rbac_write is None:
                        rbac_write = next((grant for grant in options if grant is not None), None)
                    if rbac_write is None:
                        rbac_uncertain = any(
                            any(rbac.check(group, req, ref) is not None for req in requirements)
                            for group in rbac.principals.values()
                            if group.kind == "k8s_group" and group.attrs.get("cluster") == cluster_id)
                else:
                    rbac_uncertain = True
            else:
                rbac_uncertain = True
        if rbac_write is not None and (write is None or
                                       write.confidence != "derived" and rbac_write.confidence == "derived"):
            write = rbac_write
        if write is None:
            if authenticate is not None and rbac_uncertain:
                out[ident] = ("unknown", "kcc_namespace_rbac_unresolved")
            continue
        if target.attrs.get("kcc_configuration_healthy") is False:
            continue
        if target.attrs.get("kcc_api_access") != "public":
            out[ident] = ("unknown", "cluster_api_network_route_unverified")
            continue
        if (authenticate is None or authenticate.confidence != "derived"):
            out[ident] = ("unknown", "cluster_api_authentication_unverified")
            continue
        if (write.confidence != "derived" or target.attrs["kcc_get_confidence"] != "derived" or
                target.attrs["kcc_set_confidence"] != "derived"):
            out[ident] = ("unknown", "kcc_or_source_iam_permission_conditional")
            continue
        reasons = ["kcc_reconciliation_and_admission_not_observed"]
        if target.attrs.get("kcc_configuration_healthy") is not True:
            reasons.append("kcc_controller_health_unverified")
        out[ident] = ("conditional", ";".join(reasons))
    return out
