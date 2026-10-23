"""Generated service-account key path through Config Connector and a readable Secret."""
from __future__ import annotations

from . import inventory_status, items
from .gcp_config_connector import _configuration_mode, _health, _identities, _same_cluster

TECHNIQUE = "gcp-configcontroller-kcc-service-account-key"


def unknown_scopes(model):
    out = {scope: "gke_cluster_inventory_" + status for scope, status in model.gke_status.items()
           if status not in ("collected", "empty")}
    if not model.gke_status:
        out.update({scope: "gke_cluster_inventory_missing" for scope in model.scopes
                    if scope.startswith("projects/") and scope.count("/") == 1})
    for cluster in model.gke:
        project = cluster.split("/locations/", 1)[0]
        if cluster in model.__dict__.get("_ambiguous_k8s", ()):
            out[project] = "k8s_snapshot_join_ambiguous"
            continue
        joined = (model.related_k8s or {}).get(cluster)
        if joined is None:
            out[project] = "k8s_snapshot_not_joined"
            continue
        cluster_id, snapshot = joined
        mode = _configuration_mode(snapshot, cluster_id)
        needed = ("configconnector", "api_discovery") + (("configconnectorcontext",) if mode == "namespaced"
                    else ("namespace",) if mode == "cluster" else ())
        if any(not (status := inventory_status(snapshot, kind)) or
               any(state not in ("collected", "empty") for state in status.values()) for kind in needed):
            out[project] = "kcc_configuration_inventory_incomplete"
            continue
        discoveries = [item for _, item in items(snapshot, "api_discovery")
                       if _same_cluster(item, cluster_id, snapshot)]
        if len(discoveries) != 1 or not isinstance(discoveries[0].get("kccIAMServiceAccountKeyAdvertised"), bool):
            out[project] = "kcc_key_resource_discovery_incomplete"
            continue
        if any("serviceAccount:" + email not in model.sas
               for _, email, _, _ in _identities(snapshot, cluster_id)):
            out[project] = "kcc_service_account_inventory_incomplete"
    for scope, status in inventory_status(model.snapshot, "service_account").items():
        if status not in ("collected", "empty"):
            out[model._norm_scope(scope)] = "service_account_inventory_" + status
    if not inventory_status(model.snapshot, "service_account"):
        out.update({scope: "service_account_inventory_missing" for scope in model.scopes
                    if scope.startswith("projects/") and scope.count("/") == 1})
    return out


def select(model, candidates, source):
    if source is None:
        return {}
    paths = []
    rbac_cache = {}
    for cluster in sorted(model.gke):
        if cluster in model.__dict__.get("_ambiguous_k8s", ()):
            continue
        joined = (model.related_k8s or {}).get(cluster)
        if not joined:
            continue
        cluster_id, snapshot = joined
        mode = _configuration_mode(snapshot, cluster_id)
        needed = ("configconnector", "api_discovery") + (("configconnectorcontext",) if mode == "namespaced"
                    else ("namespace",) if mode == "cluster" else ())
        if any(not (status := inventory_status(snapshot, kind)) or
               any(state not in ("collected", "empty") for state in status.values()) for kind in needed):
            continue
        discoveries = [item for _, item in items(snapshot, "api_discovery")
                       if _same_cluster(item, cluster_id, snapshot)]
        if len(discoveries) != 1 or discoveries[0].get("kccIAMServiceAccountKeyAdvertised") is not True:
            continue
        create = model.check(source, {"action": "container.thirdPartyObjects.create"}, cluster)
        authenticate = model.check(source, {"action": "container.clusters.get"}, cluster)
        iam_reads = [
            ("generated_secret", model.check(source, {"action": "container.secrets.get"}, cluster)),
            ("key_resource_status", model.check(source, {"action": "container.thirdPartyObjects.get"}, cluster)),
        ]
        if create is None and authenticate is None:
            continue
        rbac_ready = all(
            (status := inventory_status(snapshot, kind)) and
            all(state in ("collected", "empty") for state in status.values())
            for kind in ("role", "clusterrole", "rolebinding", "clusterrolebinding"))
        rbac = None
        rbac_user = None
        if rbac_ready:
            from .k8s import K8sModel
            rbac = rbac_cache.setdefault(cluster, K8sModel(snapshot))
            if source.id.startswith("user:"):
                user_name = source.id.split(":", 1)[1]
            elif source.id.startswith("serviceAccount:") and source.attrs.get("unique_id"):
                user_name = str(source.attrs["unique_id"])
            else:
                user_name = None
            if user_name:
                rbac_user = rbac.external_user(cluster_id, user_name)
        gke = model.gke[cluster]
        private = gke.get("privateClusterConfig") or {}
        authorized = gke.get("masterAuthorizedNetworksConfig") or {}
        public_api = (isinstance(gke.get("endpoint"), str) and bool(gke["endpoint"]) and
                      private.get("enablePrivateEndpoint") is not True and authorized.get("enabled") is not True)
        for namespace, email, configuration, config in _identities(snapshot, cluster_id):
            kcc = model.sas.get("serviceAccount:" + email)
            if kcc is not None and not kcc.attrs.get("disabled"):
                ref = (namespace, None, "")
                rbac_create = (rbac.check(rbac_user, {
                    "verb": "create", "api_group": "iam.cnrm.cloud.google.com",
                    "resource": "iamserviceaccountkeys", "_rbac_only": True}, ref)
                    if rbac_user is not None else None)
                actor_create = (create if create is not None and
                                (rbac_create is None or create.confidence == "derived")
                                else rbac_create)
                if actor_create is None:
                    group_route = (rbac is not None and any(
                        rbac.check(principal, {
                            "verb": "create", "api_group": "iam.cnrm.cloud.google.com",
                            "resource": "iamserviceaccountkeys", "_rbac_only": True}, ref)
                        for principal in rbac.principals.values()
                        if principal.kind == "k8s_group" and principal.attrs.get("cluster") == cluster_id))
                    if authenticate is not None and (not rbac_ready or rbac_user is None or group_route):
                        # Missing RBAC or unresolved Google Group membership can
                        # still authorize the actor. A complete, nonmatching RBAC
                        # inventory does not create an invented key route.
                        for route in ("generated_secret", "provided_public_key"):
                            paths.append((cluster, namespace, kcc, _health(configuration, config),
                                          public_api, "unknown", "unknown",
                                          authenticate.confidence, route))
                    continue
                for route, iam_read in iam_reads:
                    resource, group = (("secrets", "") if route == "generated_secret"
                                       else ("iamserviceaccountkeys", "iam.cnrm.cloud.google.com"))
                    rbac_read = (rbac.check(rbac_user, {
                        "verb": "get", "api_group": group, "resource": resource,
                        "_rbac_only": True}, ref) if rbac_user is not None else None)
                    read = (iam_read if iam_read is not None and
                            (rbac_read is None or iam_read.confidence == "derived")
                            else rbac_read)
                    if read is None:
                        continue
                    paths.append((cluster, namespace, kcc, _health(configuration, config),
                                  public_api, actor_create.confidence, read.confidence,
                                  authenticate.confidence if authenticate is not None else None, route))
                # KCC also accepts an attacker-supplied public key. Its matching
                # private key is already held by the creator, so no read route is needed.
                paths.append((cluster, namespace, kcc, _health(configuration, config),
                              public_api, actor_create.confidence, "derived",
                              authenticate.confidence if authenticate is not None else None,
                              "provided_public_key"))
    if not paths:
        return {}
    out = {}
    policy_cache = {}
    for ident, target in candidates.items():
        if target.kind != "gcp_service_account" or target.attrs.get("disabled") or ident == source.id:
            continue
        resource = target.attrs.get("resource")
        project = target.attrs.get("project") or target.scope
        if not resource or not project:
            continue
        direct = model.check(source, {"action": "iam.serviceAccountKeys.create"}, resource)
        token = model.check(source, {"action": "iam.serviceAccounts.getAccessToken"}, resource)
        if any(grant is not None and grant.confidence == "derived" for grant in (direct, token)):
            continue
        best = None
        for cluster, namespace, kcc, healthy, public_api, create_conf, read_conf, auth_conf, route in paths:
            policy_kind = "Upload" if route == "provided_public_key" else "Creation"
            policy_key = (project, policy_kind)
            if policy_key not in policy_cache:
                policy_cache[policy_key] = model._sa_key_policy(
                    project, "iam.managed.disableServiceAccountKey" + policy_kind,
                    "iam.disableServiceAccountKey" + policy_kind)
            policy = policy_cache[policy_key]
            delegated = model.check(kcc, {"action": "iam.serviceAccountKeys.create"}, resource)
            if delegated is None or healthy is False or policy is True:
                continue
            lifecycle = [model.check(kcc, {"action": "iam.serviceAccountKeys." + action}, resource)
                         for action in ("get", "list", "delete")]
            if direct is not None or token is not None:
                verdict = ("unknown", "target_service_account_already_accessible_uncertain")
            elif policy is None:
                verdict = ("unknown", "effective_key_creation_policy_unverified")
            elif not public_api:
                verdict = ("unknown", "cluster_api_network_route_unverified")
            elif auth_conf != "derived":
                verdict = ("unknown", "cluster_api_authentication_unverified")
            elif any(grant is None or grant.confidence != "derived" for grant in lifecycle):
                verdict = ("unknown", "kcc_key_lifecycle_permissions_unverified")
            elif (create_conf != "derived" or read_conf != "derived" or delegated.confidence != "derived"):
                verdict = ("unknown", "source_or_controller_permission_conditional")
            else:
                reason = (f"kcc_generated_key_{route}:{cluster}:{namespace};"
                          "key_creation_and_reconciliation_not_observed")
                if healthy is not True:
                    reason += ";kcc_controller_health_unverified"
                verdict = ("conditional", reason)
            if best is None or best[0] == "unknown" and verdict[0] == "conditional":
                best = verdict
                if verdict[0] == "conditional":
                    break
        if best is not None:
            out[ident] = best
    return out
