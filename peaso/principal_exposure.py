"""Evidence-bound entry points into identities, shared by both principal views.

Trust declarations are potential access, not proof that a caller can authenticate.
Internet workload paths require a separate application compromise to obtain identity.
"""
from __future__ import annotations

from collections import defaultdict
from fnmatch import fnmatchcase

from peaso.analysis.common import as_list, externality, native_id, with_analysis_context
from peaso.analysis.iam import document, grants
from peaso.analysis.internet_exposure import assess, describe, Assessment, pset, union, _public_ip
from peaso.analysis.trust import restrictive_conditions, aws_federated_trust, _k8s_self_info_binding

LIMITATIONS = [
    "External means outside the scanned or explicitly trusted boundary; ownership and business approval are not inferred.",
    "Trust and impersonation grants remain subject to caller permissions, conditions, denies and provider guardrails.",
    "Internet workload exposure requires an application compromise to obtain its identity; no exploit or traffic probe was performed.",
    "Missing identity, federation, backend or network inventory leaves exposure unresolved; absence of a signal does not establish isolation.",
]
# Include the path inventories even when only Least Privilege or Privesc is selected.
from peaso.principal_exposure_requirements import REQUIRED_TYPES

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def increased(severity, signals):
    if not any(s["state"] == "declared" for s in signals):
        return severity
    return {"high": "critical", "medium": "high", "low": "medium"}.get(severity, severity)


def canonical(provider, value, scope=""):
    value = str(value or "")
    if provider == "azure":
        return value.lower()
    if provider == "gcp" and "@" in value and ":" not in value:
        return "serviceAccount:" + value
    if provider == "k8s" and value.startswith("system:serviceaccount:"):
        return f"{scope}|{value}"
    return value


def _cluster(row):
    data = row.get("data", {})
    return str((data.get("provenance") or {}).get("cluster_id") or (data.get("metadata") or {}).get("cluster_id") or row.get("scope", "cluster").split("/", 1)[0])


@with_analysis_context
def project(snapshot, resources):
    """Return principal records with reproducible native evidence and explicit uncertainty."""
    provider = snapshot["provider"]
    resources = list(resources)
    by_type = defaultdict(list)
    resources = [row for row in resources if isinstance(row.get("data"), dict)]
    for row in resources:
        by_type[row["type"]].append(row)
    output = {}

    def record(identity, row, label=None):
        key = canonical(provider, identity, _cluster(row) if provider == "k8s" else row.get("scope", ""))
        if not identity:
            return None
        card = output.setdefault(key, {"principal": str(identity), "label": label or str(identity),
            "scopes": [], "exposures": [], "base_severity": "info", "grant_reviews": []})
        if row.get("scope", "") not in card["scopes"]:
            card["scopes"].append(row.get("scope", ""))
        return card

    def signal(identity, row, kind, state, **evidence):
        card = record(identity, row)
        if card is None:
            return
        item = {"kind": kind, "state": state, "resource_id": row.get("id", str(native_id(row))),
            "scope": row.get("scope", ""), **evidence}
        if item not in card["exposures"]:
            card["exposures"].append(item)

    def review(identity, row, values=None):
        values = grants(row) if values is None else values
        high = [g for g in values if g.get("allowed_declaration") and RANK.get(g.get("severity"), 4) <= 1]
        if high and identity:
            card = record(identity, row)
            card["base_severity"] = min([card["base_severity"]] + [g["severity"] for g in high], key=RANK.get)
            card["grant_reviews"].append({"resource_id": row.get("id", str(native_id(row))), "scope": row.get("scope", "")})

    if provider == "aws":
        for row in by_type["iam_role"] + by_type["iam_user"]:
            data = row["data"]
            identity = data.get("Arn")
            record(identity, row, data.get("RoleName") or data.get("UserName"))
            review(identity, row)
            attached = {p.get("PolicyArn") for p in data.get("AttachedManagedPolicies") or []}
            for policy_row in by_type["iam_policy"]:
                if policy_row["data"].get("Arn") in attached:
                    review(identity, row, grants(policy_row))
            federation_review = aws_federated_trust(snapshot, row)
            unpinned = {(r["federated_principal"], r["statement"]) for r in federation_review[2]["federated_trusts"]
                        if r.get("multi_tenant_issuer") and any(p.get("severity") not in {"low", "review"} for p in r["problems"])} if federation_review else set()
            policy = document(data.get("AssumeRolePolicyDocument")) or {}
            for statement_index, statement in enumerate(as_list(policy.get("Statement"))):
                if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                    continue
                if not any(fnmatchcase(action, str(pattern).lower()) for pattern in as_list(statement.get("Action"))
                           for action in ("sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml")):
                    continue
                principal = statement.get("Principal")
                entries = principal.items() if isinstance(principal, dict) else [("AWS", principal)]
                for kind, members in entries:
                    for member in as_list(members):
                        classification = externality(snapshot, member)
                        federation = kind == "Federated"
                        if kind == "Service" or not federation and classification not in {"external", "public", "unknown"}:
                            continue
                        condition = statement.get("Condition")
                        state = "conditional" if condition or federation else "unknown" if classification == "unknown" else "declared"
                        if federation and (member, f"AssumeRolePolicyDocument.Statement[{statement_index}]") in unpinned and not restrictive_conditions(condition):
                            state = "declared"
                        signal(identity, row, "federated_trust" if federation else "external_assumption", state,
                            caller=member, classification=classification, conditions=condition,
                            restrictions=restrictive_conditions(condition), grant=statement)
    elif provider == "gcp":
        # Impersonation can be inherited from project/folder/org policies as well as SA policies.
        impersonation = {"roles/iam.serviceAccountTokenCreator", "roles/iam.workloadIdentityUser", "roles/iam.serviceAccountUser", "roles/owner", "roles/editor"}
        for row in by_type["iam_role"]:
            data = row["data"]
            if set(data.get("includedPermissions") or []) & {"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signJwt", "iam.serviceAccounts.signBlob", "iam.serviceAccounts.actAs"}:
                impersonation.add(data.get("name"))
        accounts = by_type["service_account"]
        for row in accounts:
            record(row["data"].get("email"), row, row["data"].get("displayName"))
        for row in resources:
            data = row["data"]
            policy = data.get("iamPolicy", data.get("policy", data))
            if not isinstance(policy, dict):
                continue
            for binding in policy.get("bindings") or []:
                if not isinstance(binding, dict):
                    continue
                role = binding.get("role")
                for member in binding.get("members") or []:
                    if role in {"roles/owner", "roles/editor"}:
                        review(member, row, [{"severity": "high", "allowed_declaration": True}])
                    if role not in impersonation:
                        continue
                    classification = externality(snapshot, member)
                    federation = str(member).startswith(("principal://", "principalSet://"))
                    if classification not in {"external", "public", "unknown"} and not federation:
                        continue
                    # Scope ancestry must be collected; never apply an unrelated project grant.
                    targets = [row] if row["type"] == "service_account" else [sa for sa in accounts if sa["scope"] == row["scope"]
                        or row["type"] in {"organization", "folder"} and row["scope"] in as_list(sa["data"].get("ancestors"))]
                    for target in targets:
                        state = "conditional" if binding.get("condition") or federation or target["data"].get("disabled") is True or role == "roles/iam.serviceAccountUser" else "unknown" if classification == "unknown" else "declared"
                        signal(target["data"].get("email"), row, "federated_trust" if federation else "external_impersonation", state,
                            caller=member, classification=classification, role=role, conditions=binding.get("condition"),
                            target_resource=target.get("id"), requires_workload_control=role == "roles/iam.serviceAccountUser")
    elif provider == "azure":
        definitions = {str(r["data"].get("name", "")).rsplit("/", 1)[-1].lower(): r for r in by_type["role_definition"]}
        for row in by_type["directory_user"] + by_type["directory_service_principal"]:
            data = row["data"]
            identity = data.get("id")
            record(identity, row, data.get("displayName") or data.get("userPrincipalName"))
            if externality(snapshot, identity) == "external":
                signal(identity, row, "external_identity", "conditional" if data.get("accountEnabled") is False else "declared", owner_tenant=data.get("appOwnerOrganizationId"), user_type=data.get("userType"), account_enabled=data.get("accountEnabled"))
        for row in by_type["role_assignment"]:
            props = row["data"].get("properties") or {}
            definition = definitions.get(str(props.get("roleDefinitionId", "")).rsplit("/", 1)[-1].lower())
            if definition:
                review(props.get("principalId"), row, grants(definition))
        for row in by_type["directory_federated_credential"] + by_type["managed_identity_federated_credential"]:
            data = row["data"]
            props = data.get("properties", data)
            targets = [r["data"].get("id") for r in by_type["directory_service_principal"] if data.get("appId") and r["data"].get("appId") == data["appId"]]
            parent = str(data.get("id", "")).lower().split("/federatedidentitycredentials/")[0]
            targets += [r["data"].get("properties", {}).get("principalId") for r in by_type["managed_identity"] if str(r["data"].get("id", "")).lower() == parent]
            for identity in targets:
                signal(identity, row, "federated_trust", "conditional", issuer=props.get("issuer"), subject=props.get("subject"), audiences=props.get("audiences"), classification="ownership_unverified")
    elif provider == "k8s":
        roles = {(_cluster(r), r["type"], r["data"].get("metadata", {}).get("namespace", "default"), r["data"].get("metadata", {}).get("name")): r
                 for r in by_type["role"] + by_type["clusterrole"]}
        for row in by_type["rolebinding"] + by_type["clusterrolebinding"]:
            if _k8s_self_info_binding(snapshot, row):
                continue
            data = row["data"]
            meta, ref = data.get("metadata", {}), data.get("roleRef", {})
            namespace = meta.get("namespace", "default")
            role = roles.get((_cluster(row), str(ref.get("kind", "")).lower(), namespace if ref.get("kind") == "Role" else "default", ref.get("name")))
            for subject in data.get("subjects") or []:
                identity = f"system:serviceaccount:{subject.get('namespace', namespace)}:{subject.get('name')}" if subject.get("kind") == "ServiceAccount" else subject.get("name")
                if role:
                    review(identity, row, grants(role))
                classification = externality(snapshot, identity)
                if classification in {"external", "public", "everyone_authenticated", "unknown"}:
                    state = "unknown" if classification == "unknown" else "declared"
                    signal(identity, row, "external_identity", state, classification=classification, role_ref=ref)
                    for rule in role["data"].get("rules") or [] if role else []:
                        if not set(rule.get("verbs") or []) & {"impersonate", "*"} or not set(rule.get("resources") or []) & {"serviceaccounts", "*"} or not set(rule.get("apiGroups") or []) & {"", "*"}:
                            continue
                        for sa in by_type["serviceaccount"]:
                            meta = sa["data"].get("metadata") or {}
                            sa_ns = meta.get("namespace", "default")
                            names = rule.get("resourceNames")
                            if _cluster(sa) != _cluster(row) or row["type"] == "rolebinding" and sa_ns != namespace or names and meta.get("name") not in names:
                                continue
                            signal(f"system:serviceaccount:{sa_ns}:{meta.get('name')}", sa, "external_impersonation", state,
                                caller=identity, classification=classification, role_ref=ref, binding_resource=row.get("id"), rule=rule)

    _workloads(snapshot, resources, by_type, signal)
    for card in output.values():
        base = card["base_severity"]
        if card["exposures"] and base == "info":
            base = "medium"
        card["base_severity"] = base
        card["severity"] = increased(base, card["exposures"])
    return output


def _workloads(snapshot, resources, by_type, signal):
    provider = snapshot["provider"]
    profiles = {r["data"].get("Arn"): r["data"] for r in by_type["iam_instance_profile"]}
    # IAM role inventory embeds instance profiles on some collector versions.
    for role in by_type["iam_role"]:
        for profile in role["data"].get("InstanceProfileList") or []:
            profiles.setdefault(profile.get("Arn"), {**profile, "Roles": [role["data"]]})

    def identities(row):
        data = row["data"]
        if provider == "aws":
            if row["type"] == "lambda_function":
                return [data.get("Role")]
            if row["type"] == "ecs_task":
                definition = next((r["data"] for r in by_type["ecs_task_definition"] if r["data"].get("taskDefinitionArn") == data.get("taskDefinitionArn")), {})
                return [data.get("taskRoleArn") or definition.get("taskRoleArn")]
            profile = profiles.get((data.get("IamInstanceProfile") or {}).get("Arn"), {})
            return [r.get("Arn") for r in profile.get("Roles") or []]
        if provider == "gcp":
            if row["type"] == "instance":
                return [sa.get("email") for sa in data.get("serviceAccounts") or []]
            config = data.get("serviceConfig") or data.get("template") or data
            return [config.get("serviceAccount") or config.get("serviceAccountEmail")]
        if provider == "azure":
            identity = data.get("identity") or {}
            result = [identity.get("principalId")]
            for ident, props in (identity.get("userAssignedIdentities") or {}).items():
                result.append(props.get("principalId"))
                if not props.get("principalId"):
                    result.extend(r["data"].get("properties", {}).get("principalId") for r in by_type["managed_identity"] if str(r["data"].get("id", "")).lower() == ident.lower())
            return result
        return []

    def k8s_pods(service):
        data = service["data"]
        selector = (data.get("spec") or {}).get("selector")
        meta = data.get("metadata") or {}
        if not selector:
            return []  # Empty/missing selector must never select every Pod.
        return [pod for pod in by_type["pod"] if _cluster(pod) == _cluster(service)
                and pod["data"].get("metadata", {}).get("namespace", "default") == meta.get("namespace", "default")
                and all(pod["data"].get("metadata", {}).get("labels", {}).get(k) == v for k, v in selector.items())]

    assessments = assess(snapshot, resources)
    if provider == "azure":
        assessments = [*assessments, *_azure_containers(by_type)]
    for assessment in assessments:
        if assessment.verdict() == "PASS" or assessment.data_exposure or assessment.kind in {"control_plane", "external_share"}:
            continue
        row = assessment.resource
        targets = [row]
        if provider == "k8s":
            services = [row] if row["type"] == "service" else []
            if row["type"] == "ingress":
                spec = row["data"].get("spec", {})
                backends = [spec.get("defaultBackend", {})] + [p.get("backend", {}) for rule in spec.get("rules") or [] for p in (rule.get("http") or {}).get("paths") or []]
                names = {b.get("service", {}).get("name") for b in backends}
                services = [s for s in by_type["service"] if _cluster(s) == _cluster(row)
                    and s["data"].get("metadata", {}).get("namespace", "default") == row["data"].get("metadata", {}).get("namespace", "default")
                    and s["data"].get("metadata", {}).get("name") in names]
            targets = [pod for service in services for pod in k8s_pods(service)]
        elif provider == "azure" and row["type"] == "nic":
            vm_id = ((row["data"].get("properties") or {}).get("virtualMachine") or {}).get("id")
            targets = [vm for vm in by_type["vm"] if vm_id and str(vm["data"].get("id", "")).lower() == vm_id.lower()]
        elif provider == "aws" and row["type"] == "network_interface":
            instance = (row["data"].get("Attachment") or {}).get("InstanceId")
            targets = [vm for vm in by_type["instance"] if instance and vm["data"].get("InstanceId") == instance]
            eni = row["data"].get("NetworkInterfaceId")
            targets += [task for task in by_type["ecs_task"] if eni and task["data"].get("lastStatus") == "RUNNING" and any(
                d.get("name") == "networkInterfaceId" and d.get("value") == eni
                for attachment in task["data"].get("attachments") or [] for d in attachment.get("details") or [])]
        if provider == "aws" and row["type"] == "load_balancer":
            lb_arn = row["data"].get("LoadBalancerArn")
            tgs = {t["data"].get("TargetGroupArn") for t in by_type["target_group"] if lb_arn and lb_arn in (t["data"].get("LoadBalancerArns") or [])}
            service_defs = {s["data"].get("taskDefinition") for s in by_type["ecs_service"] if any(b.get("targetGroupArn") in tgs for b in s["data"].get("loadBalancers") or [])}
            targets = [task for task in by_type["ecs_task"] if task["data"].get("lastStatus") == "RUNNING" and task["data"].get("taskDefinitionArn") in service_defs]
        state = "declared" if assessment.verdict() == "FAIL" and not assessment.unresolved and not assessment.dormant and assessment.addresses else "unknown"
        if provider == "aws" and row["type"] == "load_balancer":
            state = "unknown"  # Listener routing, target health and target SG need separate resolution.
        path_state = state
        for target in targets:
            state = path_state
            identity_gaps = []
            if provider == "k8s" and (target["data"].get("metadata", {}).get("deletionTimestamp") or target["data"].get("status", {}).get("phase") in {"Succeeded", "Failed"}):
                continue
            ids = identities(target)
            token_available = None
            if provider == "k8s":
                spec = target["data"].get("spec") or {}
                meta = target["data"].get("metadata") or {}
                namespace, name = meta.get("namespace", "default"), spec.get("serviceAccountName", "default")
                ids = [f"system:serviceaccount:{namespace}:{name}"]
                sa = next((s for s in by_type["serviceaccount"] if _cluster(s) == _cluster(target)
                    and s["data"].get("metadata", {}).get("namespace", "default") == namespace and s["data"].get("metadata", {}).get("name") == name), None)
                token_available = spec.get("automountServiceAccountToken", sa["data"].get("automountServiceAccountToken", True) if sa else True)
                policies_complete = any(c.get("type") == "networkpolicy" and c.get("status") in {"collected", "empty"} for c in snapshot.get("collections", []))
                if not policies_complete:
                    state = "unknown"
                    identity_gaps.append({"layer": "networkpolicy", "reason": "NetworkPolicy inventory is incomplete"})
                if sa is None and "automountServiceAccountToken" not in spec:
                    state = "unknown"
                    identity_gaps.append({"layer": "identity", "reason": "ServiceAccount automount setting is not collected"})
                if by_type["networkpolicy"] and state == "declared":
                    state = "conditional"
                mounted = {mount.get("name") for container in list(spec.get("containers") or []) + list(spec.get("initContainers") or []) + list(spec.get("ephemeralContainers") or []) for mount in container.get("volumeMounts") or []}
                projected = any("serviceAccountToken" in source for volume in spec.get("volumes") or [] if volume.get("name") in mounted
                                for source in (volume.get("projected") or {}).get("sources") or [])
                if token_available is False and not projected:
                    continue
            for identity in ids:
                if identity:
                    signal(identity, target, "internet_workload", state, endpoint_resource=row.get("id"),
                        workload_resource=target.get("id"), ports=describe(assessment.ports or {}), public_addresses=assessment.addresses,
                        unresolved=assessment.unresolved + identity_gaps + ([{"layer": "endpoint", "reason": "No public endpoint address observed"}] if not assessment.addresses else []) + ([{"layer": "backend", "reason": "Target routing, health and security groups require resolution"}] if provider == "aws" and row["type"] == "load_balancer" else []),
                        path=assessment.path, requires_application_compromise=True,
                        token_automount=token_available,
                        limitations=["Application compromise required; network policy enforcement and downstream backend reachability are not proven."] if provider == "k8s" else [])


def _azure_containers(by_type):
    """Native ACI and Resource Graph Container Apps; missing environment data stays unknown."""
    rows = by_type["container_group"] + by_type["resource_graph"]
    environments = {str(r["data"].get("id", "")).lower(): r["data"].get("properties", {})
                    for r in by_type["resource_graph"] if str(r["data"].get("type", "")).lower() == "microsoft.app/managedenvironments"}
    seen = set()
    for row in rows:
        data = row["data"]
        rid = str(data.get("id", "")).lower()
        if rid in seen:
            continue
        kind = str(data.get("type", "")).lower()
        props = data.get("properties") or {}
        a = Assessment(row, "container")
        if kind == "microsoft.app/containerapps":
            ingress = (props.get("configuration") or {}).get("ingress") or {}
            if ingress.get("external") is not True:
                continue
            env_id = props.get("environmentId") or props.get("managedEnvironmentId")
            environment = environments.get(str(env_id or "").lower())
            if environment and (str(environment.get("publicNetworkAccess", "")).lower() == "disabled" or (environment.get("vnetConfiguration") or {}).get("internal") is True):
                continue
            a.addresses = [ingress["fqdn"]] if ingress.get("fqdn") else []
            if ingress.get("transport") == "tcp":
                port = ingress.get("exposedPort")
                if not isinstance(port, int):
                    a.gap("listener", "Container App exposed TCP port is missing")
                else:
                    a.ports = pset("tcp", port, port)
            else:
                a.ports = pset("tcp", 443, 443)
                if ingress.get("allowInsecure") is True:
                    a.ports = union(a.ports, pset("tcp", 80, 80))
            if environment is None:
                a.gap("inventory", "Container App environment public access configuration is not collected")
            if ingress.get("ipSecurityRestrictions") or ingress.get("clientCertificateMode") == "require":
                a.gap("authorization", "Container App source or client certificate restrictions require evaluation")
            a.step("container_ingress", "allow", external=True, environment_id=env_id)
        elif row["type"] == "container_group" or kind == "microsoft.containerinstance/containergroups":
            address = props.get("ipAddress") or {}
            if address.get("type") != "Public" or not _public_ip(address.get("ip")):
                continue
            a.addresses = [address["ip"]]
            a.ports = {}
            for port in address.get("ports") or []:
                if isinstance(port.get("port"), int):
                    a.ports = union(a.ports, pset(port.get("protocol", "TCP"), port["port"], port["port"]) or {})
            a.step("container_ingress", "allow", public_ip=address["ip"])
        else:
            continue
        if props.get("provisioningState") != "Succeeded":
            a.gap("inventory", "Container provisioning has not been confirmed successful")
        seen.add(rid)
        yield a


def annotate_privesc(snapshot, graph, findings, model):
    """Attach entry points without adding assumption/compromise edges or changing confidence."""
    from peaso.snapshot import resources
    cards = project(snapshot, resources(snapshot))
    matched = {}
    for node in model.principals.values():
        identity = node.attrs.get("arn") or node.attrs.get("member") or node.attrs.get("email") or node.attrs.get("user") or node.id
        card = cards.get(canonical(node.provider, identity, node.attrs.get("cluster", node.scope)))
        if card and card["exposures"]:
            matched[node.id] = card
    for node in graph["nodes"]:
        card = matched.get(node["id"])
        if card:
            node["exposures"] = card["exposures"]
        elif node.get("members"):
            node["exposed_member_count"] = sum(m in matched for m in node["members"])
            for sample in node.get("member_sample") or []:
                if sample["id"] in matched:
                    sample["exposures"] = matched[sample["id"]]["exposures"]
    adjusted = {}
    for finding in findings:
        card = matched.get(finding.get("resource_id"))
        if not card:
            continue
        evidence = finding.setdefault("evidence", {})
        evidence["principal_exposures"] = card["exposures"]
        base = finding["severity"]
        finding["base_severity"] = base
        if finding.get("status") != "UNKNOWN":
            finding["severity"] = increased(base, card["exposures"])
        if finding["severity"] != base:
            evidence["severity_adjustment"] = "Raised one tier because the source principal has a declared external or internet workload entry point."
        adjusted[finding["id"]] = finding["severity"]
    for edge in graph["edges"]:
        for detail in edge.get("technique_details") or []:
            if detail.get("finding") in adjusted:
                detail["base_severity"] = detail.get("severity")
                detail["severity"] = adjusted[detail["finding"]]
