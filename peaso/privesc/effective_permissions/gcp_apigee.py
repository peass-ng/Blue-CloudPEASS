"""Bind Apigee proxy authoring and deployment to one inventoried organization."""

from . import inventory_status, items


def _usable(grant):
    return grant is not None and grant.confidence != "unknown"


def _managed_runtime_token(model, project, target):
    numbers = [number for number, pid in model.project_alias.items()
               if pid == project.removeprefix("projects/")]
    if not numbers:
        return False
    agent_id = ("serviceAccount:service-" + numbers[0]
                + "@gcp-sa-apigee.iam.gserviceaccount.com")
    agent = model.principals.get(agent_id)
    if agent is None:
        return False
    target_resource = target.attrs.get("resource") or (
        project + "/serviceAccounts/" + str(target.attrs.get("email")))
    return _usable(model.check(agent, {"action": "iam.serviceAccounts.getAccessToken"}, target_resource))


def proxy_deploy_selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    by_project = {}
    for scope, organization in items(model.snapshot, "apigee_organization"):
        project = model._norm_scope(scope)
        name = organization.get("name")
        if (not isinstance(name, str) or not name.startswith("organizations/")
                or name.count("/") != 1 or organization.get("projectId") != project.removeprefix("projects/")):
            continue
        by_project.setdefault(project, []).append(organization)
    statuses = {model._norm_scope(scope): status
                for scope, status in inventory_status(model.snapshot, "apigee_organization").items()}
    out = {}
    for tid, target in candidates.items():
        project = target.scope
        if statuses.get(project) not in ("collected", "empty"):
            out[tid] = ("unknown", "apigee_organization_inventory_unresolved")
            continue
        unresolved = False
        for organization in by_project.get(project, ()):
            org = organization["name"]
            if organization.get("state") != "ACTIVE":
                if organization.get("state") is None:
                    unresolved = True
                continue
            if organization.get("runtimeType") != "CLOUD":
                # Hybrid uses a separately configured runtime service account.
                # The organization inventory does not identify that account.
                unresolved = True
                continue
            model.parents.setdefault(org, project)
            coverage = (organization.get("_coverage") or {}).get("apigee_environments") or {}
            if coverage.get("status") != "collected":
                unresolved = True
            create = model.check(source, {"action": "apigee.proxies.create"}, org)
            if not _usable(create):
                if create is not None:
                    unresolved = True
                continue
            proxy = org + "/apis/__new_proxy__"
            revision = proxy + "/revisions/__new_revision__"
            model.parents.setdefault(proxy, org)
            model.parents.setdefault(revision, proxy)
            deploy_revision = model.check(source, {"action": "apigee.proxyrevisions.deploy"}, revision)
            if not _usable(deploy_revision):
                unresolved |= deploy_revision is not None
                continue
            for environment in organization.get("_apigee_environments") or ():
                if environment.get("state") != "ACTIVE":
                    if environment.get("state") is None:
                        unresolved = True
                    continue
                if environment.get("deploymentType") != "PROXY":
                    if environment.get("deploymentType") != "ARCHIVE":
                        unresolved = True
                    continue
                env = environment.get("name")
                if not isinstance(env, str) or not env.startswith(org + "/environments/"):
                    unresolved = True
                    continue
                model.parents.setdefault(env, org)
                deploy = model.check(source, {"action": "apigee.deployments.create"}, env)
                if not _usable(deploy):
                    unresolved |= deploy is not None
                    continue
                if not _managed_runtime_token(model, project, target):
                    unresolved = True
                    continue
                out[tid] = ("conditional", "apigee_proxy_deploys_in_standard_environment_with_runtime_token_access")
                break
            if tid in out:
                break
        if tid not in out and unresolved:
            out[tid] = ("unknown", "apigee_exact_path_or_runtime_delegation_unresolved")
    return out


def sharedflow_hook_selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    by_project = {}
    for scope, organization in items(model.snapshot, "apigee_organization"):
        project = model._norm_scope(scope)
        name = organization.get("name")
        if (not isinstance(name, str) or not name.startswith("organizations/")
                or name.count("/") != 1 or organization.get("projectId") != project.removeprefix("projects/")):
            continue
        by_project.setdefault(project, []).append(organization)
    statuses = {model._norm_scope(scope): status
                for scope, status in inventory_status(model.snapshot, "apigee_organization").items()}
    out = {}
    hook_points = ("PreProxyFlowHook", "PostProxyFlowHook", "PreTargetFlowHook", "PostTargetFlowHook")
    for tid, target in candidates.items():
        project = target.scope
        if statuses.get(project) not in ("collected", "empty"):
            out[tid] = ("unknown", "apigee_organization_inventory_unresolved")
            continue
        unresolved = False
        for organization in by_project.get(project, ()):
            org = organization["name"]
            if organization.get("state") != "ACTIVE":
                unresolved |= organization.get("state") is None
                continue
            if organization.get("runtimeType") != "CLOUD":
                unresolved = True
                continue
            model.parents.setdefault(org, project)
            if ((organization.get("_coverage") or {}).get("apigee_environments") or {}).get("status") != "collected":
                unresolved = True
            create = model.check(source, {"action": "apigee.sharedflows.create"}, org)
            if not _usable(create):
                unresolved |= create is not None
                continue
            flow = org + "/sharedflows/__new_sharedflow__"
            revision = flow + "/revisions/__new_revision__"
            model.parents.setdefault(flow, org)
            model.parents.setdefault(revision, flow)
            deploy_revision = model.check(source, {"action": "apigee.sharedflowrevisions.deploy"}, revision)
            if not _usable(deploy_revision):
                unresolved |= deploy_revision is not None
                continue
            for environment in organization.get("_apigee_environments") or ():
                if environment.get("state") != "ACTIVE":
                    unresolved |= environment.get("state") is None
                    continue
                if environment.get("deploymentType") != "PROXY":
                    unresolved |= environment.get("deploymentType") != "ARCHIVE"
                    continue
                env = environment.get("name")
                if not isinstance(env, str) or not env.startswith(org + "/environments/"):
                    unresolved = True
                    continue
                model.parents.setdefault(env, org)
                deploy = model.check(source, {"action": "apigee.deployments.create"}, env)
                if not _usable(deploy):
                    unresolved |= deploy is not None
                    continue
                hooked = False
                for point in hook_points:
                    hook = env + "/flowhooks/" + point
                    model.parents.setdefault(hook, env)
                    hook_grant = model.check(source, {"action": "apigee.flowhooks.attachSharedFlow"}, hook)
                    if _usable(hook_grant):
                        hooked = True
                        break
                    unresolved |= hook_grant is not None
                if not hooked:
                    continue
                coverage = (environment.get("_coverage") or {}).get("proxyDeployments") or {}
                if coverage.get("status") != "collected":
                    unresolved = True
                    continue
                deployed = environment.get("_proxy_deployments")
                if not isinstance(deployed, list):
                    unresolved = True
                    continue
                env_short = env.rsplit("/", 1)[-1]
                if not any(isinstance(row, dict) and isinstance(row.get("apiProxy"), str)
                           and row["apiProxy"] and row.get("environment") in (env, env_short)
                           and row.get("revision") and row.get("state") not in ("ERROR", "PROGRESSING")
                           for row in deployed):
                    # A future proxy deployment may make this hook effective.
                    unresolved = True
                    continue
                if not _managed_runtime_token(model, project, target):
                    unresolved = True
                    continue
                out[tid] = ("conditional", "apigee_sharedflow_hook_on_deployed_proxy_environment")
                break
            if tid in out:
                break
        if tid not in out and unresolved:
            out[tid] = ("unknown", "apigee_sharedflow_hook_or_runtime_delegation_unresolved")
    return out
