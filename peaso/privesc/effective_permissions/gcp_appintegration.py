"""Bind an Application Integration run-as path to one project and integration."""
from __future__ import annotations

import re

from . import inventory_status, items


VERSION = re.compile(r"(projects/[^/]+)/locations/[^/]+/integrations/[^/]+/versions/[^/]+\Z")
SERVICE = "integrations.googleapis.com"


def _usable(grant):
    return grant is not None and grant.confidence != "unknown"


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    snap = model.snapshot
    service_status = {model._norm_scope(scope): status for scope, status in
                      inventory_status(snap, "service_usage").items()}
    services = {}
    for scope, item in items(snap, "service_usage"):
        if model._norm_scope(item.get("name")) == f"{model._norm_scope(scope)}/services/{SERVICE}":
            services.setdefault(model._norm_scope(scope), []).append(item)
    facts = {}
    for scope, item in items(snap, "gcp_v4_workload_facts"):
        project = model._norm_scope(scope)
        if item.get("scope") == project and item.get("name") == project:
            facts.setdefault(project, []).append(item)
    out = {}
    for tid, target in candidates.items():
        project = target.scope
        email = target.attrs.get("email")
        if target.attrs.get("disabled") is True:
            continue
        if not isinstance(email, str):
            out[tid] = ("unknown", "appintegration_target_identity_unresolved")
            continue
        actas = model.check(source, {"action": "iam.serviceAccounts.actAs"},
                            target.attrs.get("resource") or f"{project}/serviceAccounts/{email}")
        if not _usable(actas):
            if actas is not None:
                out[tid] = ("unknown", "appintegration_run_as_authorization_unresolved")
            continue
        if service_status.get(project) not in ("collected", "empty"):
            out[tid] = ("unknown", "appintegration_service_state_not_collected")
            continue
        service_rows = services.get(project, ())
        if len(service_rows) != 1 or service_rows[0].get("state") not in ("ENABLED", "DISABLED"):
            out[tid] = ("unknown", "appintegration_service_state_unresolved")
            continue
        if service_rows[0]["state"] == "DISABLED":
            continue
        project_facts = facts.get(project, ())
        if len(project_facts) != 1:
            out[tid] = ("unknown", "appintegration_region_inventory_not_collected")
            continue
        integration = project_facts[0].get("application_integration")
        if not isinstance(integration, dict) or integration.get("status") not in ("collected", "empty"):
            out[tid] = ("unknown", "appintegration_version_inventory_incomplete")
            continue
        versions = integration.get("versions")
        if not isinstance(versions, list):
            out[tid] = ("unknown", "appintegration_version_inventory_malformed")
            continue
        unresolved = False
        for version in versions:
            name = version.get("name") if isinstance(version, dict) else None
            match = VERSION.fullmatch(name) if isinstance(name, str) else None
            if not match or match[1] != project:
                unresolved = True
                continue
            if version.get("state") not in ("ACTIVE", "DRAFT", "SNAPSHOT"):
                if version.get("state") not in ("ARCHIVED", "DELETED"):
                    unresolved = True
                continue
            parent = name.rsplit("/versions/", 1)[0]
            model.parents.setdefault(parent, project)
            invoke = model.check(source, {"action": "integrations.integrations.invoke"}, parent)
            created = model.check(source, {"action": "integrations.integrationVersions.create"}, parent)
            future = parent + "/versions/__new__"
            model.parents.setdefault(future, parent)
            deploy = model.check(source, {"action": "integrations.integrationVersions.deploy"}, future)
            if _usable(created) and _usable(deploy) and _usable(invoke):
                out[tid] = ("conditional", "same_integration_publish_invoke_and_run_as_account")
                break
            if _usable(invoke):
                # integrations.test accepts a caller-supplied draft definition.
                out[tid] = ("conditional", "same_integration_draft_test_and_run_as_account")
                break
            if invoke is not None:
                unresolved = True
            if any(grant is not None and grant.confidence == "unknown" for grant in (created, deploy)):
                unresolved = True
            # Publishing an authored scheduled trigger may start execution
            # without the author's invoke permission. The trigger identity and
            # schedule are not established by the current projection.
            if _usable(created) and _usable(deploy):
                unresolved = True
        if tid not in out:
            if unresolved or not versions:
                out[tid] = ("unknown", "appintegration_publish_or_trigger_path_unresolved")
    return out
