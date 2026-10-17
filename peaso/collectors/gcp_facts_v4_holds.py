"""Read-only GCP workload metadata for four v4 semantic holds.

The collector exposes this as an opt-in inventory and includes it in the
default full inventory selection. It uses the bounded read/pagination layer
and never creates a VerifiedPreconditions assertion or authority edge.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from peaso.collectors.gcp import ReadError

PROJECT = re.compile(r"projects/[a-z][a-z0-9-]*[a-z0-9]$")
VERSION = re.compile(r"apps/[a-z][a-z0-9-]*[a-z0-9]/services/[a-z0-9-]+/versions/[a-z0-9-]+$")
REGION = re.compile(r"[a-z][a-z0-9-]{0,62}$")
INTEGRATION_VERSION = re.compile(
    r"projects/[a-z][a-z0-9-]*[a-z0-9]/locations/[a-z0-9-]+/integrations/[A-Za-z0-9_-]+/versions/[A-Za-z0-9_-]+$")
GCR_REPOS = {"gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"}
COMPLETE = {"collected", "empty"}


def project_transport_response(method, url, params, data):
    """Allowlist new read responses before the shared transport cache stores them."""
    if method != "GET":
        return data
    parsed = urlsplit(url)
    path = parsed.path
    if parsed.hostname == "appengine.googleapis.com" and re.fullmatch(
            r"/v1/apps/[a-z0-9-]+/services/[a-z0-9-]+/versions/[a-z0-9-]+", path):
        return {k: data[k] for k in ("name", "serviceAccount", "runtime", "env", "servingStatus") if k in data}
    if parsed.hostname == "artifactregistry.googleapis.com" and re.fullmatch(
            r"/v1/projects/[a-z0-9-]+/projectSettings", path):
        return {k: data[k] for k in ("name", "legacyRedirectionState", "pullPercent") if k in data}
    if parsed.hostname == "integrations.googleapis.com" and re.fullmatch(
            r"/v1/projects/[a-z0-9-]+/locations/[a-z0-9-]+/integrations/-/versions", path):
        rows = data.get("integrationVersions", [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ReadError("malformed", "malformed_integration_versions")
        safe = []
        for row in rows:
            tasks, triggers = row.get("taskConfigs", []), row.get("triggerConfigs", [])
            if not isinstance(tasks, list) or not isinstance(triggers, list) or any(
                    not isinstance(item, dict) for item in tasks + triggers):
                raise ReadError("malformed", "malformed_integration_task_or_trigger")
            item = {k: row[k] for k in ("name", "state", "createTime", "runAsServiceAccount") if k in row}
            item["taskConfigs"] = [{k: task[k] for k in ("task", "taskId") if isinstance(task.get(k), str)}
                                   for task in tasks]
            item["triggerConfigs"] = []
            for trigger in triggers:
                projected = {k: trigger[k] for k in ("trigger", "triggerId", "triggerType")
                             if isinstance(trigger.get(k), str)}
                scheduler = trigger.get("cloudSchedulerConfig")
                if isinstance(scheduler, dict) and isinstance(scheduler.get("serviceAccountEmail"), str):
                    projected["cloudSchedulerConfig"] = {"serviceAccountEmail": scheduler["serviceAccountEmail"]}
                item["triggerConfigs"].append(projected)
            safe.append(item)
        return {"integrationVersions": safe, **{k: data[k] for k in
                ("nextPageToken", "warning", "unreachables", "unreachable", "failedLocations") if k in data}}
    if parsed.hostname == "www.googleapis.com" and re.fullmatch(
            r"/deploymentmanager/v2/projects/[a-z0-9-]+/global/deployments", path):
        rows = data.get("deployments", [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ReadError("malformed", "malformed_dm_deployments")
        return {"deployments": [{k: row[k] for k in ("name", "id", "insertTime", "updateTime", "fingerprint")
                                 if k in row} for row in rows],
                **{k: data[k] for k in ("nextPageToken", "warning", "unreachables", "unreachable", "failedLocations")
                   if k in data}}
    return data


def _envelope(collector, kind, scope, service, fetch):
    # Collector.envelope keeps denied, unavailable, malformed and partial
    # separate, including request IDs. Supplemental reads become nested
    # coverage inside the one scoped workload-facts inventory.
    return collector.envelope(kind, scope, service, fetch)


def collect_supplemental(collector, scope, *, integration_regions=()):
    """Read documented API metadata with an injected collector transport.

    `integration_regions` must be explicitly supplied by the owner; a lack of
    region discovery is recorded as unavailable, never treated as empty.
    """
    if not isinstance(scope, str) or not PROJECT.fullmatch(scope):
        raise ValueError("exact project scope required")
    project = scope.split("/", 1)[1]
    if not isinstance(integration_regions, (list, tuple)) or len(integration_regions) > 100 or any(
            not isinstance(x, str) or not REGION.fullmatch(x) for x in integration_regions):
        raise ValueError("explicit, bounded Application Integration regions required")

    versions = collector.collections.get(("app_engine_version", scope))
    def app_version_details():
        if versions is None or versions.get("coverage_status") not in COMPLETE:
            raise ReadError("unavailable", "appengine_version_inventory_incomplete")
        for item in versions["items"]:
            name = item.get("name")
            if not isinstance(name, str) or not VERSION.fullmatch(name) or not name.startswith(f"apps/{project}/"):
                raise ReadError("malformed", "wrong_appengine_version_scope")
            # FULL_VIEW is documented on versions.get. The existing bounded
            # version list intentionally omits serviceAccount and runtime.
            yield from collector.pages(f"https://appengine.googleapis.com/v1/{name}", scope,
                single=True, params={"view": "FULL_VIEW",
                                     "fields": "name,serviceAccount,runtime,env,servingStatus"},
                transform=lambda raw, name=name: _app_version(raw, name))

    def project_settings():
        yield from collector.pages(f"https://artifactregistry.googleapis.com/v1/{scope}/projectSettings",
            scope, single=True, transform=lambda raw: _settings(raw, scope))

    def integration_versions():
        if not integration_regions:
            raise ReadError("unavailable", "integration_regions_not_supplied")
        failures = []
        for region in dict.fromkeys(integration_regions):
            try:
                # versions.list explicitly documents the '-' wildcard for all
                # integrations inside one region; no guessed list endpoint.
                parent = f"{scope}/locations/{region}/integrations/-"
                yield from collector.pages(f"https://integrations.googleapis.com/v1/{parent}/versions",
                    scope, key="integrationVersions",
                    transform=lambda raw, parent=parent: _integration(raw, scope, parent))
            except ReadError as exc:
                failures.append(exc)
        if failures:
            raise failures[0]

    def dm_deployments():
        yield from collector.pages(
            f"https://www.googleapis.com/deploymentmanager/v2/{scope}/global/deployments",
            scope, key="deployments", page_size_key=None,
            transform=lambda raw: _deployment(raw, project))

    return {
        "app_engine_version_detail": _envelope(collector, "app_engine_version_detail", scope,
                                                "appengine", app_version_details),
        "artifact_project_settings": _envelope(collector, "artifact_project_settings", scope,
                                                "artifactregistry", project_settings),
        "integration_version_detail": _envelope(collector, "integration_version_detail", scope,
                                                 "integrations", integration_versions),
        "dm_deployment": _envelope(collector, "dm_deployment", scope,
                                   "deploymentmanager", dm_deployments),
    }


def _app_version(raw, expected):
    if raw.get("name") != expected:
        raise ReadError("malformed", "wrong_appengine_version_target")
    return {key: raw[key] for key in ("name", "serviceAccount", "runtime", "env", "servingStatus")
            if isinstance(raw.get(key), str)}


def _settings(raw, scope):
    if raw.get("name") != f"{scope}/projectSettings":
        raise ReadError("malformed", "wrong_artifact_settings_target")
    return {key: raw[key] for key in ("name", "legacyRedirectionState", "pullPercent")
            if key in raw and isinstance(raw[key], (str, int))}


def _integration(raw, scope, parent):
    name = raw.get("name")
    if not isinstance(name, str) or not INTEGRATION_VERSION.fullmatch(name) or not name.startswith(
            f"{scope}/locations/{parent.split('/locations/', 1)[1].split('/', 1)[0]}/integrations/"):
        raise ReadError("malformed", "wrong_integration_version_target")
    # Task parameters/auth configs can contain sensitive values. Retain only
    # task identity/type and trigger identity/type, not their configuration.
    tasks = raw.get("taskConfigs", [])
    triggers = raw.get("triggerConfigs", [])
    if not isinstance(tasks, list) or not isinstance(triggers, list):
        raise ReadError("malformed", "integration_task_or_trigger_projection_missing")
    projected_triggers = []
    for trigger in triggers:
        if not isinstance(trigger, dict):
            raise ReadError("malformed", "malformed_integration_trigger")
        row = {k: trigger[k] for k in ("trigger", "triggerId", "triggerType")
               if isinstance(trigger.get(k), str)}
        scheduler = trigger.get("cloudSchedulerConfig")
        if isinstance(scheduler, dict) and isinstance(scheduler.get("serviceAccountEmail"), str):
            row["scheduler_service_account"] = scheduler["serviceAccountEmail"]
        projected_triggers.append(row)
    return {"name": name, "state": raw.get("state"), "createTime": raw.get("createTime"),
            "runAsServiceAccount": raw.get("runAsServiceAccount"),
            "tasks": [{k: task[k] for k in ("task", "taskId") if isinstance(task.get(k), str)}
                      for task in tasks if isinstance(task, dict)],
            "triggers": projected_triggers}


def _deployment(raw, project):
    name = raw.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]*[a-z0-9]", name):
        raise ReadError("malformed", "malformed_dm_deployment")
    return {"name": name, "project": project,
            **{k: raw[k] for k in ("id", "insertTime", "updateTime", "fingerprint")
               if isinstance(raw.get(k), (str, int))}}


def _collection(existing, supplemental, kind, scope):
    return supplemental.get(kind) or existing.get((kind, scope)) or {
        "type": kind, "scope": scope, "coverage_status": "missing", "items": []}


def _status(collection):
    return collection.get("coverage_status", "missing")


def _coverage(collection):
    return {"status": _status(collection), "error": collection.get("error"),
            "source_requests": collection.get("source_requests", [])}


def _items(collection):
    # Partial reads can still contain observed rows, but the status remains
    # partial and no absence or completeness inference may use them.
    rows = collection.get("items", [])
    return rows if isinstance(rows, list) else []


def _observed_version_cohorts(rows, status):
    if status not in COMPLETE:
        return {}
    grouped = {}
    for item in rows:
        name, stamp = item.get("name"), item.get("createTime")
        if not isinstance(name, str) or not isinstance(stamp, str):
            continue
        try:
            created = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            continue
        parent = name.rsplit("/versions/", 1)[0]
        grouped[parent] = min(grouped.get(parent, created), created)
    boundary = datetime(2026, 10, 15, tzinfo=timezone.utc)
    return {parent: {"earliest_observed_version_create_time": created.isoformat(),
                     "earliest_observed_version_cohort":
                     "before_2026_10_15" if created < boundary else "on_or_after_2026_10_15"}
            for parent, created in grouped.items()}


def normalize_facts(existing, supplemental, scope, *, catalog_versions=None,
                    catalog_attachments=None):
    """Coalesce only observed metadata; all operational/authority claims unknown.

    `existing` is Collector.collections keyed by (kind, scope). Private Catalog
    inputs are optional producer/consumer API envelopes; no adapter supplies
    them in the current collector. Missing inputs remain missing.
    """
    if not PROJECT.fullmatch(scope):
        raise ValueError("exact project scope required")
    app = _collection(existing, supplemental, "app_engine_application", scope)
    app_versions = _collection(existing, supplemental, "app_engine_version_detail", scope)
    repositories = _collection(existing, supplemental, "artifact_repository", scope)
    settings = _collection(existing, supplemental, "artifact_project_settings", scope)
    integrations = _collection(existing, supplemental, "integration_version_detail", scope)
    deployments = _collection(existing, supplemental, "dm_deployment", scope)
    products = catalog_versions or {"coverage_status": "missing", "items": []}
    attachments = catalog_attachments or {"coverage_status": "missing", "items": []}
    workloads = []
    workload_status = {}
    for kind in ("cloudrun_service", "cloudrun_job"):
        collection = _collection(existing, supplemental, kind, scope)
        workload_status[kind] = _status(collection)
        for item in _items(collection):
            template = item.get("template", {})
            if kind == "cloudrun_job":
                template = template.get("template", {}) if isinstance(template, dict) else {}
            if not isinstance(template, dict):
                continue
            containers = template.get("containers", [])
            if not isinstance(containers, list):
                continue
            for container in containers:
                image = container.get("image") if isinstance(container, dict) else None
                if isinstance(image, str) and isinstance(item.get("name"), str) and item["name"].startswith(scope + "/"):
                    workloads.append({"name": item.get("name"), "kind": kind,
                                      "image": image,
                                      "service_account": template.get("serviceAccount")})
    app_present = None
    if _status(app) in COMPLETE:
        if not _items(app):
            app_present = False
        elif len(_items(app)) == 1 and _items(app)[0].get("name") == "apps/" + scope.split("/", 1)[1]:
            app_present = True
    versions = [{k: item.get(k) for k in ("name", "serviceAccount", "runtime", "env", "servingStatus")}
                for item in _items(app_versions)]
    repo_rows = [{k: item.get(k) for k in ("name", "format", "mode")}
                 for item in _items(repositories) if isinstance(item.get("name"), str)
                 and item["name"].startswith(scope + "/locations/")
                 and item["name"].rsplit("/", 1)[-1] in GCR_REPOS]
    redirection = next((item.get("legacyRedirectionState") for item in _items(settings)), None)
    integration_rows = []
    for item in _items(integrations):
        integration_rows.append({k: item.get(k) for k in
            ("name", "state", "createTime", "runAsServiceAccount", "tasks", "triggers")})
    catalog_rows = []
    for item in _items(products):
        name = item.get("name")
        if isinstance(name, str) and re.fullmatch(r"catalogs/[^/]+/products/[^/]+/versions/[^/]+", name):
            catalog_rows.append({"name": name, "createTime": item.get("createTime"),
                                 "updateTime": item.get("updateTime"),
                                 "asset_type": item.get("assetType")})
    attachment_rows = []
    for item in _items(attachments):
        target = item.get("target")
        ancestors = item.get("ancestor_targets", [])
        if target == scope or isinstance(ancestors, list) and target in ancestors:
            attachment_rows.append({"catalog": item.get("catalog"), "target": target})
    return {
        "schema": "private-gcp-four-hold-metadata-v1", "scope": scope,
        "coverage": {"app_engine_application": _coverage(app),
                     "app_engine_version_detail": _coverage(app_versions),
                     "artifact_repository": _coverage(repositories),
                     "artifact_project_settings": _coverage(settings),
                     "integration_version_detail": _coverage(integrations),
                     "dm_deployment": _coverage(deployments),
                     "catalog_versions": _coverage(products),
                     "catalog_attachments": _coverage(attachments)},
        "app_engine": {"status": _status(app), "application_present": app_present,
                       "version_status": _status(app_versions), "versions": versions,
                       "new_version_artifact_deployability": "unknown",
                       "runtime_artifact_access": "unknown"},
        "artifact_registry": {"repository_status": _status(repositories), "gcr_repositories": repo_rows,
                              "settings_status": _status(settings), "redirection_state": redirection,
                              "workload_status": workload_status, "observed_workloads": workloads,
                              "tag_mutability": "unknown", "future_repull": "unknown",
                              "repository_upload_authorization": "unknown"},
        "application_integration": {"status": _status(integrations), "versions": integration_rows,
                                    "observed_version_cohorts": _observed_version_cohorts(
                                        integration_rows, _status(integrations)),
                                    "integration_creation_cohort": "unknown",
                                    "region_governance": "unknown",
                                    "authorized_invocation": "unknown",
                                    "source_specific_act_as": "unknown",
                                    "rollout_stage": "unknown",
                                    "rollout_boundary_utc": "2026-10-15T00:00:00Z"},
        "private_catalog": {"product_version_status": _status(products),
                            "product_versions": catalog_rows,
                            "attachment_status": _status(attachments),
                            "attachments": attachment_rows,
                            "deployment_status": _status(deployments),
                            "observed_deployments": _items(deployments),
                            "validated_asset_writability": "unknown",
                            "consumer_deployment_link": "unknown",
                            "dm_legacy_eligibility": "unknown"},
        "authority": "not_attested",
    }
