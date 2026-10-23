"""Allowlisted App Engine service/version facts from read-only list APIs."""
from __future__ import annotations

import re

from .gcp import ReadError


_PROJECT_ID = re.compile(r"[a-z](?:[a-z0-9-]*[a-z0-9])?\Z")
_SEGMENT = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z")
SERVICES_FIELDS = "services(id,name),nextPageToken"
VERSIONS_FIELDS = "versions(id,name,servingStatus,env,runtime,serviceAccount,handlers(securityLevel)),nextPageToken"
INSTANCES_FIELDS = "instances(id,name,vmName,vmZoneName,vmStatus,vmDebugEnabled,vmIp,vmLiveness),nextPageToken"


def approved_version_maxima(options, scopes=()):
    """Persist explicit owner maxima against the projects in this snapshot."""
    keys = ("appengine_max_installed_versions", "appengine_max_serving_versions")
    supplied = {key: options[key] for key in keys if key in options}
    if not supplied:
        return None
    for key, value in supplied.items():
        if type(value) is not int or value < 0:
            raise ValueError(key + " must be an explicit nonnegative integer")
    return {"status": "collected", "project_scopes": sorted(s for s in scopes if s.startswith("projects/")),
            **supplied}


def _project(scope):
    if not isinstance(scope, str) or not scope.startswith("projects/"):
        raise ReadError("malformed", "invalid_appengine_project_scope")
    project = scope.removeprefix("projects/")
    if not _PROJECT_ID.fullmatch(project):
        raise ReadError("malformed", "invalid_appengine_project_scope")
    return project


def _service(raw, project):
    if not isinstance(raw, dict):
        raise ReadError("malformed", "malformed_appengine_service")
    if set(raw) - {"id", "name"}:
        raise ReadError("unavailable", "appengine_service_fields_mask_not_honored")
    sid, name = raw.get("id"), raw.get("name")
    if not isinstance(sid, str) or not _SEGMENT.fullmatch(sid) or name != f"apps/{project}/services/{sid}":
        raise ReadError("malformed", "malformed_appengine_service_identity")
    return {"id": sid, "name": name, "_field_mask": SERVICES_FIELDS, "_representation": "partial"}


def _version(raw, service):
    if not isinstance(raw, dict):
        raise ReadError("malformed", "malformed_appengine_version")
    if set(raw) - {"id", "name", "servingStatus", "env", "runtime", "serviceAccount", "handlers"}:
        raise ReadError("unavailable", "appengine_version_fields_mask_not_honored")
    vid, name = raw.get("id"), raw.get("name")
    if not isinstance(vid, str) or not _SEGMENT.fullmatch(vid) or name != f"{service}/versions/{vid}":
        raise ReadError("malformed", "malformed_appengine_version_identity")
    output = {"id": vid, "name": name, "serviceName": service,
              "_field_mask": VERSIONS_FIELDS, "_representation": "partial"}
    for field in ("servingStatus", "env", "runtime", "serviceAccount"):
        if field in raw:
            if not isinstance(raw[field], str):
                raise ReadError("malformed", "malformed_appengine_" + field)
            output[field] = raw[field]
    if "handlers" in raw:
        handlers = raw["handlers"]
        if not isinstance(handlers, list) or any(not isinstance(row, dict) for row in handlers):
            raise ReadError("malformed", "malformed_appengine_handlers")
        if any(set(row) - {"securityLevel"} for row in handlers):
            raise ReadError("unavailable", "appengine_handler_fields_mask_not_honored")
        output["handlers"] = [{"securityLevel": row["securityLevel"]} if isinstance(row.get("securityLevel"), str)
                              else {} for row in handlers]
    return output


def list_services(collector, scope):
    project = _project(scope)
    yield from collector.pages(f"https://appengine.googleapis.com/v1/apps/{project}/services", scope,
        key="services", params={"fields": SERVICES_FIELDS},
        transform=lambda raw: _service(raw, project))


def list_versions(collector, scope, services):
    project = _project(scope)
    if not isinstance(services, list):
        raise ReadError("malformed", "malformed_appengine_service_inventory")
    seen = set()
    for service in services:
        if not isinstance(service, dict) or service.get("_field_mask") != SERVICES_FIELDS:
            raise ReadError("malformed", "appengine_service_projection_unproven")
        validated = _service({key: service.get(key) for key in ("id", "name")}, project)
        name = validated["name"]
        if name in seen:
            raise ReadError("malformed", "duplicate_appengine_service")
        seen.add(name)
        yield from collector.pages(f"https://appengine.googleapis.com/v1/{name}/versions", scope,
            key="versions", params={"view": "FULL", "fields": VERSIONS_FIELDS},
            transform=lambda raw, name=name: _version(raw, name))


def _instance(raw, version):
    if not isinstance(raw, dict) or set(raw) - {
            "id", "name", "vmName", "vmZoneName", "vmStatus", "vmDebugEnabled", "vmIp", "vmLiveness"}:
        raise ReadError("unavailable", "appengine_instance_fields_mask_not_honored")
    ident, name = raw.get("id"), raw.get("name")
    if not isinstance(ident, str) or not ident or name != f"{version}/instances/{ident}":
        raise ReadError("malformed", "malformed_appengine_instance_identity")
    output = {"id": ident, "name": name, "versionName": version,
              "_field_mask": INSTANCES_FIELDS, "_representation": "partial"}
    for field in ("vmName", "vmZoneName", "vmStatus", "vmIp", "vmLiveness"):
        if field in raw:
            if not isinstance(raw[field], str):
                raise ReadError("malformed", "malformed_appengine_" + field)
            output[field] = raw[field]
    if "vmDebugEnabled" in raw:
        if type(raw["vmDebugEnabled"]) is not bool:
            raise ReadError("malformed", "malformed_appengine_vmDebugEnabled")
        output["vmDebugEnabled"] = raw["vmDebugEnabled"]
    return output


def list_instances(collector, scope, versions):
    _project(scope)
    if not isinstance(versions, list):
        raise ReadError("malformed", "malformed_appengine_version_inventory")
    seen = set()
    for version in versions:
        if not isinstance(version, dict) or version.get("_field_mask") != VERSIONS_FIELDS:
            raise ReadError("malformed", "appengine_version_projection_unproven")
        name = version.get("name")
        if not isinstance(name, str) or not name.startswith(f"apps/{_project(scope)}/services/") or "/versions/" not in name:
            raise ReadError("malformed", "malformed_appengine_version_identity")
        if name in seen:
            raise ReadError("malformed", "duplicate_appengine_version")
        seen.add(name)
        if version.get("env") == "standard" or version.get("servingStatus") == "STOPPED":
            continue
        if version.get("env") != "flex" or version.get("servingStatus") != "SERVING":
            raise ReadError("unavailable", "appengine_version_environment_or_state_unknown")
        yield from collector.pages(f"https://appengine.googleapis.com/v1/{name}/instances", scope,
            key="instances", params={"fields": INSTANCES_FIELDS},
            transform=lambda raw, name=name: _instance(raw, name))
