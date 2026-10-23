"""Native, secret-free Container Apps Job and environment inventories."""

from __future__ import annotations

import re


ARM = "https://management.azure.com"
VERSION = "2025-07-01"
JOB_KIND = "container_app_job"
ENV_KIND = "container_app_environment"
NATIVE_TYPES = (JOB_KIND, ENV_KIND)
CONTRACTS = {
    JOB_KIND: ("jobs", "microsoft.app/jobs"),
    ENV_KIND: ("managedEnvironments", "microsoft.app/managedenvironments"),
}
PARENT = re.compile(r"/subscriptions/[^/?#%\\\s]+/resourcegroups/[^/?#%\\\s]+/providers/microsoft\.app/", re.I)


def _resource_id(value, scope, segment):
    if (not isinstance(value, str)
            or not re.fullmatch(PARENT.pattern + re.escape(segment) + r"/[^/?#%\\\s]+", value, re.I)
            or not value.casefold().startswith(scope.casefold() + "/")
            or any(part in (".", "..") for part in value.split("/"))):
        raise ValueError("foreign or malformed Container Apps resource")
    return value


def _project(raw, rid, kind):
    _, expected_type = CONTRACTS[kind]
    if (not isinstance(raw, dict) or str(raw.get("id") or "").casefold() != rid.casefold()
            or str(raw.get("type") or "").casefold() != expected_type
            or not isinstance(raw.get("properties"), dict)):
        raise ValueError("native Container Apps GET unavailable")
    props = raw["properties"]
    fields = (("provisioningState", "runningState", "environmentId", "workloadProfileName") if kind == JOB_KIND
              else ("provisioningState",))
    projected = {"id": rid, "type": raw["type"], "location": raw.get("location"),
            "properties": {key: props[key] for key in fields if key in props},
            "_provenance": {"method": "LIST+GET", "api_version": VERSION, "read_only": True}}
    if kind == JOB_KIND:
        identity = raw.get("identity") or {}
        if not isinstance(identity, dict):
            raise ValueError("Container Apps Job identity malformed")
        assigned = identity.get("userAssignedIdentities") or {}
        if not isinstance(assigned, dict) or any(
                not isinstance(key, str) or not isinstance(value, dict)
                for key, value in assigned.items()):
            raise ValueError("Container Apps Job identities malformed")
        projected["identity"] = {
            "type": identity.get("type"), "principalId": identity.get("principalId"),
            "userAssignedIdentities": {key: {"principalId": value.get("principalId")}
                                       for key, value in assigned.items()},
        }
        configuration = props.get("configuration") or {}
        if not isinstance(configuration, dict):
            raise ValueError("Container Apps Job configuration malformed")
        settings = configuration.get("identitySettings")
        if settings is not None and (not isinstance(settings, list) or any(
                not isinstance(setting, dict) or not isinstance(setting.get("identity"), str)
                or setting.get("lifecycle") is not None and not isinstance(setting["lifecycle"], str)
                for setting in settings)):
            raise ValueError("Container Apps Job identity settings malformed")
        projected["properties"]["configuration"] = {
            "identitySettings": ([{"identity": setting["identity"],
                                  "lifecycle": setting.get("lifecycle")}
                                 for setting in settings] if settings is not None else None)}
    else:
        profiles = props.get("workloadProfiles")
        if profiles is not None and (not isinstance(profiles, list) or any(
                not isinstance(profile, dict) or not isinstance(profile.get("name"), str)
                or not isinstance(profile.get("workloadProfileType"), str)
                for profile in profiles)):
            raise ValueError("Container Apps environment workload profiles malformed")
        projected["properties"]["workloadProfiles"] = (
            [{"name": profile["name"], "workloadProfileType": profile["workloadProfileType"]}
             for profile in profiles] if profiles is not None else None)
    return projected


def collect(reader, request, scopes, wanted):
    jobs = []
    for kind in NATIVE_TYPES:
        if kind not in wanted:
            continue
        segment, expected_type = CONTRACTS[kind]
        for scope in scopes:
            def fetch(scope=scope, segment=segment, expected_type=expected_type, kind=kind):
                selected, seen = [], set()
                url = ARM + scope + "/providers/Microsoft.App/" + segment + "?api-version=" + VERSION
                for page in reader.pages(request, url):
                    for row in page:
                        rid = _resource_id(row.get("id") if isinstance(row, dict) else None, scope, segment)
                        if str(row.get("type") or "").casefold() != expected_type or rid.casefold() in seen:
                            raise ValueError("foreign or duplicate Container Apps resource")
                        seen.add(rid.casefold())
                        selected.append(rid)
                for rid in selected:
                    raw = reader.call(request, ARM + rid + "?api-version=" + VERSION)
                    yield [_project(raw, rid, kind)]
            jobs.append((kind, scope, "Microsoft.App", fetch))
    reader.run(jobs)
