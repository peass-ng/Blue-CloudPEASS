"""Signed App Engine per-service version-count predicate over cached list facts."""
from __future__ import annotations

from . import register, result
from .facts import Unavailable, complete_items, get, memoized
from .fixtures import CASES


CHECK_ID = "gcp.appengine.service_version_count"
SPEC_SHA256 = "4d10a031bbecda0476874e4e369c16db1dc068d17c3fc7eaa9a0421f85585029"
_FIELDS = "versions(id,name,servingStatus,env,handlers(securityLevel)),nextPageToken"


def _maxima(index):
    def parse():
        context = get(index, "context", dict)
        scope = get(context, "scope", str)
        if not scope.startswith("projects/"):
            raise Unavailable("App Engine project scope unavailable")
        metadata = get(context, "metadata", dict)
        policy = get(metadata, "appengine_version_policy", dict)
        if get(policy, "status", str) != "collected":
            raise Unavailable("App Engine owner maxima unavailable")
        scopes = get(policy, "project_scopes", list)
        if any(not isinstance(value, str) or not value.startswith("projects/") for value in scopes) or scope not in scopes:
            raise Unavailable("App Engine owner maxima not bound to this project")
        maxima = []
        for field in ("appengine_max_installed_versions", "appengine_max_serving_versions"):
            value = get(policy, field, int)
            if value < 0:
                raise Unavailable("App Engine owner maximum invalid")
            maxima.append(value)
        return scope, tuple(maxima)
    return memoized(index, ("appengine_version_owner_maxima",), parse)


def _counts(index):
    def build():
        context = get(index, "context", dict)
        scope = get(context, "scope", str)
        if not scope.startswith("projects/"):
            raise Unavailable("App Engine project scope unavailable")
        prefix = "apps/" + scope.removeprefix("projects/") + "/services/"
        services = complete_items(index, "app_engine_service")
        versions = complete_items(index, "app_engine_version")
        counts = {}
        for service in services:
            if get(service, "_field_mask", str) != "services(id,name),nextPageToken":
                raise Unavailable("App Engine service projection unproven")
            name = get(service, "name", str)
            sid = get(service, "id", str)
            if name != prefix + sid or not sid or name in counts:
                raise Unavailable("App Engine service identity malformed or duplicated")
            counts[name] = [0, 0]
        seen = set()
        for version in versions:
            parent = get(version, "serviceName", str)
            if parent not in counts:
                raise Unavailable("App Engine version refers to an uncollected service")
            version_name = get(version, "name", str)
            vid = get(version, "id", str)
            if not vid or version_name != parent + "/versions/" + vid or version_name in seen:
                raise Unavailable("App Engine version identity malformed or duplicated")
            seen.add(version_name)
            if get(version, "_field_mask", str) != _FIELDS:
                raise Unavailable("App Engine serving status projection unproven")
            status = version.get("servingStatus", "SERVING")
            if not isinstance(status, str) or status not in {"SERVING", "STOPPED"}:
                raise Unavailable("App Engine serving status unavailable or unrecognized")
            counts[parent][0] += 1
            counts[parent][1] += status == "SERVING"
        return counts
    return memoized(index, ("appengine_service_version_counts",), build)


@register(
    CHECK_ID, "gcp", "hardening", "app_engine_service",
    "App Engine service stays within approved installed and serving version limits",
    "low", "CM-6",
    "Review service traffic and rollback needs; stop older versions or remove them only after the owner confirms they are no longer needed.",
    dependencies=["app_engine_service", "app_engine_version"],
)
def service_version_count(item, index):
    scope, (installed_max, serving_max) = _maxima(index)
    counts = _counts(index)
    name = get(item, "name", str)
    if not name.startswith("apps/" + scope.removeprefix("projects/") + "/services/"):
        raise Unavailable("App Engine service belongs to another project")
    if name not in counts:
        raise Unavailable("App Engine service inventory missing or ambiguous")
    installed, serving = counts[name]
    return result(installed > installed_max or serving > serving_max,
                  service=name, installed_versions=installed, serving_versions=serving,
                  approved_installed_maximum=installed_max, approved_serving_maximum=serving_max,
                  semantics="Complete cached App Engine versions.list inventory and explicit project-bound owner maxima")


_service = {"id": "default", "name": "apps/p-one/services/default",
    "_field_mask": "services(id,name),nextPageToken"}
_version = {"id": "v1", "name": "apps/p-one/services/default/versions/v1",
    "serviceName": "apps/p-one/services/default", "_field_mask": _FIELDS,
    "servingStatus": "SERVING"}


def _appengine_index(*, installed_max=1, serving_max=1, version_status="collected"):
    return {"context": {"scope": "projects/p-one", "metadata": {
        "appengine_version_policy": {"status": "collected",
            "project_scopes": ["projects/p-one"],
            "appengine_max_installed_versions": installed_max,
            "appengine_max_serving_versions": serving_max}}},
        "collections": {
            "app_engine_service": [{"status": "collected", "items": [_service]}],
            "app_engine_version": [{"status": version_status, "items": [_version]}]},
        "app_engine_service": [{"data": _service}],
        "app_engine_version": [{"data": _version}]}


CASES[CHECK_ID] = {"pass": _service, "pass_index": _appengine_index(),
    "fail": _service, "fail_index": _appengine_index(installed_max=0),
    "unknown": _service, "unknown_index": _appengine_index(version_status="partial"),
    "index": _appengine_index()}
