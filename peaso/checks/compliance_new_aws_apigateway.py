"""Signed REST API stage setting checks over complete cached GetStages facts.

These checks grade declared stage settings. They do not infer deployed routes,
CloudWatch log delivery, cache contents, or method-setting field inheritance.
"""
from __future__ import annotations

import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, guard, memoized
from .fixtures import CASES


LOGGING_ID = "aws.pci.apigateway.all_methods_logging"
CACHE_ID = "aws.pci.apigateway.all_methods_cache_encrypted"
LOGGING_SPEC_SHA256 = "e9aa2380393b6fc8c69c68b574b2e0a2baed8bd4e9b5cc6aa4d254af5a42a5f3"
CACHE_SPEC_SHA256 = "38d3fa49e17972ee0d4d0b00c89debfb863a76f72d30e7a165af7332702fa029"
_STAGE_ARN = re.compile(r"^arn:(aws(?:-[a-z0-9-]+)?):apigateway:([a-z0-9-]+)::/(restapis|apis)/([A-Za-z0-9]+)/stages/([A-Za-z0-9_-]{1,128})$")
_SCOPE = re.compile(r"^[0-9]{12}/([a-z0-9-]+)$")
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"}
_PATH = re.compile(r"^~1[A-Za-z0-9~{}+._%-]*$")


def _stage_inventory(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("API Gateway provider authority unavailable")
    scope = _SCOPE.fullmatch(get(context, "scope", str))
    if scope is None:
        raise Unavailable("regional API Gateway scope unavailable")
    envelopes = get(index, "collections", dict).get("rest_api_stage")
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or
            envelopes[0].get("type") != "rest_api_stage" or
            envelopes[0].get("scope") != context["scope"]):
        raise Unavailable("stage collection scope authority unavailable")
    stages = complete_items(index, "rest_api_stage")
    by_arn, identities, partition = {}, set(), None
    for row in stages:
        api_id = get(row, "ParentApiId", str)
        stage_name = get(row, "stageName", str)
        arn = get(row, "id", str)
        parsed = _STAGE_ARN.fullmatch(arn)
        if (not parsed or parsed.group(2) != scope.group(1) or
                parsed.group(4) != api_id or parsed.group(5) != stage_name):
            raise Unavailable("REST API stage ARN does not match collected identity")
        # Before this collector correction the internal REST stage ID used
        # /apis/. Accept that exact historical form only with the same
        # GetStages provenance and parent identity; new reads use /restapis/.
        provenance = get(row, "_provenance", dict)
        if (provenance.get("source_operation") != "get_stages" or
                provenance.get("parent_api_id") != api_id or
                provenance.get("read_only") is not True):
            raise Unavailable("complete GetStages provenance unavailable")
        identity = (api_id, stage_name)
        if arn in by_arn or identity in identities:
            raise Unavailable("duplicate REST API stage identity")
        if partition is not None and parsed.group(1) != partition:
            raise Unavailable("ambiguous stage ARN partition in regional inventory")
        partition = parsed.group(1)
        by_arn[arn] = row
        identities.add(identity)
    return by_arn


def _settings(item, index, *, allow_missing=False):
    by_arn = memoized(index, ("verified_rest_api_stage_inventory",),
                      lambda: _stage_inventory(index))
    api_id = get(item, "ParentApiId", str)
    stage_name = get(item, "stageName", str)
    arn = get(item, "id", str)
    if by_arn.get(arn) != item or get(by_arn[arn], "ParentApiId", str) != api_id or get(by_arn[arn], "stageName", str) != stage_name:
        raise Unavailable("stage identity differs from collected GetStages fact")
    if allow_missing and "methodSettings" not in item and "methodSettings" not in item.get("_coverage", {}):
        return arn, {}
    settings = get(item, "methodSettings", dict)
    if not settings and not allow_missing:
        raise Unavailable("stage method settings unavailable")
    for key, value in settings.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            raise Unavailable("malformed method setting map")
        if key != "*/*":
            path, sep, method = key.rpartition("/")
            if not sep or not _PATH.fullmatch(path) or method not in _METHODS:
                raise Unavailable("unrecognized stage method setting key")
        guard(value)
    return arn, settings


def _enum(settings, key, field, allowed):
    row = settings[key]
    if field not in row:
        return None
    value = get(row, field, str)
    if value not in allowed:
        raise Unavailable("unrecognized method setting " + field)
    return value


def _boolean(settings, key, field):
    row = settings[key]
    return get(row, field, bool) if field in row else None


@register(LOGGING_ID, "aws", "hardening", "rest_api_stage",
          "All REST API stage methods declare execution logging", "medium", "AU-12",
          "Set ERROR or INFO execution logging on the stage wildcard and review each method override.",
          dependencies=["rest_api_stage"])
def all_methods_logging(item, index):
    arn, settings = _settings(item, index)
    unsafe, incomplete = [], []
    for key in settings:
        try:
            level = _enum(settings, key, "loggingLevel", {"OFF", "ERROR", "INFO"})
        except Unavailable:
            incomplete.append(key)
            continue
        if level is None:
            incomplete.append(key)
        elif key != "*/*" and level == "OFF":
            unsafe.append(key)
    if unsafe:
        return result(True, stage_arn=arn, unsafe_method_overrides=sorted(unsafe),
                      semantics="Explicit configured method overrides; deployed traffic and log delivery unverified")
    if "*/*" not in settings or settings["*/*"].get("loggingLevel") == "OFF":
        return unknown("no safe covering stage wildcard; deployed method inventory unavailable",
                       stage_arn=arn)
    if incomplete:
        return unknown("method override logging value unavailable or unrecognized",
                       stage_arn=arn, uncertain_method_settings=sorted(incomplete))
    return result(False, stage_arn=arn, logging_level=settings["*/*"]["loggingLevel"],
                  checked_override_count=len(settings) - 1,
                  semantics="Declared complete GetStages settings; CloudWatch delivery is separate")


@register(CACHE_ID, "aws", "hardening", "rest_api_stage",
          "Enabled REST API stage method caches declare encryption", "high", "SC-28",
          "Enable cache data encryption only for methods whose cache is already approved; do not activate optional caching solely for this check.",
          dependencies=["rest_api_stage"])
def all_enabled_method_caches_encrypted(item, index):
    cluster_enabled = get(item, "cacheClusterEnabled", bool)
    arn, settings = _settings(item, index, allow_missing=not cluster_enabled)
    coverage = item.get("_coverage", {})
    marker = coverage.get("cacheClusterStatus")
    status = None
    empty_omission = ("cacheClusterStatus" not in item and isinstance(marker, dict)
                      and marker.get("status") == "empty")
    if not empty_omission and ("cacheClusterStatus" in item or "cacheClusterStatus" in coverage):
        status = get(item, "cacheClusterStatus", str)
    if status is not None and (not isinstance(status, str) or status not in {
            "CREATE_IN_PROGRESS", "AVAILABLE", "DELETE_IN_PROGRESS", "NOT_AVAILABLE", "FLUSH_IN_PROGRESS"}):
        return unknown("unrecognized stage cache cluster status", stage_arn=arn)
    if not cluster_enabled:
        if status not in (None, "NOT_AVAILABLE"):
            return unknown("disabled cache conflicts with cluster status", stage_arn=arn)
        return "NOT_APPLICABLE", {"stage_arn": arn, "reason": "stage cache cluster is disabled"}
    if status != "AVAILABLE":
        return unknown("enabled cache cluster is not proven available", stage_arn=arn,
                       cache_cluster_status=status)
    unsafe, uncertain, enabled = [], [], []
    for key in settings:
        try:
            caching = _boolean(settings, key, "cachingEnabled")
            encryption = _boolean(settings, key, "cacheDataEncrypted") if caching else None
        except Unavailable:
            uncertain.append(key)
            continue
        if caching is None:
            uncertain.append(key)
        elif caching:
            enabled.append(key)
            if encryption is None:
                uncertain.append(key)
            elif not encryption and key != "*/*":
                unsafe.append(key)
    if unsafe:
        return result(True, stage_arn=arn, unencrypted_enabled_overrides=sorted(unsafe),
                      semantics="Explicit configured enabled method caches; cached data not inspected")
    if "*/*" not in settings:
        return unknown("no covering cache wildcard; deployed method inventory unavailable",
                       stage_arn=arn)
    if uncertain:
        return unknown("method cache setting unavailable or inheritance unproven",
                       stage_arn=arn, uncertain_method_settings=sorted(uncertain))
    if _boolean(settings, "*/*", "cachingEnabled") and not _boolean(settings, "*/*", "cacheDataEncrypted"):
        return unknown("unencrypted wildcard lacks stage-bound deployed method proof",
                       stage_arn=arn)
    if not enabled:
        return "NOT_APPLICABLE", {"stage_arn": arn,
                                  "reason": "all declared method caches are disabled"}
    return result(False, stage_arn=arn, enabled_method_settings=sorted(enabled),
                  semantics="Declared complete GetStages settings; cached responses and routes unverified")


def _fixture_stage(**fields):
    stage = {"stageName": "prod", "ParentApiId": "abc123", "id":
        "arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod",
        "_provenance": {"source_operation": "get_stages", "parent_api_id": "abc123",
            "read_only": True}, **fields}
    return stage


def _fixture_index(stage):
    scope = "123456789012/us-east-1"
    return {"context": {"provider": "aws", "scope": scope},
        "collections": {"rest_api_stage": [{"type": "rest_api_stage",
            "scope": scope, "status": "collected", "items": [stage]}]},
        "rest_api_stage": [{"type": "rest_api_stage", "scope": scope, "data": stage}]}


_log_pass = _fixture_stage(methodSettings={"*/*": {"loggingLevel": "INFO"}})
_log_fail = _fixture_stage(methodSettings={"*/*": {"loggingLevel": "INFO"},
    "~1pets/GET": {"loggingLevel": "OFF"}})
_log_unknown = _fixture_stage(methodSettings={"~1pets/GET": {"loggingLevel": "INFO"}})
CASES[LOGGING_ID] = {"pass": _log_pass, "pass_index": _fixture_index(_log_pass),
    "fail": _log_fail, "fail_index": _fixture_index(_log_fail),
    "unknown": _log_unknown, "unknown_index": _fixture_index(_log_unknown),
    "index": _fixture_index(_log_pass)}
_cache_pass = _fixture_stage(cacheClusterEnabled=True, cacheClusterStatus="AVAILABLE",
    methodSettings={"*/*": {"cachingEnabled": True, "cacheDataEncrypted": True}})
_cache_fail = _fixture_stage(cacheClusterEnabled=True, cacheClusterStatus="AVAILABLE",
    methodSettings={"*/*": {"cachingEnabled": True, "cacheDataEncrypted": True},
        "~1pets/GET": {"cachingEnabled": True, "cacheDataEncrypted": False}})
_cache_unknown = _fixture_stage(cacheClusterEnabled=True, cacheClusterStatus="AVAILABLE",
    methodSettings={"*/*": {"cachingEnabled": True, "cacheDataEncrypted": False}})
CASES[CACHE_ID] = {"pass": _cache_pass, "pass_index": _fixture_index(_cache_pass),
    "fail": _cache_fail, "fail_index": _fixture_index(_cache_fail),
    "unknown": _cache_unknown, "unknown_index": _fixture_index(_cache_unknown),
    "index": _fixture_index(_cache_pass)}
