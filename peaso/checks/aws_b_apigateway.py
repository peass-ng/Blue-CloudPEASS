"""API stage checks retain both REST and APIv2 relation families and defaults."""
from . import result, unknown
from .facts import get, list_of_objects
from .aws_b_core import install, SOURCES


def stage(item, family):
    get(item, "stageName" if family == "rest" else "StageName", str)
    return item


def method_settings(item):
    stage(item, "rest")
    settings = get(item, "methodSettings", dict)
    if "/*/*" in settings and "*/*" in settings:
        raise ValueError("duplicate wildcard method settings")
    wildcard = settings.get("/*/*", settings.get("*/*", {}))
    if not isinstance(wildcard, dict):
        raise ValueError("malformed wildcard method settings")
    return wildcard


@install("aws.b.apigateway.wildcard_cache_encryption", "rest_api_stage", "REST API wildcard method settings enable caching and encryption", {"stageName": "prod", "methodSettings": {"*/*": {"cachingEnabled": True, "cacheDataEncrypted": True}}}, {"stageName": "prod", "methodSettings": {"*/*": {"cachingEnabled": False, "cacheDataEncrypted": True}}}, query="apigateway_stage_cache_encryption_at_rest_enabled")
def cache(item, index):
    settings = method_settings(item)
    values = {name: settings.get(name, False) for name in ("cachingEnabled", "cacheDataEncrypted")}
    if any(type(value) is not bool for value in values.values()):
        return unknown("malformed caching configuration")
    return result(not all(values.values()), wildcard_method_settings=values, semantics="Exact source requires caching and encryption together; it is not solely an encryption-when-caching control.")


for _family, _kind in [("rest", "rest_api_stage"), ("http", "http_api_stage")]:
    def _logging(family, kind):
        path = "methodSettings" if family == "rest" else "DefaultRouteSettings"
        name_key = "stageName" if family == "rest" else "StageName"
        good = {name_key: "prod", path: {"*/*": {"loggingLevel": "INFO"}} if family == "rest" else {"LoggingLevel": "INFO"}}
        bad = {name_key: "prod", path: {"*/*": {"loggingLevel": "OFF"}} if family == "rest" else {"LoggingLevel": "OFF"}}
        cid = "aws.b.apigateway." + family + "_execution_logging"
        @install(cid, kind, "API stage execution logging is enabled", good, bad)
        def evaluate(item, index):
            if family == "rest":
                level = method_settings(item).get("loggingLevel", "OFF")
            else:
                stage(item, family)
                defaults = get(item, "DefaultRouteSettings", dict)
                level = defaults.get("LoggingLevel", "OFF")
            if level not in {"OFF", "INFO", "ERROR", ""}:
                return unknown("unrecognized stage logging level")
            return result(level in ("OFF", ""), logging_level=level, stage_family=family)
        SOURCES.setdefault("apigateway_stage_logging_enabled", []).append(cid)
    _logging(_family, _kind)


@install("aws.b.apigateway.rest_xray", "rest_api_stage", "REST API stage enables X-Ray tracing", {"stageName": "prod", "tracingEnabled": True}, {"stageName": "prod", "tracingEnabled": False}, query="apigateway_rest_api_stage_xray_tracing_enabled")
def xray(item, index):
    stage(item, "rest")
    enabled = get(item, "tracingEnabled", bool)
    return result(not enabled, tracing_enabled=enabled)


for _field, _suffix, _query in [("clientCertificateId", "client_certificate", "apigateway_rest_api_stage_use_ssl_certificate"), ("webAclArn", "waf_reference", "apigateway_stage_use_waf_web_acl")]:
    def _presence(field, suffix, query):
        @install("aws.b.apigateway." + suffix, "rest_api_stage", "REST API stage declares " + field, {"stageName": "prod", field: "configured"}, {"stageName": "prod"}, query=query)
        def evaluate(item, index):
            stage(item, "rest")
            value = item.get(field)
            if value is not None and not isinstance(value, str):
                return unknown("malformed stage reference", field=field)
            return result(not value, field=field, declared_reference=value, semantics="Reference presence only; certificate validity/WAF effectiveness is not inferred.")
    _presence(_field, _suffix, _query)


@install("aws.b.apigateway.private_endpoint_type", "rest_api", "REST API endpoint configuration contains PRIVATE type", {"endpointConfiguration": {"types": ["PRIVATE"]}}, {"endpointConfiguration": {"types": ["REGIONAL"]}}, query="apigateway_rest_api_endpoint_restrict_public_access", category="exposure")
def private_api(item, index):
    types = get(item, "endpointConfiguration.types", list)
    if any(value not in {"PRIVATE", "REGIONAL", "EDGE"} for value in types):
        return unknown("unknown endpoint configuration type")
    return result("PRIVATE" not in types, endpoint_types=types, semantics="Endpoint configuration only; authorizers, policies and routing are separate controls.")
