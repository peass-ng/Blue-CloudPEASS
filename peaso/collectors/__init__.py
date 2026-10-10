"""Read-only provider collection dispatcher."""
from .base import Collector, TYPES


def collect_live(connector, requirements=None):
    provider = connector["provider"]
    scopes = connector.get("scopes", [])
    normalized = {**connector, "scopes": list(dict.fromkeys(scopes))}
    from importlib import import_module
    return import_module("peaso.collectors." + provider).collect(normalized, requirements)


def supported_types(provider):
    from importlib import import_module
    module = import_module("peaso.collectors." + provider)
    kinds = sorted(getattr(module, "AWS_TYPES", getattr(module, "SUPPORTED_TYPES", getattr(module, "TYPES", TYPES[provider]))))
    TYPES[provider] = kinds
    return kinds

# Provider modules import cloud SDKs lazily; publishing this registry requires no
# credentials or cloud calls and avoids a stale subset in shared consumers.
for _provider in tuple(TYPES):
    supported_types(_provider)
