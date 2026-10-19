"""Read-only provider collection dispatcher."""
from .base import Collector, TYPES


def collect_live(connector, requirements=None):
    provider = connector["provider"]
    scopes = connector.get("scopes", [])
    normalized = {**connector, "scopes": list(dict.fromkeys(scopes))}
    from peaso.progress import current_callback
    callback = current_callback()
    if callback is not None:
        # Runtime-only copy: neither the input connector nor saved snapshots
        # contain this callable. Provider owners keep it out of metadata.
        def runtime_progress(event):
            callback(event)
        normalized["options"] = {**connector.get("options", {}), "_progress_callback": runtime_progress}
    from importlib import import_module
    from .bulk_evidence import collect
    from peaso.cancellation import current_event
    cancelled = current_event()
    if cancelled is not None:
        normalized["options"] = {**normalized.get("options", {}), "cancel_event": cancelled}
    result = collect(import_module("peaso.collectors." + provider), normalized, requirements)
    if cancelled is not None and cancelled.is_set():
        raise KeyboardInterrupt
    return result


def supported_types(provider):
    from importlib import import_module
    module = import_module("peaso.collectors." + provider)
    kinds = sorted(getattr(module, "AWS_TYPES", getattr(module, "SUPPORTED_TYPES", getattr(module, "TYPES", TYPES[provider]))))
    from .bulk_evidence import ALIASES
    kinds = sorted(set(kinds) | {alias for alias,source in ALIASES[provider].items() if source in kinds})
    TYPES[provider] = kinds
    return kinds

# Provider modules import cloud SDKs lazily; publishing this registry requires no
# credentials or cloud calls and avoids a stale subset in shared consumers.
for _provider in tuple(TYPES):
    supported_types(_provider)
