"""Signed Cloud Build inline-trigger logging check over sanitized cached facts."""
from __future__ import annotations

from . import register, result, unknown
from .facts import Unavailable, full_representation, get, omitted
from .fixtures import CASES


@register("gcp_pci_cloudbuild_trigger_3302edf7cb18", "gcp", "hardening", "cloudbuild_trigger",
          "Enabled inline Cloud Build trigger declares a stored-log mode", "medium", "AU-12",
          "Set an approved logging destination in the inline trigger or referenced build file and verify a new build.")
def trigger_logging(item, index):
    name = item.get("resourceName") or item.get("id")
    if not isinstance(name, str) or not name:
        raise Unavailable("Cloud Build trigger identity unavailable")
    if not full_representation(item):
        raise Unavailable("Cloud Build trigger does not have unmasked full-response provenance")
    # BuildTrigger.disabled is an implicit-presence proto3 bool. Its omitted
    # value is false only on an unmasked full BuildTrigger representation.
    disabled = omitted(item, "disabled", False, bool)
    if disabled:
        return "NOT_APPLICABLE", {"trigger": name, "reason": "trigger is explicitly disabled"}
    inline = item.get("inlineBuild")
    file_backed = any(field in item for field in ("filename", "gitFileSource", "autodetect"))
    if file_backed and inline is not None:
        return unknown("ambiguous inline and file-backed trigger configuration", trigger=name)
    if file_backed:
        return unknown("current file-backed build logging configuration was not collected", trigger=name)
    if not isinstance(inline, dict):
        return unknown("inline build logging configuration unavailable", trigger=name)
    state = get(inline, "logging_field_state", str)
    if state == "omitted":
        if "logging" in inline:
            return unknown("inconsistent omitted logging projection", trigger=name)
        logging = "LEGACY"
    elif state == "present":
        logging = get(inline, "logging", str)
    else:
        return unknown("malformed inline build logging configuration", trigger=name)
    if logging not in {"NONE", "LEGACY", "GCS_ONLY", "CLOUD_LOGGING_ONLY"}:
        return unknown("unrecognized Cloud Build logging enum", trigger=name, logging=logging)
    return result(logging == "NONE", trigger=name, logging=logging,
                  semantics="inline trigger configuration only; build execution is separate")


_trigger = {"id": "t1", "resourceName": "projects/p-one/locations/global/triggers/t1",
    "disabled": False, "_provenance": {"representation": "full"},
    "inlineBuild": {"logging_field_state": "present", "logging": "GCS_ONLY"}}
CASES["gcp_pci_cloudbuild_trigger_3302edf7cb18"] = {
    "pass": _trigger,
    "fail": {**_trigger, "inlineBuild": {"logging_field_state": "present",
        "logging": "NONE"}},
    "unknown": {**_trigger, "filename": "cloudbuild.yaml"},
}
