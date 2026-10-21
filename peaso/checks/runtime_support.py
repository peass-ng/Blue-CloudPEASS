"""Isolated, pure App Service Linux web-app runtime lifecycle proposal.

Inputs are unmodified ARM GET responses. This module is intentionally not imported
by the provider, collector, check registry, or full test suite.
"""

from datetime import datetime, timezone
import re

CHECK_ID = "azure.review.app_service.runtime_support_declared"
GROUP = "Hardening"
_SITE = re.compile(r"^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+$", re.I)


def _result(status, evidence):
    return {"check_id": CHECK_ID, "group": GROUP, "status": status, "evidence": evidence}


def _unknown(reason):
    return _result("UNKNOWN", reason)


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except ValueError:
        return None


def evaluate(site_response, config_response, catalog_pages, *, as_of):
    """Assess an exact Linux web app against complete regional webAppStacks pages.

    Responses are {status: HTTP status, body: ARM JSON}. ``catalog_pages`` is an
    ordered list of such responses; continuation is accepted only when every
    preceding page advertises nextLink and the final page does not. The caller
    must fetch the advertised URL and preserve order; no cloud call occurs here.
    """
    if not isinstance(as_of, datetime) or as_of.tzinfo is None:
        return _unknown("The observation time is missing or has no time zone.")
    now = as_of.astimezone(timezone.utc)
    for label, response in (("site", site_response), ("configuration", config_response)):
        if not isinstance(response, dict) or type(response.get("status")) is not int or response["status"] != 200 or not isinstance(response.get("body"), dict):
            return _unknown(f"The exact {label} read was denied, missing, or malformed.")
    site = site_response["body"]
    site_id = site.get("id")
    if not isinstance(site_id, str) or not _SITE.fullmatch(site_id):
        return _unknown("The selected site has a malformed or unsupported native ID.")
    if "type" in site and str(site["type"]).casefold() != "microsoft.web/sites":
        return _unknown("The selected site declares a foreign native resource type.")
    props = site.get("properties")
    if not isinstance(props, dict) or props.get("reserved") is not True:
        return _unknown("The selected site is not proven to be a Linux App Service app.")
    kind = site.get("kind")
    if (not isinstance(kind, str) or "app" not in {v.strip().lower() for v in kind.split(",")}
            or "functionapp" in kind.lower() or "container" in kind.lower()):
        return _unknown("The selected site may use Functions or a custom container runtime.")
    location = site.get("location")
    if not isinstance(location, str) or not location.strip():
        return _unknown("The selected site's Azure region is missing.")
    config = config_response["body"]
    if str(config.get("id", "")).lower() != (site_id + "/config/web").lower():
        return _unknown("The configuration does not belong to the selected site.")
    if "type" in config and str(config["type"]).casefold() != "microsoft.web/sites/config":
        return _unknown("The configuration declares a foreign native resource type.")
    settings = config.get("properties")
    runtime = settings.get("linuxFxVersion") if isinstance(settings, dict) else None
    if not isinstance(runtime, str) or not runtime.strip():
        return _unknown("The Linux runtime declaration is missing.")
    if runtime.upper().startswith(("DOCKER|", "COMPOSE|")) or "|" not in runtime:
        return _unknown("The runtime is a container or an unresolved stack alias.")
    if not isinstance(catalog_pages, list) or not catalog_pages:
        return _unknown("Regional web app stack metadata is missing.")
    entries = []
    for index, page in enumerate(catalog_pages):
        if not isinstance(page, dict) or type(page.get("status")) is not int or page["status"] != 200 or not isinstance(page.get("body"), dict):
            return _unknown("Regional web app stack metadata was denied or malformed.")
        body = page["body"]
        if not isinstance(body.get("value"), list):
            return _unknown("A regional stack page has no value list.")
        next_link = body.get("nextLink")
        if next_link is not None and (not isinstance(next_link, str) or not next_link):
            return _unknown("Regional stack pages have a malformed continuation link.")
        if index < len(catalog_pages) - 1 and (not isinstance(next_link, str) or not next_link):
            return _unknown("Regional stack pages have an invalid continuation chain.")
        if index == len(catalog_pages) - 1 and next_link:
            return _unknown("Regional stack metadata is incomplete because another page exists.")
        entries.extend(body["value"])
    matches = []
    seen_ids = set()
    for entry in entries:
        if not isinstance(entry, dict):
            return _unknown("A regional stack entry is malformed.")
        entry_id = entry.get("id")
        entry_location = entry.get("location")
        if not isinstance(entry_id, str) or not isinstance(entry_location, str):
            return _unknown("A regional stack entry has no native ID or region.")
        if str(entry.get("type", "")).lower() != "microsoft.web/locations/webappstacks":
            return _unknown("The stack catalog contains a foreign resource type.")
        if entry_location.replace(" ", "").lower() != location.replace(" ", "").lower():
            return _unknown("The stack catalog contains a foreign region.")
        # The location-specific GET sample identifies each item with a
        # /locations/webAppStacks/{name} ID and carries region separately.
        expected_prefix = "/providers/microsoft.web/locations/webappstacks/"
        name = entry_id[len(expected_prefix):] if entry_id.lower().startswith(expected_prefix) else ""
        if not name or "/" in name or name in (".", "..") or name.casefold() in seen_ids:
            return _unknown("The stack catalog contains a foreign resource ID.")
        seen_ids.add(name.casefold())
        if ("name" in entry and (not isinstance(entry["name"], str) or entry["name"].casefold() != name.casefold())):
            return _unknown("The stack catalog entry name disagrees with its native ID.")
        major_versions = entry.get("properties", {}).get("majorVersions") if isinstance(entry.get("properties"), dict) else None
        if not isinstance(major_versions, list):
            return _unknown("A regional stack entry has no major versions.")
        for major in major_versions:
            if not isinstance(major, dict) or not isinstance(major.get("minorVersions"), list):
                return _unknown("A regional stack major version is malformed.")
            for minor in major["minorVersions"]:
                if not isinstance(minor, dict):
                    return _unknown("A regional stack minor version is malformed.")
                stack_settings = minor.get("stackSettings")
                linux = stack_settings.get("linuxRuntimeSettings") if isinstance(stack_settings, dict) else None
                native_runtime = linux.get("runtimeVersion") if isinstance(linux, dict) else None
                if native_runtime is not None and not isinstance(native_runtime, str):
                    return _unknown("A regional stack runtime identifier is malformed.")
                if isinstance(native_runtime, str) and native_runtime.lower() == runtime.lower():
                    matches.append(linux)
    if len(matches) != 1:
        return _unknown("The declared runtime has no unique exact match in complete regional metadata.")
    match = matches[0]
    for key in ("isPreview", "isEarlyAccess", "isDeprecated"):
        if key in match and type(match[key]) is not bool:
            return _unknown("The matching runtime has a malformed lifecycle flag.")
    if match.get("isPreview") is True or match.get("isEarlyAccess") is True:
        return _unknown("The matching runtime is preview or early access; its support claim is unresolved.")
    eol_raw = match.get("endOfLifeDate")
    eol = _date(eol_raw) if eol_raw is not None else None
    if eol_raw is not None and eol is None:
        return _unknown("The matching runtime has a malformed end of life date.")
    if match.get("isDeprecated") is True or (eol is not None and eol <= now):
        return _result("FAIL", f"The Linux web app declares {runtime}; its exact regional stack is deprecated or past its stated end of life date. This is provider lifecycle evidence, not an application compatibility test.")
    if match.get("isDeprecated") is False and (eol is None or eol > now):
        return _result("PASS", f"The Linux web app declares {runtime}; its exact regional stack is not deprecated and any stated end of life date is in the future. Its patch level and application compatibility were not tested.")
    return _unknown("The matching regional stack does not explicitly declare deprecation state.")
