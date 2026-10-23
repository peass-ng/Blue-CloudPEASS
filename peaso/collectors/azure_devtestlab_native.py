"""Read DevTest Labs VM and artifact metadata without collecting repository secrets."""
from __future__ import annotations

import re
from urllib.parse import quote, urlsplit


ARM = "https://management.azure.com"
VERSION = "2018-09-15"
CHILDREN = ("devtest_lab_vm", "devtest_lab_artifact_source", "devtest_lab_artifact")
_SEGMENT = re.compile(r"[^/?#%\\\x00-\x1f\x7f]+")
_PATHS = {
    "devtest_lab_vm": ("virtualmachines", "microsoft.devtestlab/labs/virtualmachines"),
    "devtest_lab_artifact_source": ("artifactsources", "microsoft.devtestlab/labs/artifactsources"),
    "devtest_lab_artifact": ("artifacts", "microsoft.devtestlab/labs/artifactsources/artifacts"),
}


def required_types(wanted):
    chosen = set(wanted)
    if not chosen.intersection(CHILDREN):
        return set()
    required = {"devtest_lab"}
    if "devtest_lab_vm" in chosen:
        required.update(("devtest_lab_artifact_source", "devtest_lab_artifact"))
    if "devtest_lab_artifact" in chosen:
        required.add("devtest_lab_artifact_source")
    return required


def _valid_id(value, parent, kind):
    segment, expected_type = _PATHS[kind]
    prefix = parent.rstrip("/") + "/" + segment + "/"
    if (not isinstance(value, str) or not value.casefold().startswith(prefix.casefold())
            or not _SEGMENT.fullmatch(value[len(prefix):])
            or value[len(prefix):] in (".", "..")):
        raise ValueError("foreign or malformed DevTest Labs child ID")
    return expected_type


def _project(raw, parent, kind):
    if not isinstance(raw, dict):
        raise ValueError("malformed DevTest Labs child")
    ident = raw.get("id")
    expected_type = _valid_id(ident, parent, kind)
    if (str(raw.get("type") or "").casefold() != expected_type
            or str(raw.get("name") or "").casefold() != ident.rsplit("/", 1)[-1].casefold()
            or not isinstance(raw.get("properties"), dict)):
        raise ValueError("DevTest Labs child identity or properties unavailable")
    props = raw["properties"]
    if kind == "devtest_lab_vm":
        kept = ("computeId", "osType", "provisioningState", "lastKnownPowerState",
                "canApplyArtifacts")
    elif kind == "devtest_lab_artifact_source":
        kept = ("status", "sourceType", "provisioningState")
    else:
        kept = ("targetOsType", "title", "publisher")
    projected = {key: props[key] for key in kept if key in props}
    if kind == "devtest_lab_artifact_source":
        uri = props.get("uri")
        try:
            parsed = urlsplit(uri) if isinstance(uri, str) else None
            official = (parsed is not None and parsed.scheme == "https"
                        and parsed.hostname == "github.com" and not parsed.username
                        and not parsed.password and parsed.port in (None, 443)
                        and parsed.path.rstrip("/").removesuffix(".git").casefold()
                        == "/azure/azure-devtestlab" and not parsed.query and not parsed.fragment)
        except ValueError:
            official = False
        projected["officialPublicRepository"] = official
    return {"id": ident, "name": raw["name"], "type": raw["type"],
            "properties": projected,
            "_provenance": {"source_operation": "List", "read_only": True,
                            "api_version": VERSION, "parent_id": parent}}


def _jobs(reader, request, parents, kind):
    segment = _PATHS[kind][0]
    jobs = []
    for parent in sorted(set(parents)):
        if not _SEGMENT.fullmatch(parent.rsplit("/", 1)[-1]):
            raise ValueError("malformed DevTest Labs parent ID")
        url = ARM + quote(parent, safe="/") + "/" + segment + "?api-version=" + VERSION

        def fetch(parent=parent, url=url, kind=kind):
            seen = set()
            for page in reader.pages(request, url):
                projected = []
                for row in page:
                    item = _project(row, parent, kind)
                    ident = item["id"].casefold()
                    if ident in seen:
                        raise ValueError("duplicate DevTest Labs child")
                    seen.add(ident)
                    projected.append(item)
                yield projected

        jobs.append((kind, parent, "Microsoft.DevTestLab", fetch))
    if jobs:
        reader.run(jobs)


def collect(reader, request, scopes, wanted):
    selected = set(wanted).intersection(CHILDREN)
    if not selected:
        return
    labs = []
    for collection in reader.collections:
        if collection.get("type") != "devtest_lab" or collection.get("status") not in ("collected", "empty"):
            continue
        for row in collection.get("items") or ():
            ident = row.get("id") if isinstance(row, dict) else None
            if (isinstance(ident, str)
                    and re.fullmatch(r"/subscriptions/[^/?#%\\]+/resourcegroups/[^/?#%\\]+/providers/microsoft\.devtestlab/labs/[^/?#%\\]+", ident, re.I)
                    and str(row.get("type") or "").casefold() == "microsoft.devtestlab/labs"):
                labs.append(ident)
    if "devtest_lab_vm" in selected:
        _jobs(reader, request, labs, "devtest_lab_vm")
    if selected.intersection(("devtest_lab_artifact_source", "devtest_lab_artifact")):
        _jobs(reader, request, labs, "devtest_lab_artifact_source")
    if "devtest_lab_artifact" in selected:
        enabled = []
        for collection in reader.collections:
            if (collection.get("type") != "devtest_lab_artifact_source"
                    or collection.get("status") not in ("collected", "empty")):
                continue
            for row in collection.get("items") or ():
                if str((row.get("properties") or {}).get("status") or "").casefold() == "enabled":
                    enabled.append(row["id"])
        _jobs(reader, request, enabled, "devtest_lab_artifact")
