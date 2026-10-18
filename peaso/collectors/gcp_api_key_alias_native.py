"""Bind API Keys and Service Usage project aliases to an independent CRM read.

This changes only evaluator-facing `name`; `_resource_id`, `native_id`, and
`rawNativeName` continue to identify the exact returned native resource.
"""
from __future__ import annotations

import re


_NUMBER = re.compile(r"projects/[1-9][0-9]*\Z", re.ASCII)
_PROJECT_ID = re.compile(r"projects/[a-z][a-z0-9-]*[a-z0-9]\Z", re.ASCII)


def _readable(row, *fields):
    coverage = row.get("_coverage", {})
    return (isinstance(coverage, dict) and all(
        field not in coverage or isinstance(coverage[field], dict) and
        coverage[field].get("status") == "collected" for field in fields))


def _complete(envelope, scope, kind):
    return (isinstance(envelope, dict) and envelope.get("type") == kind and
            envelope.get("scope") == scope and envelope.get("status") == "collected" and
            envelope.get("coverage_status") == "collected" and
            isinstance(envelope.get("items"), list) and
            isinstance(envelope.get("source_requests"), list) and
            bool(envelope["source_requests"]) and
            all(isinstance(ref, str) and ref for ref in envelope["source_requests"]))


def _request(ledger, refs, scope, url):
    """Return a current successful GET request that owns the native fact."""
    if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not ref for ref in refs):
        return None
    hits = [ledger.get(ref) for ref in refs]
    return next((row for row in hits if isinstance(row, dict) and row.get("method") == "GET" and
                 row.get("scope") == scope and row.get("status") == "collected" and
                 row.get("url") == url), None)


def _refs_current(ledger, refs, scope):
    return (isinstance(refs, list) and bool(refs) and
            all(isinstance(ref, str) and ref and isinstance(ledger.get(ref), dict) and
                ledger[ref].get("scope") == scope and ledger[ref].get("status") == "collected"
                for ref in refs))


def _project_binding(collector, scope, ledger):
    envelope = collector.collections.get(("project", scope))
    if not _complete(envelope, scope, "project") or len(envelope["items"]) != 1:
        return None
    row = envelope["items"][0]
    if not isinstance(row, dict) or not _readable(row, "name", "projectId", "projectNumber"):
        return None
    provenance = row.get("_provenance")
    if (not isinstance(provenance, dict) or provenance.get("scope") != scope or
            provenance.get("collected_at") != collector.read_time):
        return None
    refs = provenance.get("source_requests")
    if (not _refs_current(ledger, refs, scope) or not set(refs) <= set(envelope["source_requests"]) or
            not _request(ledger, refs, scope, "https://cloudresourcemanager.googleapis.com/v3/" + scope)):
        return None
    number, project_id = row.get("name"), row.get("projectId")
    if (not isinstance(number, str) or not _NUMBER.fullmatch(number) or
            not isinstance(project_id, str) or not _PROJECT_ID.fullmatch("projects/" + project_id) or
            scope != "projects/" + project_id or
            row.get("native_id") != number or row.get("_resource_id") != number):
        return None
    declared = row.get("projectNumber")
    if declared is not None and str(declared) != number.removeprefix("projects/"):
        return None
    return number, tuple(sorted(set(refs)))


def _native_row(collector, envelope, row, ledger, scope, kind):
    if not _readable(row, "name"):
        return False
    provenance = row.get("_provenance")
    if (not isinstance(provenance, dict) or provenance.get("scope") != scope or
            provenance.get("collected_at") != collector.read_time):
        return False
    refs = provenance.get("source_requests")
    if not _refs_current(ledger, refs, scope) or not set(refs) <= set(envelope["source_requests"]):
        return False
    url = ("https://apikeys.googleapis.com/v2/" + scope + "/locations/global/keys" if kind == "api_key"
           else "https://serviceusage.googleapis.com/v1/" + scope + "/services")
    return bool(_request(ledger, refs, scope, url))


def materialize(collector):
    """Annotate only rows bound to one complete, independently read project.

    An unavailable, duplicate, stale or foreign project leaves native names
    untouched, so the signed evaluator returns UNKNOWN for numeric aliases.
    """
    rows = getattr(collector.transport, "evidence", None)
    if not isinstance(rows, list):
        return set()
    ledger = {row["id"]: row for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)}
    if len(ledger) != len(rows):
        return set()
    proven = set()
    for scope in collector.scopes:
        if not isinstance(scope, str) or not _PROJECT_ID.fullmatch(scope):
            continue
        binding = _project_binding(collector, scope, ledger)
        if binding is None:
            continue
        number, proof_requests = binding
        for kind, suffix in (("api_key", "/locations/global/keys/"), ("service_usage", "/services/")):
            envelope = collector.collections.get((kind, scope))
            if not _complete(envelope, scope, kind):
                continue
            for row in envelope["items"]:
                if not isinstance(row, dict):
                    continue
                native = row.get("name")
                prefix = number + suffix
                if (not isinstance(native, str) or not native.startswith(prefix) or
                        not native[len(prefix):] or "/" in native[len(prefix):] or
                        row.get("native_id") != native or row.get("_resource_id") != native or
                        not _native_row(collector, envelope, row, ledger, scope, kind)):
                    continue
                canonical = scope + suffix + native[len(prefix):]
                row["rawNativeName"] = native
                row["name"] = canonical
                row["_provenance"]["derived_project_alias"] = {
                    "canonical_name": canonical, "native_name": native,
                    "project_identity_source_requests": list(proof_requests),
                    "basis": "complete same-scope Cloud Resource Manager project identity"}
                proven.add(scope)
    return proven
