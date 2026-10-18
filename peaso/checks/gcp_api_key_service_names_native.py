"""Conservative DNS identity join for API Keys and Service Usage native facts."""

import re
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from .facts import get


_DNS = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z"
)

CHECK_ID = "gcp.apikeys.active_service_restrictions"
PRIOR_SPEC_SHA256 = "7c91d652644f5e1644dacb522fc4fd15d2f30eabdbe7ec4c9481e87fa85c69db"
CORRECTED_SPEC_SHA256 = "0cae3df2c44dcab5f9ce736977ff4a191d83dba2406161be7fb1cdb1a959dd31"
ERRATUM_SHA256 = "fe2e9bd7e9f6bde4af987a6a3ca40d358cbf24bef3541506c25233b5a7146eb9"
FROZEN_SOURCE_SHA256 = "6d7937b1bc0f2045e18dfcd9863ad3fc97122a6559904cedbf271cab4fd0f71f"
SNAPSHOT_SHA256 = "5275f43a023c1079832cff9a22ec12b11d9dbbb7c5496e1b81e62db2bffeca97"


def source_correction(signed_spec_sha256):
    """Admit only the pinned one-check schema erratum over unchanged source."""
    root = Path(__file__).resolve().parents[2]
    ledger = root / "docs/compliance-ledgers"
    erratum = Path(__file__).with_name("gcp_api_key_service_name_erratum.json")
    checkout_erratum = ledger / "gcp-api-key-service-name-erratum-20261018.json"
    source = ledger / "new-checks-gcp.json"
    # Wheels retain the byte-pinned record and its exact original spec below.
    # A source checkout additionally verifies the complete original ledger file.
    if (signed_spec_sha256 != PRIOR_SPEC_SHA256 or
            source.exists() and hashlib.sha256(source.read_bytes()).hexdigest() != FROZEN_SOURCE_SHA256 or
            checkout_erratum.exists() and hashlib.sha256(checkout_erratum.read_bytes()).hexdigest() != ERRATUM_SHA256 or
            hashlib.sha256(erratum.read_bytes()).hexdigest() != ERRATUM_SHA256):
        raise ValueError("GCP API key service-name source correction changed")
    row = json.loads(erratum.read_text())
    digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    prior = row.get("prior_frozen_spec")
    corrected = row.get("corrected_spec")
    if (row.get("check_id") != CHECK_ID or row.get("status") != "source_erratum_successor" or
            row.get("frameworks") != [] or
            row.get("prior_frozen_signed_spec_sha256") != PRIOR_SPEC_SHA256 or
            row.get("current_canonical_spec_sha256") != CORRECTED_SPEC_SHA256 or
            row.get("frozen_source_file_sha256") != FROZEN_SOURCE_SHA256 or
            row.get("sealed_native_counterexample", {}).get("snapshot_sha256") != SNAPSHOT_SHA256 or
            not isinstance(prior, dict) or not isinstance(corrected, dict) or
            digest(prior) != PRIOR_SPEC_SHA256 or digest(corrected) != CORRECTED_SPEC_SHA256 or
            corrected.get("id") != CHECK_ID or
            {key: value for key, value in corrected.items() if key != "data_source"} !=
            {key: value for key, value in prior.items() if key != "data_source"}):
        raise ValueError("GCP API key service-name source correction is inapplicable")
    provenance = {key: deepcopy(value) for key, value in row.items()
                  if key not in ("prior_frozen_spec", "corrected_spec")}
    return deepcopy(corrected), provenance


def canonical_target(value):
    """ApiTarget.service is case-insensitive; retain only a valid DNS join key."""
    if not isinstance(value, str) or not _DNS.fullmatch(value):
        raise ValueError("malformed API target service")
    return value.lower()


def canonical_service(row, scope):
    """Validate one Service Usage row without discarding its raw identity."""
    if not isinstance(row, dict) or not isinstance(scope, str):
        raise ValueError("malformed or foreign Service Usage fact")
    get(row, "name", str)
    coverage = row.get("_coverage", {})
    for field, kind in (("parent", str), ("config", dict), ("rawNativeName", str)):
        if field in row or field in coverage:
            get(row, field, kind)
    name = row.get("name")
    prefix = scope + "/services/"
    if not isinstance(name, str) or not name.startswith(prefix):
        raise ValueError("malformed or foreign Service Usage fact")
    service = canonical_target(name[len(prefix):])

    if "config" in row:
        config = row["config"]
        if not isinstance(config, dict):
            raise ValueError("malformed or foreign Service Usage fact")
        if "name" in config or "name" in config.get("_coverage", {}):
            get(config, "name", str)
        if "name" in config and canonical_target(config["name"]) != service:
            raise ValueError("Service Usage config name contradicts resource name")

    raw = row.get("rawNativeName")
    parent = row.get("parent")
    provenance = row.get("_provenance")
    alias = provenance.get("derived_project_alias") if isinstance(provenance, dict) else None
    if isinstance(provenance, dict) and ("derived_project_alias" in provenance or
            "derived_project_alias" in provenance.get("_coverage", {})):
        alias = get(provenance, "derived_project_alias", dict)
        for field, kind in (("canonical_name", str), ("native_name", str), ("basis", str),
                            ("project_identity_source_requests", list)):
            get(alias, field, kind)
    if raw is not None or alias is not None:
        if (not isinstance(raw, str) or not isinstance(alias, dict) or
                alias.get("canonical_name") != name or alias.get("native_name") != raw or
                row.get("native_id") != raw or row.get("_resource_id") != raw or
                alias.get("basis") != "complete same-scope Cloud Resource Manager project identity" or
                not isinstance(alias.get("project_identity_source_requests"), list) or
                not alias["project_identity_source_requests"] or
                any(not isinstance(ref, str) or not ref for ref in alias["project_identity_source_requests"])):
            raise ValueError("unproved Service Usage project alias")
        native_parent, separator, native_service = raw.partition("/services/")
        if (not separator or not re.fullmatch(r"projects/[0-9]+", native_parent) or
                canonical_target(native_service) != service or
                (parent is not None and parent != native_parent)):
            raise ValueError("Service Usage native identity contradicts alias")
    elif parent is not None and parent != scope:
        raise ValueError("foreign Service Usage parent")
    return service
