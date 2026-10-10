"""Validate the deliberately high-level, original defensive review catalog."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

DEFAULT = Path(__file__).resolve().parents[1] / "peaso" / "risk_catalog" / "reviews.yaml"
ROOT_FIELDS = {"schema_version", "title", "authoring_license", "coverage_statement", "sources", "reviews", "unsupported"}
SOURCE_FIELDS = {"id", "repository", "revision", "reference", "title", "license_status", "license_reference", "imported_text", "note"}
REVIEW_FIELDS = {"id", "provider", "title", "description", "source", "coverage", "supported", "missing_context", "mitigation"}


def validate_catalog(data):
    errors = []
    if not isinstance(data, dict):
        return ["catalog must be a mapping"]
    def fields(value, expected, label):
        if not isinstance(value, dict):
            errors.append(f"{label} must be a mapping")
            return False
        if set(value) != expected:
            errors.append(f"{label} fields mismatch: missing={sorted(expected-set(value))}, extra={sorted(set(value)-expected)}")
        return True
    fields(data, ROOT_FIELDS, "catalog")
    if data.get("schema_version") != "1.0" or data.get("authoring_license") != "AGPL-3.0-only":
        errors.append("schema_version and authoring_license must be explicit supported values")
    for key in ("title", "coverage_statement"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            errors.append(f"catalog {key} must be nonempty")
    sources = data.get("sources", [])
    if not isinstance(sources, list) or not sources:
        errors.append("sources must be a nonempty list")
        sources = []
    ids = set()
    for source in sources:
        if not fields(source, SOURCE_FIELDS, "source"):
            continue
        sid = source.get("id")
        if not isinstance(sid, str) or not sid or sid in ids:
            errors.append("source id missing or duplicated")
        elif isinstance(sid, str):
            ids.add(sid)
        revision = source.get("revision")
        if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{40}", revision):
            errors.append("source revision must be pinned to a 40-character commit")
        for key in ("reference", "license_reference"):
            value = source.get(key)
            parsed = urlsplit(value) if isinstance(value, str) else None
            if not parsed or parsed.scheme != "https" or parsed.hostname != "github.com" or str(revision) not in parsed.path:
                errors.append(f"source {key} must be a pinned HTTPS GitHub reference")
        if source.get("license_status") not in {"verified", "unverified"}:
            errors.append("source license_status must explicitly be verified or unverified")
        if source.get("license_status") == "verified":
            errors.append("this schema has no source license verification artifact; source license_status must remain unverified")
        if source.get("imported_text") is not False:
            errors.append("this original-review schema permits no copied source text")
        for key in ("repository", "title", "note"):
            if not isinstance(source.get(key), str) or not source[key].strip():
                errors.append(f"source {key} must be nonempty")
    reviews = data.get("reviews", [])
    if not isinstance(reviews, list) or not reviews:
        errors.append("reviews must be a nonempty list")
        reviews = []
    providers, review_ids = set(), set()
    for review in reviews:
        if not fields(review, REVIEW_FIELDS, "review"):
            continue
        if review.get("provider") not in {"aws", "gcp", "azure", "k8s"}:
            errors.append("unsupported provider")
        else:
            providers.add(review["provider"])
        if review.get("source") not in ids:
            errors.append("unknown review source")
        if review.get("coverage") not in {"supported", "manual-review", "unsupported"}:
            errors.append("review requires honest supported/manual-review/unsupported coverage")
        for key in REVIEW_FIELDS - {"provider", "source", "coverage"}:
            if not isinstance(review.get(key), str) or not review[key].strip():
                errors.append(f"review {key} must be nonempty")
        rid = review.get("id")
        if isinstance(rid, str):
            if rid in review_ids:
                errors.append("duplicate review id")
            review_ids.add(rid)
    if providers != {"aws", "gcp", "azure", "k8s"}:
        errors.append("catalog must disclose review scope for all four providers")
    unsupported = data.get("unsupported")
    if not isinstance(unsupported, list) or not unsupported or not all(isinstance(x, str) and x.strip() for x in unsupported):
        errors.append("explicit unsupported coverage list required")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=DEFAULT)
    args = parser.parse_args()
    try:
        data = yaml.safe_load(args.path.read_text())
        errors = validate_catalog(data)
        errors.extend(validate_bundled_provenance(data))
    except (OSError, yaml.YAMLError) as exc:
        parser.exit(1, f"Cannot read catalog: {type(exc).__name__}\n")
    if errors:
        parser.exit(1, "\n".join(errors) + "\n")
    print("Valid defensive review catalog: 4 providers; manual-review coverage; source licensing explicitly disclosed")


def validate_bundled_provenance(data, root=None):
    """Check recorded revision and hashes against the existing source lockfile.

    Hashes verify the bundled provenance claim; they do not verify source
    licensing, source accuracy, or completeness of runtime review coverage.
    """
    root = Path(root) if root else DEFAULT.parents[2]
    errors = []
    try:
        provenance = json.loads((root / "risk_rules" / "hacktricks-source.json").read_text())
        for source in data.get("sources", []) if isinstance(data, dict) else []:
            if isinstance(source, dict) and source.get("id") == "hacktricks-criticality":
                if source.get("revision") != provenance["revision"] or source.get("repository") != provenance["repository"]:
                    errors.append("review source does not match bundled HackTricks provenance")
        for name, expected in provenance["sha256"].items():
            if name not in {"aws.yaml", "gcp.yaml", "azure.yaml", "k8s.yaml"}:
                errors.append("unexpected source lockfile path")
                continue
            if hashlib.sha256((root / "risk_rules" / name).read_bytes()).hexdigest() != expected:
                errors.append(f"bundled source hash mismatch: {name}")
    except (OSError, ValueError, KeyError, AttributeError):
        errors.append("bundled provenance unavailable or malformed")
    return errors


if __name__ == "__main__":
    main()
