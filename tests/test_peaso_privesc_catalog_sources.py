"""Every privesc catalog `source` (entries and `_excluded*.yaml` lines) must point at an existing
hacktricks-cloud page and, when it has one, an existing heading anchor.

Sources are checked against a checkout at the revision they cite (`source_revision`); a source without
one must resolve in at least one available checkout. Checkouts must be explicitly selected with HACKTRICKS_CLOUD_ROOT
(one path or several separated by os.pathsep). The test is skipped when none is selected; strict
validation fails when any cited revision is unavailable.
"""
from __future__ import annotations

import os
import re
import subprocess
from collections import Counter
from pathlib import Path

import pytest
import yaml

from peaso.privesc.schema import CATALOG_DIR, HACKTRICKS_CLOUD, checkout_revision, revision_matches

SCRATCHPAD_CHECKOUT = Path("/private/tmp/claude-501/-Users-carlospolop-git-Blue-CloudPEASS/"
                           "32170eee-6a9b-41b2-90e5-63caa171ca85/scratchpad/hacktricks-cloud-head")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def _checkouts():
    candidates = [p for p in os.environ.get("HACKTRICKS_CLOUD_ROOT", "").split(os.pathsep) if p]
    # External source validation is opt-in; never inspect another session's
    # absolute scratchpad or a developer-specific checkout implicitly.
    out, seen = [], set()
    for path in candidates:
        root = Path(path).expanduser()
        if root.is_dir() and (root / "src").is_dir() and root.resolve() not in seen:
            seen.add(root.resolve())
            out.append((root, checkout_revision(root)))
    return out


def _slug(text):
    """mdBook heading id: link/tag text kept, lower-cased alphanumerics, '_' and '-', whitespace -> '-'."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    # Inline-code angle brackets are literal heading text in mdBook, while
    # arrow markup contributes only its two hyphens to the generated ID.
    text = re.sub(r"`([^`]*)`", lambda match: match.group(1).replace("<", "").replace(">", ""), text)
    text = re.sub(r"\s*-->\s*", "--", text)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    return "".join(ch if (ch.isalnum() or ch in "_-") else "-" if ch.isspace() else "" for ch in text)


_ANCHORS = {}


def _anchors(page):
    if page not in _ANCHORS:
        anchors, seen, in_code = set(), Counter(), False
        for line in page.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lstrip().startswith("```"):
                in_code = not in_code
                continue
            match = None if in_code else _HEADING.match(line)
            if not match:
                continue
            slug = _slug(match.group(2))
            anchors.update({slug, slug if seen[slug] == 0 else f"{slug}-{seen[slug]}"})
            seen[slug] += 1
        _ANCHORS[page] = anchors
    return _ANCHORS[page]


def _anchors_in_text(contents):
    anchors, seen, in_code = set(), Counter(), False
    for line in contents.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        match = None if in_code else _HEADING.match(line)
        if match:
            slug = _slug(match.group(2))
            anchors.add(slug if seen[slug] == 0 else f"{slug}-{seen[slug]}")
            seen[slug] += 1
    return anchors


def _sources():
    for path in sorted(CATALOG_DIR.rglob("*.yaml")):
        rel = path.relative_to(CATALOG_DIR)
        for i, item in enumerate(yaml.safe_load(path.read_text()) or []):
            if not isinstance(item, dict):
                continue
            revision = item.get("source_revision")
            sources = item.get("source")
            for source in sources if isinstance(sources, list) else [sources]:
                if isinstance(source, str) and source:
                    yield f"{rel}[{i}] {item.get('id') or item.get('technique') or ''}".strip(), source, revision


def test_catalog_sources_exist_in_hacktricks_checkout():
    strict = os.environ.get("PEASO_PRIVESC_STRICT_SOURCES") == "1"
    checkouts = _checkouts()
    if not checkouts:
        if strict:
            pytest.fail("strict source validation requires every cited checkout")
        pytest.skip("no hacktricks-cloud checkout (set HACKTRICKS_CLOUD_ROOT)")
    problems, checked, unmatched = [], 0, Counter()
    for where, source, revision in _sources():
        if revision:
            roots = [r for r, rev in checkouts if rev and revision_matches(revision, rev)][:1]
        else:
            roots = [r for r, _ in checkouts]
        if not roots:
            unmatched[revision] += 1
            continue
        checked += 1
        page, _, anchor = source.partition("#")
        found = [r for r in roots if (r / page).is_file()]
        label = revision or "any checkout"
        if not found:
            problems.append(f"{where}: page not found at {label}: {page}")
        elif anchor and not any(anchor in _anchors(r / page) for r in found):
            problems.append(f"{where}: anchor not found at {label}: {source}")
    if strict:
        assert not unmatched, f"strict source validation lacks cited revisions: {dict(unmatched)}"
    if not checked:
        pytest.skip(f"no checkout matches the cited revisions {dict(unmatched)}")
    assert not problems, f"{len(problems)} broken catalog sources:\n" + "\n".join(problems)


def test_anchor_slug_matches_mdbook():
    assert _slug("iam:PassRole, ec2:RunInstances") == "iampassrole-ec2runinstances"
    assert _slug("eks:CreateAccessEntry — IAM-only `path`") == "ekscreateaccessentry--iam-only-path"
    assert _slug("[sts:AssumeRole](https://x)") == "stsassumerole"
    assert _slug("Pivoting AD --> Entra ID") == "pivoting-ad--entra-id"
    assert _slug("`<service>.<resource>.setIamPolicy` — self-grant") == "serviceresourcesetiampolicy--self-grant"


def test_active_sources_resolve_at_their_pinned_revisions():
    """Check the exact published revision, including commits not checked out as HEAD."""
    checkouts = _checkouts()
    if not checkouts:
        if os.environ.get("PEASO_PRIVESC_STRICT_SOURCES") == "1":
            pytest.fail("strict source validation requires a HackTricks Git checkout")
        pytest.skip("no HackTricks Git checkout selected")
    from peaso.privesc.schema import load_catalog
    repo = checkouts[0][0]
    cache, errors = {}, []
    for entry in load_catalog(strict=True)["entries"]:
        source = entry["source"]
        page, anchor = source.split("#", 1)
        revision = entry["source_revision"]
        key = (revision, page)
        if key not in cache:
            shown = subprocess.run(["git", "show", f"{revision}:{page}"], cwd=repo,
                                   capture_output=True, text=True, check=False)
            cache[key] = _anchors_in_text(shown.stdout) if shown.returncode == 0 else None
        if cache[key] is None or anchor not in cache[key]:
            errors.append(f"{entry['id']}: {revision}:{source}")
    assert not errors, "active sources missing at pinned revisions:\n" + "\n".join(errors)


def test_archived_source_audit_binds_every_current_reference():
    import gzip
    import hashlib
    import json
    root = Path(__file__).resolve().parents[1]
    report = json.loads(gzip.decompress((root / "docs/privesc-ledgers/source-validation-disclosure-v7.json.gz").read_bytes()))
    from peaso.privesc.versioned_catalog import PRIOR_SOURCE_MANIFEST, PRIOR_CATALOG_ARCHIVE
    assert report["catalog_manifest_sha256"] == hashlib.sha256(PRIOR_SOURCE_MANIFEST.read_bytes()).hexdigest()
    assert report["counts"] == {"valid": 4081}
    historical_path = root / "docs/privesc-ledgers/source-validation-20261014.json.gz"
    historical = json.loads(gzip.decompress(historical_path.read_bytes()))
    from peaso.privesc.versioned_catalog import PRIOR_DISCLOSURE_MANIFEST
    assert report["schema"] == "additive-source-audit-v1"
    assert report["base_audit_sha256"] == hashlib.sha256(historical_path.read_bytes()).hexdigest()
    assert report["base_manifest_sha256"] == historical["catalog_manifest_sha256"] == PRIOR_DISCLOSURE_MANIFEST
    assert historical["counts"] == {"valid": 4074} and len(report["references"]) == 7
    references = historical["references"] + report["references"]
    import tarfile
    archived_sources = []
    with tarfile.open(PRIOR_CATALOG_ARCHIVE, "r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            rel = member.name.removeprefix("catalog/")
            for i, item in enumerate(yaml.safe_load(archive.extractfile(member).read()) or []):
                if not isinstance(item, dict):
                    continue
                sources = item.get("source")
                for source in sources if isinstance(sources, list) else [sources]:
                    if isinstance(source, str) and source:
                        archived_sources.append((f"{rel}[{i}] {item.get('id') or item.get('technique') or ''}".strip(),
                                                 source, item.get("source_revision")))
    assert Counter((row["catalog_location"], row["source"], row["cited_revision"]) for row in references) == Counter(archived_sources)
    assert all(row["status"] == "valid" and re.fullmatch(r"[0-9a-f]{64}", row["page_sha256"])
               and re.fullmatch(r"[0-9a-f]{40}", row["resolved_revision"]) for row in references)


def test_safe_c_parser_preserves_every_catalog_entry_and_exclusion(monkeypatch):
    from peaso.privesc import schema
    if not hasattr(yaml,'CSafeLoader'):
        pytest.skip('LibYAML binding is unavailable; safe fallback remains supported')
    monkeypatch.setattr(schema,'SAFE_YAML_LOADER',yaml.SafeLoader)
    python_catalog=schema.load_catalog(strict=True)
    monkeypatch.setattr(schema,'SAFE_YAML_LOADER',yaml.CSafeLoader)
    native_catalog=schema.load_catalog(strict=True)
    assert native_catalog==python_catalog
    assert native_catalog['entries'] and native_catalog['excluded']


@pytest.mark.parametrize('loader',[yaml.SafeLoader,getattr(yaml,'CSafeLoader',yaml.SafeLoader)])
def test_both_safe_parsers_reject_python_object_tags(monkeypatch,tmp_path,loader):
    from peaso.privesc import schema
    root=tmp_path/'aws';root.mkdir()
    (root/'unsafe.yaml').write_text('!!python/object/apply:builtins.eval ["1 + 1"]\n')
    monkeypatch.setattr(schema,'SAFE_YAML_LOADER',loader)
    with pytest.raises(schema.CatalogError):schema.load_catalog(tmp_path,strict=True)
    assert schema.load_catalog(tmp_path)['entries']==[]
