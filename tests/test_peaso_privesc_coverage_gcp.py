"""GCP privesc coverage ledger <-> catalog consistency.

The ledger (``docs/privesc-ledgers/privesc-gcp.md``; ``PEASO_GCP_PRIVESC_LEDGER`` overrides the path) maps every HackTricks Cloud GCP heading to catalog ids,
an ``_excluded.yaml`` item or a NEEDS SCHEMA proposal. These tests keep the ledger and the catalog in sync. With explicitly selected source checkouts, the current GCP tree is also enumerated at the canonical pinned revision; historical citations are checked separately by test_peaso_privesc_catalog_sources.py.
"""
import os
import re
from collections import Counter

import pytest
from pathlib import Path

import yaml

from peaso.privesc.schema import load_catalog
from test_peaso_privesc_catalog_sources import _checkouts, _slug, _HEADING

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "peaso" / "privesc" / "catalog" / "gcp"
LEDGER = Path(os.environ.get("PEASO_GCP_PRIVESC_LEDGER") or ROOT / "docs" / "privesc-ledgers" / "privesc-gcp.md")

ROW = re.compile(r"^\| `#([^`]+)` \| (.*) \| ([A-Z+-]+) \| (.*) \|$")
PAGE = re.compile(r"^### `(src/[^`]+\.md)`$")


def _ledger_rows(text=None):
    assert LEDGER.is_file(), f"GCP privesc ledger not found at {LEDGER}"
    page = None
    rows = []
    for line in (LEDGER.read_text(encoding="utf-8") if text is None else text).splitlines():
        m = PAGE.match(line)
        if m:
            page = m.group(1)
            continue
        m = ROW.match(line)
        if m and page:
            rows.append((page, m.group(1), m.group(3), m.group(4)))
    assert rows, "ledger has no mapping rows"
    return rows


def _catalog_ids():
    catalog = load_catalog()
    gcp_errors = [e for e in catalog["errors"] if "gcp" in str(e)]
    assert not gcp_errors, "GCP catalog errors:\n" + "\n".join(map(str, gcp_errors))
    return {e["id"] for e in catalog["entries"] if e.get("provider") == "gcp"}


def _excluded_sources():
    return {item["source"] for item in yaml.safe_load((CATALOG / "_excluded.yaml").read_text()) or []}


def test_ledger_mapped_ids_exist_in_gcp_catalog():
    ids = _catalog_ids()
    missing = []
    for page, anchor, status, mapping in _ledger_rows():
        if not status.startswith("COVERED"):
            continue
        mapped = re.findall(r"`(gcp-[a-z0-9-]+)`", mapping)
        assert mapped, f"{page}#{anchor}: COVERED row without catalog ids"
        missing += [f"{page}#{anchor} -> {i}" for i in mapped if i not in ids]
    assert not missing, "ledger ids missing from catalog:\n" + "\n".join(missing)


def test_ledger_excluded_rows_are_in_excluded_yaml():
    excluded = _excluded_sources()
    # The ledger inventories the pinned historical GCP tree. These sections
    # were relocated to privilege-escalation pages in the current source tree;
    # the exclusion catalog cites their live anchors instead of dead ones.
    relocated = {
        "gcp-to-workspace-pivoting/README.md#direct-service-account-workspace-resources-without-dwd": "gcp-privilege-escalation/gcp-workspace-privesc.md#direct-service-account-workspace-resources-without-dwd",
        "gcp-to-workspace-pivoting/README.md#gcp-generate-delegation-token": "gcp-privilege-escalation/gcp-workspace-privesc.md#gcp-generate-delegation-token",
        "gcp-to-workspace-pivoting/README.md#delepwn": "gcp-privilege-escalation/gcp-workspace-privesc.md#delepwn",
        "gcp-to-workspace-pivoting/README.md#delefriend": "gcp-privilege-escalation/gcp-workspace-privesc.md#delefriend",
        "gcp-to-workspace-pivoting/README.md#gitlabs-python-script": "gcp-privilege-escalation/gcp-workspace-privesc.md#gitlabs-python-script",
    }
    for page, anchors in {
        "gcp-agent-identity-auth-manager-privesc.md": (
            "agent-identity-auth-manager", "read-only-enumeration-and-no-list-fallback",
            "conditional-gcp-to-workspace-pivot", "references"),
        "gcp-workspace-addons-privesc.md": (
            "google-workspace-add-ons", "preconditions", "enumerate-safely",
            "authorized-lab-proof", "references"),
    }.items():
        for anchor in anchors:
            old = f"gcp-to-workspace-pivoting/{page}#{anchor}"
            relocated[old] = f"gcp-privilege-escalation/{page}#{anchor}"
    prefix = "src/pentesting-cloud/gcp-security/"
    def current_source(page, anchor):
        old = page + "#" + anchor
        moved = relocated.get(old.removeprefix(prefix))
        return prefix + moved if moved else old
    missing = [f"{page}#{anchor}" for page, anchor, status, mapping in _ledger_rows()
               if (status == "EXCLUDED" or "(_excluded)" in mapping)
               and current_source(page, anchor) not in excluded]
    assert not missing, "ledger EXCLUDED rows missing from _excluded.yaml:\n" + "\n".join(missing)


def test_ledger_has_no_unresolved_rows():
    statuses = {"COVERED", "COVERED+NEEDS-SCHEMA", "EXCLUDED", "NEEDS-SCHEMA", "STRUCTURAL", "NON-PRIVESC"}
    bad = [f"{p}#{a}: {s}" for p, a, s, _ in _ledger_rows() if s not in statuses]
    assert not bad, "\n".join(bad)
    root = _current_gcp_checkout()
    if root is not None:
        pages = sorted((root / GCP_SOURCE_TREE).rglob("*.md"))
        headings = _gcp_heading_sources(root)
        assert len(pages) == 435 and len(headings) == 3303, "canonical GCP source tree size changed"
        _assert_gcp_heading_dispositions(headings, _gcp_disposition_sources())


def test_every_gcp_catalog_entry_is_referenced_by_the_ledger():
    referenced = set()
    for _, _, status, mapping in _ledger_rows():
        referenced |= set(re.findall(r"`(gcp-[a-z0-9-]+)`", mapping))
    unreferenced = sorted(_catalog_ids() - referenced)
    assert not unreferenced, "catalog entries not mapped by any ledger row: " + ", ".join(unreferenced)


def test_needs_schema_section_present():
    assert LEDGER.is_file(), f"GCP privesc ledger not found at {LEDGER}"
    text = LEDGER.read_text(encoding="utf-8")
    assert "## NEEDS SCHEMA" in text
    for key in sorted(set(re.findall(r"\bNS-\d+\b", text))):
        assert f"### {key} " in text, f"{key} referenced but not defined in NEEDS SCHEMA"


# Current heading exhaustiveness has one explicit source contract. Older cited
# revisions (including a53b4639's 723 renamed/removed anchors) remain historical
# source-link contracts, validated at their authored revisions by catalog_sources.
# They must neither silently replace this tree nor count as current omissions.
GCP_CURRENT_SOURCE_REVISION = "171e422299df4e3c1477847d80439c13aadf55fc"
GCP_SOURCE_TREE = Path("src/pentesting-cloud/gcp-security")


def _current_gcp_checkout():
    selected = os.environ.get("HACKTRICKS_CLOUD_ROOT", "")
    if not selected:
        assert os.environ.get("PEASO_PRIVESC_STRICT_SOURCES") != "1", "strict GCP heading coverage requires explicitly selected source checkouts"
        # Ordinary catalog-consistency checks remain local; no implicit checkout
        # inspection and no extra default pytest skip is introduced.
        return None
    matching = [root for root, revision in _checkouts()
                if revision == GCP_CURRENT_SOURCE_REVISION and (root / GCP_SOURCE_TREE).is_dir()]
    assert matching, ("current GCP heading coverage requires canonical source revision "
                      + GCP_CURRENT_SOURCE_REVISION
                      + "; historical source links use their separate authored-revision validation")
    return matching[0]


def _gcp_heading_sources(root):
    headings = set()
    for page in sorted((root / GCP_SOURCE_TREE).rglob("*.md")):
        seen, fence = Counter(), None
        for line in page.read_text(encoding="utf-8").splitlines():
            marker = re.match(r"^\s*(`{3,}|~{3,})", line)
            if marker:
                char = marker.group(1)[0]
                if fence is None:
                    fence = char
                elif fence == char:
                    fence = None
                continue
            match = None if fence else _HEADING.match(line)
            if not match:
                continue
            slug = _slug(match.group(2))
            anchor = slug if seen[slug] == 0 else f"{slug}-{seen[slug]}"
            seen[slug] += 1
            headings.add(page.relative_to(root).as_posix() + "#" + anchor)
    return headings


def _gcp_disposition_sources(text=None):
    # Ordinary ledger rows carry COVERED/EXCLUDED/NON-PRIVESC/STRUCTURAL. The
    # compressed structural rows explicitly enumerate another 1,993 anchors.
    text = LEDGER.read_text(encoding="utf-8") if text is None else text
    sources = {page + "#" + anchor for page, anchor, _, _ in _ledger_rows(text)}
    page = None
    for line in text.splitlines():
        match = PAGE.match(line)
        if match:
            page = match.group(1)
        elif page and "| STRUCTURAL |" in line:
            sources.update(page + "#" + anchor for anchor in re.findall(r"`#([^`]+)`", line))
    # Existing consistency tests validate every mapped catalog ID/exclusion.
    return sources


def _assert_gcp_heading_dispositions(headings, dispositions):
    missing = sorted(headings - dispositions)
    assert not missing, f"{len(missing)} current GCP headings lack a declared disposition: {missing[:10]}"


def test_gcp_heading_regression_detects_a_removed_disposition(tmp_path):
    root = _current_gcp_checkout()
    if root is None:
        # Local mode still checks duplicate anchors and both fence styles. The
        # strict source gate exercises the actual pinned 3,303-heading tree.
        root = tmp_path
        page = root / GCP_SOURCE_TREE / "example.md"
        page.parent.mkdir(parents=True)
        page.write_text("# Same\n# Same\n```sh\n# ignored\n```\n~~~sh\n# ignored-too\n~~~\n", encoding="utf-8")
    headings = _gcp_heading_sources(root)
    dispositions = _gcp_disposition_sources() if root != tmp_path else set(headings)
    _assert_gcp_heading_dispositions(headings, dispositions)
    victim = sorted(headings)[0]
    with pytest.raises(AssertionError, match=re.escape(victim)):
        _assert_gcp_heading_dispositions(headings, dispositions - {victim})
    if root != tmp_path:
        # Remove one real grouped STRUCTURAL anchor from an in-memory ledger copy.
        # The source checkout, catalog and historical ledger remain immutable.
        target_page = "src/pentesting-cloud/gcp-security/gcp-services/gcp-vertex-ai-enum.md"
        target_anchor = "privilege-escalation"
        target = target_page + "#" + target_anchor
        assert target in headings and target in dispositions
        marker = "### `" + target_page + "`"
        text = LEDGER.read_text(encoding="utf-8")
        assert marker in text
        before, section = text.split(marker, 1)
        block, separator, rest = section.partition("\n### `")
        token = "`#" + target_anchor + "`"
        assert token in block and "| STRUCTURAL |" in block
        changed = before + marker + block.replace(token, "(removed by counterexample)", 1) + separator + rest
        with pytest.raises(AssertionError, match=re.escape(target)):
            _assert_gcp_heading_dispositions(headings, _gcp_disposition_sources(changed))
    if root == tmp_path:
        assert headings == {str(GCP_SOURCE_TREE / "example.md") + "#same", str(GCP_SOURCE_TREE / "example.md") + "#same-1"}


def test_strict_gcp_heading_sources_cannot_silently_skip(monkeypatch):
    monkeypatch.setenv("PEASO_PRIVESC_STRICT_SOURCES", "1")
    monkeypatch.delenv("HACKTRICKS_CLOUD_ROOT", raising=False)
    with pytest.raises(AssertionError, match="explicitly selected"):
        _current_gcp_checkout()


def test_historical_checkout_cannot_replace_current_gcp_tree(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("a53b46392c11fa2a1b2ce85e69e7f704b8f79fbf\n")
    (tmp_path / GCP_SOURCE_TREE).mkdir(parents=True)
    monkeypatch.setenv("HACKTRICKS_CLOUD_ROOT", str(tmp_path))
    with pytest.raises(AssertionError, match=GCP_CURRENT_SOURCE_REVISION):
        _current_gcp_checkout()
