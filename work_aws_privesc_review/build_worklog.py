"""Render one complete AWS privilege-escalation work register from the TSVs."""

import csv
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "WORKLOG.md"


def rows(name):
    with (ROOT / name).open(newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def cell(value):
    return str(value or "").replace("|", "\\|").replace("\n", "<br>")


def table(lines, headings, records, fields):
    lines.append("| " + " | ".join(headings) + " |")
    lines.append("| " + " | ".join("---" for _ in headings) + " |")
    for record in records:
        lines.append("| " + " | ".join(cell(record.get(field)) for field in fields) + " |")
    lines.append("")


def main():
    active = rows("verification-status.tsv")
    retired = rows("retired-technique-status.tsv")
    additional = rows("additional-technique-status.tsv")
    pages = rows("page-status.tsv")
    drift = rows("static-parity-source-drift.tsv")
    assert len(active) == 211 and len(retired) == 362 and len(additional) == 19
    assert len(pages) == 137 and not drift
    assert len({row["id"] for row in active}) == 211
    assert len({row["id"] for row in retired}) == 362

    active_tests = sum(bool(row["located_test_file"]) for row in active)
    proof = sum(row["external_proof_route"] == "yes" for row in active)
    retired_counts = Counter(row["review_state"] for row in retired)
    page_counts = Counter(row["review_state"] for row in pages)
    lines = [
        "# AWS privilege escalation: complete work register", "",
        "This is the single status file for the AWS privilege escalation work. Regenerate it after changing any underlying TSV with `python3 work_aws_privesc_review/build_verification_status.py` followed by `python3 work_aws_privesc_review/build_worklog.py`. A catalog review is not end-to-end validation.", "",
        "## Current counts", "",
        f"- Active catalog: {len(active)} reviewed; {active_tests} have at least one located test file; {len(active)} still need exact positive/negative coverage sign-off and a full suite result.",
        f"- External evidence: {proof} active techniques have at least one route that reads `aws_privesc_challenge_evidence`; its production and absent-evidence behavior remain to be audited route by route.",
        f"- Retired cohort: {retired_counts['candidate']} candidates unresolved, {retired_counts['excluded_verified']} exclusions verified, {retired_counts['implemented']} restored or implemented.",
        f"- Additional routes: {len(additional)} candidates unresolved.",
        f"- HackTricks pages: {page_counts['reviewed']} reviewed, {page_counts['triaged']} still need sign-off.",
        "- Source and data presentation pins: reconciled; 12,145 cold parity witnesses passed. No source drift remains.",
        "- AWS privilege escalation test glob: 77 tests passed, then `test_k8s_openshift_techniques_need_openshift_api` expected FAIL but received MANUAL. This mixed-provider test failure has not been adjudicated.",
        "- Full test suite: cloud and test extras are installed. Current `origin/main` import of `peaso.checks` fails in `k8s_annotation_native_source_successor_20261021._current_functions` on `_component_config`. The earlier full-suite run also exposed an AWS workload secret-source receipt mismatch for two changed source files; recheck it after import is repaired. Both are global gates, not proof that an AWS privesc technique passed or failed.",
        "- Publication gate: CSPM work must be present on `origin/main`, and HackTricks Cloud YAML must remain byte-identical to the CSPM catalog. The 138 YAML files matched at this checkpoint; verify both remote heads before final sign-off.",
        "", "## Active techniques: work completed and exact remaining action", "",
    ]
    table(lines, ["ID", "Review", "External proof", "Located tests", "Focused result", "Graph result", "Completed review evidence", "Remaining"],
          active, ["id", "catalog_review", "external_proof_route", "located_test_file", "focused_helper_result", "isolated_graph_result", "work_done", "remaining_work"])
    lines.extend(["## Retired techniques: decisions and unresolved candidates", ""])
    table(lines, ["ID", "State", "Source", "Decision evidence / missing join"], retired,
          ["id", "review_state", "old_source", "review_evidence"])
    lines.extend(["## Additional candidate routes", ""])
    table(lines, ["ID", "State", "Source", "Evidence and missing join"], additional,
          ["id", "review_state", "source", "review_evidence"])
    lines.extend(["## HackTricks Cloud pages", ""])
    table(lines, ["Page", "State", "Review evidence / remaining question"], pages,
          ["page", "review_state", "review_evidence"])
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUTPUT}: {len(active)} active, {len(retired)} retired, {len(additional)} additional, {len(pages)} pages")


if __name__ == "__main__":
    main()
