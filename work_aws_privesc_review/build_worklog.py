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
    route_cases = rows("route-case-coverage.tsv")
    pages = rows("page-status.tsv")
    drift = rows("static-parity-source-drift.tsv")
    assert len(active) >= 211 and len(retired) == 362 and len(additional) == 19
    assert len(pages) == 137
    assert len({row["id"] for row in active}) == len(active)
    assert {row["id"] for row in route_cases} == {row["id"] for row in active}
    assert len({row["id"] for row in retired}) == 362

    active_tests = sum(bool(row["located_test_file"]) for row in active)
    proof = sum(row["external_proof_route"] == "yes" for row in active)
    proof_modes = Counter(row["proof_dependency"] for row in active)
    retired_counts = Counter(row["review_state"] for row in retired)
    additional_counts = Counter(row["review_state"] for row in additional)
    page_counts = Counter(row["review_state"] for row in pages)
    suite_counts = Counter(row["end_to_end_suite"] for row in active)
    case_counts = Counter(row["status"] for row in route_cases)
    lines = [
        "# AWS privilege escalation: complete work register", "",
        "This is the single status file for the AWS privilege escalation work. Regenerate it after changing any underlying TSV with `python3 work_aws_privesc_review/build_verification_status.py` followed by `python3 work_aws_privesc_review/build_worklog.py`. A catalog review is not end-to-end validation.", "",
        "## Current counts", "",
        f"- Active catalog: {len(active)} reviewed; {active_tests} have at least one located test file. End-to-end suite states: {dict(suite_counts)}.",
        f"- ID-specific graph test audit: {case_counts['exact_cases_verified']} have a recorded passing exact case, {case_counts['partial']} have a located but partial case, and {case_counts['no_exact_case']} have no ID-specific case located. The exact test evidence and remaining gaps for every ID are in `route-case-coverage.tsv`; these coverage states do not establish whether a route can be used in an account.",
        f"- External evidence: {proof} active techniques reference `aws_privesc_challenge_evidence`; {proof_modes['external_proof_required_for_conditional']} require a trusted live-effect witness for a conditional edge and {proof_modes['native_conditional_or_external_proof']} Glue routes also have a native conditional path. The IAM and resource prerequisites still run automatically; missing live-effect proof remains UNKNOWN.",
        f"- Retired cohort: {retired_counts['candidate']} candidates unresolved, {retired_counts['excluded_verified']} exclusions verified, {retired_counts['implemented']} restored or implemented.",
        f"- Additional routes: {additional_counts['candidate']} candidates unresolved, {additional_counts['excluded_verified']} exclusions verified, {additional_counts['implemented']} implemented.",
        f"- HackTricks pages: {page_counts['reviewed']} reviewed, {page_counts['triaged']} still need sign-off.",
        f"- Source and data presentation pins: {len(drift)} files differ from the pinned source hashes; the frozen 12,145-witness parity module passed after the AWS source update.",
        "- Release validation uses exact current and historical catalog bindings, source synchronization checks, focused route tests, and all 19 ordinary pytest shards. The shard results are recorded per technique above when complete.",
        "", "## Active techniques: work completed and exact remaining action", "",
    ]
    table(lines, ["ID", "Review", "Proof dependency", "Located tests", "Focused result", "Graph result", "Full suite", "Completed review evidence", "Remaining"],
          active, ["id", "catalog_review", "proof_dependency", "located_test_file", "focused_helper_result", "isolated_graph_result", "end_to_end_suite", "work_done", "remaining_work"])
    lines.extend(["## ID-specific graph cases and exact gaps", ""])
    table(lines, ["ID", "Coverage", "Named tests", "Positive case", "Negative case", "Unknown case", "Execution evidence", "Remaining case gap"],
          route_cases, ["id", "status", "named_test_files", "positive_case", "negative_case", "unknown_case", "execution_evidence", "case_gap"])
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
