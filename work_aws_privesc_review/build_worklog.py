"""Render one complete AWS privilege-escalation work register from the TSVs."""

import csv
import json
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
    partial_cases = [row for row in route_cases if row["status"] == "partial"]
    missing_positive = [row["id"] for row in partial_cases if not row["positive_case"]]
    missing_negative = [row["id"] for row in partial_cases if not row["negative_case"]]
    suite_result = ROOT / "final-suite-result.json"
    suite = json.loads(suite_result.read_text()) if suite_result.is_file() else None
    focused_results = json.loads((ROOT / "focused-validation.json").read_text())
    perf_path = ROOT / "performance-validation.json"
    performance = json.loads(perf_path.read_text()) if perf_path.is_file() else None
    optimized_perf_path = ROOT / "performance-optimization-validation.json"
    optimized_performance = json.loads(optimized_perf_path.read_text()) if optimized_perf_path.is_file() else None
    assert all(result["tests"] > 0 and result["failures"] == result["errors"] == result["skipped"] == 0
               and len(result["tested_revision"]) == len(result["hacktricks_source_revision"]) == 40
               and len(result["junit_sha256"]) == 64 for result in focused_results)
    lines = [
        "# AWS privilege escalation: complete work register", "",
        "This is the single status file for the AWS privilege escalation work. Regenerate it after changing any underlying TSV with `python3 work_aws_privesc_review/build_verification_status.py` followed by `python3 work_aws_privesc_review/build_worklog.py`. A catalog review is not end-to-end validation.", "",
        "## Current counts", "",
        f"- Active catalog: {len(active)} reviewed; {active_tests} have at least one located test file. End-to-end suite states: {dict(suite_counts)}.",
        (f"- Final pytest run used CSPM commit `{suite['tested_revision']}` and HackTricks Cloud revision "
         f"`{suite['hacktricks_source_revision']}`. Its result applies to those exact revisions; later changes need their own validation."
         if suite else "- Final pytest run remains pending; no complete 19-shard result is recorded."),
        (f"- The full run's JUnit suite attributes recorded {suite['tests']} tests: {suite['failures']} failures, "
         f"{suite['errors']} errors, and {suite['skipped']} skips. The XML contains {suite['testcase_elements']} "
         f"testcase elements, of which {suite['testcases_with_error']} carry an error; suite counters include "
         "pytest reporting beyond emitted testcase nodes. "
         f"{len(suite['skip_allowlist_exceptions'])} skips were outside the skip allowlist "
         "(four Linux tmpfs cases on macOS, one explicit SQLite transition case, and one unavailable local Trivy cache); "
         "their exact test names and reasons are in `final-suite-result.json`."
         if suite else "- Full-suite test, failure, error, and skip counts remain pending."),
        "- Separate focused runs at later exact revisions: " + "; ".join(
            f"{result['scope']} passed {result['tests']}/{result['tests']} on CSPM `{result['tested_revision']}` "
            f"with HackTricks Cloud `{result['hacktricks_source_revision']}` "
            f"(JUnit SHA-256 `{result['junit_sha256']}`)" for result in focused_results)
        + ". These runs cover only their named test selections, not the full suite.",
        (f"- Separate performance gate at CSPM `{performance['tested_revision']}` with HackTricks Cloud "
         f"`{performance['hacktricks_source_revision']}`: {performance['passed']} passed, "
         f"{performance['failures']} failed, {performance['errors']} errors, and {performance['skipped']} "
         f"expected skip (JUnit SHA-256 `{performance['junit_sha256']}`). The 1x run used "
         f"{performance['one_x_rss_mib']} MiB and a repeat used {performance['one_x_repeat_rss_mib']} MiB, "
         f"above the {performance['one_x_rss_limit_mib']} MiB limit; a pre-PR baseline at "
         f"`{performance['baseline_revision']}` used {performance['baseline_one_x_rss_mib']} MiB with the same "
         f"{performance['compared_registered_checks']} checks and {performance['compared_findings']} findings. "
         f"The AWS 10x test took {performance['aws_privesc_ten_x_wall_seconds']} seconds against a "
         f"{performance['aws_privesc_ten_x_wall_limit_seconds']}-second limit. "
         f"{performance['aws_privesc_ten_x_caveat']}"
         if performance else "- A separate performance gate result has not been recorded."),
        (f"- After the IAM cache change, the performance gate at CSPM `{optimized_performance['tested_revision']}` "
         f"with HackTricks Cloud `{optimized_performance['hacktricks_source_revision']}` still failed "
         f"{optimized_performance['failures']}/{optimized_performance['tests']} tests "
         f"(JUnit SHA-256 `{optimized_performance['junit_sha256']}`). The 1x run used "
         f"{optimized_performance['one_x_rss_mib']} MiB against a "
         f"{optimized_performance['one_x_rss_limit_mib']} MiB limit. The AWS 10x run took "
         f"{optimized_performance['aws_privesc_ten_x_wall_seconds']} seconds against a "
         f"{optimized_performance['aws_privesc_ten_x_wall_limit_seconds']}-second limit, with "
         f"{optimized_performance['aws_privesc_ten_x_principals']} principals and "
         f"{optimized_performance['aws_privesc_ten_x_edges']} edges. The earlier timed run took "
         f"{optimized_performance['previous_ten_x_wall_seconds']} seconds. "
         f"{optimized_performance['caveat']}"
         if optimized_performance else "- No post-optimization performance result has been recorded."),
        f"- ID-specific graph test audit: {case_counts['exact_cases_verified']} have a recorded passing exact case, {case_counts['partial']} have a located but partial case, and {case_counts['no_exact_case']} have no ID-specific case located. The exact test evidence and remaining gaps for every ID are in `route-case-coverage.tsv`; these coverage states do not establish whether a route can be used in an account.",
        f"- Among the {len(partial_cases)} partial routes, {sum(bool(row['positive_case']) for row in partial_cases)} name a positive assertion, {sum(bool(row['negative_case']) for row in partial_cases)} name a negative assertion, and {sum(bool(row['unknown_case']) for row in partial_cases)} name an unknown-result assertion. These are located assertions, not recorded passing exact graph cases.",
        f"- Partial routes without a named positive assertion: {', '.join(missing_positive) or 'none'}.",
        f"- Partial routes without a named negative assertion: {', '.join(missing_negative) or 'none'}.",
        f"- External evidence: {proof} active techniques reference `aws_privesc_challenge_evidence`; {proof_modes['external_proof_required_for_conditional']} require a trusted live-effect witness for a conditional edge and {proof_modes['native_conditional_or_external_proof']} Glue routes also have a native conditional path. The IAM and resource prerequisites still run automatically; missing live-effect proof remains UNKNOWN.",
        f"- Retired cohort: {retired_counts['candidate']} candidates unresolved, {retired_counts['excluded_verified']} exclusions verified, {retired_counts['implemented']} restored or implemented.",
        f"- Additional routes: {additional_counts['candidate']} candidates unresolved, {additional_counts['excluded_verified']} exclusions verified, {additional_counts['implemented']} implemented.",
        f"- HackTricks pages: {page_counts['reviewed']} reviewed, {page_counts['triaged']} still need sign-off.",
        (f"- Source and data presentation pins: {len(drift)} files differ from the pinned source hashes; resolve the listed drift before claiming current presentation parity."
         if drift else "- Source and data presentation pins: 0 files differ from the pinned source hashes in the current source manifest."),
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
