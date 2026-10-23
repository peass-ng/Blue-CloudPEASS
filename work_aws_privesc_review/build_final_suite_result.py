"""Record the completed 19-shard pytest gate from its JUnit reports."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


OUTPUT = Path(__file__).with_name("final-suite-result.json")
SKIP_ALLOWLIST_EXCEPTIONS = {
    (2, "tests.test_peaso_secret_scanning_batch", "test_pinned_linux_batch_preserves_repeated_sources_and_windows"): "Linux tmpfs required",
    (2, "tests.test_peaso_secret_scanning_batch", "test_unrecognized_filesystem_source_falls_back_to_serial"): "Linux tmpfs required",
    (2, "tests.test_peaso_secret_scanning_batch", "test_batch_process_failure_reaps_child_and_falls_back[deadline]"): "Linux tmpfs required",
    (2, "tests.test_peaso_secret_scanning_batch", "test_batch_process_failure_reaps_child_and_falls_back[output]"): "Linux tmpfs required",
    (7, "tests.test_peaso_scan_queue", "test_reconcile_recovers_workflow_failure_after_terminal_write[sqlite]"): "SQLite terminal transition releases its count in the same transaction",
    (14, "tests.test_azure_acr_image_vulnerabilities_20261021", "test_pinned_trivy_stale_local_db_cannot_pass"): "existing pinned local Trivy cache unavailable",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit_dir", type=Path)
    parser.add_argument("--tested-root", required=True, type=Path,
                        help="Immutable source checkout used by the JUnit run")
    args = parser.parse_args()
    tested_revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=args.tested_root, text=True).strip()
    assert len(tested_revision) == 40 and all(c in "0123456789abcdef" for c in tested_revision)
    tracked_changes = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=args.tested_root, text=True).strip()
    assert not tracked_changes, "tested source checkout has tracked changes"
    source = json.loads((args.tested_root / "risk_rules/hacktricks-privesc-source.json").read_text())
    hacktricks_revision = source["revision"]
    assert len(hacktricks_revision) == 40 and all(c in "0123456789abcdef" for c in hacktricks_revision)
    shards = []
    skip_exceptions = []
    testcase_elements = 0
    testcase_error_elements = 0
    testcases_with_error = 0
    totals = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    for number in range(19):
        path = args.junit_dir / f"shard-{number:02d}.xml"
        data = path.read_bytes()
        root = ET.fromstring(data)
        suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
        assert suites and all(suite.tag == "testsuite" for suite in suites), path
        counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in totals}
        assert counts["tests"] > 0, path
        for case in root.iter("testcase"):
            testcase_elements += 1
            error_children = sum(child.tag == "error" for child in case)
            testcase_error_elements += error_children
            testcases_with_error += error_children > 0
            skip = case.find("skipped")
            if skip is None:
                continue
            key = (number, case.get("classname"), case.get("name"))
            if key in SKIP_ALLOWLIST_EXCEPTIONS:
                reason = SKIP_ALLOWLIST_EXCEPTIONS[key]
                assert skip.get("message") == reason, key
                skip_exceptions.append({"shard": number, "case": f"{key[1]}::{key[2]}", "reason": reason})
        for key in totals:
            totals[key] += counts[key]
        shards.append({"number": number, "sha256": hashlib.sha256(data).hexdigest(), **counts})
    failures = totals["failures"] + totals["errors"]
    assert len(skip_exceptions) == len(SKIP_ALLOWLIST_EXCEPTIONS)
    record = {
        "state": "executed_with_failures_global" if failures else "passed_global",
        "shards_total": 19,
        "shards_completed": len(shards),
        "tested_revision": tested_revision,
        "hacktricks_source_revision": hacktricks_revision,
        "failed": failures,
        "count_basis": "JUnit testsuite attributes",
        "testcase_elements": testcase_elements,
        "testcase_error_elements": testcase_error_elements,
        "testcases_with_error": testcases_with_error,
        "skip_allowlist_exceptions": skip_exceptions,
        **totals,
        "shards": shards,
    }
    OUTPUT.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {OUTPUT}: {totals['tests']} tests, {failures} failures/errors, {totals['skipped']} skipped")


if __name__ == "__main__":
    main()
