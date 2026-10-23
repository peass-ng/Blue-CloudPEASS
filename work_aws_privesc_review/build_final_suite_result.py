"""Record the completed 19-shard pytest gate from its JUnit reports."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


OUTPUT = Path(__file__).with_name("final-suite-result.json")


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
    totals = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    for number in range(19):
        path = args.junit_dir / f"shard-{number:02d}.xml"
        data = path.read_bytes()
        root = ET.fromstring(data)
        suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
        assert suites and all(suite.tag == "testsuite" for suite in suites), path
        counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in totals}
        assert counts["tests"] > 0, path
        for key in totals:
            totals[key] += counts[key]
        shards.append({"number": number, "sha256": hashlib.sha256(data).hexdigest(), **counts})
    failures = totals["failures"] + totals["errors"]
    record = {
        "state": "executed_with_failures_global" if failures else "passed_global",
        "shards_total": 19,
        "shards_completed": len(shards),
        "tested_revision": tested_revision,
        "hacktricks_source_revision": hacktricks_revision,
        "failed": failures,
        **totals,
        "shards": shards,
    }
    OUTPUT.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {OUTPUT}: {totals['tests']} tests, {failures} failures/errors, {totals['skipped']} skipped")


if __name__ == "__main__":
    main()
