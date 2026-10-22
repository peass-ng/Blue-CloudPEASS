"""Record the completed 19-shard pytest gate from its JUnit reports."""

import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


OUTPUT = Path(__file__).with_name("final-suite-result.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit_dir", type=Path)
    args = parser.parse_args()
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
        "failed": failures,
        **totals,
        "shards": shards,
    }
    OUTPUT.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {OUTPUT}: {totals['tests']} tests, {failures} failures/errors, {totals['skipped']} skipped")


if __name__ == "__main__":
    main()
