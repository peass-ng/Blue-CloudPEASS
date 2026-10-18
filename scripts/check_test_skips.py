#!/usr/bin/env python3
"""Fail CI when tests are skipped for anything other than the documented optional reasons.

    python scripts/check_test_skips.py pytest  report.xml          # pytest --junitxml output
    python scripts/check_test_skips.py playwright results.json     # Playwright JSON reporter output

Every skip must match one allowlisted reason below, and no reason may be used more often than
its budget. A missing dependency (importorskip), a missing HackTricks checkout, Terraform, or a
newly added unconditional skip therefore fails the build instead of silently shrinking coverage.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

# (reason regex, maximum skips, why it is optional in CI)
PYTEST_ALLOWED = (
    (r'set PEASO_BENCH=1 to run the 10x synthetic benchmark', 1,
     'opt-in performance benchmark (tests/test_peaso_perf_benchmark.py)'),
    (r'set PEASO_PRIVESC_BENCH=1 for the 100x benchmark', 1,
     'opt-in privesc benchmark (tests/test_peaso_privesc_audit_fixes.py)'),
    (r'Set K8S_NETWORK_QA_SNAPSHOT to the immutable native directive13 snapshot', 1,
     'private live-cluster QA snapshot (tests/test_peaso_network_k8s_qa.py)'),
    (r'private QA capture is unavailable; no live collection attempted', 3,
     'private captured cloud snapshots under .cache/peaso-qa (tests/test_peaso_reachability.py)'),
    (r'saved native snapshot is not part of the portable source checkout', 1,
     'optional private PSP replay; synthetic applicability regressions remain mandatory'),
)
PLAYWRIGHT_ALLOWED = (
    # One env-gated test per spec; each needs an isolated real backend or captured snapshot.
    (r'^cancel\.spec\.ts$', 1, 'PEASO_CANCEL_TOKEN'),
    (r'^compose-api\.spec\.ts$', 1, 'PEASO_COMPOSE_TOKEN'),
    (r'^full-report-live\.spec\.ts$', 1, 'PEASO_LIVE_TOKEN + PEASO_FULL_SCAN'),
    (r'^large\.spec\.ts$', 1, 'PEASO_LARGE_TOKEN + PEASO_LARGE_SNAPSHOT_PATH'),
    (r'^live\.spec\.ts$', 1, 'PEASO_LIVE_TOKEN'),
    (r'^privesc-live\.spec\.ts$', 1, 'PEASO_LIVE_TOKEN + PEASO_LIVE_PRIVESC_SCAN'),
    (r'^review\.spec\.ts$', 1, 'PEASO_REVIEW_TOKEN'),
)


def pytest_skips(path: Path):
    """[(test id, reason)] from a JUnit XML report."""
    out = []
    for case in ET.parse(path).getroot().iter('testcase'):
        skipped = case.find('skipped')
        if skipped is not None:
            ident = f"{case.get('classname', '')}::{case.get('name', '')}"
            out.append((ident, f"{skipped.get('message', '')} {skipped.text or ''}".strip()))
    return out


def playwright_skips(path: Path):
    """[(test title, spec file name)] from a Playwright JSON report; raises on failures."""
    report = json.loads(path.read_text())
    stats = report.get('stats', {})
    if stats.get('unexpected', 0) or stats.get('flaky', 0):
        raise SystemExit(f"Playwright reported {stats.get('unexpected', 0)} failed and {stats.get('flaky', 0)} flaky tests")
    out = []

    def walk(suite, file):
        file = suite.get('file') or file
        for spec in suite.get('specs', []):
            for test in spec.get('tests', []):
                if test.get('status') == 'skipped':
                    out.append((spec.get('title', ''), Path(spec.get('file') or file or '').name))
        for child in suite.get('suites', []):
            walk(child, file)
    for suite in report.get('suites', []):
        walk(suite, None)
    return out


def check(skips, allowed):
    used, problems = [0] * len(allowed), []
    for ident, reason in skips:
        index = next((i for i, (pattern, _, _) in enumerate(allowed) if re.search(pattern, reason)), None)
        if index is None:
            problems.append(f'unexpected skip: {ident}: {reason}')
        else:
            used[index] += 1
    for (pattern, budget, why), count in zip(allowed, used):
        if count > budget:
            problems.append(f'{count} skips for {pattern!r} exceed the budget of {budget} ({why})')
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('kind', choices=('pytest', 'playwright'))
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    if args.kind == 'pytest':
        skips, allowed = pytest_skips(args.report), PYTEST_ALLOWED
    else:
        skips, allowed = playwright_skips(args.report), PLAYWRIGHT_ALLOWED
    problems = check(skips, allowed)
    for problem in problems:
        print(problem)
    budget = sum(b for _, b, _ in allowed)
    print(f'{len(skips)} skipped tests (allowlisted budget {budget}); {len(problems)} problems')
    sys.exit(1 if problems else 0)


if __name__ == '__main__':
    main()
