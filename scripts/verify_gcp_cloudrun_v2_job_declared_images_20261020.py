#!/usr/bin/env python3
"""Focused, source-bound offline proof for the unregistered Job image proposal."""
import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
STEM = 'gcp_cloudrun_v2_job_declared_images_20261020'
TEST = 'tests/test_' + STEM + '.py'
OWNED = [
    'peaso/collectors/' + STEM + '.py', TEST,
    'scripts/verify_' + STEM + '.py',
    'docs/gcp-review/recheck-20261020/' + STEM + '_setup.md',
]
DEPENDENCIES = [
    'peaso/checks/gcp_workload_image_source_association_20261020.py',
    'peaso/collectors/gcp_image_secret_indicators.py',
    'peaso/collectors/gcp_cloudrun_image_inspection.py',
    'peaso/collectors/gcp_registry_image_uri.py',
    'peaso/collectors/aws_package_content_indicators.py',
    'peaso/secret_scanning.py',
    'tests/test_gcp_image_secret_review_20261019.py',
    'peaso/collectors/gcp.py', 'peaso/collectors/__init__.py',
    'peaso/checks/__init__.py', 'peaso/engine.py', 'peaso/server/validation.py',
    'pyproject.toml',
]


def hashes(paths):
    return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path,
                        default=ROOT / 'docs/gcp-review/recheck-20261020')
    parser.add_argument('--baseline', type=Path,
                        help='Optional source SHA256 map recorded before proposal work began')
    args = parser.parse_args()
    # No installation, authentication, remote API call or broad test discovery.
    sys.path.insert(0, str(ROOT))
    from peaso import secret_scanning
    kingfisher = version('kingfisher-secret-scanner')
    if kingfisher != secret_scanning.KINGFISHER_VERSION:
        raise SystemExit('Exact pinned Kingfisher SDK is required')
    trufflehog = Path(secret_scanning._trufflehog())
    before = hashes(DEPENDENCIES + OWNED)
    baseline = json.loads(args.baseline.read_text()) if args.baseline else None
    if baseline is not None and (type(baseline) is not dict or not set(baseline) <= set(DEPENDENCIES)):
        raise SystemExit('Baseline must be an exact subset of existing dependency source hashes')
    with tempfile.TemporaryDirectory(prefix='gcp-job-declared-image-proof-') as scratch:
        junit = Path(scratch) / 'focused.xml'
        command = [sys.executable, '-m', 'pytest', '-q', TEST, '--disable-warnings',
                   '-o', 'junit_family=legacy', '--junitxml=' + str(junit)]
        run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=240)
        if not junit.exists():
            raise SystemExit('Focused pytest did not produce its proof: ' + run.stdout[-4000:])
        tree = ET.parse(junit)
        cases = tree.findall('.//testcase')
        failed = [case.get('name') for case in cases if case.find('failure') is not None
                  or case.find('error') is not None]
        skipped = [case.get('name') for case in cases if case.find('skipped') is not None]
        witnesses = [json.loads(prop.get('value')) for prop in tree.findall('.//property')
                     if prop.get('name') == 'native_capture_witness']
    after = hashes(DEPENDENCIES + OWNED)
    unchanged = before == after
    baseline_unchanged = baseline is None or all(after[path] == digest for path, digest in baseline.items())
    success = (run.returncode == 0 and bool(cases) and not failed and not skipped
               and unchanged and baseline_unchanged and len(witnesses) == 2)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    log = args.output_dir / (STEM + '_proof.txt')
    log.write_text(run.stdout + run.stderr)
    receipt = {
        'schema': 'gcp-cloudrun-v2-job-declared-images-local-proof-20261020-v1',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'outcome': 'succeeded' if success else 'failed',
        'scope': 'Unregistered default-off native proposal; local REST/OCI fixtures only',
        'runtime_integrated': False, 'live_cloud_requests': False,
        'cloud_resources_created': False, 'credential_validation': False,
        'executed_runtime_digest_proven': False,
        'pytest': {'command': command, 'exit_code': run.returncode,
                   'tests': len(cases), 'passed': len(cases) - len(failed) - len(skipped),
                   'failed': failed, 'skipped': skipped},
        'detectors': {'kingfisher_sdk': kingfisher,
                      'trufflehog': secret_scanning.TRUFFLEHOG_VERSION,
                      'trufflehog_binary_sha256': hashlib.sha256(trufflehog.read_bytes()).hexdigest(),
                      'verification': 'not_attempted'},
        'source_sha256': after,
        'sources_unchanged_during_proof': unchanged,
        'task_start_dependency_sha256': baseline,
        'task_start_dependencies_unchanged': baseline_unchanged if baseline is not None else None,
        'existing_dependencies_not_modified': {path: before[path] == after[path] for path in DEPENDENCIES},
        'native_capture_witnesses': witnesses,
        'proof_log': str(log.relative_to(ROOT)) if log.is_relative_to(ROOT) else str(log),
        'proof_log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
        'supported': ['exact Cloud Run v2 Job desired immutable digest declaration',
                      'independent exact project/repository/DockerImage GET binding',
                      'unchanged native OCI Reader GET and digest checks',
                      'offline real Kingfisher and TruffleHog byte detection',
                      'fresh metadata revalidation and positive retention after incomplete reads'],
        'unsupported': ['executed or resolved runtime digest', 'mutable tag resolution',
                        'multi-arch index', 'cross-project alias', 'remote/virtual repository',
                        'App Engine runtime association', 'all-service runtime admission'],
    }
    output = args.output_dir / (STEM + '_receipt.json')
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'outcome': receipt['outcome'], 'tests': len(cases),
                      'source_files_unchanged': unchanged, 'receipt': str(output)}, indent=2))
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
