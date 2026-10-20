"""Review a dedicated CSPM plan and publish its frozen public assets.

The plan command is read-only. A separate GitHub Actions run may apply only
the exact saved plan hash supplied after reviewing its private JSON.
"""
from __future__ import annotations

from peaso import deployment
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
import zipfile
from urllib.request import urlopen

from scripts import peaso_deploy as deploy


ACCOUNT = deployment.value("account_id")
REGION = "us-east-1"
WORKER_REPOSITORY = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/hacktricks-cspm-worker"
ADDRESS = re.compile(r'^([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)(?:\[(?:[0-9]+|"[^"\\]*(?:\\.[^"\\]*)*")\])?$')
REPLACEABLE = {'aws_ecs_task_definition.tasks', 'aws_ecs_task_definition.ai'}
REQUIRED_RUNTIME = {'aws_lambda_function.api', 'aws_lambda_function.scheduler',
                    'aws_ecs_task_definition.tasks'}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def verify_source_archive(manifest: dict) -> Path:
    """Bound and verify the complete corresponding source for this release."""
    version = manifest.get('source_version')
    if not isinstance(version, str) or not re.fullmatch(r'[0-9a-f]{64}', version):
        raise ValueError('Frozen source version is invalid')
    source_zip = deploy.BUILD / f'peaso-source-{version}.zip'
    if not source_zip.is_file() or source_zip.stat().st_size > deploy.CURRENT_SOURCE_ARCHIVE_LIMIT:
        raise ValueError('Frozen source archive is missing or exceeds reviewed size')
    with zipfile.ZipFile(source_zip) as archive:
        members = archive.infolist()
        if len(members) != len(set(row.filename for row in members)) or len(members) > deploy.CURRENT_SOURCE_MEMBER_LIMIT:
            raise ValueError('Frozen source archive member count is invalid')
        if sum(row.file_size for row in members) > deploy.CURRENT_SOURCE_UNCOMPRESSED_LIMIT:
            raise ValueError('Frozen source archive expands beyond reviewed size')
        if archive.read('release.json') != json.dumps(manifest, indent=2).encode():
            raise ValueError('Frozen source archive manifest differs from release')
    return source_zip


def verify_api_archive() -> None:
    archive_path = deploy.BUILD / 'api.zip'
    if not archive_path.is_file() or archive_path.stat().st_size > deploy.CURRENT_API_ARCHIVE_LIMIT:
        raise ValueError('API archive is missing or exceeds reviewed size')
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if len(members) != len(set(row.filename for row in members)) or len(members) > deploy.CURRENT_API_MEMBER_LIMIT:
            raise ValueError('API archive member count is invalid')
        if sum(row.file_size for row in members) > deploy.CURRENT_API_UNCOMPRESSED_LIMIT:
            raise ValueError('API archive expands beyond reviewed size')


def review_plan(data: dict, release: dict) -> dict:
    """Return only nonsecret plan facts; reject an unrelated or destructive plan."""
    version = release.get('source_version')
    if not isinstance(version, str) or not re.fullmatch(r'[0-9a-f]{64}', version):
        raise ValueError('Frozen source version is missing')
    variables = data.get('variables') or {}
    value = lambda name: (variables.get(name) or {}).get('value')
    if value('source_version') != version or value('region') != REGION:
        raise ValueError('Plan source or region differs from the frozen release')
    if value('enable_public_customer_role_template') is not True:
        raise ValueError('Plan would remove the existing public customer role template')
    gcp_secret = value('gcp_platform_sa_secret_arn')
    if not isinstance(gcp_secret, str) or gcp_secret != deployment.value('gcp_platform_sa_secret_arn'):
        raise ValueError('Plan service-account integration differs from private configuration')
    image = value('worker_image')
    if not isinstance(image, str) or not re.fullmatch(re.escape(WORKER_REPOSITORY) + r'@sha256:[0-9a-f]{64}', image):
        raise ValueError('Worker image is not an immutable dedicated ECR digest')
    api_zip = value('api_zip')
    if not isinstance(api_zip, str) or Path(api_zip).resolve() != (deploy.BUILD / 'api.zip').resolve():
        raise ValueError('API ZIP differs from the frozen build path')
    prior = ((data.get('prior_state') or {}).get('values') or {}).get('root_module') or {}
    if prior.get('child_modules'):
        raise ValueError('CSPM state contains an unexpected child module')
    allowed = set(deploy.ALLOWED_RESOURCES)
    changes = []
    changed_runtime = set()
    changed_tasks = set()
    for row in data.get('resource_changes') or []:
        if row.get('mode') != 'managed':
            continue
        address = row.get('address')
        match = ADDRESS.fullmatch(address or '')
        if not match or match.group(1) not in allowed or row.get('module_address'):
            raise ValueError(f'Unowned Terraform change: {address}')
        base = match.group(1)
        actions = (row.get('change') or {}).get('actions')
        if actions not in (['no-op'], ['create'], ['update']):
            if base not in REPLACEABLE or actions not in (['delete', 'create'], ['create', 'delete']):
                raise ValueError(f'Destructive or unsupported Terraform change: {address}')
        if actions != ['no-op']:
            changes.append({'address': address, 'actions': actions})
            if base in REQUIRED_RUNTIME:
                changed_runtime.add(base)
            if base == 'aws_ecs_task_definition.tasks':
                changed_tasks.add(address)
    if changed_runtime != REQUIRED_RUNTIME:
        raise ValueError('Plan does not update all CSPM API and worker runtimes')
    if changed_tasks != {'aws_ecs_task_definition.tasks["collector"]',
                         'aws_ecs_task_definition.tasks["analyzer"]'}:
        raise ValueError('Plan must replace both collector and analyzer task definitions')
    if not changes:
        raise ValueError('Plan has no CSPM changes')
    drift = data.get('resource_drift') or []
    for row in drift:
        address = row.get('address')
        match = ADDRESS.fullmatch(address or '')
        if not match or match.group(1) not in allowed or row.get('module_address'):
            raise ValueError(f'Unowned provider refresh drift: {address}')
    return {'source_version': version, 'worker_image': image,
            'changes': sorted(changes, key=lambda row: row['address']),
            'drift_count': len(drift), 'drift_sha256': sha256(canonical(drift))}


def review_files(plan: Path, plan_json: Path, release_path: Path,
                 expected_plan_sha256: str = '', expected_drift_sha256: str = '') -> dict:
    deploy.verify_backend()
    if not plan.is_file() or not plan_json.is_file() or not release_path.is_file():
        raise ValueError('Saved plan, private JSON, or release manifest is missing')
    plan_digest = sha256(plan.read_bytes())
    if expected_plan_sha256 and plan_digest != expected_plan_sha256:
        raise ValueError('Saved binary plan differs from the reviewed SHA-256')
    data = json.loads(plan_json.read_text())
    release = json.loads(release_path.read_text())
    verify_source_archive(release)
    verify_api_archive()
    result = review_plan(data, release)
    if expected_drift_sha256 and result['drift_sha256'] != expected_drift_sha256:
        raise ValueError('Provider refresh differs from the reviewed SHA-256')
    result.update(plan_sha256=plan_digest, plan_json_sha256=sha256(plan_json.read_bytes()))
    return result


def publish_frontend() -> None:
    session = deploy.aws_identity()
    snapshot = deploy.source_root()
    release = json.loads((deploy.BUILD / 'release.json').read_text())
    manifest = json.loads((deploy.BUILD / 'frontend-build.json').read_text())
    frontend = snapshot / 'frontend'
    dist = frontend / 'dist'
    files = {str(path.relative_to(dist)): sha256(path.read_bytes())
             for path in dist.rglob('*') if path.is_file()}
    if manifest.get('source_version') != release['source_version'] or files != manifest.get('files') or 'index.html' not in files:
        raise ValueError('Frontend assets differ from the frozen build')
    source_zip = verify_source_archive(release)
    verify_api_archive()
    output = json.loads(deploy.terraform('output', '-json', capture=True).stdout)
    bucket = output['frontend_bucket']['value']
    distribution = output['cloudfront_distribution_id']['value']
    if bucket != f'hacktricks-cspm-frontend-{ACCOUNT}' or not re.fullmatch(r'[A-Z0-9]{8,20}', distribution):
        raise ValueError('Terraform output is not the dedicated CSPM frontend')
    deploy.run(deploy.frontend_sync_command(frontend, bucket))
    deploy.run(['aws', 's3', 'cp', dist / 'index.html', f's3://{bucket}/index.html',
                '--cache-control', 'no-cache', '--content-type', 'text/html'])
    deploy.run(['aws', 's3', 'cp', source_zip, f's3://{bucket}/source/{source_zip.name}',
                '--cache-control', 'public,max-age=31536000,immutable', '--content-type', 'application/zip'])
    deploy.run(['aws', 's3', 'cp', deploy.BUILD / 'release.json', f's3://{bucket}/source/release.json',
                '--cache-control', 'no-cache', '--content-type', 'application/json'])
    session.client('cloudfront').create_invalidation(
        DistributionId=distribution,
        InvalidationBatch={'Paths': {'Quantity': 1, 'Items': ['/*']},
                           'CallerReference': f"cspm-{release['source_version']}-{time.time_ns()}"})
    print(json.dumps({'published_source_version': release['source_version'], 'url': 'https://cspm.hacktricks.wiki'}))


def verify_host(source_version: str) -> None:
    if not re.fullmatch(r'[0-9a-f]{64}', source_version):
        raise ValueError('Expected source version is invalid')
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            with urlopen('https://cspm.hacktricks.wiki/api/health', timeout=15) as response:
                payload = json.load(response)
            if payload.get('status') == 'ok' and payload.get('source_version') == source_version:
                deploy.run([__import__('sys').executable, 'scripts/peaso_deploy.py', 'verify-host'])
                print(json.dumps({'verified_source_version': source_version}))
                return
        except (OSError, ValueError):
            pass
        time.sleep(10)
    raise RuntimeError('Hosted API did not report the published source version')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    review = sub.add_parser('review')
    review.add_argument('--plan', type=Path, required=True)
    review.add_argument('--plan-json', type=Path, required=True)
    review.add_argument('--release', type=Path, required=True)
    review.add_argument('--expected-plan-sha256', default='')
    review.add_argument('--expected-drift-sha256', default='')
    sub.add_parser('publish')
    verify = sub.add_parser('verify-host')
    verify.add_argument('--source-version', required=True)
    args = parser.parse_args()
    if args.command == 'review':
        print(json.dumps(review_files(args.plan, args.plan_json, args.release,
                                      args.expected_plan_sha256, args.expected_drift_sha256), indent=2))
    elif args.command == 'publish':
        publish_frontend()
    else:
        verify_host(args.source_version)


if __name__ == '__main__':
    main()
