#!/usr/bin/env python3
"""Validate and synchronize the HackTricks Cloud privilege-escalation path catalog.

Upstream layout (reviewed CSPM catalog, in HackTricks Cloud):
    src/privilege-escalation-paths/<provider>/<service>.yaml
Local copy (Blue-CloudPEASS):
    peaso/privesc/catalog/<provider>/<service>.yaml

Files are copied byte for byte (comments carry modelling conventions). The merge is a
three-way comparison per file against the hashes recorded at the previous sync in
risk_rules/hacktricks-privesc-source.json:

* upstream == local                          -> unchanged
* upstream unchanged since the last sync     -> the local file wins (local-only or not yet upstreamed)
* local unchanged since the last sync        -> the upstream file wins (add, update or delete)
* both changed differently                   -> conflict, nothing is written (--prefer-upstream resolves)

Technique ids (and `_excluded*.yaml` items) present locally but absent from the effective
result are never dropped unless an explicit reviewed ledger accepts the removal. Upstream
content is validated with peaso/privesc/schema.py before anything is written; invalid
upstream content is refused. No cloud credentials, network calls, or technique execution.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import yaml

PROVIDERS = ('aws', 'gcp', 'azure', 'k8s')
REPOSITORY = 'HackTricks-wiki/hacktricks-cloud'
UPSTREAM_PATH = 'src/privilege-escalation-paths'
CATALOG_PATH = Path('peaso/privesc/catalog')
MANIFEST_PATH = Path('risk_rules/hacktricks-privesc-source.json')
LEDGER_PATH = Path('risk_rules/reviewed-privesc-ledger.json')
SCHEMA_PY = Path('peaso/privesc/schema.py')
SCHEMA_JSON = Path('peaso/privesc/privesc-technique.schema.json')
MERGE_POLICY = 'three-way-canonical-first-v1'
FILE_NAME = re.compile(r'^_?[a-z0-9][a-z0-9_.-]*\.yaml$')
ROOT_EXTRAS = re.compile(r'^(README\.md|[A-Za-z0-9_.-]+\.schema\.json)$')


class SyncError(ValueError):
    pass


def load_schema(repo_root: Path):
    """Import peaso/privesc/schema.py by path (stdlib + PyYAML only, no package side effects)."""
    path = Path(repo_root) / SCHEMA_PY
    spec = importlib.util.spec_from_file_location('peaso_privesc_schema_standalone', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def read_tree(root: Path, *, strict: bool) -> dict:
    """{'<provider>/<file>.yaml': bytes}. strict=True refuses any unexpected path (upstream input)."""
    files = {}
    if not root.is_dir():
        return files
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if path.is_symlink():
            raise SyncError(f'Refusing symbolic link in catalog tree: {rel.as_posix()}')
        if path.is_dir():
            if strict and (len(rel.parts) > 1 or rel.parts[0] not in PROVIDERS):
                raise SyncError(f'Unexpected directory in privesc tree: {rel.as_posix()}')
            continue
        if len(rel.parts) == 1:
            if strict and not ROOT_EXTRAS.match(rel.name):
                raise SyncError(f'Unexpected file at privesc tree root: {rel.name}')
            continue
        if rel.parts[0] not in PROVIDERS:
            if strict:
                raise SyncError(f'Unknown provider directory: {rel.parts[0]}')
            continue
        if len(rel.parts) != 2:
            if strict:
                raise SyncError(f'Nested path not allowed: {rel.as_posix()}')
            continue
        if not FILE_NAME.match(rel.name):
            if strict or rel.suffix in ('.yml', '.yaml'):
                raise SyncError(f'Catalog files must be lowercase <name>.yaml: {rel.as_posix()}')
            continue
        files[rel.as_posix()] = path.read_bytes()
    return files


def item_keys(files: dict) -> dict:
    """{key: file} for every technique id and excluded item (keys used by the removal guard)."""
    keys = {}
    for rel, content in files.items():
        try:
            data = yaml.safe_load(content) or []
        except yaml.YAMLError as error:
            raise SyncError(f'{rel}: YAML parse error: {str(error).splitlines()[0]}') from error
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            if rel.split('/', 1)[1].startswith('_excluded'):
                keys[f"excluded:{item.get('source')}|{item.get('technique')}"] = rel
            elif isinstance(item.get('id'), str):
                keys[item['id']] = rel
    return keys


def validate_tree(schema, files: dict, label: str, hacktricks_root) -> int:
    """Strictly validate a {rel: bytes} tree with the catalog loader; returns the entry count."""
    with tempfile.TemporaryDirectory(prefix='.privesc-validate-') as folder:
        root = Path(folder)
        for rel, content in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(content)
        result = schema.load_catalog(root, hacktricks_root=hacktricks_root)
    if result['errors']:
        shown = '; '.join(result['errors'][:20])
        more = f' (+{len(result["errors"]) - 20} more)' if len(result['errors']) > 20 else ''
        raise SyncError(f'Invalid {label} privesc catalog: {shown}{more}')
    return len(result['entries'])


def source_root(book_root: Path) -> Path:
    """Validate `source` paths against the book only when its pages were fetched."""
    if (book_root / 'src/pentesting-cloud').is_dir():
        return book_root
    return book_root / '.no-pages-fetched'  # nonexistent: the loader skips the page check


def _unique_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SyncError(f'Duplicate ledger JSON key: {key}')
        result[key] = value
    return result


def load_ledger(path: Path):
    """Reviewed ledger: {version: 1, review: {description}, accepted_removals: {key: reason}}."""
    content = path.read_bytes()
    ledger = json.loads(content, object_pairs_hook=_unique_json_keys)
    if (not isinstance(ledger, dict) or set(ledger) != {'version', 'review', 'accepted_removals'}
            or type(ledger['version']) is not int or ledger['version'] != 1):
        raise SyncError('Unsupported privesc ledger schema')
    review = ledger['review']
    if (not isinstance(review, dict) or set(review) != {'description'}
            or not isinstance(review['description'], str) or not review['description'].strip()):
        raise SyncError('Privesc ledger requires a review description')
    removals = ledger['accepted_removals']
    if not isinstance(removals, dict) or any(
            not isinstance(k, str) or not k or not isinstance(v, str) or not v.strip() for k, v in removals.items()):
        raise SyncError('Ledger accepted_removals must map ids to non-empty reasons')
    return ledger, content


def book_revision(book_root: Path):
    """HEAD of the book checkout, or None when unknown or the privesc tree is not committed there."""
    try:
        revision = subprocess.check_output(['git', '-C', str(book_root), 'rev-parse', 'HEAD'],
                                           text=True, stderr=subprocess.DEVNULL).strip()
        dirty = subprocess.check_output(['git', '-C', str(book_root), 'status', '--porcelain', '--', UPSTREAM_PATH],
                                        text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return None if dirty or not re.fullmatch(r'[0-9a-f]{40}', revision) else revision


def merge(local: dict, upstream: dict, prior: dict, *, prefer_upstream=False):
    """Three-way per-file merge. Returns (effective, conflicts)."""
    base_upstream = prior.get('canonical_sha256', {}) if isinstance(prior.get('canonical_sha256'), dict) else {}
    base_local = prior.get('sha256', {}) if isinstance(prior.get('sha256'), dict) else {}
    effective, conflicts = {}, []
    for rel in sorted(set(local) | set(upstream)):
        lh = sha256(local[rel]) if rel in local else None
        uh = sha256(upstream[rel]) if rel in upstream else None
        if lh == uh or uh == base_upstream.get(rel):
            chosen = local.get(rel)       # identical, or upstream unchanged: local wins
        elif lh == base_local.get(rel) or prefer_upstream:
            chosen = upstream.get(rel)    # local unchanged since last sync: upstream wins
        else:
            conflicts.append(rel)
            chosen = local.get(rel)
        if chosen is not None:
            effective[rel] = chosen
    return effective, conflicts


def sync(book_root: Path, target: Path, *, check=False, validate_only=False, ledger_path=None,
         prefer_upstream=False, allow_missing_upstream=False):
    book_root, target = Path(book_root), Path(target)
    schema = load_schema(target)
    upstream_dir = book_root / UPSTREAM_PATH
    if not upstream_dir.is_dir():
        if allow_missing_upstream:
            print(f'{UPSTREAM_PATH} is not present in the book; nothing to synchronize')
            return 0
        raise SyncError(f'Missing upstream privesc directory: {upstream_dir}')
    upstream = read_tree(upstream_dir, strict=True)
    if not upstream:
        raise SyncError('Upstream privesc directory contains no catalog files')
    pages = source_root(book_root)
    count = validate_tree(schema, upstream, 'upstream', pages)
    if validate_only:
        print(f'Upstream privesc catalog is valid: {len(upstream)} files, {count} techniques')
        return 0

    catalog_dir = target / CATALOG_PATH
    manifest_path = target / MANIFEST_PATH
    local = read_tree(catalog_dir, strict=False)
    prior = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    effective, conflicts = merge(local, upstream, prior, prefer_upstream=prefer_upstream)
    if conflicts:
        raise SyncError('Local and upstream privesc files both changed since the last sync '
                        '(export local changes upstream, or rerun with --prefer-upstream): ' + ', '.join(conflicts))

    explicit_ledger = ledger_path is not None
    ledger_path = Path(ledger_path) if explicit_ledger else target / LEDGER_PATH
    ledger = ledger_bytes = None
    if explicit_ledger or ledger_path.exists():
        ledger, ledger_bytes = load_ledger(ledger_path)
    accepted = set(ledger['accepted_removals']) if ledger else set()
    local_keys, effective_keys = item_keys(local), item_keys(effective)
    lost = sorted(k for k in set(local_keys) - set(effective_keys) if k not in accepted)
    # A newer upstream file can remove a locally retained item while adding
    # other valid items. Keep that complete local file until its removals are
    # reviewed; still record the newer upstream bytes as canonical provenance.
    # Full file deletion and an emptied file continue to require the ledger.
    for rel in sorted({local_keys[key] for key in lost}):
        if (not prefer_upstream and rel in upstream and rel in local
                and effective.get(rel) == upstream[rel] != local[rel]
                and item_keys({rel: upstream[rel]})):
            effective[rel] = local[rel]
    effective_keys = item_keys(effective)
    lost = sorted(k for k in set(local_keys) - set(effective_keys) if k not in accepted)
    if lost:
        raise SyncError('Synchronization would drop local privesc items not present upstream; upstream them '
                        'or accept the removal in a reviewed ledger: '
                        + ', '.join(f'{k} ({local_keys[k]})' for k in lost))
    validate_tree(schema, effective, 'effective', pages)

    canonical = {rel: sha256(content) for rel, content in sorted(upstream.items())}
    hashes = {rel: sha256(content) for rel, content in sorted(effective.items())}
    revision = book_revision(book_root)
    if prior.get('canonical_sha256') == canonical and prior.get('revision'):
        revision = prior['revision']  # Unrelated book commits must not create update commits.
    manifest = dict(repository=REPOSITORY, revision=revision, path=UPSTREAM_PATH,
                    canonical_sha256=canonical, sha256_scope='effective-catalog-files', sha256=hashes,
                    effective=dict(merge_policy=MERGE_POLICY,
                                   local_ahead_files=sorted(r for r in effective if hashes[r] != canonical.get(r)),
                                   local_deleted_files=sorted(r for r in upstream if r not in effective)))
    if ledger is not None:
        try:
            name = ledger_path.resolve().relative_to(target.resolve()).as_posix()
        except ValueError:
            name = ledger_path.name
        manifest['ledger'] = dict(path=name, sha256=sha256(ledger_bytes), review=ledger['review'])

    writes = {catalog_dir / rel: content for rel, content in effective.items()
              if local.get(rel) != content}
    deletes = [catalog_dir / rel for rel in local if rel not in effective]
    manifest_bytes = (json.dumps(manifest, indent=2) + '\n').encode()
    if not manifest_path.exists() or manifest_path.read_bytes() != manifest_bytes:
        writes[manifest_path] = manifest_bytes
    stale = sorted(str(p.relative_to(target)) for p in [*writes, *deletes])
    if check:
        if stale:
            raise SyncError('Stale privesc catalog: ' + ', '.join(stale))
        print('0 files need synchronization')
        return 0
    for path, content in writes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    for path in deletes:
        path.unlink()
    print(f'{len(stale)} files updated')
    return len(stale)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--book-root', type=Path, required=True, help='HackTricks Cloud checkout')
    parser.add_argument('--target-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--check', action='store_true', help='fail when the local catalog or manifest is stale')
    parser.add_argument('--validate-only', action='store_true', help='only validate the upstream tree')
    parser.add_argument('--ledger', type=Path,
                        help='reviewed removal ledger (default: optional target risk_rules/reviewed-privesc-ledger.json)')
    parser.add_argument('--prefer-upstream', action='store_true',
                        help='resolve files changed on both sides in favour of upstream (removal guard still applies)')
    parser.add_argument('--allow-missing-upstream', action='store_true',
                        help='succeed without changes when the book has no privesc directory yet')
    args = parser.parse_args()
    try:
        sync(args.book_root, args.target_root, check=args.check, validate_only=args.validate_only,
             ledger_path=args.ledger, prefer_upstream=args.prefer_upstream,
             allow_missing_upstream=args.allow_missing_upstream)
    except SyncError as error:
        parser.exit(1, f'error: {error}\n')


if __name__ == '__main__':
    main()
