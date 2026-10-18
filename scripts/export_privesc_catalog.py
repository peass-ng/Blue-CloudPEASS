#!/usr/bin/env python3
"""Export the Blue-CloudPEASS privesc catalog into the HackTricks Cloud upstream layout.

Writes <book-root>/src/privilege-escalation-paths/:
    README.md                          (format + contribution guide, generated, deterministic)
    privesc-technique.schema.json      (copied from peaso/privesc/ when it exists)
    <provider>/<service>.yaml          (byte-for-byte copies of peaso/privesc/catalog/<provider>/*.yaml)

The catalog is validated strictly before anything is written. Upstream catalog files or
technique ids that do not exist locally are never removed unless --prune is given (they may be
upstream contributions not yet synchronized back; run scripts/sync_hacktricks_privesc.py first).
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('sync_hacktricks_privesc', Path(__file__).resolve().parent / 'sync_hacktricks_privesc.py')
sync_module = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('sync_hacktricks_privesc', sync_module)
_spec.loader.exec_module(sync_module)

SyncError = sync_module.SyncError
SCHEMA_NAME = 'privesc-technique.schema.json'

README = """# Privilege escalation paths

{{#include ../banners/hacktricks-training.md}}

HackTricks Cloud maintains the machine-readable privilege-escalation technique catalog consumed by \
[Blue-CloudPEASS](https://github.com/peass-ng/PEASSo-CSPM). Each entry describes, without any exploitation \
steps, which permissions let a principal obtain the privileges of another principal (or an administrative \
entity), and links to the HackTricks page that documents the technique. Edit the files here; consumers \
fetch and validate them weekly.

## Layout

There is one directory per platform and one YAML file per service, mirroring the HackTricks privilege-escalation \
pages: `aws/`, `gcp/`, `azure/` (including Entra ID) and `k8s/` (Kubernetes and OpenShift). For example \
`gcp/iam.yaml` holds the techniques documented in `gcp-iam-privesc.md`. One file per service keeps reviews small, \
avoids merge conflicts between contributors, and lets a page and its catalog file be updated in the same pull request.

- `<service>.yaml` is a YAML list of technique entries.
- `_excluded*.yaml` lists HackTricks techniques that were reviewed and intentionally not modelled as \
principal-to-principal edges (`source`, `technique`, `reason`), so reviewers can tell "not modelled" from "missed".
- `_todo.yaml` holds commented-out notes for techniques still being written.
- Comments are preserved verbatim by the consumers; use them for per-file modelling conventions.

## Entry format

The authoritative validator is `peaso/privesc/schema.py` in Blue-CloudPEASS; {schema_line}

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Unique kebab-case id prefixed by the provider (`aws-`, `gcp-`, `azure-`/`entra-`, `k8s-`). Never reuse or rename an id. |
| `provider` | yes | `aws`, `gcp`, `azure` or `k8s`; must match the directory. |
| `service` | yes | Service the technique abuses (usually the file name). |
| `title` | yes | Short description of the escalation. |
| `source` | yes | HackTricks Cloud page and heading anchor, `src/...md#anchor`. The page and anchor must exist. |
| `source_revision` | no | Book revision the source was verified against. |
| `summary` | yes | One or two sentences: what the source gains. No commands or how-to steps. |
| `requires` | yes | `all_of` (every requirement) and/or `any_of` (list of alternative requirement lists). Each requirement names an `action` (permission) and the `resource` it must cover, using placeholders such as `{target.arn}` or `{target.email}`. |
| `target` | yes | `kind` of the principal or entity gained, optional `selector` limiting candidate targets, `scope` and `aggregate_as` label. |
| `severity` | yes | `critical`, `high`, `medium`, `low` or `info`. |
| `mitigation` | yes | How defenders remove or constrain the path. |
| `confidence` | no | `derived`, `conditional` or `unknown`. |
| `conditions` | no | Facts the snapshot cannot prove (each with `id` and `description`); they make an edge conditional. |
| `blockers` | no | Controls that remove the edge when present (SCPs, deny policies, admission policies...). |
| `preconditions`, `source_kind`, `source_selector`, `pivot_resource_type` | no | Advanced modelling fields; see the schema. |
| `references`, `notes` | no | Extra URLs and reviewer notes. |

Unknown fields, unknown selector keys, unsupported target kinds or placeholders, and shell commands in prose \
are rejected (or flagged) because the evaluator would not understand them.

## Contributing

1. Document the technique on its HackTricks page first, under its own heading, and use that heading anchor as `source`.
2. Add or update the entry in `<provider>/<service>.yaml` (create the file if the service has none yet).
3. Validate with a Blue-CloudPEASS checkout and PyYAML installed:
   `python /path/to/Blue-CloudPEASS/scripts/sync_hacktricks_privesc.py --book-root . --validate-only`
4. Open a pull request. Removing an entry or changing its `id` needs a reviewed ledger entry in the consumer, so prefer \
fixing an entry over deleting it, and explain removals in the pull request.

## Synchronization

Every Monday Blue-CloudPEASS checks out the current `master` of this book, validates this directory, and compares \
SHA-256 hashes with the manifest recorded at its previous sync (`risk_rules/hacktricks-privesc-source.json`). Files \
changed only here are copied byte for byte; files changed only in the consumer are kept until they are upstreamed; \
files changed on both sides fail the sync for a human to resolve. Entries are never dropped from the consumer unless a \
reviewed ledger accepts the removal. Unrelated book commits produce no consumer commit.

{{#include ../banners/hacktricks-training.md}}
"""


def render_readme(has_schema: bool) -> bytes:
    line = (f'its JSON Schema is published next to this file as [`{SCHEMA_NAME}`]({SCHEMA_NAME}) for editor '
            'completion and quick checks.' if has_schema else
            'a JSON Schema for editors will be published next to this file.')
    return README.replace('{schema_line}', line).encode()


def build(catalog_dir: Path, repo_root: Path) -> dict:
    """{upstream-relative path: bytes} for the complete upstream tree."""
    files = sync_module.read_tree(catalog_dir, strict=False)
    if not files:
        raise SyncError(f'No catalog files under {catalog_dir}')
    schema_json = repo_root / sync_module.SCHEMA_JSON
    out = dict(sorted(files.items()))
    if schema_json.is_file():
        out[SCHEMA_NAME] = schema_json.read_bytes()
    out['README.md'] = render_readme(schema_json.is_file())
    return out


def export(book_root: Path, *, catalog_dir=None, repo_root=ROOT, check=False, prune=False):
    book_root, repo_root = Path(book_root), Path(repo_root)
    catalog_dir = Path(catalog_dir) if catalog_dir else repo_root / sync_module.CATALOG_PATH
    schema = sync_module.load_schema(repo_root)
    tree = build(catalog_dir, repo_root)
    catalog = {k: v for k, v in tree.items() if '/' in k}
    pages = sync_module.source_root(book_root)
    count = sync_module.validate_tree(schema, catalog, 'local', pages)
    destination = book_root / sync_module.UPSTREAM_PATH
    existing = sync_module.read_tree(destination, strict=True) if destination.is_dir() else {}
    extras = {p.name for p in destination.iterdir() if p.is_file()} if destination.is_dir() else set()
    removed = sorted(rel for rel in existing if rel not in catalog)
    lost = sorted(set(sync_module.item_keys(existing)) - set(sync_module.item_keys(catalog)))
    if (removed or lost) and not prune:
        raise SyncError('Export would remove upstream privesc content that is not in the local catalog '
                        '(sync it first, or pass --prune): ' + ', '.join(removed + lost))
    writes = {destination / rel: content for rel, content in tree.items()
              if not (destination / rel).is_file() or (destination / rel).read_bytes() != content}
    deletes = [destination / rel for rel in removed]
    if SCHEMA_NAME in extras and SCHEMA_NAME not in tree:
        deletes.append(destination / SCHEMA_NAME)
    stale = sorted(str(p.relative_to(book_root)) for p in [*writes, *deletes])
    if check:
        if stale:
            raise SyncError('Stale upstream privesc export: ' + ', '.join(stale))
        print(f'Upstream export is current: {len(catalog)} files, {count} techniques')
        return 0
    for path, content in writes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    for path in deletes:
        path.unlink()
    print(f'Exported {len(catalog)} files, {count} techniques; {len(stale)} upstream files changed')
    return len(stale)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--book-root', type=Path, required=True, help='HackTricks Cloud checkout to write into')
    parser.add_argument('--catalog-dir', type=Path, help='default: peaso/privesc/catalog')
    parser.add_argument('--check', action='store_true', help='fail when the upstream export is stale')
    parser.add_argument('--prune', action='store_true', help='allow removing upstream files/ids absent locally')
    args = parser.parse_args()
    try:
        export(args.book_root, catalog_dir=args.catalog_dir, check=args.check, prune=args.prune)
    except SyncError as error:
        parser.exit(1, f'error: {error}\n')


if __name__ == '__main__':
    main()
