"""Join every active AWS review ID without promoting tests into live proof."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(root=ROOT):
    paths = {
        'native': root / 'docs/aws-review/native-contracts.json',
        'mappings': root / 'docs/aws-review/framework-mappings.json',
        'fields': root / 'docs/aws-review/field-producers.json',
        'groups': root / 'peaso/checks/finding_types.json',
    }
    for name in ('identity-closure-review', 'network-closure-review', 'services-closure-review',
                 'identity-sdk-closure-review', 'network-sdk-closure-review', 'data-sdk-closure-review',
                 'trail-kms-sdk-closure-review', 'network-cross-service-sdk-review',
                 'workload-sdk-closure-review', 'workload-resource-followup-review',
                 'optional-lambda-public-pipeline-review'):
        path = root / 'docs/aws-review' / (name + '.json')
        if path.is_file():
            paths[name] = path
    raw = {name: path.read_bytes() for name, path in paths.items()}
    docs = {name: json.loads(value) for name, value in raw.items()}
    native = {r['id']: r for r in docs['native']['checks'] if r['active']}
    mappings = {r['id']: r for r in docs['mappings']['checks']}
    fields = {r['id']: r for r in docs['fields']['checks']}
    if not native.keys() == mappings.keys() == fields.keys():
        raise ValueError('Review catalogs differ; refresh all per-ID ledgers first')
    group_ids = {group['id'] for group in docs['groups']['types']}
    if any(docs['groups']['checks'].get(cid) not in group_ids for cid in native):
        raise ValueError('Active AWS control is missing an existing reviewed UI group')
    closure_reviews, sdk_executions = {}, {}
    for name, report in docs.items():
        if name in {'native', 'mappings', 'fields', 'groups'}:
            continue
        for check in report.get('checks', [report] if report.get('id') else []):
            cid = check['id']
            if cid not in native:
                raise ValueError('Closure report contains non-active ID: ' + cid)
            closure_reviews.setdefault(cid, []).append(name)
            public_resource_tests = any(
                case.get('binding', {}).get('pipeline_source_fingerprint')
                for case in check.get('new_tests', []) if isinstance(case, dict)
            )
            if check.get('executed') or check.get('sdk_public_pipeline_receipts') or (
                    check.get('directed_consumer_receipts') or check.get('resource_tests')
                    or public_resource_tests or check.get('consumer_executions')):
                sdk_executions.setdefault(cid, []).append(name)
    rows = []
    for cid, row in sorted(native.items()):
        mapping, producer = mappings[cid], fields[cid]
        statuses = row['observed_status_counts']
        rows.append({
            'check_id': cid, 'title': mapping['title'], 'kind': row['kind'],
            'ui_group': docs['groups']['checks'][cid],
            'mocked_callback_executed': row['review']['runtime_mocked'],
            'observed_pass_cases': statuses.get('PASS', 0),
            'observed_fail_cases': statuses.get('FAIL', 0),
            'runtime_review': row['review']['semantic'],
            'producer_review': producer['status'],
            'compliance_mapping': mapping['mapping_review'],
            'numbered_requirement_count': mapping['requirement_count'],
            'hacktricks_mapped': mapping['hacktricks'],
            'upstream_ids': '|'.join(mapping['source_check_ids']),
            'directed_source_reviews': '|'.join(closure_reviews.get(cid, [])),
            'bounded_sdk_consumer_review_receipts': '|'.join(sdk_executions.get(cid, [])),
            'complete_semantic_review': False,
            'live_verified': producer['live_verified'],
        })
    if any(path.read_bytes() != raw[name] for name, path in paths.items()):
        raise ValueError('Review inputs changed during checklist capture')
    return rows, {str(path.relative_to(root)): hashlib.sha256(raw[name]).hexdigest()
                  for name, path in paths.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/aws-review/checklist.csv')
    parser.add_argument('--work-log', type=Path)
    args = parser.parse_args()
    rows, hashes = build()
    buffer = io.StringIO(newline='')
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    args.output.write_text(buffer.getvalue())
    args.output.with_suffix('.inputs.json').write_text(json.dumps(hashes, indent=2) + '\n')
    if args.work_log:
        lines = ['# AWS per-check review checklist — 2026-10-19', '',
                 'Every active ID is recorded below. Tests and mapping integrity are separate from producer proof and live validation.',
                 'No row claims complete semantic or exhaustive live verification. See docs/aws-review/README.md for receipts and limits.', '',
                 'New controls must reuse existing UI groups. Observed evidence must use one to three brief, direct natural-language sentences.',
                 'Example: Internet access to tcp/443 at https://example.execute-api.ca-central-1.amazonaws.com is allowed.',
                 'Action example: Consider whether this endpoint needs internet access; restrict allowed origins where possible.', '',
                 '| Check ID | Callback executed | Mapping | Field producer review |',
                 '|---|---|---|---|']
        lines.extend(f"| `{r['check_id']}` | {r['mocked_callback_executed']} | {r['compliance_mapping']} | {r['producer_review']} |" for r in rows)
        args.work_log.write_text('\n'.join(lines) + '\n')
    print(json.dumps({'active_check_rows': len(rows), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
