"""Join the GCP per-ID review records without treating fixtures as certification."""
import csv
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / 'docs/gcp-review'


def disposition(review):
    explicit = review.get('status', review.get('disposition'))
    if explicit:
        return explicit
    traces = (review.get('code_review'), review.get('producer_review'))
    if all(isinstance(value, str) and value.strip() and not value.startswith(('pending', 'not_reviewed', 'unverifiable')) for value in traces):
        return 'bounded_source_and_producer_trace_reported'
    return 'pending'


def build():
    paths = [REVIEW / 'native-contracts.json']
    paths += [p for name in ('identity-data-review', 'compute-network-review', 'project-logging-review', 'workbench-review', 'function-secret-review', 'native-extension-integration')
              if (p := REVIEW / (name + '.json')).is_file()]
    paths += [p for name in ('metric-alert-semantic-followup', 'sql-transport-semantic-followup')
              if (p := REVIEW / (name + '.json')).is_file()]
    captured = {p: p.read_bytes() for p in paths}
    native = json.loads(captured[paths[0]])
    reports, followups = {}, {}
    for path in paths[1:]:
        document = json.loads(captured[path])
        integration = document.get('root_integration', {})
        if integration.get('status') == 'installed_local_acceptance_passed':
            for cid in integration.get('affected_ids', []):
                if cid in followups:
                    raise ValueError('Duplicate native semantic follow-up: ' + cid)
                followups[cid] = path.name
        checks = document.get('checks', [])
        if path.stem == 'function-secret-review':
            checks = [{**document['declaration'], 'status': document.get('root_integration', {}).get('state', document['status'])}]
        for check in checks:
            cid = check['id']
            if cid in reports:
                raise ValueError('Duplicate GCP review ownership: ' + cid)
            reports[cid] = (path.name, check)
    rows = []
    for check in native['checks']:
        report, review = reports.get(check['id'], ('pending', {}))
        rows.append({'check_id': check['id'], 'active': check['active'],
                     'title': check['title'], 'kind': check['kind'],
                     'ui_group': check['ui_group'], 'source': check['source'],
                     'source_sha256': check['source_sha256'],
                     'upstream_ids': '|'.join(check['source_ids']),
                     'framework_ids': '|'.join(check['framework_ids']),
                     'passing_callback_test_nodes': len(check['passing_test_nodes']),
                     'observed_statuses': '|'.join(sorted(check['observed_status_counts'])),
                     'review_report': report,
                     'review_disposition': 'native_semantic_followup_integrated' if check['id'] in followups else disposition(review),
                     'semantic_followup_report': followups.get(check['id'], ''),
                     'code_review_scope': review.get('code_review', ''),
                     'producer_review_scope': review.get('producer_review', ''),
                     'live_verified': False, 'complete_semantic_certification': False,
                     'archive_reason': check['archive_reason'] or ''})
    if len(rows) != len({r['check_id'] for r in rows}):
        raise ValueError('Duplicate registered GCP IDs')
    if (reports.keys() | followups.keys()) - {r['check_id'] for r in rows}:
        raise ValueError('Review includes unregistered GCP IDs')
    if any(p.read_bytes() != raw for p, raw in captured.items()):
        raise ValueError('Review source changed during capture')
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    (REVIEW / 'checklist.csv').write_text(out.getvalue())
    (REVIEW / 'checklist.inputs.json').write_text(json.dumps({
        str(p.relative_to(ROOT)): hashlib.sha256(raw).hexdigest() for p, raw in captured.items()
    }, indent=2) + '\n')
    print(json.dumps({'registered': len(rows), 'active': sum(r['active'] for r in rows),
                      'review_reports_joined': len(paths) - 1,
                      'pending_review_report': sum(r['review_report'] == 'pending' for r in rows)}))


if __name__ == '__main__':
    build()
