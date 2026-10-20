"""Explicit paid/live deployment smoke, invoked by the release owner only."""
import json
from pathlib import Path
import tempfile
import uuid


def main():
    from .auth import default_token
    from .fargate import invoke
    from .contracts import validate_reviews
    from .pipeline import private_json
    marker = 'cspm-isolation-' + uuid.uuid4().hex
    finding = {'id': 'isolation-smoke', 'check_id': 'isolation-smoke', 'title': 'Local smoke fixture must be enabled and have a marker',
        'description': 'Verify smoke.json in the initial working directory: enabled must be true and marker must be nonempty. Include the observed marker in your reason if the original FAIL was incorrect.',
        'provider': 'aws', 'category': 'hardening', 'status': 'FAIL', 'severity': 'low',
        'resource_id': 'local-smoke-fixture', 'scope': 'local-fixture',
        'evidence': {'file': 'smoke.json', 'original_observation': 'enabled was false; marker was absent'}, 'supporting_resources': []}
    with tempfile.TemporaryDirectory(prefix='ai-live-smoke-') as directory:
        root = Path(directory)
        private_json(root/'credentials.json', {'version': 2, 'entries': []})
        private_json(root/'findings.json', {'scan': {'provider': 'aws'}, 'items': [finding]})
        private_json(root/'smoke.json', {'enabled': True, 'marker': marker})
        result = invoke('hardening', root, default_token(), 240)
        result = validate_reviews(result, [finding])
        reviewed = result['items'][0]
        if reviewed['verdict'] != 'PASS' or marker not in reviewed['reason']:
            raise RuntimeError('isolated_live_smoke_failed')
        # A real-model counterexample to the observed any-versus-all mistake.
        # This is a configuration control; routing or TLS does not make it pass.
        exposure = {'id': 'public-port-smoke',
            'check_id': 'aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis',
            'title': 'Customer-managed interfaces must have no internet-open ingress ports',
            'provider': 'aws', 'category': 'exposure', 'status': 'FAIL', 'severity': 'high',
            'resource_id': 'local-security-group', 'scope': 'local-fixture',
            'pass_when': 'No world-source ingress rule is attached to a customer-managed interface.',
            'fail_when': 'Any port is open to 0.0.0.0/0 or ::/0 on a customer-managed interface; all ports need not be open.',
            'evidence_summary': 'An ingress rule allows TCP 443 from 0.0.0.0/0 on customer-managed interface eni-123. Any internet-open port fails this configuration control.',
            'evidence': {'world_ingress_rule_found': True, 'customer_enis': ['eni-123'],
                'internet_ingress': [{'protocol': 'tcp', 'from_port': 443, 'to_port': 443, 'source': '0.0.0.0/0'}]},
            'supporting_resources': []}
        (root/'findings.json').unlink()
        private_json(root/'findings.json', {'scan': {'provider': 'aws'}, 'items': [exposure]})
        checked = validate_reviews(invoke('exposure', root, default_token(), 240), [exposure])
        if checked['items'][0]['verdict'] != 'FAIL':
            raise RuntimeError('isolated_live_any_port_semantics_failed')
    # Use only an offline native snapshot; no customer cloud credentials or
    # tenant artifacts are supplied. Exercise the shipped orchestration barrier.
    from peaso.demo import demo_snapshot
    from peaso.engine import evaluate_snapshot, hydrate_finding
    from .pipeline import review_scan
    snapshot = demo_snapshot('aws')
    report = evaluate_snapshot(snapshot, categories=['hardening', 'exposure', 'network'])
    findings = [hydrate_finding(row, report.get('check_frameworks'), report.get('check_meta'),
        report.get('check_meta_encoding'), report.get('remediation_templates')) for row in report['findings']]
    report['findings'] = [next(row for row in findings if row['category'] == category and row['status'] == 'FAIL')
                          for category in ('hardening', 'exposure')]
    result = review_scan(report, snapshot, {'ai_enabled': True},
                        tenant='release-smoke-' + uuid.uuid4().hex, artifacts=None)
    if (result['status'] != 'completed' or result.get('network', {}).get('status') != 'completed'
            or len(result['reviews']['hardening']) != 1 or len(result['reviews']['exposure']) != 1
            or result.get('coverage', {}).get('total') != 2):
        raise RuntimeError('isolated_live_pipeline_smoke_failed')
    print(json.dumps({'status': 'passed', 'stages': ['hardening', 'exposure', 'network', 'priorities'],
                      'isolated_tool_file_read_verified': True, 'reviewer_completion_barrier_verified': True, 'any_port_failure_semantics_verified': True}))


if __name__ == '__main__':
    main()
