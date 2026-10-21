"""Unused permissions remain visible outside the Least Privilege report."""
from peaso.engine import evaluate_snapshot, hydrate_frameworks
from peaso.snapshot import make_snapshot


def test_active_unused_permission_detail_is_hardening_and_hacktricks_even_if_partial():
    scope = '123456789012/us-east-2'
    permission = {'serviceNamespace': 'iam', 'actions': [{'action': 'PassRole', 'lastAccessed': '2026-01-01T00:00:00Z'}]}
    unused = {'id': 'unused-permission-1', 'status': 'ACTIVE', 'findingType': 'UnusedPermission',
              'resource': 'arn:aws:iam::123456789012:role/test-role',
              'findingDetails': [{'unusedPermissionDetails': permission}]}
    analyzer = {'arn': 'arn:aws:access-analyzer:us-east-2:123456789012:analyzer/test-unused',
                'name': 'test-unused', 'type': 'ACCOUNT_UNUSED_ACCESS', 'status': 'ACTIVE',
                'configuration': {'unusedAccess': {'unusedAccessAge': 90}}, 'Findings': [unused]}
    snapshot = make_snapshot('aws', [scope], [{'type': 'access_analyzer', 'scope': scope,
        'service': 'accessanalyzer', 'status': 'partial', 'items': [analyzer],
        'error': {'kind': 'denied', 'code': 'UnrelatedAnalyzerDenied'}}], created_at='2026-10-21T13:00:00Z')
    ident = 'aws.claude_a.accessanalyzer.active_without_findings'
    report = hydrate_frameworks(evaluate_snapshot(snapshot, categories=['hardening'], checks=[ident]))
    finding = next(f for f in report['findings'] if f['check_id'] == ident)
    assert finding['status'] == 'FAIL'
    assert 'HackTricks Cloud Best Practices' in finding['frameworks']
    evidence = finding['evidence']
    assert evidence['unused_access_findings'] == 1
    recorded = evidence['access_analyzer_findings'][0]
    assert recorded['unused_access_days'] == 90
    assert recorded['resource'] == unused['resource']
    assert recorded['findingDetails'][0]['unusedPermissionDetails'] == permission
