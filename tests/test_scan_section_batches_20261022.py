"""Whole section dependencies do not inherit unrelated scanner waits."""
from types import SimpleNamespace
from peaso.scan_sections import dependencies, states

SCOPE = '123456789012/us-east-2'


def test_network_batch_completes_while_images_and_leaks_are_running():
    needed = {'network': {'vpc', 'subnet'}, 'images': {'ecr_selected_image_vulnerabilities'},
              'leaks': {'log_group'}}
    rows = {('vpc', SCOPE): {'status': 'collected'}, ('subnet', SCOPE): {'status': 'empty'}}
    result = states('aws', [SCOPE], needed, rows, {key: 4 for key in rows})
    assert result['network']['status'] == 'complete'
    assert result['network']['data_revision'] == 4
    assert result['images']['status'] == result['leaks']['status'] == 'running'
    rows['ecr_selected_image_vulnerabilities', SCOPE] = {'status': 'partial'}
    later = states('aws', [SCOPE], needed, rows, {**{key: 4 for key in rows},
        ('ecr_selected_image_vulnerabilities', SCOPE): 5})
    assert later['images']['status'] == 'complete'
    assert later['network']['data_revision'] == 4
    assert later['leaks']['status'] == 'running'


def test_all_regions_required_and_account_global_read_is_once():
    second = '123456789012/us-east-1'
    rows = {('iam_role', '123456789012/global'): {}, ('vpc', SCOPE): {}}
    needed = {'network': {'vpc'}, 'least_privilege': {'iam_role'}}
    result = states('aws', [SCOPE, second], needed, rows, {}, global_types={'iam_role'})
    assert result['network']['status'] == 'running'
    assert result['least_privilege']['status'] == 'complete'
    rows['vpc', second] = {'status': 'access_denied'}
    assert states('aws', [SCOPE, second], needed, rows, {})['network']['status'] == 'complete'


def test_detector_and_image_checks_have_independent_dependency_batches():
    checks = [SimpleNamespace(id='aws.core', kind='vpc', dependencies=(), category='hardening'),
              SimpleNamespace(id='aws.review.log.secret_indicators', kind='log_group', dependencies=(), category='hardening'),
              SimpleNamespace(id='aws.review.image', kind='ecr_selected_image_vulnerabilities', dependencies=(), category='hardening')]
    needed = dependencies(checks, [], {}, None, {'vpc', 'log_group', 'ecr_selected_image_vulnerabilities'})
    assert needed['hardening'] == {'vpc'}
    assert needed['leaks'] == {'log_group'}
    assert needed['images'] == {'ecr_selected_image_vulnerabilities'}


def test_completed_aws_cve_batch_has_native_metadata_before_other_sections(tmp_path):
    import json
    import threading
    from pathlib import Path
    from peaso.incremental import CheckpointSession
    from peaso.aws_image_selection_20261021 import CHECK, KIND, OPTION, ENABLE
    from peaso.image_findings import build_report
    from peaso.selected_image_observations_20261021 import metadata_for_report
    item = json.loads((Path(__file__).parent / 'fixtures/aws_image_vulnerability_native_cases_20261021.json').read_text())[CHECK]['fail']
    target = item['ImageVulnerabilityReview']['selection']
    done = threading.Event()
    reports = []
    def checkpoint(snapshot, report, sequence):
        if report is not None:
            reports.append((snapshot, report))
            done.set()
    session = CheckpointSession({'connector': {'provider': 'aws', 'scopes': [target['scope']],
        'options': {ENABLE: True, OPTION: [target]}}, 'checks': [CHECK]}, checkpoint, lambda value: value, interval=.01)
    try:
        session.on_collection({'type': KIND, 'scope': target['scope'], 'service': 'ecr',
            'status': 'collected', 'items': [item]})
        assert done.wait(5)
        snapshot, report = reports[-1]
        rows = [row for row in report['findings'] if row['check_id'] == CHECK]
        assert len(rows) == 1 and rows[0]['status'] == 'FAIL'
        metadata = metadata_for_report(snapshot, report)
        projected = build_report(metadata['observations'], selected=True)
        assert projected['rows'], 'completed CVE data must be present before full collection returns'
        assert report['publication']['sections']['images']['status'] == 'complete'
        assert session.collection_finished is False
    finally:
        session.close()
