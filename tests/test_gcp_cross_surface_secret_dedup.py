"""One hidden exact-value leak across GCP services and both real detectors."""
import json
from peaso.collectors import gcp_function_secret_indicators as functions
from peaso.collectors import gcp_configuration_secret_indicators as configurations
from peaso.checks import gcp_function_secret_review_20261019 as function_check
from peaso.checks import gcp_configuration_secret_review_20261019 as configuration_checks
from peaso.secret_findings import deduplicate_secret_findings


def test_identical_literal_in_function_and_vm_is_one_leak_with_both_owners():
    scope = 'projects/review'
    token = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
    function_name = scope + '/locations/us-central1/functions/worker'
    function = functions.project_response({'name': function_name,
        'serviceConfig': {'environmentVariables': {'CONFIG': token}}, 'buildConfig': {}},
        method='GET', url='https://cloudfunctions.googleapis.com/v2/' + function_name,
        scope=scope, enabled=True)
    instance_name = scope + '/zones/us-central1-a/instances/worker'
    instance = configurations.project_response({'name': 'worker',
        'selfLink': 'https://www.googleapis.com/compute/v1/' + instance_name,
        'metadata': {'items': [{'key': 'startup-script', 'value': 'TOKEN=' + token}]}},
        method='GET', url='https://compute.googleapis.com/compute/v1/' + instance_name,
        scope=scope, enabled=True, selected_kinds=['instance'])
    findings = []
    for kind, item, cid, name, evaluate in [
        ('function', function, function_check.CHECK_ID, function_name, function_check.evaluate),
        ('instance', instance, configurations.IDS['instance'], instance_name, configuration_checks.instance)]:
        context = {'context': {'provider': 'gcp', 'scope': scope},
                   'collections': {kind: [{'scope': scope, 'status': 'collected', 'items': [item]}]}}
        status, evidence = evaluate(item, context)
        assert status == 'FAIL', evidence
        findings.append({'provider': 'gcp', 'check_id': cid, 'scope': scope, 'resource_id': name,
                         'native_resource_id': name, 'status': status, 'evidence': evidence,
                         'frameworks': [], 'finding_type': 'secrets'})
    result = deduplicate_secret_findings(findings)
    assert len(result) == 1
    assert result[0]['linked_check_ids'] == sorted([function_check.CHECK_ID, configurations.IDS['instance']])
    leak, = result[0]['evidence']['secret_leaks']
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert {loc['resource_id'] for loc in leak['locations']} == {function_name, instance_name}
    assert token not in json.dumps([function, instance, findings, result])
