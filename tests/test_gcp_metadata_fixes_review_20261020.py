"""Native producer/engine regressions for the five metadata defect families."""
from copy import deepcopy
import json

import pytest

from peaso.checks import CHECKS
from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from tests.test_gcp_metadata_final_batch_review_20261020 import (
    BASE, SPECS, SCOPE, merge, native, forbid_network_auth,
)

RUN_IDS = ['gcp.htbp.cloudrun.service_secret_env_from_secret_manager',
           'gcp.htbp.cloudrun.job_secret_env_from_secret_manager']
PR = 'gcp.htbp.cloudbuild.pr_trigger_gated'
KEY = 'gcp.ports.api_key_meaningful_restrictions'
APPROVAL = 'gcp.ports.access_approval_explicit_enrollment'
REGISTRY = {check.id: check for check in CHECKS}
RAW_VALUE = 'synthetic-literal-must-never-survive'
V2 = {'valueSource': {'secretKeyRef': {'secret': 'db', 'version': 'latest'}}}
V1 = {'valueFrom': {'secretKeyRef': {'name': 'db', 'key': 'latest'}}}


def finding(cid, kind, item, **kwargs):
    before = deepcopy(item)
    captured, api = native(kind, item, **kwargs)
    assert before == item
    frozen = deepcopy(captured)
    findings = evaluate_snapshot(captured, checks=[cid])['findings']
    assert captured == frozen
    rows = [row for row in findings if 'native_resource_id' in row]
    assert len(rows) == 1, findings
    assert RAW_VALUE not in json.dumps(captured)
    return rows[0], captured, api


ENV_CASES = [
    ('native-v2-secret', V2, 'PASS'),
    ('legacy-v1-secret', V1, 'PASS'),
    ('v2-number-version', {'valueSource': {'secretKeyRef': {'secret': 'db', 'version': '2'}}}, 'PASS'),
    ('v2-cross-project-alias', {'valueSource': {'secretKeyRef': {'secret': 'projects/other-project/secrets/db', 'version': 'prod'}}}, 'PASS'),
    ('inline-credential', {'value': RAW_VALUE}, 'FAIL'),
    ('omitted-inline-value', {}, 'FAIL'),
    ('empty-value-v2-conflict', {**V2, 'value': ''}, 'UNKNOWN'),
    ('literal-v2-conflict', {**V2, 'value': RAW_VALUE}, 'UNKNOWN'),
    ('empty-value-legacy-v1', {**V1, 'value': ''}, 'PASS'),
    ('v1-invalid-secret-name', {'valueFrom': {'secretKeyRef': {'name': 'projects/p/secrets/db', 'key': 'latest'}}}, 'UNKNOWN'),
    ('literal-v1-conflict', {**V1, 'value': RAW_VALUE}, 'UNKNOWN'),
    ('two-reference-kinds', {**V1, **V2}, 'UNKNOWN'),
    ('v2-null', {'valueSource': None}, 'UNKNOWN'),
    ('v2-wrong-scalar', {'valueSource': RAW_VALUE}, 'UNKNOWN'),
    ('v2-empty-source', {'valueSource': {}}, 'UNKNOWN'),
    ('v2-empty-selector', {'valueSource': {'secretKeyRef': {}}}, 'UNKNOWN'),
    ('v2-null-selector', {'valueSource': {'secretKeyRef': None}}, 'UNKNOWN'),
    ('v2-missing-version', {'valueSource': {'secretKeyRef': {'secret': 'db'}}}, 'UNKNOWN'),
    ('v2-empty-version', {'valueSource': {'secretKeyRef': {'secret': 'db', 'version': ''}}}, 'UNKNOWN'),
    ('v2-wrong-version-type', {'valueSource': {'secretKeyRef': {'secret': 'db', 'version': {'value': RAW_VALUE}}}}, 'UNKNOWN'),
    ('v2-invalid-secret-resource', {'valueSource': {'secretKeyRef': {'secret': 'db/versions/latest', 'version': 'latest'}}}, 'UNKNOWN'),
    ('v2-wrong-legacy-fields', {'valueSource': V1['valueFrom']}, 'UNKNOWN'),
    ('v1-wrong-v2-fields', {'valueFrom': V2['valueSource']}, 'UNKNOWN'),
    ('v1-missing-key', {'valueFrom': {'secretKeyRef': {'name': 'db'}}}, 'UNKNOWN'),
    ('v2-denied-source', {**V2, '_coverage': {'valueSource': {'status': 'denied'}}}, 'UNKNOWN'),
    ('v2-denied-selector', {'valueSource': {'secretKeyRef': V2['valueSource']['secretKeyRef'], '_coverage': {'secretKeyRef': {'status': 'denied'}}}}, 'UNKNOWN'),
    ('v2-denied-secret-name', {'valueSource': {'secretKeyRef': {**V2['valueSource']['secretKeyRef'], '_coverage': {'secret': {'status': 'denied'}}}}}, 'UNKNOWN'),
    ('v1-denied-key', {'valueFrom': {'secretKeyRef': {**V1['valueFrom']['secretKeyRef'], '_coverage': {'key': {'status': 'denied'}}}}}, 'UNKNOWN'),
]


@pytest.mark.parametrize('cid', RUN_IDS)
@pytest.mark.parametrize('label,entry,expected', ENV_CASES, ids=[row[0] for row in ENV_CASES])
def test_cloud_run_native_reference_contract(cid, label, entry, expected):
    kind = 'cloudrun_service' if '.service_' in cid else 'cloudrun_job'
    container = {'name': 'app', 'image': 'gcr.io/review-project/app', 'env': [{'name': 'DB_PASSWORD', **deepcopy(entry)}]}
    template = {'containers': [container]}
    fragment = {'template': template if kind == 'cloudrun_service' else {'template': template}}
    row, captured, api = finding(cid, kind, merge(BASE[kind], fragment))
    assert row['status'] == expected, row
    projected = captured['collections'][0]['items'][0]['template']
    if kind == 'cloudrun_job': projected = projected['template']
    env = projected['containers'][0]['env']
    assert 'value' not in env[0]
    if label == 'native-v2-secret': assert env[0]['valueSource'] == V2['valueSource']
    if label == 'legacy-v1-secret': assert env[0]['valueFrom'] == V1['valueFrom']
    assert gcp.sanitize({'env': env}) == {'env': env}


@pytest.mark.parametrize('cid', RUN_IDS)
@pytest.mark.parametrize('name,fragment,expected', [
    ('TOKEN_URL', {'value': RAW_VALUE}, 'PASS'),
    ('LOG_LEVEL', {'value': RAW_VALUE}, 'PASS'),
    ('TOKEN_URL', {'valueSource': {}}, 'UNKNOWN'),
    ('STRIPE_API_KEY', {'value': RAW_VALUE}, 'FAIL'),
])
def test_cloud_run_heuristic_does_not_hide_invalid_reference(cid, name, fragment, expected):
    kind = 'cloudrun_service' if '.service_' in cid else 'cloudrun_job'
    template = {'containers': [{'env': [{'name': name, **fragment}]}]}
    item = merge(BASE[kind], {'template': template if kind == 'cloudrun_service' else {'template': template}})
    row, _, _ = finding(cid, kind, item)
    assert row['status'] == expected, row


@pytest.mark.parametrize('source', ['github', 'repositoryEventConfig', 'developerConnectEventConfig'])
@pytest.mark.parametrize('control,approval,expected', [
    ('COMMENTS_DISABLED', False, 'FAIL'), (None, False, 'FAIL'),
    ('COMMENTS_ENABLED', False, 'PASS'),
    ('COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY', False, 'PASS'),
    ('COMMENTS_DISABLED', True, 'PASS'), ('FUTURE_ENUM', False, 'UNKNOWN'),
])
def test_native_pull_request_gate_by_source(source, control, approval, expected):
    pull = {'branch': '.*'}
    if control is not None: pull['commentControl'] = control
    config = {'pullRequest': pull}
    if source == 'developerConnectEventConfig': config['gitRepositoryLink'] = SCOPE + '/locations/us-central1/connections/c/gitRepositoryLinks/r'
    item = merge(BASE['cloudbuild_trigger'], {source: config, 'approvalConfig': {'approvalRequired': approval}})
    row, _, _ = finding(PR, 'cloudbuild_trigger', item)
    assert row['status'] == expected, row


@pytest.mark.parametrize('scenario', ['disabled', 'push', 'denied-comment', 'malformed-source', 'conflicting-sources'])
def test_developer_connect_applicability_and_guards(scenario):
    config = {'gitRepositoryLink': SCOPE + '/locations/us-central1/connections/c/gitRepositoryLinks/r',
              'pullRequest': {'branch': '.*', 'commentControl': 'COMMENTS_ENABLED'}}
    item = merge(BASE['cloudbuild_trigger'], {'developerConnectEventConfig': config})
    expected = 'UNKNOWN'
    if scenario == 'disabled': item['disabled'] = True; expected = 'NOT_APPLICABLE'
    elif scenario == 'push': config.pop('pullRequest'); config['push'] = {'branch': '.*'}; item['developerConnectEventConfig'] = config; expected = 'NOT_APPLICABLE'
    elif scenario == 'denied-comment': item['developerConnectEventConfig']['pullRequest']['_coverage'] = {'commentControl': {'status': 'denied'}}
    elif scenario == 'malformed-source': item['developerConnectEventConfig'] = []
    elif scenario == 'conflicting-sources': item['github'] = {'pullRequest': {'branch': '.*', 'commentControl': 'COMMENTS_DISABLED'}}
    row, _, _ = finding(PR, 'cloudbuild_trigger', item)
    assert row['status'] == expected, row


KEY_CASES = [
    ('case-universal', {'apiTargets': [{'service': 'CLOUDAPIS.GOOGLEAPIS.COM'}]}, 'FAIL'),
    ('case-specific', {'apiTargets': [{'service': 'STORAGE.GOOGLEAPIS.COM'}]}, 'PASS'),
    ('expanded-universal-ipv6', {'serverKeyRestrictions': {'allowedIps': ['0:0:0:0:0:0:0:0/0']}}, 'FAIL'),
    ('noncanonical-universal-ipv4', {'serverKeyRestrictions': {'allowedIps': ['0.0.0.1/0']}}, 'FAIL'),
    ('restricted-ipv6', {'serverKeyRestrictions': {'allowedIps': ['2001:db8::/64']}}, 'PASS'),
    ('restricted-ipv4', {'serverKeyRestrictions': {'allowedIps': ['192.0.2.1']}}, 'PASS'),
    ('or-api-still-restricts', {'apiTargets': [{'service': 'storage.googleapis.com'}], 'serverKeyRestrictions': {'allowedIps': ['::/0']}}, 'PASS'),
    ('or-caller-still-restricts', {'apiTargets': [{'service': 'CLOUDAPIS.GOOGLEAPIS.COM'}], 'serverKeyRestrictions': {'allowedIps': ['192.0.2.1']}}, 'PASS'),
    ('invalid-ip-string', {'serverKeyRestrictions': {'allowedIps': ['not-an-ip']}}, 'UNKNOWN'),
    ('invalid-ip-object', {'serverKeyRestrictions': {'allowedIps': [{'prefix': '::/0'}]}}, 'UNKNOWN'),
    ('denied-ip-list', {'serverKeyRestrictions': {'allowedIps': ['192.0.2.1'], '_coverage': {'allowedIps': {'status': 'denied'}}}}, 'UNKNOWN'),
    ('dns-path-invalid', {'apiTargets': [{'service': 'storage.googleapis.com/path'}]}, 'UNKNOWN'),
    ('dns-empty-invalid', {'apiTargets': [{'service': ''}]}, 'UNKNOWN'),
    ('android-native-objects', {'androidKeyRestrictions': {'allowedApplications': [{'packageName': 'com.example.app', 'sha1Fingerprint': '1234567890ABCDEF1234567890ABCDEF12345678'}]}}, 'PASS'),
]


@pytest.mark.parametrize('label,restrictions,expected', KEY_CASES, ids=[row[0] for row in KEY_CASES])
def test_native_meaningful_restrictions_preserve_structure(label, restrictions, expected):
    item = merge(BASE['api_key'], {'restrictions': restrictions})
    row, captured, _ = finding(KEY, 'api_key', item)
    assert row['status'] == expected, row
    assert captured['collections'][0]['items'][0]['restrictions'] == restrictions


@pytest.mark.parametrize('enrollment,expected', [
    ({'cloudProduct': 'Cloud Storage'}, 'PASS'),
    ({'cloudProduct': 'Cloud Storage', 'enrollmentLevel': 'ENROLLMENT_LEVEL_UNSPECIFIED'}, 'PASS'),
    ({'cloudProduct': 'Cloud Storage', 'enrollmentLevel': 'BLOCK_ALL'}, 'PASS'),
    ({'cloudProduct': 'Cloud Storage', 'enrollmentLevel': 'FUTURE_ENUM'}, 'UNKNOWN'),
    ({'cloudProduct': 'Cloud Storage', 'enrollmentLevel': None}, 'UNKNOWN'),
    ({'cloudProduct': 'Cloud Storage', '_coverage': {'enrollmentLevel': {'status': 'denied'}}}, 'UNKNOWN'),
    ({'enrollmentLevel': 'BLOCK_ALL'}, 'UNKNOWN'),
])
def test_native_access_approval_enum_defaults(enrollment, expected):
    row, _, _ = finding(APPROVAL, 'access_approval_settings', merge(BASE['access_approval_settings'], {'enrolledServices': [enrollment]}))
    assert row['status'] == expected, row


@pytest.mark.parametrize('fragment,expected', [
    ({'notificationEmails': ['security@example.com']}, 'FAIL'),
    ({'enrolledAncestor': True}, 'UNKNOWN'),
    ({'enrolledServices': [], 'enrolledAncestor': True}, 'UNKNOWN'),
    ({'enrolledServices': [], '_coverage': {'enrolledAncestor': {'status': 'denied'}}}, 'UNKNOWN'),
    ({'enrolledServices': [], '_coverage': {'enrolledServices': {'status': 'denied'}}}, 'UNKNOWN'),
])
def test_native_access_approval_notifications_ancestor_and_denial(fragment, expected):
    row, _, _ = finding(APPROVAL, 'access_approval_settings', merge(BASE['access_approval_settings'], fragment))
    assert row['status'] == expected, row
