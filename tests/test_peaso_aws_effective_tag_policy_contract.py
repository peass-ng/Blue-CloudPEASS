"""Primary effective-policy schema, privacy projection and independent control."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib
import json
import sys
import pytest

from peaso.collectors import aws, aws_effective_tag_policy_native as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.compliance_draft_isolation import staged_registry

ACCOUNT = '123456789012'
SCOPE = ACCOUNT + '/global'
CHECK = 'aws.organizations.effective_tag_policy_values'
MARKER = 'MUST-NOT-CACHE-OBSERVED-VALUE'


def response(values=None):
    return {'EffectivePolicy': {'TargetId': ACCOUNT, 'PolicyType': 'TAG_POLICY',
        'LastUpdatedTimestamp': datetime(2026, 10, 16, tzinfo=timezone.utc),
        'PolicyContent': json.dumps({'tags': {'environment': {'tag_key': 'Environment',
            'tag_value': ['Production'] if values is None else values}}})}}


def row_from_response(raw):
    projection = native.project_response(raw)
    return {**projection['EffectivePolicy'], '_metadata_projection': native.PROJECTION,
        '_resource_id': ACCOUNT, '_provenance': {'source_operation': 'DescribeEffectivePolicy',
            'read_only': True, 'target_id': ACCOUNT, 'policy_type': 'TAG_POLICY'}}


@pytest.fixture
def runtime_check():
    name = 'peaso.checks.aws_effective_tag_policy'
    from peaso.checks.fixtures import CASES
    present, previous = CHECK in CASES, CASES.get(CHECK)
    try:
        with staged_registry(['aws_effective_tag_policy']):
            if name in sys.modules: importlib.reload(sys.modules[name])
            else: importlib.import_module(name)
            yield
    finally:
        if present: CASES[CHECK] = previous
        else: CASES.pop(CHECK, None)


def verdict(row, expected=None):
    metadata = {'parameters': {'approved_ec2_tag_values': expected or {'Environment': ['Production']}}}
    snapshot = make_snapshot('aws', [SCOPE], [{'type': native.KIND, 'scope': SCOPE,
        'service': 'organizations', 'status': 'collected', 'items': [row]}], metadata=metadata)
    return next(f for f in evaluate_snapshot(snapshot, checks=[CHECK])['findings'] if f['check_id'] == CHECK)


def test_projection_excludes_policy_content_and_cloud_values():
    raw = response([MARKER]); original = deepcopy(raw)
    projected = native.project_response(raw)
    assert raw == original
    assert MARKER not in json.dumps(projected) and 'PolicyContent' not in json.dumps(projected)
    assignment = projected['EffectivePolicy']['TagAssignments'][0]
    assert assignment == {'TagKey': 'Environment', 'ConstraintKind': 'finite',
        'ValueDigests': [native.value_digest(ACCOUNT, 'Environment', MARKER)]}


def test_digest_domain_binds_account_key_and_exact_value():
    hashes = {native.value_digest(account, key, value) for account, key, value in [
        (ACCOUNT, 'Environment', 'Production'), ('999999999999', 'Environment', 'Production'),
        (ACCOUNT, 'environment', 'Production'), (ACCOUNT, 'Environment', 'production')]}
    assert len(hashes) == 4


@pytest.mark.parametrize('mode,expected', [('finite', 'PASS'), ('wrong', 'FAIL'), ('empty_finite', 'FAIL'),
    ('unrestricted', 'FAIL'), ('wildcard', 'UNKNOWN'), ('null', 'UNKNOWN'), ('operator', 'UNKNOWN'),
    ('missing_key', 'UNKNOWN'), ('unrelated_wildcard', 'PASS')])
def test_native_projected_constraint_semantics_in_real_engine(runtime_check, mode, expected):
    raw = response()
    doc = json.loads(raw['EffectivePolicy']['PolicyContent']); definition = doc['tags']['environment']
    if mode == 'wrong': definition['tag_value'] = ['Development']
    elif mode == 'empty_finite': definition['tag_value'] = []
    elif mode == 'unrestricted': definition.pop('tag_value')
    elif mode == 'wildcard': definition['tag_value'] = ['Prod*']
    elif mode == 'null': definition['tag_value'] = None
    elif mode == 'operator': definition['tag_value'] = {'@@assign': ['Production']}
    elif mode == 'missing_key': definition.pop('tag_key')
    elif mode == 'unrelated_wildcard': doc['tags']['project'] = {'tag_key': 'Project', 'tag_value': ['*']}
    raw['EffectivePolicy']['PolicyContent'] = json.dumps(doc)
    finding = verdict(row_from_response(raw))
    assert finding['status'] == expected
    assert MARKER not in json.dumps(finding)


@pytest.mark.parametrize('mode', ['missing_body', 'wrong_target', 'wrong_type', 'missing_timestamp', 'invalid_json', 'duplicate_key'])
def test_malformed_native_envelope_never_becomes_absence(mode):
    raw = response()
    if mode == 'missing_body': raw.pop('EffectivePolicy')
    elif mode == 'wrong_target': raw['EffectivePolicy']['TargetId'] = 'r-abcd'
    elif mode == 'wrong_type': raw['EffectivePolicy']['PolicyType'] = 'BACKUP_POLICY'
    elif mode == 'missing_timestamp': raw['EffectivePolicy'].pop('LastUpdatedTimestamp')
    elif mode == 'invalid_json': raw['EffectivePolicy']['PolicyContent'] = '{'
    elif mode == 'duplicate_key': raw['EffectivePolicy']['PolicyContent'] = '{"tags":{},"tags":{}}'
    with pytest.raises(aws.ReadFailure): native.project_response(raw)


def test_typed_absence_is_distinct_from_unreadable_projection(runtime_check):
    row = {'TargetId': ACCOUNT, 'PolicyType': 'TAG_POLICY', '_metadata_projection': native.PROJECTION,
        'PolicyPresent': False, 'AssignmentsComplete': True, 'TagAssignments': [],
        '_provenance': {'source_operation': 'DescribeEffectivePolicy', 'read_only': True,
            'target_id': ACCOUNT, 'policy_type': 'TAG_POLICY', 'native_error_code': native.NOT_FOUND}}
    assert verdict(row)['status'] == 'FAIL'
    row['_provenance']['native_error_code'] = 'AccessDeniedException'
    assert verdict(row)['status'] == 'UNKNOWN'


@pytest.mark.parametrize('mode', ['foreign_envelope', 'foreign_wrapper', 'foreign_resource'])
def test_projection_never_overrides_collection_or_wrapper_authority(runtime_check, mode):
    from peaso.checks import evaluate_check
    row = row_from_response(response())
    envelope_scope = '999999999999/global' if mode == 'foreign_envelope' else SCOPE
    if mode == 'foreign_resource': row['AccountId'] = '999999999999'
    index = {'context': {'provider': 'aws', 'scope': SCOPE, 'metadata': {
        'parameters': {'approved_ec2_tag_values': {'Environment': ['Production']}}}},
        'collections': {native.KIND: [{'type': native.KIND, 'scope': envelope_scope,
            'global': True, 'account_id': ACCOUNT, 'status': 'collected', 'items': [row]}]},
        native.KIND: [{'type': native.KIND, 'scope': envelope_scope,
            'provider': 'azure' if mode == 'foreign_wrapper' else 'aws', 'data': row}]}
    assert evaluate_check(CHECK, {'scope': SCOPE}, index)[0] == 'UNKNOWN'
