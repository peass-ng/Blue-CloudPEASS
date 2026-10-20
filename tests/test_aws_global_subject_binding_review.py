"""AWS global provenance contracts, using SDK-shaped GAAD and engine consumers.

Missing legacy attribution is preserved for same-scope collections; it is never
manufactured to authorize global reuse. No AWS requests leave Stubber clients.
"""
from dataclasses import replace
import copy
import pytest
from peaso import engine
from peaso.checks import Check
from peaso.snapshot import make_snapshot
from test_aws_identity_semantic_review import sdk, policy_read, index, ACCOUNT, SCOPE, NOW

OTHER = '999999999999'
REGIONS = [SCOPE, ACCOUNT+'/eu-west-1']
CID = 'aws.claude_a.iam.prowler_customer_attached_policy_no_admin'
DOCUMENT = {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]}


def evaluate(envelope, cid=CID, scopes=REGIONS):
    snapshot = make_snapshot('aws', scopes, [envelope], created_at=NOW.isoformat())
    return [r for r in engine.evaluate_snapshot(snapshot, checks=[cid])['findings'] if r['check_id'] == cid]


def envelope(sdk):
    return index('iam_policy', policy_read(sdk, DOCUMENT))['collections']['iam_policy'][0]


@pytest.mark.parametrize('foreign', ['collection', 'item', 'both', 'mixed_items'])
def test_sdk_global_subject_contradiction_is_unknown(sdk, foreign):
    env = envelope(sdk)
    if foreign in ('collection', 'both'): env['account_id'] = OTHER
    if foreign in ('item', 'both'): env['items'][0]['AccountId'] = OTHER
    if foreign == 'mixed_items': env['items'].append({**copy.deepcopy(env['items'][0]), 'Arn': f'arn:aws:iam::{ACCOUNT}:policy/other', 'AccountId': OTHER})
    before = copy.deepcopy(env)
    rows = evaluate(env)
    assert rows and all(r['status'] == 'UNKNOWN' for r in rows)
    assert env == before


def test_sdk_valid_global_policy_reports_once_across_regions(sdk):
    env = envelope(sdk)
    rows = evaluate(env)
    assert len(rows) == 1 and rows[0]['status'] == 'PASS'
    assert rows[0]['native_resource_id'] == env['items'][0]['Arn']


@pytest.mark.parametrize('missing', ['collection', 'item', 'both'])
def test_sdk_missing_legacy_provenance_is_preserved_same_scope(sdk, missing):
    env = envelope(sdk)
    if missing in ('collection', 'both'): env.pop('account_id')
    if missing in ('item', 'both'): env['items'][0].pop('AccountId')
    before = copy.deepcopy(env)
    rows = evaluate(env)
    assert len(rows) == 1 and rows[0]['status'] == 'PASS'
    assert env == before


def presence(subject, index):
    rows = index.get('service_config', [])
    return ('PASS' if rows else 'UNKNOWN'), {'observed': len(rows)}


@pytest.fixture
def scope_check(monkeypatch):
    check = Check('aws.review.global_binding_dependency', 'aws', 'hardening', 'service_config',
                  'Bounded global dependency proof', 'medium', 'CM-6', 'Review account attribution.',
                  presence, 'scope', ('service_config',))
    monkeypatch.setattr(engine, '_registry', lambda: [check])
    return check


@pytest.mark.parametrize('foreign', ['collection', 'item', 'both'])
@pytest.mark.parametrize('scope', [ACCOUNT+'/global', SCOPE])
def test_dependency_rejects_contradiction_before_scope_equality(scope_check, foreign, scope):
    env = {'type': 'service_config', 'scope': scope, 'status': 'collected', 'global': True,
           'account_id': OTHER if foreign in ('collection', 'both') else ACCOUNT,
           'items': [{'id': 'config', 'AccountId': OTHER if foreign in ('item', 'both') else ACCOUNT}]}
    rows = evaluate(env, scope_check.id, [scope])
    assert rows and all(r['status'] == 'UNKNOWN' for r in rows)


@pytest.mark.parametrize('markers,expected', [
    ('valid', 'PASS'), ('missing_collection', 'UNKNOWN'), ('missing_item', 'UNKNOWN'),
    ('missing_both', 'UNKNOWN'), ('unmarked', 'UNKNOWN')])
def test_global_cross_region_requires_positive_attribution(scope_check, markers, expected):
    env = {'type': 'service_config', 'scope': ACCOUNT+'/global', 'status': 'collected', 'global': True,
           'account_id': ACCOUNT, 'items': [{'id': 'config', 'AccountId': ACCOUNT}]}
    if markers in ('missing_collection', 'missing_both'): env.pop('account_id')
    if markers in ('missing_item', 'missing_both'): env['items'][0].pop('AccountId')
    if markers == 'unmarked': env.pop('global')
    rows = evaluate(env, scope_check.id, [SCOPE])
    assert len(rows) == 1 and rows[0]['status'] == expected


@pytest.mark.parametrize('global_marker', [None, False])
def test_unmarked_region_local_collection_behavior_preserved(scope_check, global_marker):
    env = {'type': 'service_config', 'scope': SCOPE, 'status': 'collected',
           'account_id': OTHER, 'items': [{'id': 'config', 'AccountId': OTHER}]}
    if global_marker is not None: env['global'] = global_marker
    rows = evaluate(env, scope_check.id, [SCOPE])
    assert len(rows) == 1 and rows[0]['status'] == 'PASS'


def test_azure_same_scope_untouched(scope_check, monkeypatch):
    check = replace(scope_check, id='azure.review.global_binding_unchanged', provider='azure')
    monkeypatch.setattr(engine, '_registry', lambda: [check])
    scope = '/subscriptions/sub-one'
    env = {'type':'service_config','scope':scope,'status':'collected','global':True,
           'account_id':OTHER,'items':[{'id':'config','AccountId':OTHER}]}
    rows = engine.evaluate_snapshot(make_snapshot('azure',[scope],[env]),checks=[check.id])['findings']
    assert len(rows) == 1 and rows[0]['status'] == 'PASS'
