"""Independent backup failures survive another resource's unresolved restore."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.checks import evaluate_check

CHECK = 'azure.other.infrastructure_configuration_backup'
KIND = 'configuration_backup_evidence'
BASE = json.loads((Path(__file__).parent / 'fixtures/bulk_pending_behavior.json').read_text())[CHECK]


def case(*, corrupt=False, unresolved=False, reverse=False):
    row, index = deepcopy(BASE['pass']), deepcopy(BASE['pass_index'])
    fact = index['collections'][KIND][0]['items'][0]
    payload = fact['payload']
    first = payload['exports']['items'][0]
    second = deepcopy(first)
    second['resource_id'] += '-second'
    second['artifact']['uri'] += '-second'
    payload['required_resources']['items'].append({'id': second['resource_id']})
    payload['exports']['items'].append(second)
    if corrupt:
        first['artifact']['content_base64'] = base64.b64encode(b'corrupted first artifact').decode()
    if unresolved:
        second.pop('restore')
    if reverse:
        payload['required_resources']['items'].reverse()
        payload['exports']['items'].reverse()
    return row, index, fact, first, second


def evaluate(row, index, fact):
    index[KIND][0]['data'] = deepcopy(fact)
    before = deepcopy((row, index))
    result = evaluate_check(CHECK, row, index)
    assert (row, index) == before
    return result


@pytest.mark.parametrize('reverse', [False, True], ids=['known_failure_first', 'unknown_first'])
def test_confirmed_corrupt_export_survives_other_missing_restore(reverse):
    row, index, fact, bad, unresolved = case(corrupt=True, unresolved=True, reverse=reverse)
    status, proof = evaluate(row, index, fact)
    assert status == 'FAIL', proof
    assert proof['missing_stale_corrupt_or_unrecoverable_resources'] == [bad['resource_id'].casefold()]
    assert proof['unresolved_resource_ids'] == [unresolved['resource_id'].casefold()]


def test_no_failure_with_unresolved_resource_stays_unknown():
    row, index, fact, first, second = case(unresolved=True)
    status, proof = evaluate(row, index, fact)
    assert status == 'UNKNOWN', proof
    assert proof['unresolved_resource_ids'] == [second['resource_id'].casefold()]


def test_all_required_configuration_resources_must_satisfy_every_requirement():
    row, index, fact, first, second = case()
    status, proof = evaluate(row, index, fact)
    assert status == 'PASS', proof
    assert proof['missing_stale_corrupt_or_unrecoverable_resources'] == []


def test_global_guards_cannot_be_downgraded_to_per_resource_unknown():
    for guard in ('untrusted', 'incomplete_manifest', 'foreign_required', 'foreign_export',
                  'duplicate_required', 'duplicate_export', 'partial_source'):
        row, index, fact, first, second = case(corrupt=True, unresolved=True)
        payload = fact['payload']
        if guard == 'untrusted': fact['_provenance']['policy_approved'] = False
        if guard == 'incomplete_manifest': payload['manifest_complete'] = False
        if guard == 'foreign_required': payload['required_resources']['items'][1]['id'] = '/subscriptions/foreign/resourceGroups/rg/providers/Microsoft.Web/sites/app'
        if guard == 'foreign_export': second['resource_id'] += '-foreign'
        if guard == 'duplicate_required': payload['required_resources']['items'].append(deepcopy(payload['required_resources']['items'][0]))
        if guard == 'duplicate_export': payload['exports']['items'].append(deepcopy(first))
        if guard == 'partial_source': index['collections'][KIND][0]['status'] = 'partial'
        status, proof = evaluate(row, index, fact)
        assert status == 'UNKNOWN', (guard, proof)
