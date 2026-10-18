"""A fully measured corrupt export does not depend on a restore record.

The source is the admitted external evidence fixture, not a native Azure read
or an independent attestation of the fixture's authority.
"""
import base64
from copy import deepcopy
import json
from pathlib import Path
import pytest
from peaso.checks import evaluate_check

CHECK = 'azure.other.infrastructure_configuration_backup'
KIND = 'configuration_backup_evidence'
FIXTURE = json.loads((Path(__file__).parent / 'fixtures/bulk_pending_behavior.json').read_text())[CHECK]


def case():
    index = deepcopy(FIXTURE['pass_index'])
    fact = index['collections'][KIND][0]['items'][0]
    return deepcopy(FIXTURE['pass']), index, fact, fact['payload']['exports']['items'][0]


def evaluate(row, index, fact):
    index[KIND][0]['data'] = deepcopy(fact)
    before = deepcopy((row, index))
    outcome = evaluate_check(CHECK, row, index)
    assert (row, index) == before
    return outcome


@pytest.mark.parametrize('mode,expected', [
    ('corrupt_missing_restore', 'FAIL'), ('failed_export_missing_restore', 'FAIL'),
    ('valid_missing_restore', 'UNKNOWN')])
def test_independent_export_failure_precedes_restore_requirement(mode, expected):
    row, index, fact, export = case()
    if mode != 'all_valid':
        export.pop('restore')
    if mode == 'corrupt_missing_restore':
        # Preserve the expected manifest digest; only retrieved bytes change.
        export['artifact']['content_base64'] = base64.b64encode(b'corrupted backup bytes').decode()
    if mode == 'failed_export_missing_restore':
        export['successful'] = False
    status, proof = evaluate(row, index, fact)
    assert status == expected, proof
    if expected == 'FAIL':
        assert proof['missing_stale_corrupt_or_unrecoverable_resources'] == [export['resource_id'].casefold()]
    if mode == 'valid_missing_restore':
        assert 'restore' in str(proof)


def test_corrupt_bytes_cannot_bypass_existing_evidence_guards():
    for guard in ('untrusted', 'foreign_parent', 'foreign_resource', 'incomplete_manifest',
                  'incomplete_artifact', 'malformed_bytes', 'malformed_digest', 'future_export'):
        row, index, fact, export = case()
        export.pop('restore')
        export['artifact']['content_base64'] = base64.b64encode(b'corrupted backup bytes').decode()
        if guard == 'untrusted': fact['_provenance']['policy_approved'] = False
        if guard == 'foreign_parent': fact['parent_id'] += '-foreign'
        if guard == 'foreign_resource': export['resource_id'] += '-foreign'
        if guard == 'incomplete_manifest': fact['payload']['manifest_complete'] = False
        if guard == 'incomplete_artifact': export['artifact']['read_complete'] = False
        if guard == 'malformed_bytes': export['artifact']['content_base64'] = 'not base64!'
        if guard == 'malformed_digest': export['artifact']['sha256'] = 'not-sha256'
        if guard == 'future_export': export['completed_at'] = '2099-01-01T00:00:00Z'
        status, proof = evaluate(row, index, fact)
        assert status == 'UNKNOWN', (guard, proof)
