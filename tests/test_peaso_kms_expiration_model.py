"""Focused regression for imported KMS material with no expiration."""
from copy import deepcopy
from peaso.checks import CHECKS

CHECK = next(check for check in CHECKS if check.id == 'aws_kms_key_expiry')
SCOPE = '123456789012/us-east-1'

def evaluate(row):
    index = {'context': {'provider': 'aws', 'scope': SCOPE,
             'created_at': '2026-10-12T00:00:00+00:00'},
             'collections': {'kms_key': [{'type': 'kms_key', 'scope': SCOPE,
                             'status': 'collected', 'items': [row]}]},
             'kms_key': [{'type': 'kms_key', 'scope': SCOPE, 'data': row}]}
    return CHECK.evaluate(row, index)[0]

def test_no_expiration_preserves_retirement_decision():
    row = {'KeyId': 'key-1', 'Metadata': {'KeyMetadata': {'KeyId': 'key-1',
           'Origin': 'EXTERNAL', 'KeyState': 'Enabled',
           'ExpirationModel': 'KEY_MATERIAL_DOES_NOT_EXPIRE'}}, 'Tags': []}
    assert evaluate(row) == 'PASS'
    retired = deepcopy(row)
    retired['Tags'] = [{'TagKey': 'Retired', 'TagValue': 'true'}]
    assert evaluate(retired) == 'FAIL'
    retired['Metadata']['KeyMetadata']['KeyState'] = 'Disabled'
    assert evaluate(retired) == 'PASS'
    contradictory = deepcopy(row)
    contradictory['Metadata']['KeyMetadata']['ValidTo'] = '2027-01-01T00:00:00+00:00'
    assert evaluate(contradictory) == 'UNKNOWN'
    unknown_model = deepcopy(row)
    unknown_model['Metadata']['KeyMetadata']['ExpirationModel'] = 'unexpected'
    assert evaluate(unknown_model) == 'UNKNOWN'
    absent_model = deepcopy(row)
    del absent_model['Metadata']['KeyMetadata']['ExpirationModel']
    assert evaluate(absent_model) == 'UNKNOWN'

def test_expiring_and_legacy_imported_material():
    row = {'KeyId': 'key-1', 'Metadata': {'KeyMetadata': {'KeyId': 'key-1',
           'Origin': 'EXTERNAL', 'KeyState': 'Enabled',
           'ExpirationModel': 'KEY_MATERIAL_EXPIRES',
           'ValidTo': '2027-01-01T00:00:00+00:00'}}, 'Tags': []}
    assert evaluate(row) == 'PASS'
    expired = deepcopy(row)
    expired['Metadata']['KeyMetadata']['ValidTo'] = '2026-01-01T00:00:00+00:00'
    assert evaluate(expired) == 'FAIL'
    legacy = deepcopy(row)
    del legacy['Metadata']['KeyMetadata']['ExpirationModel']
    assert evaluate(legacy) == 'PASS'


def test_unread_expiration_model_is_not_default_or_nonexpiring():
    for present in (True,False):
        for status in ('denied','partial','malformed','unknown'):
            metadata={'KeyId':'key-1','Origin':'EXTERNAL','KeyState':'Enabled',
                      '_coverage':{'ExpirationModel':{'status':status}},
                      'ValidTo':'2027-01-01T00:00:00+00:00'}
            if present:metadata['ExpirationModel']='KEY_MATERIAL_DOES_NOT_EXPIRE'
            row={'KeyId':'key-1','Metadata':{'KeyMetadata':metadata},'Tags':[]}
            assert evaluate(row)=='UNKNOWN'


def test_pending_replica_deletion_uses_native_retirement_evidence():
    row = {'KeyId': 'key-1', 'Metadata': {'KeyMetadata': {'KeyId': 'key-1',
        'Origin': 'AWS_KMS', 'KeyState': 'PendingReplicaDeletion', 'Enabled': False}}, 'Tags': []}
    assert evaluate(row) == 'PASS'
    retired = deepcopy(row)
    retired['Tags'] = [{'TagKey': 'Retired', 'TagValue': 'true'}]
    assert evaluate(retired) == 'FAIL'
    unread = deepcopy(row)
    unread.pop('Tags')
    unread['_coverage'] = {'Tags': {'status': 'denied'}}
    assert evaluate(unread) == 'UNKNOWN'
    contradictory = deepcopy(row)
    contradictory['Metadata']['KeyMetadata']['Enabled'] = True
    assert evaluate(contradictory) == 'UNKNOWN'
