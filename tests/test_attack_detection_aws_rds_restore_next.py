"""RDS restore and instance controls observed in a disposable live lab."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events

EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_rds_restore_chain_lab_events.json').read_text())
SPECS = [
    ('RestoreDBInstanceFromDBSnapshot', 'rds_public_snapshot_clone_requested'),
    ('ModifyDBInstance', 'rds_deletion_protection_disabled'),
    ('StopDBInstance', 'rds_instance_stop_requested'),
    ('ModifyDBInstance', 'rds_public_clone_password_reset_requested'),
]
RULES = tuple(Rule(id=f'test-{flag}', title=flag, description=flag, level='medium',
                   technique_id=f'test-{flag}', product='aws',
                   selection={'event.name': name, 'event.outcome': 'success', f'request.{flag}': True})
              for name, flag in SPECS)


def hits(events):
    return detect_aws_events(events, RULES)


def pick(name, key=None):
    return copy.deepcopy(next(e for e in EVENTS if e['eventName'] == name and
                              (key is None or key in e['requestParameters'])))


def test_live_chain_hits_four_distinct_rules():
    result = hits(EVENTS)
    assert {h.rule_id for h in result} == {r.id for r in RULES}
    assert len(result) == 4


def test_public_clone_reset_requires_same_actor_account_target_and_sequence():
    restore = pick('RestoreDBInstanceFromDBSnapshot')
    reset = pick('ModifyDBInstance', 'masterUserPassword')
    assert {h.rule_id for h in hits([restore, reset])} == {
        'test-rds_public_snapshot_clone_requested',
        'test-rds_public_clone_password_reset_requested',
    }
    for change in (
        lambda e: e['requestParameters'].update(dBInstanceIdentifier='other'),
        lambda e: e.update(recipientAccountId='999999999999'),
        lambda e: e['userIdentity'].update(arn='arn:aws:iam::999999999999:user/other'),
        lambda e: e['requestParameters'].pop('masterUserPassword'),
        lambda e: e['requestParameters'].update(masterUserPassword='literal-value'),
        lambda e: e['requestParameters'].update(applyImmediately=False),
        lambda e: e.update(eventTime='2026-10-19T22:25:24Z'),
    ):
        changed = copy.deepcopy(reset)
        change(changed)
        assert 'test-rds_public_clone_password_reset_requested' not in {h.rule_id for h in hits([restore, changed])}
    private = copy.deepcopy(restore)
    private['requestParameters']['publiclyAccessible'] = False
    assert not hits([private, reset])


def test_failed_and_nonmanagement_calls_do_not_match():
    for event in (pick('RestoreDBInstanceFromDBSnapshot'),
                  pick('ModifyDBInstance', 'deletionProtection'),
                  pick('StopDBInstance'), pick('ModifyDBInstance', 'masterUserPassword')):
        for key, value in (('errorCode', 'AccessDenied'), ('eventCategory', 'Data'),
                           ('managementEvent', False), ('readOnly', True)):
            changed = copy.deepcopy(event)
            changed[key] = value
            assert not hits([changed])


def test_nonrisky_modification_and_stop_without_identifier_do_not_match():
    protection = pick('ModifyDBInstance', 'deletionProtection')
    protection['requestParameters']['deletionProtection'] = True
    assert not hits([protection])
    stopped = pick('StopDBInstance')
    stopped['requestParameters'].pop('dBInstanceIdentifier')
    assert not hits([stopped])
