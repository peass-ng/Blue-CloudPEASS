"""MySQL general log, TLS and public replica controls in a disposable live lab."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events

EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_rds_mysql_replica_lab_events.json').read_text())
SPECS = [
    ('ModifyDBParameterGroup', 'rds_sql_logging_enabled'),
    ('ModifyDBParameterGroup', 'rds_tls_requirement_disabled'),
    ('CreateDBInstanceReadReplica', 'rds_public_read_replica_requested'),
    ('ModifyDBInstance', 'rds_public_replica_password_reset_requested'),
    ('PromoteReadReplica', 'rds_public_replica_promoted_after_reset_requested'),
]
RULES = tuple(Rule(id=f'test-{flag}', title=flag, description=flag, level='medium',
                   technique_id=f'test-{flag}', product='aws',
                   selection={'event.name': name, 'event.outcome': 'success', f'request.{flag}': True})
              for name, flag in SPECS)


def hits(events):
    return {h.rule_id for h in detect_aws_events(events, RULES)}


def param_event(name, value):
    return copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'ModifyDBParameterGroup'
                              and any(p.get('parameterName') == name and p.get('parameterValue') == value
                                      for p in e['requestParameters']['parameters'])))


def replica_event():
    return copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'CreateDBInstanceReadReplica'))


def test_live_mysql_changes_hit_direct_rules():
    assert hits(EVENTS) == {r.id for r in RULES}


def test_secure_and_nonfile_logging_values_are_negative():
    assert not hits([param_event('require_secure_transport', 'ON')])
    log = param_event('general_log', '1')
    next(p for p in log['requestParameters']['parameters'] if p['parameterName'] == 'log_output')['parameterValue'] = 'TABLE'
    assert not hits([log])
    log = param_event('general_log', '1')
    next(p for p in log['requestParameters']['parameters'] if p['parameterName'] == 'general_log')['parameterValue'] = '0'
    assert not hits([log])


def test_public_replica_requires_consistent_accepted_source_and_target():
    public = replica_event()
    assert 'test-rds_public_read_replica_requested' in hits([public])
    for change in (
        lambda e: e['requestParameters'].update(publiclyAccessible=False),
        lambda e: e['requestParameters'].update(sourceDBInstanceIdentifier=e['requestParameters']['dBInstanceIdentifier']),
        lambda e: e['responseElements'].update(readReplicaSourceDBInstanceIdentifier='other'),
        lambda e: e.update(errorCode='AccessDenied'),
        lambda e: e.update(eventCategory='Data'),
        lambda e: e.update(managementEvent=False),
        lambda e: e.update(readOnly=True),
    ):
        changed = copy.deepcopy(public)
        change(changed)
        assert 'test-rds_public_read_replica_requested' not in hits([changed])


def test_reset_and_promotion_chain_requires_same_replica_actor_account_and_order():
    created = replica_event()
    reset = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'ModifyDBInstance'))
    promoted = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'PromoteReadReplica'))
    reset_id = 'test-rds_public_replica_password_reset_requested'
    promote_id = 'test-rds_public_replica_promoted_after_reset_requested'
    assert {reset_id, promote_id} <= hits([created, reset, promoted])
    assert reset_id not in hits([reset])
    assert promote_id not in hits([created, promoted])
    for change in (
        lambda e: e['requestParameters'].update(dBInstanceIdentifier='another-replica'),
        lambda e: e['userIdentity'].update(arn='arn:aws:iam::999999999999:user/other'),
        lambda e: e.update(recipientAccountId='999999999999'),
        lambda e: e['requestParameters'].update(applyImmediately=False),
        lambda e: e['requestParameters'].update(masterUserPassword='literal-value'),
        lambda e: e.update(errorCode='AccessDenied'),
        lambda e: e.update(eventTime='2026-10-20T02:00:00Z'),
    ):
        changed = copy.deepcopy(reset)
        change(changed)
        assert reset_id not in hits([created, changed])
        assert promote_id not in hits([created, changed, promoted])
    private = copy.deepcopy(created)
    private['requestParameters']['publiclyAccessible'] = False
    assert reset_id not in hits([private, reset])
    for change in (
        lambda e: e['requestParameters'].update(dBInstanceIdentifier='another-replica'),
        lambda e: e.update(errorCode='AccessDenied'),
        lambda e: e.update(eventTime='2026-10-20T02:00:00Z'),
    ):
        changed = copy.deepcopy(promoted)
        change(changed)
        assert promote_id not in hits([created, reset, changed])
