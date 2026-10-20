"""RDS snapshot, log and instance changes from a disposable PostgreSQL instance."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events

EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_rds_snapshot_controls_lab_events.json').read_text())
SPECS = [
    ('DownloadDBLogFilePortion', 'rds_log_portion_read'),
    ('ModifyDBSnapshotAttribute', 'rds_snapshot_public_restore_added'),
    ('ModifyDBInstance', 'rds_instance_public_requested'),
    ('DeleteDBSnapshot', 'rds_snapshot_deleted'),
    ('DeleteDBInstance', 'rds_instance_deleted_without_backup'),
]
RULES = tuple(Rule(id=f'test-{name}', title=name, description=name, level='low',
                   technique_id=f'test-{flag}', product='aws',
                   selection={'event.name': name, 'event.outcome': 'success', f'request.{flag}': True})
              for name, flag in SPECS)


def hits(events):
    return detect_aws_events(events, RULES)


def event(name, **request):
    result = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == name and
                                (name not in ('ModifyDBSnapshotAttribute', 'ModifyDBInstance') or
                                 e['requestParameters'].get('valuesToAdd') == ['all'] or
                                 e['requestParameters'].get('publiclyAccessible') is True)))
    result['requestParameters'].update(request)
    return result


def test_live_events_hit_five_rules_and_reverse_changes_do_not():
    assert {h.rule_id for h in hits(EVENTS)} == {r.id for r in RULES}
    assert len(hits(EVENTS)) == 5
    assert not hits([event('ModifyDBSnapshotAttribute', valuesToAdd=[], valuesToRemove=['all'])])
    assert not hits([event('ModifyDBInstance', publiclyAccessible=False)])


def test_failed_or_wrong_category_events_do_not_match():
    for name, _ in SPECS:
        e = event(name)
        assert len(hits([e])) == 1
        for key, value in [('errorCode', 'AccessDenied'), ('eventCategory', 'Data'),
                           ('managementEvent', False),
                           ('readOnly', name != 'DownloadDBLogFilePortion')]:
            assert not hits([{**e, key: value}])


def test_public_snapshot_and_deletion_require_exact_risky_flags():
    share = event('ModifyDBSnapshotAttribute', valuesToAdd=['123456789012'])
    assert not hits([share])
    share = event('ModifyDBSnapshotAttribute', attributeName='other')
    assert not hits([share])
    deletion = event('DeleteDBInstance', skipFinalSnapshot=False)
    assert not hits([deletion])
    deletion = event('DeleteDBInstance', deleteAutomatedBackups=False)
    assert not hits([deletion])
    log = event('DownloadDBLogFilePortion', logFileName='')
    assert not hits([log])
