"""Closed external authentication-monitor coverage through registered snapshots.

These are explicit inert external evidence fixtures, not native ingestion or
notification-delivery observations acquired from a cloud service.
"""
from datetime import datetime, timedelta
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot

CID='azure_c5_iam_03_01ac'
TENANT='22222222-2222-2222-2222-222222222222'
SCOPE='/tenants/'+TENANT
NOW='2026-10-12T01:00:00Z'
END='2026-10-12T00:00:00Z'
START='2026-10-11T00:00:00Z'


def snapshot(*, through=NOW, created=NOW, empty=False, delivery='Delivered', recipient='responder',
             delivered='2026-10-11T23:05:00Z', notification=True, monitor_change=None, policy_change=None, foreign=False, partial=False):
    policy={'windowStart':START,'windowEnd':END,'notificationMaxDelaySeconds':3600,
            'suspiciousRiskLevels':['medium','high'],'authorizedRecipientIds':['responder']}
    policy.update(policy_change or {})
    prov={'read_only':True,'tenant_id':TENANT,'source_operation':'external:local-fixture'}
    ca={'id':'11111111-1111-1111-1111-111111111111','state':'enabled','_provenance':dict(prov)}
    event={'id':'event-1','createdDateTime':'2026-10-11T23:00:00Z','signInRiskLevel':'high',
           'status':{'errorCode':0},'_provenance':dict(prov)}
    monitor={'id':'monitor-1','scope':SCOPE,'checkId':CID,'windowStart':policy['windowStart'],'windowEnd':policy['windowEnd'],
        'detectionEnabled':True,'ingestionConfirmed':True,'observationComplete':True,'deliveryRegistryComplete':True,
        'observedThrough':through,'_provenance':dict(prov)}
    monitor.update(monitor_change or {})
    if foreign:monitor['_provenance']['tenant_id']='33333333-3333-3333-3333-333333333333'
    record={'id':'delivery-1','scope':SCOPE,'eventId':'event-1','recipientId':recipient,
            'deliveryStatus':delivery,'observedAt':delivered,'_provenance':dict(prov)}
    kinds={'conditional_access_policy':[ca],'audit_sign_in':[] if empty else [event],
           'authentication_monitoring_window':[monitor],'authentication_notification':[] if empty or not notification else [record]}
    collections=[{'type':kind,'scope':SCOPE,'service':'external:local-fixture',
        'status':'collected' if rows else 'empty','items':rows} for kind,rows in kinds.items()]
    if partial:next(env for env in collections if env['type']=='audit_sign_in')['status']='partial'
    metadata={'compliance_policy':{'sw13':{'status':'collected','scope':SCOPE,'document_id':'approved-notification-scope',
        'authorized_by':'security-owner','observed_at':START,'expires_at':'2026-11-01T00:00:00Z',
        'checks':{CID.replace('.','|'):policy}}}}
    return make_snapshot('azure',[SCOPE],collections,metadata=metadata,created_at=created)


def status(snap):
    findings=[f for f in evaluate_snapshot(snap,checks=[CID],include_not_applicable=True)['findings'] if f['check_id']==CID]
    assert len(findings)==1
    status.last_findings=findings
    return findings[0]['status']


def test_future_delivery_coverage_cannot_certify_delivered_events():
    assert status(snapshot(through='2026-10-12T01:00:01Z'))=='UNKNOWN',status.last_findings


def test_future_delivery_coverage_cannot_certify_empty_event_window():
    assert status(snapshot(through='2026-10-12T01:00:01Z',empty=True))=='UNKNOWN',status.last_findings


def test_exact_settled_boundary_and_equivalent_offset_are_valid():
    for empty in (False,True):
        for through in (NOW,'2026-10-12T03:00:00+02:00'):
            assert status(snapshot(through=through,empty=empty))=='PASS',status.last_findings


def test_insufficient_observation_interval_remains_unknown():
    for empty in (False,True):
        assert status(snapshot(through='2026-10-12T00:59:59Z',empty=empty))=='UNKNOWN'


def test_complete_past_coverage_below_context_time_does_not_need_exact_equality():
    assert status(snapshot(created='2026-10-12T02:00:00Z',through='2026-10-12T01:30:00Z'))=='PASS',status.last_findings


def test_notification_delivery_deadline_is_inclusive_and_late_delivery_fails():
    assert status(snapshot(delivered=END))=='PASS',status.last_findings
    assert status(snapshot(delivered='2026-10-12T00:00:01Z'))=='FAIL',status.last_findings


def test_known_missing_failed_or_unauthorized_delivery_still_fails():
    for changes in ({'notification':False},{'delivery':'Failed'},{'recipient':'unauthorized'}):
        assert status(snapshot(**changes))=='FAIL',status.last_findings


def test_future_notification_or_unsettled_policy_window_remains_unknown():
    assert status(snapshot(delivered='2026-10-12T01:00:01Z'))=='UNKNOWN'
    assert status(snapshot(created='2026-10-12T00:59:59Z'))=='UNKNOWN'


def test_incomplete_or_foreign_external_source_does_not_become_delivery_failure():
    for changes in ({'monitor_change':{'ingestionConfirmed':False}},{'monitor_change':{'deliveryRegistryComplete':False}},
            {'monitor_change':{'windowStart':'2026-10-10T00:00:00Z'}},{'foreign':True},{'partial':True}):
        assert status(snapshot(**changes))=='UNKNOWN',status.last_findings
