"""Closed sign-in delivery evidence is evaluated per event."""
import pytest
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
CID='azure_c5_iam_03_01ac'
TENANT='/tenants/tenant-13'
AT='2026-10-12T12:00:00Z'

def verdict(mode):
    def graph(id,**fields):return {'id':id,'_provenance':{'tenant_id':'tenant-13','read_only':True},**fields}
    def obs(id,**fields):return graph(id,scope=TENANT,**fields)
    e1=graph('event-a',createdDateTime='2026-10-11T01:00:00Z',signInRiskLevel='high',status={'errorCode':0})
    e2=graph('event-b',createdDateTime='2026-10-11T01:00:00Z',signInRiskLevel='high',status={'errorCode':0})
    events=[e2] if mode in ('pending_only','delivered_and_pending','unapproved_pending') else [e1,e2]
    deliveries=[obs('pending-b',eventId='event-b',recipientId='responder' if mode!='unapproved_pending' else 'unapproved',deliveryStatus='Pending',observedAt='2026-10-11T01:05:00Z')]
    if mode=='delivered_and_pending':deliveries.append(obs('delivered-b',eventId='event-b',recipientId='responder',deliveryStatus='Delivered',observedAt='2026-10-11T01:05:00Z'))
    if mode=='all_delivered':deliveries=[obs('delivered-'+e['id'],eventId=e['id'],recipientId='responder',deliveryStatus='Delivered',observedAt='2026-10-11T01:05:00Z') for e in events]
    policy={'windowStart':'2026-10-11T00:00:00Z','windowEnd':'2026-10-12T00:00:00Z','notificationMaxDelaySeconds':3600,'suspiciousRiskLevels':['medium','high'],'authorizedRecipientIds':['responder']}
    monitor=obs('window',checkId=CID,windowStart=policy['windowStart'],windowEnd=policy['windowEnd'],detectionEnabled=True,ingestionConfirmed=True,observationComplete=True,deliveryRegistryComplete=True,observedThrough=AT)
    rows={'conditional_access_policy':[graph('ca-1',state='enabled')],'audit_sign_in':events,'authentication_monitoring_window':[monitor],'authentication_notification':deliveries}
    collections=[{'type':k,'scope':TENANT,'status':'collected','items':v} for k,v in rows.items()]
    if mode=='partial_history':collections[-1]['status']='partial'
    metadata={'compliance_policy':{'sw13':{'status':'collected','scope':TENANT,'document_id':'approved-policy','authorized_by':'security-owner','observed_at':'2026-10-01T00:00:00Z','expires_at':'2026-11-01T00:00:00Z','checks':{CID:policy}}}}
    findings=evaluate_snapshot(make_snapshot('azure',[TENANT],collections,created_at=AT,metadata=metadata),checks=[CID])['findings']
    assert len(findings)==1
    return findings[0]

@pytest.mark.parametrize('mode,expected',[('missing_a_pending_b','FAIL'),('pending_only','UNKNOWN'),('delivered_and_pending','PASS'),('unapproved_pending','FAIL'),('all_delivered','PASS'),('partial_history','UNKNOWN')])
def test_notification_event_local_evidence_keeps_conclusive_outcomes(mode,expected):
    outcome=verdict(mode)
    assert outcome['status']==expected,outcome
