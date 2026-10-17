"""Passive supplied inventory through sealed snapshot and exact registered engine."""
import copy
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot
from tests.nsg_service_observation_fixture import CID,S,NOW,fixture,digest

def status(collections,policy,partial=False):
    envelopes=[{'type':k,'scope':scope,'service':'external:approved-fixture','status':'collected' if rows else 'empty','items':rows} for k,batches in collections.items() for scope,rows in batches]
    if partial:next(e for e in envelopes if e['type']=='nsg_service_measurement')['status']='partial'
    snap=make_snapshot('azure',[S],envelopes,created_at=NOW,metadata={'compliance_policy':{'sw31':policy}})
    rows=[r for r in evaluate_snapshot(snap,checks=[CID],include_not_applicable=True)['findings'] if r['check_id']==CID]
    assert len(rows)==1
    status.last=rows
    return rows[0]['status']
def obs(c):return c['nsg_service_measurement'][0][1][0]['properties']['observation']
def approve(c,p):p['serviceObservationAuthority']['approvedObservationSha256s']=[digest(obs(c))]

def test_bare_matching_labels_are_not_runtime_measurement():
    c,p=fixture(bare=True)
    assert status(c,p)=='UNKNOWN',status.last

def test_bound_expected_and_unexpected_service():
    for service,expected in [('https','PASS'),('ssh','FAIL')]:
        c,p=fixture(actual=service)
        assert status(c,p)==expected,status.last

def test_freshness_inclusive_stale_and_future():
    for observed,expected in [('2026-10-11T23:00:00Z','PASS'),('2026-10-11T22:59:59Z','UNKNOWN'),('2026-10-12T00:00:01Z','UNKNOWN')]:
        c,p=fixture();obs(c)['observedAt']=observed;approve(c,p)
        assert status(c,p)==expected,status.last

def test_missing_or_unapproved_external_authority():
    for key in ['serviceObservationAuthority','approvedSourceIds','approvedMethods','approvedObservationSha256s','approvedSnapshotSha256s']:
        c,p=fixture()
        if key=='serviceObservationAuthority':p.clear()
        else:p['serviceObservationAuthority'][key]=[]
        assert status(c,p)=='UNKNOWN',status.last

def test_approved_record_still_requires_exact_path_nsg_scope_port_protocol_service():
    for key,value in [('pathId','/subscriptions/sub/not-this-path'),('nsgId','/subscriptions/sub/not-this-nsg'),('scope','/subscriptions/foreign'),('protocol','Udp'),('port',22),('service','ssh'),('checkId','another-control')]:
        c,p=fixture();obs(c)[key]=value;approve(c,p)
        assert status(c,p)=='UNKNOWN',status.last

def test_capture_and_current_snapshot_digest_binding():
    for change in ['capture','digest','nsg','path']:
        c,p=fixture()
        if change=='capture':obs(c)['capture']['created_at']='2026-10-11T00:00:00Z'
        elif change=='digest':obs(c)['snapshotSha256']='b'*64
        elif change=='nsg':c['nsg'][0][1][0]['properties']['securityRules']=[{'properties':{'direction':'Inbound','priority':100}}]
        else:c['nsg_effective_internet_path'][0][1][0]['properties']['unrelatedNativeFact']='changed'
        approve(c,p)
        assert status(c,p)=='UNKNOWN',status.last

def test_approval_dates_freshness_types_and_read_only_are_required():
    for key,value in [('approvedAt','2026-10-12T00:00:01Z'),('expiresAt','2026-10-11T23:59:59Z'),('maxAgeSeconds',True),('maxAgeSeconds',0),('authorizedBy','')]:
        c,p=fixture();p['serviceObservationAuthority'][key]=value
        assert status(c,p)=='UNKNOWN',status.last
    c,p=fixture();obs(c)['readOnly']=False;approve(c,p)
    assert status(c,p)=='UNKNOWN',status.last

def test_artifact_and_exact_independent_record_approval():
    for key,value in [('artifactSha256','reference-only'),('sourceId','unapproved-inventory'),('method','port-scan')]:
        c,p=fixture();obs(c)[key]=value;approve(c,p)
        assert status(c,p)=='UNKNOWN',status.last
    c,p=fixture();obs(c)['artifactSha256']='b'*64
    assert status(c,p)=='UNKNOWN',status.last

def test_missing_duplicate_partial_and_foreign_measurements():
    for mode in ['missing','duplicate','foreign','partial']:
        c,p=fixture()
        if mode=='missing':c['nsg_service_measurement'][0]=(S,[])
        elif mode=='duplicate':c['nsg_service_measurement'][0][1].append(copy.deepcopy(c['nsg_service_measurement'][0][1][0]))
        elif mode=='foreign':c['nsg_service_measurement'][0][1][0]['parent_id']='/subscriptions/foreign/nsg'
        assert status(c,p,partial=mode=='partial')=='UNKNOWN',status.last

def test_complete_empty_exposure_and_empty_nsg_applicability():
    c,p=fixture();c['nsg_effective_internet_path'][0]=(S,[]);c['nsg_service_measurement'][0]=(S,[])
    assert status(c,{})=='PASS',status.last
    c['nsg'][0]=(S,[])
    assert status(c,{})=='NOT_APPLICABLE',status.last
