"""Explicit external federation evidence through sealed registered snapshots."""
import copy,json
from pathlib import Path
from peaso.snapshot import make_snapshot
from tests.archived_check_contract import evaluate_snapshot
CID='azure.other.human_federated_signin'
FIXTURE=Path(__file__).parent/'fixtures/bulk_pending_behavior.json'
def fixture():
    idx=copy.deepcopy(json.loads(FIXTURE.read_text())[CID]['pass_index'])
    return idx['collections'],idx['context']
def history(c):return c['human_signin_history'][0]['items'][0]
def proof(c):return history(c)['authenticationEvidence'][0]
def domain(c):return c['domain_federation'][0]['items'][0]
def subject(c,kind):return {'history':history,'proof':proof,'domain':domain}[kind](c)
def status(c,context):
    envelopes=[dict(e,service='external:retained-fixture') for batches in c.values() for e in batches]
    snapshot=make_snapshot('azure',[context['scope']],envelopes,metadata=context['metadata'],created_at=context['created_at'])
    findings=[f for f in evaluate_snapshot(snapshot,checks=[CID],include_not_applicable=True)['findings'] if f['check_id']==CID]
    assert len(findings)==1
    status.last=findings
    return findings[0]['status']

def test_future_completed_retained_history_is_not_pass():
    c,ctx=fixture();history(c)['retained_until']='2026-10-12T12:00:01Z'
    assert status(c,ctx)=='UNKNOWN',status.last

def test_explicit_foreign_tenant_evidence_is_not_pass():
    results=[]
    for kind in ('history','proof','domain'):
        for placement in ('row','provenance'):
            c,ctx=fixture();row=subject(c,kind)
            target=row if placement=='row' else row['_provenance']
            target['tenant_id']='foreign-tenant'
            results.append((kind,placement,status(c,ctx)))
    assert all(s=='UNKNOWN' for _,_,s in results),results

def test_foreign_capture_evidence_is_not_pass():
    results=[]
    for kind in ('history','proof','domain'):
        for field in ('credential_context_id','customer_context_id'):
            c,ctx=fixture();ctx['metadata'].update(credential_context_id='capture-credential',customer_context_id='capture-customer')
            for selected in ('history','proof','domain'):
                subject(c,selected)['_provenance'].update(credential_context_id='capture-credential',customer_context_id='capture-customer')
            subject(c,kind)['_provenance'][field]='foreign-capture'
            results.append((kind,field,status(c,ctx)))
    assert all(s=='UNKNOWN' for _,_,s in results),results

def test_exact_retention_and_matching_explicit_capture_authority_pass():
    c,ctx=fixture();ctx['metadata'].update(credential_context_id='capture-credential',customer_context_id='capture-customer')
    for kind in ('history','proof','domain'):
        subject(c,kind)['_provenance'].update(tenant_id=ctx['metadata']['tenant_id'],credential_context_id='capture-credential',customer_context_id='capture-customer')
    history(c)['retained_until']='2026-10-12T14:00:00+02:00'
    assert status(c,ctx)=='PASS',status.last

def test_short_history_and_no_successful_observations_remain_unknown():
    for mode in ('short','early_end','no_events','unsuccessful_only'):
        c,ctx=fixture()
        if mode=='short':history(c)['retained_from']='2026-09-12T12:00:01Z'
        elif mode=='early_end':history(c)['retained_until']='2026-10-12T11:59:59Z'
        elif mode=='no_events':history(c)['signIns']=[]
        else:history(c)['signIns'][0]['status']['errorCode']=50076
        assert status(c,ctx)=='UNKNOWN',status.last

def test_exact_identity_correlation_time_and_unique_proof_required():
    for field,value in [('userId','foreign-user'),('correlationId','foreign-correlation'),('event_time','2026-10-12T11:59:59Z'),('signInId','foreign-event')]:
        c,ctx=fixture();proof(c)[field]=value
        assert status(c,ctx)=='UNKNOWN',status.last
    c,ctx=fixture();history(c)['authenticationEvidence'].append(copy.deepcopy(proof(c)))
    assert status(c,ctx)=='UNKNOWN',status.last

def test_existing_source_and_resolution_safeguards_remain_required():
    for kind in ('history','proof','domain'):
        c,ctx=fixture();subject(c,kind)['_provenance']['source_operation']='unrelated-operation'
        assert status(c,ctx)=='UNKNOWN',status.last
    for field in ('signInPages','idpPages','humanClassification','stableCorrelation'):
        c,ctx=fixture();history(c)['resolution'][field]='partial'
        assert status(c,ctx)=='UNKNOWN',status.last

def test_measured_direct_or_unapproved_issuer_fails_despite_bad_current_domain():
    for mode in ('direct','unapproved'):
        for config in ('managed','stale','foreign_source'):
            c,ctx=fixture()
            if mode=='direct':proof(c)['authentication_kind']='direct'
            else:proof(c)['issuer_id']='unapproved-idp'
            if config=='managed':domain(c)['authenticationType']='Managed'
            elif config=='stale':domain(c)['observed_at']='2026-10-12T10:59:59Z'
            else:domain(c)['_provenance']['tenant_id']='foreign-tenant'
            assert status(c,ctx)=='FAIL',status.last

def test_current_domain_configuration_freshness_and_issuer_required_for_pass():
    for field,value in [('observed_at','2026-10-12T10:59:59Z'),('observed_at','2026-10-12T12:00:01Z'),('authenticationType','Managed'),('issuer_id','unapproved-idp'),('domain_name','foreign.example')]:
        c,ctx=fixture();domain(c)[field]=value
        assert status(c,ctx)=='UNKNOWN',status.last

def test_incomplete_or_foreign_collection_and_current_user_are_unknown():
    for kind in ('entra_user','human_signin_history','domain_federation'):
        c,ctx=fixture();c[kind][0]['status']='partial'
        assert status(c,ctx)=='UNKNOWN',status.last
    c,ctx=fixture();c['entra_user'][0]['items'][0]['tenant_id']='foreign-tenant'
    assert status(c,ctx)=='UNKNOWN',status.last
