"""Review contracts and genuine registered predicate fixtures for AWS guidance."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.aws_remaining_clarity_reviewed import ROWS,_digest,description,remediation,severity_review
from peaso.checks.aws_remaining_finding_summary import evidence_summary

ROOT=Path(__file__).resolve().parents[1]
CHECK_BY_ID={c.id:c for c in CHECKS}

@pytest.fixture(scope='module')
def originals():
    descriptions=json.loads((ROOT/'peaso/rulepacks/check_descriptions.json').read_text())['checks']
    rems={cid:None for cid,r in ROWS.items() if r['remediation_base_sha256']==_digest(None)}
    for path in (ROOT/'peaso/rulepacks').glob('remediation*.json'):
        rows=json.loads(path.read_text())
        if isinstance(rows,dict):
            for cid,value in rows.items():
                if cid in ROWS and _digest(value)==ROWS[cid]['remediation_base_sha256']:rems[cid]=value
    assert set(rems)==set(ROWS)
    return descriptions,rems

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_description_remains_brief_and_preserves_signed_criteria(cid,originals):
    original=originals[0][cid];before=deepcopy(original);actual=description(cid,original)
    assert before==original
    assert len(actual['description'].split())<=40
    assert {k:v for k,v in actual.items() if k!='description'}=={k:v for k,v in original.items() if k!='description'}

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_reviewed_actions_are_short_and_existing_approved_commands_are_preserved(cid,originals):
    original=originals[1][cid];before=deepcopy(original);actual=remediation(cid,original)
    assert original==before
    assert 1<=len(actual['steps'])<=2 and len(actual['steps'][0].split())<=40
    assert actual['caveats']
    changed=set(ROWS[cid]['remediation_fields'])
    assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in (original or {}).items() if k not in changed}
    if not original or original.get('review_status')!='approved':
        assert actual['review_status']=='approved' and actual['cli']==[] and not actual.get('iac')
        assert actual['field_binding']['fields'] and actual['references']
        assert all(x['url'].startswith('https://docs.aws.amazon.com/') for x in actual['references'])

@pytest.mark.parametrize('cid',sorted(ROWS))
@pytest.mark.parametrize('kind,apply',[('description',description),('remediation',remediation)])
def test_stale_sources_fail_closed(cid,kind,apply,originals):
    original=deepcopy(originals[kind=='remediation'][cid]) or {}
    original['unreviewed']='drift'
    with pytest.raises(ValueError,match='Reviewed AWS remaining clarity base changed'):apply(cid,original)


def _stable(v):
    if callable(v):return {'callable':v.__qualname__}
    if isinstance(v,dict):return {str(k):_stable(x) for k,x in sorted(v.items())}
    if isinstance(v,(list,tuple)):return [_stable(x) for x in v]
    if isinstance(v,(set,frozenset)):return sorted(_stable(x) for x in v)
    if isinstance(v,(str,int,float,bool)) or v is None:return v
    if hasattr(v,'isoformat') and v.__class__.__module__=='datetime':return {'datetime':v.isoformat()}
    return {'type':type(v).__name__}

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_actual_predicate_delegates_tuples_constants_and_severity_stay_reviewed(cid):
    c=CHECK_BY_ID[cid];binding=ROWS[cid]['reviewed_binding'];f=inspect.unwrap(c.evaluate)
    assert binding['kind']==c.kind
    assert binding['module']==f.__module__ and binding['source_qualname']==f.__qualname__
    closure=inspect.getclosurevars(f).nonlocals
    assert binding['closure']==_stable(closure)
    funcs={f.__module__+'.'+f.__qualname__:f}
    for value in closure.values():
        if callable(value) and inspect.isfunction(value):funcs[value.__module__+'.'+value.__qualname__]=value
    for fn in list(funcs.values()):
        for name in fn.__code__.co_names:
            value=fn.__globals__.get(name)
            if inspect.isfunction(value) and value.__module__.startswith('peaso.checks') and value.__name__ not in {'result','unknown','get','optional','complete_items','list_of_objects'}:
                funcs[value.__module__+'.'+value.__qualname__]=value
    assert binding['predicate_sources']=={key:hashlib.sha256(inspect.getsource(value).encode()).hexdigest() for key,value in sorted(funcs.items())}
    constants={key:_stable(value) for fn in funcs.values() for key in fn.__code__.co_names if key in fn.__globals__ and key.isupper() and isinstance((value:=fn.__globals__[key]),(str,int,float,bool,list,tuple,set,frozenset,dict))}
    assert constants==binding['constants']
    assert severity_review(cid,c.severity)==ROWS[cid]['reviewed_severity']
    with pytest.raises(ValueError):severity_review(cid,'different')


def _cases(cid):
    # These two existing registry fixtures live in test_peaso_checks.py.
    if cid=='aws.iam.no_full_admin':
        return {'pass':{'PolicyDocument':{'Statement':[]}},'fail':{'PolicyDocument':{'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]}}}
    if cid=='aws.ec2.restrict_internet_ingress':
        return {'pass':{'IpPermissions':[]},'fail':{'IpPermissions':[{'IpProtocol':'tcp','FromPort':22,'ToPort':22,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]}]}}
    return CASES[cid]

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_registered_positive_negative_or_explicit_review_branches(cid):
    cases=_cases(cid)
    branches=['pass','fail']
    if cid in {'aws.b.acm.pending_validation_review','aws.claude2_a.config.aggregation_authorization_trusted','aws.claude2_a.dlm.snapshot_sharing_trusted_accounts'}:
        branches=['pass','manual']
    for branch in branches:
        status,evidence=CHECK_BY_ID[cid].evaluate(deepcopy(cases[branch]),deepcopy(cases.get(branch+'_index',cases.get('index',{}))))
        expected='UNKNOWN' if cid=='aws.c2b.ecs.container_instance_in_vpc' and branch=='fail' else branch.upper()
        assert status==expected,(cid,branch,status,evidence)
        finding={'provider':'aws','status':status,'check_id':cid,'evidence':evidence};before=deepcopy(finding)
        summary=evidence_summary(finding)
        if status != 'FAIL':assert summary is None
        if summary:assert isinstance(summary,str) and len(summary)<300
        assert finding==before


def test_unknown_unowned_and_nonfailure_observations_are_not_fabricated():
    cid=next(iter(ROWS))
    for status in ['PASS','UNKNOWN','MANUAL','DENIED','NOT_APPLICABLE']:
        assert evidence_summary({'provider':'aws','status':status,'check_id':cid,'evidence':{}}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':None}) is None
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':'other','evidence':{}}) is None
    assert evidence_summary({'provider':'gcp','status':'FAIL','check_id':cid,'evidence':{}}) is None
    value={'nested':[]};result=description('unreviewed',value);result['nested'].append(1)
    assert value['nested']==[]

@pytest.mark.parametrize('port',[22,443,5432])
def test_broad_ingress_observation_names_protocol_port_without_claiming_reachability(port):
    finding={'provider':'aws','status':'FAIL','check_id':'aws.ec2.restrict_internet_ingress','evidence':{'internet_ingress':[{'protocol':'tcp','from_port':port,'to_port':port,'source':'0.0.0.0/0'}]}}
    assert evidence_summary(finding)==f'The security group allows Internet ingress to tcp/{port}.'


def test_longer_kinesis_retention_is_not_described_as_short_retention():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.cb.kinesis.retention_exactly_168h','evidence':{'retention_hours':8760}}
    assert evidence_summary(finding)=='Kinesis retention is 8760 hours; this profile prefers exactly 168.'


def test_aws_managed_key_does_not_become_plaintext_claim():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.cb.sqs.cmk_encryption','evidence':{'kms_master_key_id':'alias/aws/sqs'}}
    assert evidence_summary(finding)=='The queue declares the AWS-managed SQS KMS alias; this profile prefers a customer-managed key.'


def test_redshift_disabled_and_encrypted_missing_reference_are_distinct_observations():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.b.redshift.kms_key_declared','evidence':{'encrypted':False}}
    assert evidence_summary(finding)=='The Redshift cluster declares storage encryption disabled.'
    finding['evidence']={'encrypted':True,'kms_key_id':None}
    assert evidence_summary(finding)=='The encrypted Redshift cluster has no KMS key reference in the complete native inventory.'


def test_expired_certificate_uses_past_tense():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.b.acm.expiry_thirty_days','evidence':{'remaining_calendar_days':-4}}
    assert evidence_summary(finding)=='The certificate expired 4 calendar days before the snapshot date.'


@pytest.mark.parametrize('cid',sorted(ROWS))
@pytest.mark.parametrize('evidence',[{}, {'unrelated':True}, {'internet_ingress':[None]}, {'configured':True}, {'short_retention_rules':[{'delete_after_days':'7'}]}])
def test_incomplete_or_malformed_facts_do_not_get_static_failure_claims(cid,evidence):
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_native_positive_evidence_relabelled_fail_does_not_invent_weakness(cid):
    fixture=_cases(cid)
    status,evidence=CHECK_BY_ID[cid].evaluate(deepcopy(fixture['pass']),deepcopy(fixture.get('pass_index',fixture.get('index',{}))))
    if status=='PASS':assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None
