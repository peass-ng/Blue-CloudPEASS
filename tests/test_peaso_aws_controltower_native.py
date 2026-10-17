"""Real SDK schemas and collection→signed SW44 evaluation, without cloud calls."""
import copy
import json
import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live
from peaso.engine import plan_collection, evaluate_snapshot
from peaso.collectors import aws_controltower_native as native

CHECK = 'aws_controltower_landing_zone_active'
SCOPE = ACCOUNT + '/' + REGION
ORG = 'o-abcdefghij'
ARN = 'arn:aws:controltower:' + REGION + ':' + ACCOUNT + ':landingzone/ABCDEFGHIJKLMNOP'
SECRET = 'PRIVATE_MANIFEST_OR_EMAIL_NOT_FOR_CACHE'
POLICY = {'scope': SCOPE, 'organization_id': ORG, 'ai_account_ids': [ACCOUNT]}


def capture(sdk, monkeypatch, mode='active', validated=None):
    session, add = sdk
    sts = add('sts'); org = add('organizations'); ct = add('controltower')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT, 'Arn': 'arn:aws:iam::'+ACCOUNT+':user/reader', 'UserId': 'reader'}, {})
    options = {'retry_attempts': 1, 'service_concurrency': 1,
               'compliance_parameters': {'aws_controltower': copy.deepcopy(POLICY)}}
    query_region = 'ap-east-1' if mode == 'opt_in_query' else REGION
    scope = ACCOUNT+'/'+query_region
    options['compliance_parameters']['aws_controltower']['scope'] = scope
    if validated is not None:options.update(copy.deepcopy(validated))
    if mode == 'no_policy':options.pop('compliance_parameters')
    zonearn=ARN.replace(REGION,'us-west-2') if mode=='home_region' else ARN
    if mode not in ('no_policy', 'opt_in_query'):
        organization = {'Id': 'o-foreignabcde' if mode=='foreign_org' else ORG,
            'Arn': 'arn:aws:organizations::'+ACCOUNT+':organization/'+ORG,
            'MasterAccountId': '999999999999' if mode=='member_account' else ACCOUNT,
            'MasterAccountEmail': SECRET}
        if mode=='missing_org_arn':organization.pop('Arn')
        if mode=='org_denied':org.add_client_error('describe_organization','AccessDeniedException',expected_params={})
        else:org.add_response('describe_organization',{'Organization':organization},{})
        early = mode in ('org_denied', 'foreign_org', 'member_account', 'missing_org_arn')
        if not early:
            row = {'arn': ARN.replace(ACCOUNT,'999999999999') if mode=='foreign_zone' else zonearn}
            rows = [] if mode=='empty' else [row]
            if mode=='duplicate':rows*=2
            paged = mode in ('two_pages','partial')
            if mode=='list_denied':ct.add_client_error('list_landing_zones','AccessDeniedException',expected_params={})
            else:ct.add_response('list_landing_zones',{'landingZones':[] if paged else rows,**({'nextToken':'cursor'} if paged else {})},{})
            if paged:ct.add_response('list_landing_zones',{'landingZones':rows},{'nextToken':'cursor'})
            early = mode in ('empty','duplicate','foreign_zone','list_denied','partial')
            if not early:
                zone = {'arn': ARN.replace('ABCDEFGHIJKLMNOP','ZZZZZZZZZZZZZZZZ') if mode=='detail_mismatch' else zonearn,
                    'status': {'failed':'FAILED','processing':'PROCESSING','invalid_status':'INVALID'}.get(mode,'ACTIVE'),
                    'version':'4.0','manifest':{'private':SECRET}}
                if mode=='missing_status':zone.pop('status')
                if mode=='detail_denied':ct.add_client_error('get_landing_zone','AccessDeniedException',expected_params={'landingZoneIdentifier':zonearn})
                elif mode=='detail_404':ct.add_client_error('get_landing_zone','ResourceNotFoundException',expected_params={'landingZoneIdentifier':zonearn})
                else:ct.add_response('get_landing_zone',{'landingZone':zone},{'landingZoneIdentifier':zonearn})
    monkeypatch.setattr(aws, '_session', lambda auth,region:(session,'fixture-pinned'))
    if mode=='partial':options['max_pages']=1
    connector={'provider':'aws','scopes':[scope],'options':options}
    required=plan_collection({'connector':connector,'checks':[CHECK]})
    assert required==[native.KIND]
    snapshot=collect_live(connector,required)
    findings=evaluate_snapshot(snapshot,checks=[CHECK])['findings']
    assert len(findings)==1 and SECRET not in json.dumps(snapshot)
    if mode=='partial':
        assert len(ct._queue)==1 and ct._queue[0]['expected_params']=={'nextToken':'cursor'}
        env=next(c for c in snapshot['collections'] if c['type']==native.KIND)
        assert env['status'] not in ('collected','empty') and env['error']['code']=='page_limit'
    else:ct.assert_no_pending_responses()
    org.assert_no_pending_responses();sts.assert_no_pending_responses()
    return findings[0]['status'],snapshot


@pytest.mark.parametrize('mode,expected',[
 ('active','PASS'),('home_region','PASS'),('missing_org_arn','UNKNOWN'),('invalid_status','UNKNOWN'),('failed','FAIL'),('processing','FAIL'),('empty','FAIL'),('two_pages','PASS'),
 ('no_policy','UNKNOWN'),('opt_in_query','UNKNOWN'),('foreign_org','UNKNOWN'),('member_account','UNKNOWN'),
 ('foreign_zone','UNKNOWN'),('detail_mismatch','UNKNOWN'),('missing_status','UNKNOWN'),
 ('duplicate','UNKNOWN'),('partial','UNKNOWN'),('org_denied','DENIED'),('list_denied','DENIED'),
 ('detail_denied','DENIED'),('detail_404','UNKNOWN')])
def test_native_pipeline(sdk,monkeypatch,mode,expected):
    status,snapshot=capture(sdk,monkeypatch,mode)
    assert status==expected
    if expected=='PASS':
        item=next(c for c in snapshot['collections'] if c['type']==native.KIND)['items'][0]
        assert item['OrganizationId']==ORG and item['InScopeAiAccountIds']==[ACCOUNT]
        assert item['_provenance']['regional_governance_or_workload_enforcement_proven'] is False


@pytest.mark.parametrize('change',[None,{}, {'scope':None},{'scope':'999999999999/us-east-1'},
 {'organization_id':'o-bad'},{'ai_account_ids':[]},{'ai_account_ids':[ACCOUNT,ACCOUNT]},
 {'ai_account_ids':['999999999999']},{'LandingZones':[]},{'status':'collected'}])
def test_normative_only_preflight_rejects_before_transport(monkeypatch,change):
    value=copy.deepcopy(POLICY)
    if isinstance(change,dict):value.update(change)
    else:value=change
    # {} itself is incomplete, rather than an empty update to a valid policy.
    if change=={}:value={}
    monkeypatch.setattr(aws,'_session',lambda *a:pytest.fail('transport before preflight'))
    with pytest.raises(ValueError):
        aws.collect({'scopes':[SCOPE],'options':{'compliance_parameters':{native.OPTION:value}}},[native.KIND])


@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_hosted_and_local_reject_invalid_or_foreign_policy_before_auth(auth_mode,provider):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    value=copy.deepcopy(POLICY)
    if provider=='aws':value['ai_account_ids']=[]
    with pytest.raises(HTTPException) as exc:
        validate_connector(provider,{}, {'compliance_parameters':{native.OPTION:value}},SimpleNamespace(auth_mode=auth_mode))
    assert exc.value.status_code==422


@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_intake_roundtrip(sdk,monkeypatch,auth_mode):
    from types import SimpleNamespace
    from peaso.server.validation import validate_connector
    options={'compliance_parameters':{native.OPTION:copy.deepcopy(POLICY)}}
    validate_connector('aws',{'method':'assume_role','role_arn':'arn:aws:iam::'+ACCOUNT+':role/reader','external_id':'peaso-fixture-external'},options,SimpleNamespace(auth_mode=auth_mode),server_external_id=True)
    assert capture(sdk,monkeypatch,validated=options)[0]=='PASS'


def test_pre_cache_projection_drops_manifest_and_email(sdk):
    session,add=sdk;ct=add('controltower');org=add('organizations')
    ct.add_response('get_landing_zone',{'landingZone':{'arn':ARN,'version':'4.0','status':'ACTIVE','manifest':{'secret':SECRET}}},{'landingZoneIdentifier':ARN})
    org.add_response('describe_organization',{'Organization':{'Id':ORG,'MasterAccountEmail':SECRET}},{})
    requests=aws.Requests({});requests.controltower_policy=copy.deepcopy(POLICY)
    requests.detail(session,'controltower',REGION,'get_landing_zone',landingZoneIdentifier=ARN)
    requests.detail(session,'organizations',REGION,'describe_organization')
    assert SECRET not in repr([future.result() for future in requests._cache.values()])
    assert requests.calls==2
    ct.assert_no_pending_responses();org.assert_no_pending_responses()


def test_scope_mismatch_is_rejected_before_transport(monkeypatch):
    monkeypatch.setattr(aws,'_session',lambda *a:pytest.fail('scope mismatch reached API'))
    with pytest.raises(ValueError):
        aws.collect({'scopes':[ACCOUNT+'/eu-west-1'],'options':{'compliance_parameters':{native.OPTION:POLICY}}},[native.KIND])


def test_detail_uses_proven_native_home_region(sdk,monkeypatch):
    original=aws.Requests.client
    calls=[]
    def client(self,session,service,region):
        calls.append((service,region))
        return original(self,session,service,region)
    monkeypatch.setattr(aws.Requests,'client',client)
    assert capture(sdk,monkeypatch,'home_region')[0]=='PASS'
    assert ('controltower','us-east-1') in calls
    assert ('controltower','us-west-2') in calls
