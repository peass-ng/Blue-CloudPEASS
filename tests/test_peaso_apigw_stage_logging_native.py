"""Portable collector-to-engine API Gateway stage execution-logging cases."""
from __future__ import annotations
import copy
import pytest
from peaso.collectors.aws import ReadResult
from peaso.collectors.aws_b_services import FETCHERS as STAGE_FETCHERS
from peaso.collectors.aws_apigateway_native import FETCHERS as NATIVE_FETCHERS
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE='123456789012/us-east-1'
CHECK='aws_nist_apigateway_stage_logging_enabled'

class Session:
    def get_partition_for_region(self, region):
        assert region == 'us-east-1'
        return 'aws'

class SDKResponses:
    def __init__(self, *, rest=None, v2=None, summary=None, v2_protocol='WEBSOCKET', method_status='collected', parent_coverage=None):
        self.rest=rest or []
        self.v2=v2 or []
        self.summary=summary if summary is not None else {'/pets': {'GET': {}}}
        self.v2_protocol=v2_protocol
        self.method_status=method_status
        self.parent_coverage=parent_coverage
        self.calls=[]
    def pages(self, session, service, region, operation, expression, **arguments):
        self.calls.append((service,operation,arguments))
        if operation=='get_rest_apis': return ReadResult([{'id':'api123'}] if self.rest else [],'collected' if self.rest else 'empty')
        if operation=='get_apis':
            return ReadResult([{'ApiId':'ws123','ProtocolType':self.v2_protocol,**({'_coverage':self.parent_coverage} if self.parent_coverage else {})}] if self.v2 else [],'collected' if self.v2 else 'empty')
        if operation=='get_stages' and service=='apigateway': return ReadResult(copy.deepcopy(self.rest),'collected' if self.rest else 'empty')
        if operation=='get_stages' and service=='apigatewayv2': return ReadResult(copy.deepcopy(self.v2),'collected' if self.v2 else 'empty')
        raise AssertionError((service,operation,arguments))
    def detail(self, session, service, region, operation, **arguments):
        self.calls.append((service,operation,arguments))
        assert (service,operation)==('apigateway','get_deployment')
        assert arguments=={'restApiId':'api123','deploymentId':'dep123','embed':['apisummary']}
        if self.method_status!='collected': return {'collection_status':self.method_status,'error':{'code':'Denied'}}
        return {'collection_status':'collected','id':'dep123','apiSummary':copy.deepcopy(self.summary)}

def scan(*, rest=None, v2=None, protocol='WEBSOCKET', summary=None, method_status='collected', collection_override=None, parent_coverage=None):
    sdk=SDKResponses(rest=rest,v2=v2,summary=summary,v2_protocol=protocol,method_status=method_status,parent_coverage=parent_coverage)
    session=Session()
    reads={
        'rest_api_stage':STAGE_FETCHERS['rest_api_stage'](sdk,session,'us-east-1','123456789012'),
        'http_api_stage':STAGE_FETCHERS['http_api_stage'](sdk,session,'us-east-1','123456789012'),
        'rest_api_method':NATIVE_FETCHERS['rest_api_method'](sdk,session,'us-east-1','123456789012'),
    }
    if collection_override: collection_override(reads)
    collections=[{'type':kind,'scope':SCOPE,'service':'apigateway','status':read.status,'items':read.items,
                  **({'error':read.error} if read.error else {})} for kind,read in reads.items()]
    report=evaluate_snapshot(make_snapshot('aws',[SCOPE],collections,created_at='2026-10-18T00:00:00+00:00'),
                             categories=['compliance'],checks=[CHECK])
    matches=[row for row in report['findings'] if row['check_id']==CHECK]
    assert len(matches)==1
    return matches[0],reads,sdk.calls

def rest_stage(settings=None, **extra):
    return {'stageName':'prod','deploymentId':'dep123','methodSettings':settings if settings is not None else {'*/*':{'loggingLevel':'INFO'}},**extra}

def v2_stage(default=None, overrides=None):
    return {'StageName':'prod','DefaultRouteSettings':default if default is not None else {'LoggingLevel':'INFO'},
            'RouteSettings':overrides if overrides is not None else {}}

@pytest.mark.parametrize('settings,expect',[
    ({'*/*':{'loggingLevel':'INFO'}},'PASS'),
    ({'*/*':{'loggingLevel':'ERROR'},'~1pets/GET':{'metricsEnabled':True}},'PASS'),
    ({'*/*':{'loggingLevel':'INFO'},'~1pets/GET':{'loggingLevel':'OFF'}},'FAIL'),
    ({'*/*':{'loggingLevel':'OFF'},'~1pets/GET':{'loggingLevel':'INFO'}},'PASS'),
    ({'~1pets/GET':{'loggingLevel':'INFO'}},'PASS'),
    ({'*/*':{'loggingLevel':'OFF'}},'FAIL'),
    ({},'FAIL'),
    ({'*/*':{}},'FAIL'),
    ({'~1pets/GET':{'metricsEnabled':True}},'FAIL'),
    ({'*/*':{'loggingLevel':None}},'UNKNOWN'),
    ({'*/*':{'loggingLevel':'INVALID'}},'UNKNOWN'),
    ({'*/*':{'loggingLevel':'INFO','_coverage':{'loggingLevel':{'status':'denied'}}}},'UNKNOWN'),
    ({'*/*':{'loggingLevel':'INFO'},'~1pets/*':{'loggingLevel':'OFF'}},'UNKNOWN'),
    ({'*/*':{'loggingLevel':'INFO'},'_coverage':{'*/*':{'status':'denied'}}},'UNKNOWN'),
])
def test_rest_deployed_method_settings(settings,expect):
    finding,reads,calls=scan(rest=[rest_stage(settings)])
    assert finding['status']==expect
    assert reads['rest_api_method'].status=='collected'
    assert ('apigateway','get_deployment',{'restApiId':'api123','deploymentId':'dep123','embed':['apisummary']}) in calls

@pytest.mark.parametrize('rest,method_status,expect',[
    (rest_stage(canarySettings={'percentTraffic':10}), 'collected','UNKNOWN'),
    (rest_stage(), 'denied','DENIED'),
    (rest_stage(methodSettings={'*/*':{'loggingLevel':'INFO','_coverage':{'loggingLevel':{'status':'denied'}}}}),'collected','UNKNOWN'),
])
def test_rest_incomplete_is_unknown(rest,method_status,expect):
    finding,_,_=scan(rest=[rest],method_status=method_status)
    assert finding['status']==expect

@pytest.mark.parametrize('protocol,v2,expected',[
    ('HTTP',v2_stage(), 'NOT_APPLICABLE'),
    ('WEBSOCKET',v2_stage(),'PASS'),
    ('WEBSOCKET',v2_stage(overrides={'$connect':{'LoggingLevel':'ERROR'}}),'PASS'),
    ('WEBSOCKET',v2_stage(overrides={'$connect':{'DetailedMetricsEnabled':True}}),'PASS'),
    ('WEBSOCKET',v2_stage(overrides={'$connect':{'LoggingLevel':'OFF'}}),'UNKNOWN'),
    ('WEBSOCKET',v2_stage(default={'LoggingLevel':'OFF'}),'UNKNOWN'),
    ('WEBSOCKET',v2_stage(default={'LoggingLevel':None}),'UNKNOWN'),
    ('WEBSOCKET',v2_stage(default={'LoggingLevel':'INFO','_coverage':{'LoggingLevel':{'status':'denied'}}}),'UNKNOWN'),
    ('WEBSOCKET',v2_stage(overrides={'$connect':{'LoggingLevel':'INFO'},'_coverage':{'$connect':{'status':'denied'}}}),'UNKNOWN'),
    ('WEBSOCKET',{'StageName':'prod','DefaultRouteSettings':{'LoggingLevel':'INFO'},'_coverage':{'RouteSettings':{'status':'denied'}}},'UNKNOWN'),
    ('MALFORMED',v2_stage(),'UNKNOWN'),
])
def test_v2_protocol_and_route_boundary(protocol,v2,expected):
    finding,reads,calls=scan(v2=[v2],protocol=protocol)
    assert finding['status']==expected
    assert not any(operation=='get_deployment' for _,operation,_ in calls)

@pytest.mark.parametrize('level,expected',[('INFO','PASS'),('OFF','FAIL')])
def test_mixed_http_and_rest_excludes_http(level,expected):
    finding,_,_=scan(rest=[rest_stage({'*/*':{'loggingLevel':level}})],
                     v2=[v2_stage()],protocol='HTTP')
    assert finding['status']==expected
    assert finding['evidence']['http_not_applicable_stages']==1
    assert finding['evidence']['evaluated_rest_methods']==1

def test_foreign_method_cannot_prove_stage():
    def mutate(reads): reads['rest_api_method'].items[0]['stageArn']='arn:aws:apigateway:us-east-1::/restapis/other/stages/prod'
    finding,_,_=scan(rest=[rest_stage()],collection_override=mutate)
    assert finding['status']=='UNKNOWN'

@pytest.mark.parametrize('field', ['ApiId','ProtocolType'])
def test_denied_parent_api_fact_never_classifies_v2(field):
    finding,reads,_=scan(v2=[v2_stage()],parent_coverage={field:{'status':'denied'}})
    assert reads['http_api_stage'].status=='malformed'
    assert finding['status']=='UNKNOWN'


def test_denied_carried_protocol_never_classifies_v2():
    def mutate(reads):
        reads['http_api_stage'].items[0]['_coverage']={'ParentProtocolType':{'status':'denied'}}
    finding,_,_=scan(v2=[v2_stage()],collection_override=mutate)
    assert finding['status']=='UNKNOWN'

@pytest.mark.parametrize('settings,expected,deployment_mode',[
    ('OMITTED','FAIL','collected'), ({},'FAIL','collected'), ({'*/*':{}},'FAIL','collected'),
    ({'~1pets/GET':{'metricsEnabled':True}},'FAIL','collected'),
    ({'~1pets/GET':{'loggingLevel':'INFO'}},'PASS','collected'),
    ({'*/*':{'loggingLevel':'INFO'}},'PASS','collected'),
    ({'*/*':{'loggingLevel':'INFO'}},'DENIED','denied'),
    ({'*/*':{'loggingLevel':'INFO'}},'UNKNOWN','missing_summary'),
])
def test_botocore_stubber_through_bulk_native_collector_and_registered_engine(monkeypatch, settings, expected, deployment_mode):
    """Real SDK response validation and whole native collection, without network."""
    import boto3
    from botocore.stub import Stubber
    from peaso.collectors import aws

    sdk_session=boto3.Session(aws_access_key_id='inert',aws_secret_access_key='inert',region_name='us-east-1')
    real_client=boto3.session.Session.client
    clients={name:real_client(sdk_session,name,region_name='us-east-1')
             for name in ('sts','apigateway','apigatewayv2')}
    stubs={name:Stubber(client) for name,client in clients.items()}
    stubs['sts'].add_response('get_caller_identity',
        {'Account':'123456789012','Arn':'arn:aws:iam::123456789012:user/inert','UserId':'AIDAEXAMPLE'}, {})
    stubs['apigateway'].add_response('get_rest_apis',{'items':[{'id':'api123','name':'example'}]}, {})
    rest_row={'stageName':'prod','deploymentId':'dep123'}
    if settings != 'OMITTED': rest_row['methodSettings']=settings
    stubs['apigateway'].add_response('get_stages', {'item':[rest_row]}, {'restApiId':'api123'})
    deployment_args={'restApiId':'api123','deploymentId':'dep123','embed':['apisummary']}
    if deployment_mode=='denied':
        stubs['apigateway'].add_client_error('get_deployment',service_error_code='AccessDeniedException',
            http_status_code=403,expected_params=deployment_args)
    else:
        deployment={'id':'dep123'}
        if deployment_mode=='collected':deployment['apiSummary']={'/pets':{'GET':{}}}
        stubs['apigateway'].add_response('get_deployment',deployment,deployment_args)
    stubs['apigatewayv2'].add_response('get_apis',
        {'Items':[{'ApiId':'ws123','ProtocolType':'WEBSOCKET','Name':'ws-example','RouteSelectionExpression':'$request.body.action'},
                  {'ApiId':'http123','ProtocolType':'HTTP','Name':'http-example','RouteSelectionExpression':'$request.method $request.path'}]}, {})
    stubs['apigatewayv2'].add_response('get_stages',
        {'Items':[{'StageName':'prod','DefaultRouteSettings':{'LoggingLevel':'INFO'},
                   'RouteSettings':{}}]}, {'ApiId':'ws123'})
    stubs['apigatewayv2'].add_response('get_stages',
        {'Items':[{'StageName':'prod'}]}, {'ApiId':'http123'})
    for stub in stubs.values(): stub.activate()
    def stubbed_sdk_client(self, service_name, **kwargs):
        assert service_name in clients
        return clients[service_name]
    # Inject only real, Stubber-wrapped SDK clients at the SDK factory seam.
    # Collector functions, the check registry, and engine dispatch stay intact.
    monkeypatch.setattr(boto3.session.Session,'client',stubbed_sdk_client)
    kinds=['rest_api_stage','http_api_stage','rest_api_method']
    snapshot=aws.collect({'provider':'aws','scopes':[SCOPE],
        'auth':{'method':'access_keys','aws_access_key_id':'inert',
                'aws_secret_access_key':'inert','region_name':'us-east-1'},
        'options':{'regions':['us-east-1'],'inventories':kinds,
                   'max_calls':12,'service_concurrency':1,'scope_concurrency':1,
                   'region_concurrency':1}}, kinds)
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()
    chosen={row['type']:row for row in snapshot['collections']
            if row['scope']==SCOPE and row['type'] in kinds}
    assert chosen['rest_api_stage']['status']=='collected'
    assert chosen['http_api_stage']['status']=='collected'
    assert chosen['rest_api_method']['status']=={'collected':'collected','denied':'denied',
        'missing_summary':'malformed'}[deployment_mode]
    rest=chosen['rest_api_stage']['items'][0]
    if deployment_mode=='collected':
        method=chosen['rest_api_method']['items'][0]
        assert method['stageArn']==rest['id']
        assert method['deploymentId']==rest['deploymentId']=='dep123'
        assert method['methodSettingKey']=='/pets/GET'
        assert method['_provenance']['stage_deployment_join_verified'] is True
    protocols={row['ParentApiId']:row['ParentProtocolType']
               for row in chosen['http_api_stage']['items']}
    assert protocols=={'ws123':'WEBSOCKET','http123':'HTTP'}
    report=evaluate_snapshot(snapshot,categories=['compliance'],checks=[CHECK])
    finding=next(row for row in report['findings'] if row['check_id']==CHECK)
    assert finding['status']==expected
    if deployment_mode=='collected':
        assert finding['evidence']['evaluated_rest_methods']==1
        assert finding['evidence']['configured_websocket_stages']==1
        assert finding['evidence']['http_not_applicable_stages']==1

def test_native_absent_map_requires_collector_completeness_marker():
    def mutate(reads):
        row=reads['rest_api_stage'].items[0]
        row['_provenance']['optional_fields_complete']=['accessLogSettings']
    finding,_,_=scan(rest=[{'stageName':'prod','deploymentId':'dep123'}],collection_override=mutate)
    assert finding['status']=='UNKNOWN'

def test_native_absent_map_with_collector_marker_is_missing_logging():
    finding,reads,_=scan(rest=[{'stageName':'prod','deploymentId':'dep123'}])
    assert 'methodSettings' in reads['rest_api_stage'].items[0]['_provenance']['optional_fields_complete']
    assert finding['status']=='FAIL'

@pytest.mark.parametrize('stage',[{'stageName':'prod','deploymentId':'dep123','methodSettings':None},
                                  {'stageName':'prod','deploymentId':'dep123','methodSettings':[]},
                                  {'stageName':'prod','deploymentId':'dep123','_coverage':{'methodSettings':{'status':'denied'}}}])
def test_null_malformed_or_denied_map_unknown(stage):
    assert scan(rest=[stage])[0]['status']=='UNKNOWN'

def test_complete_deployment_summary_missing_unknown():
    finding,reads,_=scan(rest=[rest_stage({})],summary={})
    assert reads['rest_api_method'].status in ('malformed','partial')
    assert finding['status']=='UNKNOWN'

def test_fully_overridden_two_deployed_methods_pass_without_wildcard():
    settings={'~1pets/GET':{'loggingLevel':'INFO'},'~1pets/POST':{'loggingLevel':'ERROR'}}
    finding,reads,_=scan(rest=[rest_stage(settings)],summary={'/pets':{'GET':{},'POST':{}}})
    assert reads['rest_api_method'].status=='collected'
    assert finding['status']=='PASS'


def test_foreign_partition_cannot_satisfy_stage_scope():
    def foreign(reads):
        for result in reads.values():
            for row in result.items:
                for field in ("id", "stageArn"):
                    if isinstance(row.get(field), str):
                        row[field] = row[field].replace("arn:aws:", "arn:aws-cn:")
    finding, _, _ = scan(rest=[rest_stage()], collection_override=foreign)
    assert finding["status"] == "UNKNOWN"
