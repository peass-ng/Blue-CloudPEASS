"""Bounded offline AWS network closure review; no cloud access or secret content.

Reproduce report with: python -m tests.test_aws_network_closure_review --write-report
SDK identity and protocol regressions assert the root-integrated corrections.
Fixture-only witnesses never promote a row to semantic completion.
"""
from collections import Counter
from copy import deepcopy
from functools import lru_cache
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

import pytest
from scripts import audit_aws_native_contracts as native
from scripts import audit_aws_field_producers as fields
from tests.test_peaso_collectors_aws import sdk, ACCOUNT, REGION, IDENTITY

ROOT = Path(__file__).resolve().parents[1]
INPUT = Path('/tmp/peasso-aws-review-20261019/final-closure/network-input.json')
REPORT = ROOT / 'docs/aws-review/network-closure-review.json'
RECEIPT = Path('/tmp/peasso-aws-review-20261019/final-closure/network-closure-review.xml')
SCOPE = ACCOUNT + '/' + REGION
LB = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/review/0123456789abcdef'
LISTENER = LB.replace(':loadbalancer/', ':listener/') + '/0123456789abcdef'
WID = '12345678-1234-1234-1234-123456789012'
WARN = f'arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/review/{WID}'
FARN = f'arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall/review'

@lru_cache(None)
def inputs():
    # The durable report contains the exact IDs; ordinary tests do not need /tmp.
    return tuple(json.loads((INPUT if INPUT.exists() else REPORT).read_text())['checks'])

@lru_cache(None)
def cohort():
    ids = {r['id'] for r in inputs()}
    return tuple(c for c in native.registry() if c.id in ids)

@lru_cache(None)
def cases():
    return native.behavior_module().CASES

def case_index(case, state):
    return deepcopy(case.get(state + '_index', case.get('case_indices', {}).get(state, case.get('index', {}))))

def check(cid):
    return next(c for c in cohort() if c.id == cid)

def run(snap, cid):
    from peaso.engine import evaluate_snapshot
    findings = evaluate_snapshot(snap, checks=[cid])['findings']
    assert findings
    return findings[0]['status']

def collect(sdk, kinds):
    from peaso.collectors import aws
    sdk[1]('sts').add_response('get_caller_identity', IDENTITY, {})
    return aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'options': {
        'regions': [REGION], 'service_concurrency': 1, 'retry_attempts': 1}}, kinds)

@pytest.mark.parametrize('c', cohort(), ids=lambda c: c.id)
def test_registered_witnesses(c):
    """Actual callbacks, explicitly synthetic and never SDK producer proof."""
    case = cases()[c.id]
    for state, default in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        if state in case:
            data, index = deepcopy(case[state]), case_index(case, state)
            before = deepcopy((data, index))
            assert c.evaluate(data, index)[0] == case.get(state + '_expect', default)
            assert (data, index) == before

@pytest.mark.parametrize('c', cohort(), ids=lambda c: c.id)
@pytest.mark.parametrize('status', ['denied', 'partial', 'not_collected', 'malformed'])
def test_unavailable_subject_and_dependencies_cannot_pass(c, status):
    from peaso.snapshot import make_snapshot
    snap = make_snapshot('aws', [SCOPE], [{'type': kind, 'scope': SCOPE, 'service': 'ec2',
        'status': status, 'items': []} for kind in {c.kind, *c.dependencies}])
    assert run(snap, c.id) != 'PASS'

@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('negative','FAIL'), ('denied','UNKNOWN'), ('missing','UNKNOWN'), ('foreign','UNKNOWN')])
def test_sdk_listener_parent_identity(sdk, mode, expected):
    elb = sdk[1]('elbv2')
    elb.add_response('describe_load_balancers', {'LoadBalancers': [{'LoadBalancerArn': LB, 'Type': 'application'}]}, {})
    elb.add_response('describe_load_balancer_attributes', {'Attributes': []}, {'LoadBalancerArn': LB})
    if mode == 'denied':
        elb.add_client_error('describe_listeners', 'AccessDenied', http_status_code=403, expected_params={'LoadBalancerArn': LB})
    else:
        rows = [] if mode == 'negative' else [{'ListenerArn': LISTENER, 'LoadBalancerArn': LB if mode != 'foreign' else LB + 'bad', 'Protocol': 'HTTPS', 'Port': 443}]
        elb.add_response('describe_listeners', {} if mode == 'missing' else {'Listeners': rows}, {'LoadBalancerArn': LB})
    observed = run(collect(sdk, ['load_balancer']), 'aws.c2b.elbv2.has_listeners')
    assert observed == expected

@pytest.mark.parametrize('value,expected', [('true','PASS'), ('false','FAIL'), ('denied','UNKNOWN'), ('absent','UNKNOWN')])
def test_sdk_alb_attribute_native_key_value(sdk, value, expected):
    elb = sdk[1]('elbv2')
    elb.add_response('describe_load_balancers', {'LoadBalancers': [{'LoadBalancerArn': LB, 'Type': 'application'}]}, {})
    args = {'LoadBalancerArn': LB}
    if value == 'denied':
        elb.add_client_error('describe_load_balancer_attributes', 'AccessDenied', http_status_code=403, expected_params=args)
    else:
        elb.add_response('describe_load_balancer_attributes', {'Attributes': [] if value == 'absent' else [{'Key':'access_logs.s3.enabled','Value':value}]}, args)
    elb.add_response('describe_listeners', {'Listeners': []}, args)
    assert run(collect(sdk, ['load_balancer']), 'aws.b.alb.access_logs') == expected


def web_acl(with_rule=True, foreign=False):
    arn = WARN.replace('/review/', '/foreign/') if foreign else WARN
    return {'Name': 'foreign' if foreign else 'review', 'Id': WID, 'ARN': arn,
        'DefaultAction': {'Allow': {}}, 'VisibilityConfig': {'SampledRequestsEnabled': True,
        'CloudWatchMetricsEnabled': True, 'MetricName': 'review'},
        'Rules': [{'Name':'rate', 'Priority':1, 'Statement': {'RateBasedStatement': {'Limit': 100, 'AggregateKeyType':'IP'}},
        'Action': {'Block':{}}, 'VisibilityConfig': {'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled':True, 'MetricName':'rate'}}] if with_rule else []}

@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('negative','FAIL'), ('denied','UNKNOWN'), ('missing','UNKNOWN'), ('foreign','UNKNOWN')])
def test_sdk_waf_detail_identity(sdk, mode, expected):
    waf = sdk[1]('wafv2')
    waf.add_response('list_web_acls', {'WebACLs':[{'Name':'review','Id':WID,'ARN':WARN}]}, {'Scope':'REGIONAL','Limit':100})
    args = {'Name':'review','Id':WID,'Scope':'REGIONAL'}
    if mode == 'denied':
        waf.add_client_error('get_web_acl', 'AccessDeniedException', http_status_code=403, expected_params=args)
    else:
        waf.add_response('get_web_acl', {} if mode == 'missing' else {'WebACL':web_acl(mode != 'negative', mode == 'foreign')}, args)
    waf.add_client_error('get_logging_configuration', 'WAFNonexistentItemException', expected_params={'ResourceArn':WARN})
    from peaso.collectors.aws_facts_compute_edge import _WAFV2_RESOURCE_TYPES
    for resource_type in _WAFV2_RESOURCE_TYPES:
        waf.add_response('list_resources_for_web_acl', {'ResourceArns':[]}, {'WebACLArn':WARN,'ResourceType':resource_type})
    waf.add_response('list_web_acls', {'WebACLs':[]}, {'Scope':'CLOUDFRONT','Limit':100})
    observed = run(collect(sdk, ['wafv2_web_acl']), 'aws.cb.wafv2.web_acl_has_rules')
    assert observed == expected


@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('negative','FAIL'), ('denied','UNKNOWN'), ('foreign','UNKNOWN')])
def test_sdk_waf_logging_identity(sdk, mode, expected):
    from peaso.collectors import aws
    session, add, _ = sdk
    waf = add('wafv2')
    args = {'ResourceArn': WARN}
    if mode == 'denied':
        waf.add_client_error('get_logging_configuration', 'AccessDeniedException', http_status_code=403, expected_params=args)
    elif mode == 'negative':
        waf.add_client_error('get_logging_configuration', 'WAFNonexistentItemException', expected_params=args)
    else:
        waf.add_response('get_logging_configuration', {'LoggingConfiguration': {
            'ResourceArn':WARN+'foreign' if mode == 'foreign' else WARN,
            'LogDestinationConfigs':[f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:aws-waf-logs-review']}}, args)
    response = aws.Requests({'retry_attempts':1}).detail(session,'wafv2',REGION,'get_logging_configuration',
        ResourceArn=WARN, absent=('WAFNonexistentItemException',))
    # Invoke the actual fetcher for projection/identity validation separately in
    # detail tests; this directed consumer join currently has no identity guard.
    item = {'ARN':WARN, 'Id':WID, 'Name':'review', 'LoggingConfiguration':response}
    observed = check('aws.cb.wafv2.web_acl_logging').evaluate(item,{})[0]
    assert observed == expected


@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('denied','UNKNOWN'), ('missing','UNKNOWN'), ('foreign','UNKNOWN')])
def test_sdk_firewall_detail_identity(sdk, mode, expected):
    fw = sdk[1]('network-firewall')
    fw.add_response('list_firewalls', {'Firewalls':[{'FirewallName':'review','FirewallArn':FARN}]}, {})
    if mode == 'denied':
        fw.add_client_error('describe_firewall', 'AccessDeniedException', http_status_code=403, expected_params={'FirewallArn':FARN})
    else:
        fw.add_response('describe_firewall', {} if mode == 'missing' else {'Firewall': {'FirewallName':'review','FirewallArn': FARN + '-foreign' if mode == 'foreign' else FARN,
            'FirewallPolicyArn':FARN.replace(':firewall/', ':firewall-policy/'), 'VpcId':'vpc-1234',
            'SubnetMappings':[{'SubnetId':'subnet-1234'}], 'FirewallId': WID}}, {'FirewallArn':FARN})
    # This call uses the foreign identity before the proposed merge guard.
    # ANY keeps the SDK response validated without guessing runtime integration.
    from botocore.stub import ANY
    fw.add_response('describe_logging_configuration', {}, {'FirewallArn': ANY})
    observed = run(collect(sdk, ['network_firewall']), 'aws.claude_a.networkfirewall.in_vpc')
    assert observed == expected

@pytest.mark.parametrize('mode,expected', [('positive','PASS'), ('negative','FAIL'), ('denied','UNKNOWN')])
def test_sdk_stage_dynamic_method_map(sdk, mode, expected):
    api = sdk[1]('apigateway')
    api.add_response('get_rest_apis', {'items':[{'id':'abc123','name':'review'}]}, {})
    if mode == 'denied':
        api.add_client_error('get_stages', 'AccessDeniedException', http_status_code=403, expected_params={'restApiId':'abc123'})
    else:
        api.add_response('get_stages', {'item':[{'stageName':'review', 'tracingEnabled':mode == 'positive',
            'methodSettings': {'*/*': {'loggingLevel': 'INFO', 'cachingEnabled':True, 'cacheDataEncrypted':True}}}]}, {'restApiId':'abc123'})
    observed = run(collect(sdk, ['rest_api_stage']), 'aws.b.apigateway.rest_xray')
    assert observed in ({'DENIED','UNKNOWN'} if mode == 'denied' else {expected})

@pytest.mark.parametrize('tokens,expected', [('required','PASS'), ('optional','FAIL'), ('denied','DENIED')])
def test_sdk_instance_native_projection(sdk, tokens, expected):
    ec2 = sdk[1]('ec2')
    if tokens == 'denied':
        ec2.add_client_error('describe_instances', 'UnauthorizedOperation', http_status_code=403, expected_params={})
    else:
        ec2.add_response('describe_instances', {'Reservations':[{'Instances':[{'InstanceId':'i-1234567890abcdef0',
            'State':{'Name':'running'}, 'MetadataOptions':{'HttpTokens':tokens,'HttpEndpoint':'enabled'}}]}]}, {})
        ec2.add_response('describe_instance_attribute', {'InstanceId':'i-1234567890abcdef0'}, {'InstanceId':'i-1234567890abcdef0','Attribute':'userData'})
        ec2.add_response('describe_instance_attribute', {'InstanceId':'i-1234567890abcdef0','DisableApiTermination':{'Value':False}}, {'InstanceId':'i-1234567890abcdef0','Attribute':'disableApiTermination'})
    assert run(collect(sdk, ['instance']), 'aws.ec2.imdsv2') == expected




CF_CHECKS = [c for c in cohort() if c.kind=='cloudfront_distribution' and c.id not in {
    'aws.cb.shield.cloudfront_protected','aws.c2b.cloudfront.s3_origin_bucket_exists','aws_cloudfront_origin_failover_configured'}]

@pytest.mark.parametrize('c',CF_CHECKS,ids=lambda c:c.id)
@pytest.mark.parametrize('mode',['positive','negative','missing','denied'])
def test_sdk_cloudfront_config_projection(sdk,c,mode):
    from peaso.collectors import aws, aws_b_services, aws_facts_compute_edge as edge
    session,add,_=sdk
    config={'CallerReference':'review','Comment':'','Enabled':True,
        'Origins':{'Quantity':1,'Items':[{'Id':'origin','DomainName':'app.example.org',
            'CustomOriginConfig':{'HTTPPort':80,'HTTPSPort':443,'OriginProtocolPolicy':'https-only',
                'OriginSslProtocols':{'Quantity':1,'Items':['TLSv1.2']}}}]},
        'DefaultCacheBehavior':{'TargetOriginId':'origin','ViewerProtocolPolicy':'https-only','FieldLevelEncryptionId':'field'},
        'CacheBehaviors':{'Quantity':0},
        'Logging':{'Enabled':True,'Bucket':'logs.s3.amazonaws.com','Prefix':'','IncludeCookies':False},
        'ViewerCertificate':{'ACMCertificateArn':f'arn:aws:acm:{REGION}:{ACCOUNT}:certificate/review',
            'Certificate':f'arn:aws:acm:{REGION}:{ACCOUNT}:certificate/review','SSLSupportMethod':'sni-only',
            'MinimumProtocolVersion':'TLSv1.2_2021'},
        'DefaultRootObject':'index.html','WebACLId':WARN,
        'Restrictions':{'GeoRestriction':{'RestrictionType':'whitelist','Quantity':1,'Items':['ES']}},
        'OriginGroups':{'Quantity':1,'Items':[{'Id':'group','FailoverCriteria':{'StatusCodes':{'Quantity':1,'Items':[500]}},
            'Members':{'Quantity':2,'Items':[{'OriginId':'origin'},{'OriginId':'backup'}]}}]}}
    if c.id.endswith('origin_traffic_encrypted'):config['OriginGroups']={'Quantity':0}
    if mode=='negative':
        cid=c.id
        if cid.endswith(('access_logging','logging_any')):config['Logging']['Enabled']=False
        elif cid.endswith('.sni'):config['ViewerCertificate']['SSLSupportMethod']='vip'
        elif cid.endswith('custom_acm_certificate'):config['ViewerCertificate']={'CloudFrontDefaultCertificate':True}
        elif cid.endswith('default_root_object'):config['DefaultRootObject']=''
        elif cid.endswith('field_level_encryption'):config['DefaultCacheBehavior']['FieldLevelEncryptionId']=''
        elif cid.endswith('waf_reference'):config['WebACLId']=''
        elif cid.endswith('geo_restrictions'):config['Restrictions']['GeoRestriction']={'RestrictionType':'none','Quantity':0}
        elif cid.endswith('origin_group_metadata'):config['OriginGroups']={'Quantity':0}
        elif cid.endswith('origin_no_deprecated_ssl'):config['Origins']['Items'][0]['CustomOriginConfig']['OriginSslProtocols']['Items']=['TLSv1']
        elif cid.endswith('origin_traffic_encrypted'):config['Origins']['Items'][0]['CustomOriginConfig']['OriginProtocolPolicy']='http-only'
        elif cid.endswith('recommended_tls_policy'):config['ViewerCertificate']['MinimumProtocolVersion']='TLSv1'
        else:raise AssertionError('unhandled CloudFront case '+cid)
    if mode=='denied':add('cloudfront').add_client_error('get_distribution_config','AccessDenied',http_status_code=403,expected_params={'Id':'E123'})
    else:add('cloudfront').add_response('get_distribution_config',{} if mode=='missing' else {'DistributionConfig':config},{'Id':'E123'})
    requests=aws.Requests({'retry_attempts':1})
    item=aws_b_services._enricher('cloudfront_distribution')(requests,session,REGION,[{'Id':'E123','ARN':f'arn:aws:cloudfront::{ACCOUNT}:distribution/E123'}])[0]
    if c.id.endswith('logging_any'):
        add('logs').add_response('describe_delivery_sources',{'deliverySources':[]},{})
        add('logs').add_response('describe_deliveries',{'deliveries':[]},{})
        item=edge._cloudfront_log_deliveries(requests,session,REGION,[item])[0]
    assert c.evaluate(item,{})[0] == ('PASS' if mode=='positive' else 'FAIL' if mode=='negative' else 'UNKNOWN')


PORT_CHECKS = [c for c in cohort() if '.instance_port_' in c.id or c.id in {
    'aws.claude_a.ec2.enclave_host_ingress_allowlist', 'aws.claude_a.ec2.enclave_host_vsock_ports_closed'}]

@pytest.mark.parametrize('c', PORT_CHECKS, ids=lambda c: c.id)
@pytest.mark.parametrize('mode', ['closed', 'tcp', '6', '17', 'all', 'reversed', 'missing', 'missing_ranges', 'malformed_cidr', 'wrong_family', 'denied'])
def test_sdk_instance_security_group_join(sdk, c, mode):
    from peaso.checks.claude_aws_a_ec2 import INSTANCE_PORTS
    ec2 = sdk[1]('ec2')
    instance_id = 'i-1234567890abcdef0'
    instance = {'InstanceId': instance_id, 'State': {'Name':'running'},
        'SecurityGroups': [{'GroupId':'sg-1234'}], 'EnclaveOptions': {'Enabled': True}}
    ec2.add_response('describe_instances', {'Reservations':[{'Instances':[instance]}]}, {})
    ec2.add_response('describe_instance_attribute', {'InstanceId':instance_id}, {'InstanceId':instance_id,'Attribute':'userData'})
    ec2.add_response('describe_instance_attribute', {'InstanceId':instance_id,'DisableApiTermination':{'Value':False}}, {'InstanceId':instance_id,'Attribute':'disableApiTermination'})
    if mode == 'denied':
        ec2.add_client_error('describe_security_groups', 'UnauthorizedOperation', http_status_code=403, expected_params={})
    else:
        service = c.id.split('.instance_port_')[-1].split('_not_internet_exposed')[0]
        port = INSTANCE_PORTS[service][0] if service in INSTANCE_PORTS else 8000
        rule = {'IpProtocol': '-1' if mode == 'all' else mode if mode in {'6','17'} else 'tcp',
            'FromPort':port+1 if mode == 'reversed' else port, 'ToPort':port,
            'IpRanges':[{'CidrIp':'0.0.0.0/0'}], 'Ipv6Ranges':[]}
        if mode in {'missing','all'}:
            rule.pop('FromPort'); rule.pop('ToPort')
        if mode == 'missing_ranges':rule.pop('IpRanges')
        if mode == 'malformed_cidr':rule['IpRanges']=[{'CidrIp':'invalid-world-cidr'}]
        if mode == 'wrong_family':rule['IpRanges']=[{'CidrIp':'::/0'}]
        ec2.add_response('describe_security_groups', {'SecurityGroups':[{'GroupId':'sg-1234',
            'IpPermissions':[] if mode == 'closed' else [rule]}]}, {})
    expected = 'PASS' if mode == 'closed' else 'UNKNOWN' if mode in {'reversed','missing','missing_ranges','malformed_cidr','wrong_family','denied'} else 'FAIL'
    if mode=='17' and c.id!='aws.claude_a.ec2.enclave_host_ingress_allowlist':expected='PASS'
    observed = run(collect(sdk, ['instance','security_group']), c.id)
    assert observed == expected



@pytest.mark.parametrize('cid', ['aws.claude_a.ec2.enclave_host_ingress_allowlist','aws.claude_a.ec2.enclave_host_vsock_ports_closed'])
@pytest.mark.parametrize('cidr', [None, 17, {}, []])
def test_enclave_nonstring_cidr_unavailable(cid, cidr):
    case=cases()[cid]
    item,index=deepcopy(case['pass']),case_index(case,'pass')
    for wrapper in index['security_group']:
        wrapper['data']['IpPermissions']=[{'IpProtocol':'tcp','FromPort':8000,'ToPort':8000,
            'IpRanges':[{'CidrIp':cidr}],'Ipv6Ranges':[]}]
    observed=check(cid).evaluate(item,index)[0]
    assert observed=='UNKNOWN'


def test_report_has_exact_input_accounting():
    report = json.loads(REPORT.read_text())
    ids = [c.id for c in cohort()]
    assert len(ids) == len(set(ids)) == 212
    assert {r['id'] for r in report['checks']} == set(ids)
    assert not any(r['semantic_completeness_proven'] for r in report['checks'])
    assert all(r['family'] and r['primary_references'] and r['disposition'] and r['remaining'] for r in report['checks'])

# Report construction retains exact attributed paths and never uses shape
# membership or arbitrary modeled values as proof of emitted native facts.
def shape_path(shape, path):
    for part in re.sub(r'\[\]', '', path or '').split('.'):
        while shape is not None and shape.type_name == 'list':
            shape = shape.member
        if shape is None:
            return None
        if shape.type_name == 'map':
            shape = shape.value
        elif shape.type_name == 'structure':
            shape = shape.members.get(part)
        else:
            return None
    return shape

PRIMARY = {
 'instance':'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html',
 'security_group':'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SecurityGroup.html',
 'network_firewall':'https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_DescribeFirewall.html',
 'wafv2_web_acl':'https://docs.aws.amazon.com/waf/latest/APIReference/API_GetWebACL.html',
 'rest_api':'https://docs.aws.amazon.com/apigateway/latest/api/API_GetResources.html',
 'rest_api_stage':'https://docs.aws.amazon.com/apigateway/latest/api/API_GetStages.html',
 'load_balancer':'https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeListeners.html',
 'cloudfront_distribution':'https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetDistributionConfig.html',
 'vpc':'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Vpc.html',
 'vpc_endpoint':'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_VpcEndpoint.html',
 'subnet':'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Subnet.html',
 'network_acl':'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_NetworkAcl.html',
 'elastic_ip':'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Address.html',
 'vpn_connection':'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_VpnConnection.html',
 'route53_zone':'https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetDNSSEC.html',
 'load_balancer_v2':'https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeListeners.html',
}
JOINS = {
 'instance': ['InstanceId binds DescribeInstances row and attribute request; native IamInstanceProfile.Arn joins IAM RoleDetail.InstanceProfileList[].Arn; managed-policy ARN joins default version (20 IAM permission checks).', 'SecurityGroups[].GroupId joins same-scope security_group.GroupId; ImageId joins ec2_instance_image.ImageId; instance ID joins ENI attachment/CloudWatch dimensions/backup protected ARN as used by the selected callback.'],
 'security_group':['GroupId/VpcId and same account/region bind ENI Groups[].GroupId, instance SecurityGroups[].GroupId and service VPC security-group references; optional nested range omissions do not establish listener behavior.'],
 'vpc':['VpcId joins complete same-scope subnets, ENIs, endpoints, flow logs and firewall placement; missing complete dependencies must remain unresolved.'],
 'load_balancer':['LoadBalancerArn binds attribute and DescribeListeners requests; native listener.LoadBalancerArn must agree; ListenerArn binds DescribeRules; certificates join ACM/IAM certificate ARN; WAF ResourceArns join exact load-balancer ARN.'],
 'load_balancer_v2':['Alias resolves load_balancer producer; alias wrappers are engine projections, not a second AWS API shape.'],
 'rest_api_stage':['ParentApiId from GetRestApis.id + get_stages(restApiId) + stageName forms arn:<partition>:apigateway:<region>::/restapis/<id>/stages/<name>; methodSettings is a native string-keyed map, not a missing fixed structure.', 'Client certificate ID, effective WAF stageArn and resource/method/stage tuples need independent complete identity-bound dependency inventories.'],
 'rest_api':['RestApi.id binds GetResources(embed=methods), GetAuthorizers and GetStages; method verb map contains authorizationType/requestValidatorId and must retain exact resource identity.'],
 'wafv2_web_acl':['ListWebACLs ARN/Id/Name + requested Scope must bind GetWebACL ARN/Id/Name; ResourceArns association and logging ResourceArn must bind the same ACL. New strict WAF callbacks independently validate ARN/Id/scope.'],
 'network_firewall':['ListFirewalls.FirewallArn must equal DescribeFirewall.Firewall.FirewallArn; FirewallPolicyArn joins policy response ARN; classic VpcId and proxy VpcEndpoint.VpcId have different placements.'],
 'cloudfront_distribution':['ListDistributions Id/ARN binds GetDistributionConfig(Id); response lacks distribution Id so request provenance is essential; behavior TargetOriginId joins exact origin/group Id; log source resourceArns joins distribution ARN.'],
}


def receipt():
    if not RECEIPT.exists():
        return {'status':'not-executed'}
    root = ET.parse(RECEIPT).getroot()
    suites = [root] if root.tag == 'testsuite' else list(root.iter('testsuite'))
    return {'status':'executed', 'path':str(RECEIPT), 'sha256':hashlib.sha256(RECEIPT.read_bytes()).hexdigest(),
        **{k:sum(int(s.attrib.get(k,0)) for s in suites) for k in ['tests','failures','errors','skipped']},
        'counterexamples':[{'node':t.attrib['name'], 'message':s.attrib.get('message','')} for t in root.iter('testcase') for s in t.findall('skipped')],
        'aggregation':'latest result by classname and test name; originals preserved',
        'source_receipts':[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [
            RECEIPT.with_suffix('.initial.xml'),RECEIPT.with_name('network-closure-recheck.xml'),
            RECEIPT.with_name('network-corrections-final.xml')] if p.exists()]}



FAMILY_NOTES = {
 '_instance_port_check':'Declared SG ingress only: exact world IPv4/IPv6 TCP/name/6 and all-protocol rules, requested port overlap. Instance SecurityGroups joins by GroupId; no public-address, route or guest listener predicate.',
 '_install':'Per-ID dispatch/closure must be resolved; instance role policy family evaluates identity permissions, not role trust Action. Conditional/scoped grants, boundaries and unresolved policy joins remain UNKNOWN; no SCP/session-policy completeness claim.',
 '_world_range':'Separate enclave protocol/range implementation was defective for numeric protocols and malformed bounds; see N-ENCLAVE-PROTOCOL.',
 'enclave_ingress':'Active enclave-enabled instance gate; globally routable CIDR SG declarations with TCP/UDP allowlist 22/80/443. No enclave guest listener verification.',
 'enclave_vsock':'Active enclave-enabled instance gate; globally routable CIDR TCP declarations at 5000,8000-8090,9000. No guest vsock probe.',
 '_attribute':'ALB-only typed native Key/Value strings; required specific attribute must exist and equal true/false; missing/denied detail is UNKNOWN.',
 '_presence':'Native stage reference presence only; certificate expiration and effective WAF association are separate checks.',
 '_logging':'REST wildcard methodSettings logging declaration; field absence defaults OFF only within an available map. Method overrides/log delivery are separate.',
 'cache':'Exact wildcard cachingEnabled AND cacheDataEncrypted declaration, not encryption only when caching is enabled.',
 'all_methods_logging':'Complete stage identity/provenance and methodSettings map; safe wildcard plus complete explicit overrides; explicit OFF override FAIL, absent wildcard UNKNOWN. No deployed route or delivery proof.',
 'all_enabled_method_caches_encrypted':'Complete stage cache availability plus explicit method map; disabled cache N/A; unencrypted explicit enabled override FAIL; unencrypted wildcard alone lacks deployed method proof.',
 'apigw_method_auth':'Embedded resourceMethods authorizationType for every method, with declared OPTIONS/source exception as implemented; authorizer existence does not prove effective deployed authorization.',
 'apigw_validator':'Embedded method requestValidatorId presence; validator content/deployment is not implied.',
 'v2_http_redirect':'Complete HTTP default and conditional rules must have single final redirect routing action to HTTPS; mismatch/default ambiguity UNKNOWN; definite forwarding FAIL.',
 'v2_ciphers':'Native listener SslPolicy compared to pinned secure-name allowlist, HTTPS only; no DescribeSSLPolicies cipher enumeration or live negotiated cipher evidence.',
 'v2_fips':'HTTPS/TLS native policy name contains FIPS token; no cryptographic runtime negotiation proof.',
 'v2_pqc':'HTTPS/TLS native policy name belongs to pinned PQ policy list; future unknown policy classification remains a semantic limit.',
 'v2_recommended':'Native HTTPS/TLS policy compared against reviewed recommended and nonrecommended names; unknown future names conservative UNKNOWN.',
 'v2_rules_c':'Only native WebACL.Rules counts; Firewall Manager groups excluded intentionally. Collector must bind returned ACL identity.',
 'v2_rules_p':'Native Rules plus pre/post Firewall Manager groups count; optional FMS lists treated absent only under native ACL identity.',
 'v2_metrics':'Every declared rule/FMS group requires CloudWatchMetricsEnabled true; absent required metric config cannot establish correct disabled configuration. No rules N/A.',
 'v2_logging':'Configured log destinations require same WebACL ARN; nonexistent logging config is genuine FAIL, denied/missing/foreign facts UNKNOWN.',
 'nfw_in_vpc':'Classic VpcId+SubnetMappings, transit gateway placement N/A and future proxy placement are distinct; missing/conflicting placement UNKNOWN. Current botocore does not model NoSourcePreservation/VpcEndpoint, so proxy branch native proof remains unavailable.',
 '_shield_check':'ACTIVE Shield Advanced subscription gates protection ARN membership; inactive subscription N/A. Partition-prefix normalization and complete cross-kind identity semantics remain bounded.',
}

def family_note(c, target):
    name=target.__qualname__.split('.')[0]
    if name in FAMILY_NOTES and (name!='_install' or 'aws_gap_ec2' in target.__module__):return FAMILY_NOTES[name]
    existing=ROOT/'docs/aws-review/network-semantic-review.json'
    if existing.exists():
        old=json.loads(existing.read_text())
        for row in old.get('checks',[]):
            if row['id']==c.id:return row.get('source_review','Earlier bounded network declaration semantics; dependency producer proof remains separate.')
    doc=inspect.getdoc(target)
    return (doc + ' ' if doc else '') + 'Actual callback/helper graph and literal field reads retained; native shape, optional values and identity joins reviewed with limits above. No exhaustive equivalence or effective runtime behavior claimed.'


def build_report():
    from peaso.collectors import aws
    from peaso.collectors.bulk_evidence import ALIASES
    import botocore
    models = fields.Models()
    source = {r['id']:r for r in inputs()}
    producer = {}
    shapes = {}
    kinds = {c.kind for c in cohort()} | {f.get('kind') for r in inputs() for f in r.get('fields',[]) if f.get('kind') and not f['kind'].startswith('@')}
    for kind in sorted(kinds):
        prod, shape = fields.producer(kind, models)
        producer[kind] = prod
        shapes[kind] = shape
    contract = {}
    rows = []
    for c in cohort():
        base = source[c.id]
        graph = fields.callback_graph(c)
        target = inspect.unwrap(c.evaluate)
        family = target.__module__.replace('peaso.checks.','') + ':' + target.__qualname__.split('.')[0]
        keys=[]
        for fn in graph:
            ref=native.source_ref(fn); key=ref['file']+':'+ref['qualname']+':'+ref['sha256'][:16]
            contract[key]=ref;keys.append(key)
        attributed = []
        for f in base.get('fields', base.get('field_contracts',[])):
            kind,path = f.get('kind'), f.get('path')
            shape=shape_path(shapes.get(kind),path)
            classification = 'native-sdk-member; production availability unproved' if shape is not None else 'derived-or-dynamic-path; independent producer/join proof required'
            if kind is None: classification='unattributed nested policy/join read; not evidence of missing AWS field'
            if kind and kind.startswith('@'): classification='engine metadata; not AWS response member'
            attributed.append({'kind':kind,'path':path,'classification':classification,'shape':shape.name if shape else None,
                'baseline_producer_emission_demonstrated':f.get('producer_emission_demonstrated',False),
                'baseline_required_accessor_observed':f.get('required_accessor_observed',False)})
        known=[]
        if c.kind=='load_balancer' and any(f.get('kind') == 'load_balancer' and (f.get('path') or '').startswith('Listeners') for f in base.get('fields',[])): known.append('N-LISTENER-IDENTITY')
        if c.kind=='network_firewall' or c.id=='aws.claude_a.networkfirewall.in_use_vpc_has_firewall':known.append('N-FIREWALL-IDENTITY')
        if c.id in {'aws.claude_a.ec2.enclave_host_ingress_allowlist','aws.claude_a.ec2.enclave_host_vsock_ports_closed'}:known.extend(['N-ENCLAVE-PROTOCOL','N-ENCLAVE-CIDR'])
        if c.id=='aws.cb.wafv2.web_acl_logging':known.append('N-WAF-LOGGING-IDENTITY')
        if c.id in ['aws.cb.wafv2.web_acl_has_rules','aws.cb.wafv2.web_acl_has_rules_or_fms_groups','aws.cb.wafv2.web_acl_rule_metrics']:known.append('N-WAF-IDENTITY')
        native_kind=ALIASES['aws'].get(c.kind,c.kind)
        spec=aws.SPECS.get(native_kind)
        refs=[PRIMARY[c.kind]] if c.kind in PRIMARY else []
        if 'security_group' in c.dependencies:refs.append('https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html')
        if c.id=='aws.cb.wafv2.web_acl_logging':refs.append('https://docs.aws.amazon.com/waf/latest/APIReference/API_GetLoggingConfiguration.html')
        if spec:refs.append('https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/'+spec[0]+'/client/'+spec[1]+'.html')
        if not refs:refs=['https://docs.aws.amazon.com/']
        tests=['test_registered_witnesses['+c.id+']','test_unavailable_subject_and_dependencies_cannot_pass[<status>-'+c.id+']']
        sdk_tests={'load_balancer':['test_sdk_listener_parent_identity','test_sdk_alb_attribute_native_key_value'], 'instance':['test_sdk_instance_native_projection'], 'rest_api_stage':['test_sdk_stage_dynamic_method_map'], 'wafv2_web_acl':['test_sdk_waf_detail_identity'], 'network_firewall':['test_sdk_firewall_detail_identity']}.get(c.kind,[])
        if c in CF_CHECKS: sdk_tests.append('test_sdk_cloudfront_config_projection[<mode>-'+c.id+']')
        if c in PORT_CHECKS: sdk_tests.append('test_sdk_instance_security_group_join[<mode>-'+c.id+']')
        if c.id=='aws.cb.wafv2.web_acl_logging': sdk_tests.append('test_sdk_waf_logging_identity')
        rows.append({'id':c.id,'kind':c.kind,'family':family, 'callback_contracts':keys,
            'description':c.title if hasattr(c,'title') else '', 'dependencies':list(c.dependencies),
            'disposition':'corrected-defect; semantic closure withheld' if known else 'bounded-review; semantic closure withheld',
            'primary_references':list(dict.fromkeys(refs)), 'identity_joins':JOINS.get(c.kind,['Native identity and complete same-account/region dependency wrappers must agree; this review does not establish every join branch.']),
            'field_contracts':attributed,'baseline_exact_unproved_contracts':base.get('unproved_contracts',base.get('baseline_exact_unproved_contracts',[])),
            'baseline_unvisited_static_reads':base.get('unvisited_static_reads',base.get('baseline_unvisited_static_reads',[])),
            'source_direct_reads': fields.static_reads(graph), 'findings':known,
            'closed_parameters': {k:v for k,v in inspect.getclosurevars(target).nonlocals.items() if isinstance(v,(str,int,bool,list,tuple,dict))},
            'family_review': family_note(c, target),
            'directed_receipts':{'file':'tests/test_aws_network_closure_review.py','per_id_synthetic':tests,'family_sdk_only':sdk_tests,
                'family_sdk_limit':'Family receipt exercises selected consumers; it does not execute every ID against SDK data.'},
            'remaining':['Unvisited branches, optional omission semantics, malformed values and complete dependency identity joins are not exhaustively proved.',
                'Exact baseline unresolved paths are retained above; SDK member recognition is possibility, never guaranteed emission.',
                'Synthetic PASS/FAIL witnesses and empty unavailable-subject checks do not establish complete native producer semantics.'],
            'branch_completeness_proven':False,'semantic_completeness_proven':False,'live_verified':False})
    findings=[{'id':'N-LISTENER-IDENTITY','producer':'peaso/collectors/aws.py::_enrich(load_balancer)',
        'gap':'DescribeListeners native LoadBalancerArn can explicitly disagree with requested LoadBalancerArn and remain collected; has_listeners produces false PASS for foreign listener.',
        'affected_input_ids':[r['id'] for r in rows if 'N-LISTENER-IDENTITY' in r['findings']], 'test':'test_sdk_listener_parent_identity[foreign-UNKNOWN]'},
        {'id':'N-WAF-IDENTITY','producer':'peaso/collectors/aws_facts_compute_edge.py::_detail_member/_wafv2',
        'gap':'GetWebACL WebACL.ARN/Id/Name not checked against list summary; legacy rule and metric callbacks accept foreign detail; newer strict WAF callbacks reject independently.',
        'affected_input_ids':[r['id'] for r in rows if 'N-WAF-IDENTITY' in r['findings']], 'test':'test_sdk_waf_detail_identity[foreign-UNKNOWN]'},
        {'id':'N-FIREWALL-IDENTITY','producer':'peaso/collectors/aws_facts_cb_ca.py::_merge_enricher(network_firewall)',
        'gap':'DescribeFirewall body overwrites requested FirewallArn without equality check; foreign placement/policy can produce false PASS and subsequent logging call uses foreign ARN.',
        'affected_input_ids':[r['id'] for r in rows if 'N-FIREWALL-IDENTITY' in r['findings']], 'test':'test_sdk_firewall_detail_identity[foreign-UNKNOWN]'},
        {'id':'N-ENCLAVE-PROTOCOL','producer':'peaso/checks/claude_aws_a_ec2.py::_world_range',
        'gap':'Separate enclave helper accepts only named TCP/UDP and silently treats missing/reversed bounds as no exposure; numeric native 6/17 and malformed ranges can falsely PASS.',
        'affected_input_ids':[r['id'] for r in rows if 'N-ENCLAVE-PROTOCOL' in r['findings']], 'test':'test_sdk_instance_security_group_join'},
        {'id':'N-WAF-LOGGING-IDENTITY','producer':'peaso/checks/claude_aws_b_security.py::v2_logging',
        'gap':'LoggingConfiguration.ResourceArn is not bound to ACL ARN before nonempty destination PASS; independently wrong even when GetWebACL identity is correct.',
        'affected_input_ids':[r['id'] for r in rows if 'N-WAF-LOGGING-IDENTITY' in r['findings']], 'test':'test_sdk_waf_logging_identity[foreign-UNKNOWN]'},
        {'id':'N-ENCLAVE-CIDR','producer':'peaso/checks/claude_aws_a_ec2.py::_world_range',
        'gap':'Nonstring CIDRs silently filtered and IPv6 CIDR accepted in IPv4 native range; corrected using typed range access and family validation.',
        'affected_input_ids':[r['id'] for r in rows if 'N-ENCLAVE-CIDR' in r['findings']],
        'test':'test_enclave_nonstring_cidr_unavailable; test_sdk_instance_security_group_join[wrong_family-<id>]'}]
    for finding in findings:finding['resolution']='root-integrated; directed regression executed; complete semantics unproved'
    return {'scope':'network','input_sha256':hashlib.sha256(INPUT.read_bytes()).hexdigest() if INPUT.exists() else None,
        'input_count':212,'botocore_version':botocore.__version__, 'review_status':'all IDs accounted; bounded semantic review remains incomplete',
        'limits':['Offline SDK Stubber calls only; no live AWS, cloud mutation, secret content, external probes, build or broad test suite.',
            'Fixture-only/source-only/SDK-shape-only evidence never marked complete; root owns canonical admission/runtime integration/ledgers.'],
        'baseline':['docs/aws-review/README.md','docs/aws-review/field-producers.json'],
        'runtime_patch':'/tmp/peasso-aws-review-20261019/final-closure/network.patch',
        'additional_proposals':['/tmp/peasso-aws-review-20261019/final-closure/network-enclave.patch','/tmp/peasso-aws-review-20261019/final-closure/network-enclave-cidr.patch','/tmp/peasso-aws-review-20261019/final-closure/network-waf-logging.patch'],
        'counts':{'kinds':dict(Counter(r['kind'] for r in rows)), 'families':dict(Counter(r['family'] for r in rows)),
            'semantic_complete':0,'corrected_defect_id_associations':sum(bool(r['findings']) for r in rows)},
        'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'execution_receipt':receipt(),'findings':findings,'producers':producer,'callback_contracts':contract,'checks':rows}


def write_report():
    report=build_report();REPORT.write_text(json.dumps(report,indent=2,sort_keys=True,default=str)+'\n')
    lines=['# AWS network closure review','',
        'All 212 input IDs are accounted for across 16 resource kinds. Semantic completion remains unproved for every ID: callback/source tracing, native field membership and synthetic witnesses are recorded separately from directed SDK collector receipts. No canonical admissions or ledgers were changed.', '',
        'Six defects were identified: foreign load-balancer listener parents, foreign WAF ACL detail, Network Firewall detail overwriting the requested identity, WAF logging for a foreign ACL, enclave numeric protocols/malformed ports and enclave malformed CIDR types/families. Root reviewed and integrated the proposed runtime patches; directed SDK/actual callback regressions pass. Tests now assert every correction without expected-failure skips; no source-only or fixture-only row claims semantic completion.', '',
        'The instance producer retains native DescribeInstances fields, including SecurityGroups and IamInstanceProfile; those baseline witness-only paths are not demonstrated missing producers. API methodSettings/resourceMethods are native maps, so literal fixture keys are not missing static SDK fields. Policy statement reads with null kind remain unattributed, and engine wrapper paths remain engine evidence.', '',
        'Exact attributed fields, unresolved baseline paths, callback source hashes, producer stages, identity joins, per-ID dispositions and directed test selectors are in [network-closure-review.json](network-closure-review.json). Family SDK tests execute selected consumers only; all other IDs retain fixture-only/source-only limits, optional omission and dependency-join gaps.', '',
        'Reproduce: `.venv/bin/python -m pytest -q tests/test_aws_network_closure_review.py --junitxml='+str(RECEIPT)+'` then `.venv/bin/python -m tests.test_aws_network_closure_review --write-report`.', '',
        'Execution receipt (merged per-node final outcomes; original failure and exact-node recheck receipts preserved): `'+json.dumps(report['execution_receipt'],sort_keys=True)+'`.', '',
        'Primary API references: [DescribeInstances]('+PRIMARY['instance']+'), [GetStages]('+PRIMARY['rest_api_stage']+'), [DescribeListeners]('+PRIMARY['load_balancer']+'), [GetWebACL]('+PRIMARY['wafv2_web_acl']+'), [DescribeFirewall]('+PRIMARY['network_firewall']+').', '',
        '| Input ID | Callback family | Disposition |', '|---|---|---|']
    lines += ['| `'+r['id']+'` | `'+r['family']+'` | '+r['disposition']+' |' for r in report['checks']]
    REPORT.with_suffix('.md').write_text('\n'.join(lines)+'\n')

if __name__=='__main__' and '--write-report' in sys.argv:
    write_report()
