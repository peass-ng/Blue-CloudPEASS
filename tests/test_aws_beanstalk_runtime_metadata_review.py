"""Real SDK responses -> Requests cache -> scoped snapshot -> registered checks."""
from copy import deepcopy
import json

import boto3
from botocore.stub import Stubber
import pytest

from peaso import engine
from peaso.collectors import aws
from peaso.collectors import aws_facts_compute_edge as edge
from peaso.collectors import aws_beanstalk_runtime_metadata as metadata
from peaso.snapshot import make_snapshot

ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
ENV = {'EnvironmentArn': f'arn:aws:elasticbeanstalk:{REGION}:{ACCOUNT}:environment/app/prod',
       'EnvironmentName': 'prod', 'EnvironmentId': 'e-review123', 'ApplicationName': 'app', 'Status': 'Ready'}
LB_NAME = 'review-lb'
LB_ARN = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/{LB_NAME}/1234567890123456'
CERT = f'arn:aws:acm:{REGION}:{ACCOUNT}:certificate/12345678-1234-1234-1234-123456789012'
IDS = ('aws_cis_elasticbeanstalk_https_listener', 'aws_cis_elasticbeanstalk_load_balancer_access_logs',
       'aws_cis_beanstalk_persistent_logs_s3')


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    clients, stubs = {}, {}
    def add(service):
        if service not in clients:
            clients[service] = session.client(service, region_name=REGION)
            stubs[service] = Stubber(clients[service])
            stubs[service].activate()
        return stubs[service]
    monkeypatch.setattr(aws.Requests, 'client', lambda self, session, service, region: clients[service])
    yield session, add
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def config(kind='application', publish='true'):
    options = [{'Namespace': metadata.LB_TYPE[0], 'OptionName': metadata.LB_TYPE[1], 'Value': kind},
               {'Namespace': 'aws:elasticbeanstalk:application:environment', 'OptionName': 'DB_PASSWORD', 'Value': 'SYNTHETIC_DO_NOT_CACHE'}]
    if publish is not None:
        options.append({'Namespace': metadata.HOSTMANAGER[0], 'OptionName': metadata.HOSTMANAGER[1], 'Value': publish})
    return {'ApplicationName': 'app', 'EnvironmentName': 'prod', 'DeploymentStatus': 'deployed', 'OptionSettings': options}


def setup(sdk, *, kind='application', tls=True, access=True, publish='true', scenario=None, no_lb=False):
    session, add = sdk
    eb = add('elasticbeanstalk')
    env = deepcopy(ENV)
    if scenario == 'foreign_environment':
        env['EnvironmentArn'] = env['EnvironmentArn'].replace(ACCOUNT, '999999999999')
    eb.add_response('describe_environments', {'Environments': [env]}, {'IncludeDeleted': False})
    setting = config(kind, publish)
    if scenario == 'foreign_config': setting['EnvironmentName'] = 'other-env'
    if scenario == 'pending_config': setting['DeploymentStatus'] = 'pending'
    if scenario == 'duplicate_option': setting['OptionSettings'].append(deepcopy(setting['OptionSettings'][-1]))
    if scenario == 'missing_options': setting.pop('OptionSettings')
    config_args = {'ApplicationName': 'app', 'EnvironmentName': 'prod'}
    if scenario == 'denied_config':
        eb.add_client_error('describe_configuration_settings', service_error_code='AccessDenied', expected_params=config_args)
    else:
        eb.add_response('describe_configuration_settings', {'ConfigurationSettings': [setting]}, config_args)
    if scenario == 'foreign_environment': return
    args = {'EnvironmentId': ENV['EnvironmentId'], 'EnvironmentName': ENV['EnvironmentName']}
    if scenario == 'denied_resources':
        eb.add_client_error('describe_environment_resources', service_error_code='AccessDenied', expected_params=args)
        return
    resources = {'EnvironmentName': 'other-env' if scenario == 'foreign_resources' else 'prod',
                 'LoadBalancers': [] if no_lb else [{'Name': LB_NAME}]}
    if scenario == 'missing_resources_list': resources.pop('LoadBalancers')
    if scenario == 'duplicate_lb': resources['LoadBalancers'] *= 2
    eb.add_response('describe_environment_resources', {'EnvironmentResources': resources}, args)
    if scenario in {'foreign_config', 'pending_config', 'duplicate_option', 'missing_options', 'denied_config', 'foreign_resources', 'duplicate_lb', 'missing_resources_list'} or no_lb or publish == 'maybe': return
    if kind == 'classic':
        lb = add('elb')
        args = {'LoadBalancerNames': [LB_NAME]}
        if scenario == 'denied_lb':
            lb.add_client_error('describe_load_balancers', service_error_code='AccessDenied', expected_params=args)
            return
        listener = {'Protocol': 'HTTPS' if tls else 'HTTP', 'LoadBalancerPort': 443 if tls else 80,
                    'InstanceProtocol': 'HTTP', 'InstancePort': 80}
        if scenario and scenario.startswith('classic_ssl'):
            listener.update(Protocol='SSL', InstanceProtocol='TCP')
        if tls and scenario != 'classic_ssl_missing_certificate':
            listener['SSLCertificateId'] = CERT.replace(ACCOUNT, '999999999999') if scenario == 'classic_ssl_foreign_certificate' else CERT
        lb.add_response('describe_load_balancers', {'LoadBalancerDescriptions': [{'LoadBalancerName': LB_NAME,
            'ListenerDescriptions': [{'Listener': listener}]}]}, args)
        lb.add_response('describe_load_balancer_attributes', {'LoadBalancerAttributes': {'AccessLog': {'Enabled': access}}}, {'LoadBalancerName': LB_NAME})
        return
    lb = add('elbv2')
    arn = LB_ARN if kind == 'application' else LB_ARN.replace('/app/', '/net/')
    if scenario == 'foreign_lb': arn = arn.replace(ACCOUNT, '999999999999')
    args = {'Names': [LB_NAME]}
    if scenario == 'denied_lb':
        lb.add_client_error('describe_load_balancers', service_error_code='AccessDenied', expected_params=args)
        return
    lb.add_response('describe_load_balancers', {'LoadBalancers': [{'LoadBalancerArn': arn, 'LoadBalancerName': LB_NAME, 'Type': kind}]}, args)
    if scenario == 'foreign_lb': return
    listener = {'ListenerArn': arn.replace(':loadbalancer/', ':listener/') + '/abcdef1234567890', 'LoadBalancerArn': arn,
                'Protocol': ('HTTPS' if kind == 'application' else 'TLS') if tls else ('HTTP' if kind == 'application' else 'TCP'),
                'Port': 443 if tls else 80, 'DefaultActions': [{'Type': 'forward'}]}
    if tls: listener['Certificates'] = [{'CertificateArn': CERT}]
    if scenario == 'v2_ssl': listener['Protocol'] = 'SSL'
    if scenario == 'foreign_listener': listener['LoadBalancerArn'] = arn.replace(ACCOUNT, '999999999999')
    if scenario == 'foreign_certificate': listener['Certificates'][0]['CertificateArn'] = CERT.replace(ACCOUNT, '999999999999')
    if scenario == 'denied_listeners':
        lb.add_client_error('describe_listeners', service_error_code='AccessDenied', expected_params={'LoadBalancerArn': arn})
    else:
        response = {'Listeners': [listener]}
        if scenario in {'redirect', 'mixed_plaintext'}:
            plain = {'ListenerArn': arn.replace(':loadbalancer/', ':listener/') + '/1111111111111111',
                'LoadBalancerArn': arn, 'Protocol': 'HTTP', 'Port': 80,
                'DefaultActions': [{'Type': 'redirect', 'RedirectConfig': {'Protocol': 'HTTPS', 'StatusCode': 'HTTP_301'}}]
                    if scenario == 'redirect' else [{'Type': 'forward'}]}
            response['Listeners'].append(plain)
        if scenario == 'partial_listeners': response['NextMarker'] = 'more'
        lb.add_response('describe_listeners', response, {'LoadBalancerArn': arn})
    if scenario == 'denied_attributes':
        lb.add_client_error('describe_load_balancer_attributes', service_error_code='AccessDenied', expected_params={'LoadBalancerArn': arn})
    else:
        lb.add_response('describe_load_balancer_attributes', {'Attributes': [{'Key': 'access_logs.s3.enabled', 'Value': str(access).lower()}]}, {'LoadBalancerArn': arn})


def collect(sdk, **kwargs):
    setup(sdk, **kwargs)
    session, _ = sdk
    requests = aws.Requests({'retry_attempts': 1, **({'max_pages': 1} if kwargs.get('scenario') == 'partial_listeners' else {})})
    read = edge.FETCHERS['elastic_beanstalk_environment'](requests, session, REGION, ACCOUNT)
    for row in read.items: row['AccountId'] = ACCOUNT  # Production's verified account stamp.
    enriched = edge.ENRICHERS['elastic_beanstalk_environment'](requests, session, REGION, read.items)
    cached = edge.ENRICHERS['elastic_beanstalk_environment'](requests, session, REGION, read.items)
    assert cached == enriched and requests.cache_hits >= 1
    envelope = {'type': 'elastic_beanstalk_environment', 'scope': SCOPE, 'status': read.status, 'items': enriched}
    snapshot = make_snapshot('aws', [SCOPE], aws._safe([envelope]), created_at='2026-10-19T00:00:00Z')
    result = engine.evaluate_snapshot(snapshot, checks=list(IDS))
    findings = {r['check_id']: r for r in result['findings'] if r['check_id'] in IDS}
    assert set(findings) == set(IDS)
    cached_results = []
    for future in requests._cache.values():
        try:
            cached_results.append(future.result())
        except Exception as exc:
            cached_results.append({'error_type': type(exc).__name__})
    serialized = json.dumps(snapshot, default=str) + json.dumps(cached_results, default=str)
    assert 'SYNTHETIC_DO_NOT_CACHE' not in serialized and 'DB_PASSWORD' not in serialized
    return requests, enriched[0], {i: findings[i]['status'] for i in IDS}


def test_real_dispatcher_admits_only_the_required_read_actions():
    assert metadata.READ_ACTIONS <= aws.READ_ACTIONS
    assert all(op.startswith('describe_') for service, op in metadata.READ_ACTIONS)
    assert not any('environment_info' in op for service, op in metadata.READ_ACTIONS)


@pytest.mark.parametrize('kind', ['classic', 'application', 'network'])
@pytest.mark.parametrize('secure', [True, False])
def test_real_sdk_cache_and_registered_snapshot_positive_negative(sdk, kind, secure):
    requests, item, statuses = collect(sdk, kind=kind, tls=secure, access=secure, publish=str(secure).lower())
    assert statuses == dict.fromkeys(IDS, 'PASS' if secure else 'FAIL')
    assert requests.calls == (5 if kind == 'classic' else 6)
    assert item['Configuration']['hostmanager_options_complete'] is True
    destination = item['S3LogDestination']
    assert destination['bucket'] == f'elasticbeanstalk-{REGION}-{ACCOUNT}'
    assert destination['prefix'] == f"resources/environments/logs/publish/{ENV['EnvironmentId']}/"
    assert destination['delivery_observed'] is False and destination['retention_assessed'] is False


@pytest.mark.parametrize('scenario', ['denied_resources', 'foreign_resources', 'missing_resources_list', 'duplicate_lb', 'denied_lb', 'foreign_lb'])
def test_missing_or_foreign_association_never_becomes_not_applicable_or_pass(sdk, scenario):
    _, _, statuses = collect(sdk, scenario=scenario)
    assert statuses[IDS[0]] == statuses[IDS[1]] == 'UNKNOWN'
    assert statuses[IDS[2]] == 'PASS'


@pytest.mark.parametrize('scenario', ['foreign_config', 'pending_config', 'missing_options', 'duplicate_option', 'denied_config', 'foreign_environment'])
def test_unbound_incomplete_configuration_stays_unknown(sdk, scenario):
    _, _, statuses = collect(sdk, scenario=scenario)
    assert statuses == dict.fromkeys(IDS, 'UNKNOWN')


@pytest.mark.parametrize('scenario', ['denied_listeners', 'partial_listeners', 'foreign_listener', 'foreign_certificate'])
def test_partial_denied_or_foreign_listeners_do_not_hide_access_log_evidence(sdk, scenario):
    _, _, statuses = collect(sdk, scenario=scenario)
    assert statuses == {IDS[0]: 'UNKNOWN', IDS[1]: 'PASS', IDS[2]: 'PASS'}


def test_denied_attributes_do_not_hide_https_evidence(sdk):
    _, _, statuses = collect(sdk, scenario='denied_attributes')
    assert statuses == {IDS[0]: 'PASS', IDS[1]: 'UNKNOWN', IDS[2]: 'PASS'}


def test_authoritative_no_load_balancer_is_not_applicable(sdk):
    _, _, statuses = collect(sdk, no_lb=True)
    assert statuses == {IDS[0]: 'NOT_APPLICABLE', IDS[1]: 'NOT_APPLICABLE', IDS[2]: 'PASS'}


def test_missing_option_is_documented_disabled_default_only_when_complete(sdk):
    _, _, statuses = collect(sdk, no_lb=True, publish=None)
    assert statuses[IDS[2]] == 'FAIL'


def test_invalid_option_cannot_disappear_into_disabled_default(sdk):
    _, _, statuses = collect(sdk, publish='maybe')
    assert statuses == dict.fromkeys(IDS, 'UNKNOWN')


@pytest.mark.parametrize('value', [None, {}, 'true', [{'Namespace': 'x'}],
    [{'Namespace': metadata.HOSTMANAGER[0], 'OptionName': metadata.HOSTMANAGER[1], 'Value': {}}]])
def test_raw_completeness_marker_rejects_malformed_shapes(value):
    assert metadata.configuration_options_complete(value) is False


@pytest.mark.parametrize('scenario,expected', [('redirect', 'PASS'), ('mixed_plaintext', 'FAIL')])
def test_http_redirect_vs_plaintext_alongside_https(sdk, scenario, expected):
    _, _, statuses = collect(sdk, scenario=scenario)
    assert statuses == {IDS[0]: expected, IDS[1]: 'PASS', IDS[2]: 'PASS'}


@pytest.mark.parametrize('scenario,expected', [('classic_ssl', 'PASS'),
    ('classic_ssl_missing_certificate', 'UNKNOWN'), ('classic_ssl_foreign_certificate', 'UNKNOWN')])
def test_classic_ssl_requires_bound_native_certificate(sdk, scenario, expected):
    _, _, statuses = collect(sdk, kind='classic', scenario=scenario)
    assert statuses == {IDS[0]: expected, IDS[1]: 'PASS', IDS[2]: 'PASS'}


def test_ssl_protocol_is_not_blanket_accepted_for_v2(sdk):
    _, _, statuses = collect(sdk, scenario='v2_ssl')
    assert statuses == {IDS[0]: 'UNKNOWN', IDS[1]: 'PASS', IDS[2]: 'PASS'}
