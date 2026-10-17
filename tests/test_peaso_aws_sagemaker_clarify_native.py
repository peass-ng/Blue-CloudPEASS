"""Real SDK shapes through native collection, pinned SW48 and the public engine."""
import copy
from datetime import datetime, timezone
import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, collect_live
from peaso.engine import evaluate_snapshot, plan_collection

CHECK = 'aws_sagemaker_model_clarify_bias_job'
SCOPE = ACCOUNT + '/' + REGION
PREFIX = 'arn:aws:sagemaker:' + REGION + ':' + ACCOUNT + ':'
TIME = datetime(2026, 10, 15, tzinfo=timezone.utc)


def capture(sdk, monkeypatch, mode='good'):
    session, add = sdk
    sts = add('sts'); sm = add('sagemaker')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/reviewer', 'UserId': 'reviewer'}, {})
    endpoint = {'EndpointName': 'endpoint', 'EndpointArn': PREFIX + 'endpoint/endpoint',
        'CreationTime': TIME, 'LastModifiedTime': TIME, 'EndpointStatus': 'InService'}
    ep_rows = [] if mode == 'no_endpoints' else [copy.deepcopy(endpoint)]
    if mode == 'foreign_endpoint':ep_rows[0]['EndpointArn'] = ep_rows[0]['EndpointArn'].replace(ACCOUNT, '999999999999')
    if mode == 'duplicate_endpoint':ep_rows *= 2
    if mode == 'endpoint_denied':sm.add_client_error('list_endpoints', 'AccessDeniedException', expected_params={})
    else:
        response = {'Endpoints': ep_rows}
        if mode in ('endpoint_two_pages', 'endpoint_partial'):response['NextToken'] = 'next-endpoint-page'
        sm.add_response('list_endpoints', response, {})
        if mode in ('endpoint_two_pages', 'endpoint_partial'):
            sm.add_response('list_endpoints', {'Endpoints': []}, {'NextToken': 'next-endpoint-page'})
    early = mode in ('endpoint_denied', 'no_endpoints', 'foreign_endpoint', 'endpoint_partial')
    if not early:
        detail = dict(endpoint, EndpointConfigName='config')
        if mode == 'endpoint_pending':detail['EndpointStatus'] = 'Updating'
        sm.add_response('describe_endpoint', detail, {'EndpointName': 'endpoint'})
        config = {'EndpointConfigName': 'config', 'EndpointConfigArn': PREFIX + 'endpoint-config/config',
            'ProductionVariants': [{'VariantName': 'primary', 'ModelName': 'model'}], 'CreationTime': TIME}
        if mode == 'foreign_config':config['EndpointConfigArn'] = config['EndpointConfigArn'].replace(ACCOUNT, '999999999999')
        sm.add_response('describe_endpoint_config', config, {'EndpointConfigName': 'config'})
        if mode != 'foreign_config':
            model = {'ModelName': 'model', 'ModelArn': PREFIX + 'model/model', 'CreationTime': TIME}
            if mode == 'foreign_model':model['ModelArn'] = model['ModelArn'].replace(ACCOUNT, '999999999999')
            if mode == 'model_denied':sm.add_client_error('describe_model', 'AccessDeniedException', expected_params={'ModelName': 'model'})
            else:sm.add_response('describe_model', model, {'ModelName': 'model'})
    schedule = {'MonitoringScheduleName': 'schedule', 'MonitoringScheduleArn': PREFIX + 'monitoring-schedule/schedule',
        'CreationTime': TIME, 'LastModifiedTime': TIME, 'MonitoringScheduleStatus': 'Scheduled',
        'EndpointName': 'endpoint', 'MonitoringType': 'ModelBias'}
    if mode == 'stopped':schedule['MonitoringScheduleStatus'] = 'Stopped'
    if mode == 'wrong_type':schedule['MonitoringType'] = 'ModelQuality'
    schedules = [] if mode == 'no_schedule' else [schedule]
    sm.add_response('list_monitoring_schedules', {'MonitoringScheduleSummaries': schedules}, {})
    job = {'ProcessingJobName': 'job', 'ProcessingJobArn': PREFIX + 'processing-job/job',
        'CreationTime': TIME, 'ProcessingJobStatus': 'Completed'}
    jobs = [] if mode == 'no_jobs' else [copy.deepcopy(job)]
    if mode in ('mixed_unrelated', 'mixed_unresolved'):jobs.append(dict(job, ProcessingJobName='other', ProcessingJobArn=PREFIX + 'processing-job/other'))
    sm.add_response('list_processing_jobs', {'ProcessingJobSummaries': jobs}, {})
    def detail_job(summary, unrelated=False):
        result = dict(summary, ProcessingResources={'ClusterConfig': {'InstanceCount': 1,
            'InstanceType': 'ml.m5.xlarge', 'VolumeSizeInGB': 5}},
            AppSpecification={'ImageUri': 'registry.example/other:latest' if unrelated else 'registry.example/sagemaker-clarify:latest'},
            MonitoringScheduleArn=PREFIX + 'monitoring-schedule/schedule')
        if mode == 'stale':result['CreationTime'] = datetime(2020, 1, 1, tzinfo=timezone.utc)
        if mode == 'missing_link' or (summary['ProcessingJobName'] == 'other' and mode == 'mixed_unresolved'):result.pop('MonitoringScheduleArn')
        return result
    for summary in jobs:
        # The existing detail enricher runs first for every job; the new
        # linkage enricher consumes that exact single-flight cached response.
        sm.add_response('describe_processing_job', detail_job(summary, mode == 'mixed_unrelated' and summary['ProcessingJobName'] == 'other'), {'ProcessingJobName': summary['ProcessingJobName']})
    if jobs and mode not in ('missing_link', 'no_schedule', 'wrong_type'):
        execution = {'MonitoringScheduleName': 'schedule', 'ScheduledTime': TIME,
            'CreationTime': TIME, 'LastModifiedTime': TIME, 'MonitoringExecutionStatus': 'Completed',
            'ProcessingJobArn': job['ProcessingJobArn'], 'EndpointName': 'endpoint', 'MonitoringType': 'ModelBias'}
        if mode == 'foreign_execution':execution['ProcessingJobArn'] = execution['ProcessingJobArn'].replace(ACCOUNT, '999999999999')
        if mode == 'foreign_execution_endpoint':execution['EndpointName'] = 'foreign'
        if mode == 'duplicate_execution':rows = [execution, copy.deepcopy(execution)]
        else:rows = [execution]
        params = {'MonitoringScheduleName': 'schedule'}
        if mode == 'execution_denied':sm.add_client_error('list_monitoring_executions', 'AccessDeniedException', expected_params=params)
        else:
            response = {'MonitoringExecutionSummaries': [] if mode in ('execution_two_pages', 'execution_partial') else rows}
            if mode in ('execution_two_pages', 'execution_partial'):response['NextToken'] = 'next-execution-page'
            sm.add_response('list_monitoring_executions', response, params)
            if mode in ('execution_two_pages', 'execution_partial'):
                sm.add_response('list_monitoring_executions', {'MonitoringExecutionSummaries': rows}, dict(params, NextToken='next-execution-page'))
    if mode == 'endpoint_partial':
        unread = sm._queue[1]
        del sm._queue[1]
        sm._queue.append(unread)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-pinned'))
    options = {'service_concurrency': 1, 'retry_attempts': 1,
        'compliance_parameters': {'clarify_monitoring_interval_days': 7}}
    if mode in ('endpoint_partial', 'execution_partial'):options['max_pages'] = 1
    if mode == 'no_policy':options.pop('compliance_parameters')
    connector = {'provider': 'aws', 'scopes': [SCOPE], 'options': options}
    requirements = plan_collection({'connector': connector, 'checks': [CHECK]})
    assert set(requirements) == {'sagemaker_endpoint', 'sagemaker_processing_job', 'sagemaker_monitoring_schedule'}
    snapshot = collect_live(connector, requirements)
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert len(findings) == 1
    if mode in ('endpoint_partial', 'execution_partial'):
        assert len(sm._queue) == 1
        pending = sm._queue[0]
        expected_token = 'next-endpoint-page' if mode == 'endpoint_partial' else 'next-execution-page'
        assert pending['expected_params']['NextToken'] == expected_token
        envs = {c['type']: c for c in snapshot['collections']}
        assert envs['sagemaker_monitoring_schedule']['status'] == 'collected'
        assert envs['sagemaker_processing_job']['status'] == 'collected'
        if mode == 'endpoint_partial':
            assert envs['sagemaker_endpoint']['status'] == 'partial'
            assert envs['sagemaker_endpoint']['error']['code'] == 'page_limit'
        else:
            assert envs['sagemaker_endpoint']['status'] == 'collected'
            assert envs['sagemaker_processing_job']['items'][0]['EndpointLinkageStatus'] == 'unresolved'
    else:
        # Denied/malformed paths may stop detail reads, but all scheduled SDK
        # source responses above remain deliberate and accounted for below.
        sm.assert_no_pending_responses()
    return findings[0]['status'], snapshot


@pytest.mark.parametrize('mode,expected', [
    ('good', 'PASS'), ('mixed_unrelated', 'PASS'), ('mixed_unresolved', 'UNKNOWN'),
    ('endpoint_two_pages', 'PASS'), ('execution_two_pages', 'PASS'),
    ('endpoint_denied', 'DENIED'), ('model_denied', 'DENIED'), ('execution_denied', 'UNKNOWN'),
    ('foreign_endpoint', 'UNKNOWN'), ('foreign_config', 'UNKNOWN'), ('foreign_model', 'UNKNOWN'),
    ('foreign_execution', 'UNKNOWN'), ('foreign_execution_endpoint', 'UNKNOWN'),
    ('duplicate_endpoint', 'UNKNOWN'), ('duplicate_execution', 'UNKNOWN'),
    ('endpoint_pending', 'UNKNOWN'), ('endpoint_partial', 'UNKNOWN'), ('execution_partial', 'UNKNOWN'),
    ('missing_link', 'UNKNOWN'), ('wrong_type', 'UNKNOWN'), ('no_policy', 'UNKNOWN'),
    ('stopped', 'FAIL'), ('no_jobs', 'FAIL'), ('stale', 'FAIL'), ('no_schedule', 'UNKNOWN'),
    ('no_endpoints', 'NOT_APPLICABLE')])
def test_native_sdk_collection_to_frozen_engine(sdk, monkeypatch, mode, expected):
    status, snapshot = capture(sdk, monkeypatch, mode)
    assert status == expected
    if mode == 'good':
        endpoint = next(c for c in snapshot['collections'] if c['type'] == 'sagemaker_endpoint')['items'][0]
        job = next(c for c in snapshot['collections'] if c['type'] == 'sagemaker_processing_job')['items'][0]
        assert endpoint['ModelArns'] == [PREFIX + 'model/model']
        assert job['_ClarifyJoin']['ProcessingJobArn'] == PREFIX + 'processing-job/job'
        assert job['EndpointName'] == 'endpoint' and job['EndpointLinkedInput'] is True
