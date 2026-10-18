"""Metadata-only SageMaker endpoint/model and monitoring-execution joins.

No container environment, input records, model content, output reports or data
plane calls are emitted. All reads share the scan's bounded request cache.
"""
import copy
import re

SPECS = {'sagemaker_endpoint': ('sagemaker', 'list_endpoints', 'Endpoints')}
NATIVE_IDS = {'sagemaker_endpoint': 'EndpointArn'}
READ_ACTIONS = {('sagemaker', 'list_endpoints'), ('sagemaker', 'describe_endpoint'),
                ('sagemaker', 'list_monitoring_executions')}
_NAME = re.compile(r'[a-zA-Z0-9](?:-*[a-zA-Z0-9]){0,62}')


def _name(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ValueError('invalid_sagemaker_name')
    return value


def _arn(value, partition, region, account, resource, name):
    if value != f'arn:{partition}:sagemaker:{region}:{account}:{resource}/{_name(name)}':
        raise ValueError('foreign_sagemaker_identity')


def _detail(requests, session, region, operation, **arguments):
    from .aws import ReadFailure
    value = requests.detail(session, 'sagemaker', region, operation, **arguments)
    if not isinstance(value, dict) or value.get('collection_status') != 'collected':
        raise ReadFailure(value.get('collection_status', 'unknown') if isinstance(value, dict) else 'malformed',
                          'clarify_native_detail_unavailable')
    return value


def _pages(requests, session, region, operation, expression, **arguments):
    from .aws import ReadFailure
    read = requests.pages(session, 'sagemaker', region, operation, expression, **arguments)
    if read.status not in ('collected', 'empty'):
        raise ReadFailure(read.status, (read.error or {}).get('code', 'clarify_native_list_incomplete'))
    if any(not isinstance(row, dict) for row in read.items):
        raise ValueError('invalid_sagemaker_list')
    return read.items


def endpoints(requests, session, region, account):
    from .aws import ReadFailure, ReadResult
    output = []
    try:
        partition = session.get_partition_for_region(region)
        rows = _pages(requests, session, region, 'list_endpoints', 'Endpoints')
        seen = set()
        for row in rows:
            name = _name(row.get('EndpointName'))
            _arn(row.get('EndpointArn'), partition, region, account, 'endpoint', name)
            if name in seen:
                raise ValueError('duplicate_sagemaker_endpoint')
            seen.add(name)
            detail = _detail(requests, session, region, 'describe_endpoint', EndpointName=name)
            if detail.get('EndpointName') != name:
                raise ValueError('endpoint_detail_identity_mismatch')
            _arn(detail.get('EndpointArn'), partition, region, account, 'endpoint', name)
            config_name = _name(detail.get('EndpointConfigName'))
            config = _detail(requests, session, region, 'describe_endpoint_config', EndpointConfigName=config_name)
            if config.get('EndpointConfigName') != config_name:
                raise ValueError('endpoint_config_identity_mismatch')
            _arn(config.get('EndpointConfigArn'), partition, region, account, 'endpoint-config', config_name)
            variants = config.get('ProductionVariants')
            shadows = config.get('ShadowProductionVariants', [])
            if not isinstance(variants, list) or not variants or not isinstance(shadows, list):
                raise ValueError('endpoint_model_variants_unavailable')
            models = []
            for variant in variants + shadows:
                if not isinstance(variant, dict):
                    raise ValueError('endpoint_model_variant_invalid')
                model_name = _name(variant.get('ModelName'))
                model = _detail(requests, session, region, 'describe_model', ModelName=model_name)
                if model.get('ModelName') != model_name:
                    raise ValueError('endpoint_model_identity_mismatch')
                _arn(model.get('ModelArn'), partition, region, account, 'model', model_name)
                models.append(model['ModelArn'])
            # Transitional endpoint configurations can have unresolved current
            # vs desired model linkage. Preserve uncertainty until InService.
            output.append({'EndpointName': name, 'EndpointArn': detail['EndpointArn'],
                           'EndpointConfigName': config_name, 'EndpointStatus': detail.get('EndpointStatus'),
                           'ModelArns': sorted(set(models)),
                           'ModelLinkageStatus': 'verified' if detail.get('EndpointStatus') == 'InService' else 'unresolved',
                           '_provenance': {'operations': ['ListEndpoints', 'DescribeEndpoint',
                               'DescribeEndpointConfig', 'DescribeModel'], 'read_only': True}})
        return ReadResult(output, 'collected' if output else 'empty')
    except ReadFailure as exc:
        return ReadResult([], exc.status, {'code': exc.code})
    except (ValueError, TypeError, KeyError):
        return ReadResult([], 'malformed', {'code': 'clarify_endpoint_join_invalid'})


def processing_jobs(requests, session, region, items):
    if not getattr(requests, 'sagemaker_clarify_requested', False):
        return items
    output = []
    for original in items:
        item = copy.deepcopy(original)
        item['EndpointLinkageStatus'] = 'unresolved'
        # Imported flags must never survive a native join failure.
        item.pop('EndpointName', None)
        item.pop('EndpointLinkedInput', None)
        try:
            name = _name(item.get('ProcessingJobName'))
            partition = session.get_partition_for_region(region)
            arn = item.get('ProcessingJobArn')
            match = re.fullmatch(r'arn:' + re.escape(partition) + ':sagemaker:' + re.escape(region)
                                 + r':([0-9]{12}):processing-job/' + re.escape(name), arn or '')
            if match is None:
                raise ValueError('processing_job_identity_invalid')
            account = match.group(1)
            job = _detail(requests, session, region, 'describe_processing_job', ProcessingJobName=name)
            if job.get('ProcessingJobName') != name or job.get('ProcessingJobArn') != arn:
                raise ValueError('processing_job_detail_identity_mismatch')
            image = job.get('AppSpecification', {}).get('ImageUri')
            if not isinstance(image, str) or not image:
                raise ValueError('processing_job_image_unavailable')
            item['AppSpecification'] = {'ImageUri': image}
            item['ProcessingJobStatus'] = job.get('ProcessingJobStatus')
            item['CreationTime'] = job.get('CreationTime')
            if 'clarify' not in image.lower():
                item['EndpointLinkageStatus'] = 'not_clarify'
                output.append(item)
                continue
            schedule_arn = job.get('MonitoringScheduleArn')
            prefix = f'arn:{partition}:sagemaker:{region}:{account}:monitoring-schedule/'
            if not isinstance(schedule_arn, str) or not schedule_arn.startswith(prefix):
                raise ValueError('processing_job_monitoring_link_unavailable')
            schedule_name = _name(schedule_arn[len(prefix):])
            schedules = _pages(requests, session, region, 'list_monitoring_schedules', 'MonitoringScheduleSummaries')
            matches = [s for s in schedules if s.get('MonitoringScheduleName') == schedule_name]
            if len(matches) != 1 or matches[0].get('MonitoringScheduleArn') != schedule_arn:
                raise ValueError('monitoring_schedule_join_ambiguous')
            schedule = matches[0]
            endpoint = _name(schedule.get('EndpointName'))
            if schedule.get('MonitoringType') != 'ModelBias':
                raise ValueError('monitoring_type_not_model_bias')
            executions = _pages(requests, session, region, 'list_monitoring_executions',
                                'MonitoringExecutionSummaries', MonitoringScheduleName=schedule_name)
            matches = [e for e in executions if e.get('ProcessingJobArn') == arn]
            if len(matches) != 1:
                raise ValueError('monitoring_execution_join_ambiguous')
            execution = matches[0]
            if (execution.get('EndpointName') != endpoint
                    or execution.get('MonitoringScheduleName') != schedule_name
                    or execution.get('MonitoringType') != 'ModelBias'
                    or execution.get('MonitoringExecutionStatus') not in ('Completed', 'CompletedWithViolations')):
                raise ValueError('monitoring_execution_identity_or_state_invalid')
            item.update({'EndpointName': endpoint, 'EndpointLinkedInput': True,
                         'EndpointLinkageStatus': 'verified',
                         '_ClarifyJoin': {'MonitoringScheduleArn': schedule_arn,
                             'ProcessingJobArn': arn, 'EndpointName': endpoint,
                             'operations': ['DescribeProcessingJob', 'ListMonitoringSchedules', 'ListMonitoringExecutions']}})
        except Exception:
            # Optional enrichment must not invalidate other processing-job
            # controls or expose provider messages. The Clarify check alone
            # consumes this unresolved state; unrelated checks retain raw data.
            item['EndpointLinkageStatus'] = 'unresolved'
        output.append(item)
    return output


FETCHERS = {'sagemaker_endpoint': endpoints}
ENRICHERS = {'sagemaker_processing_job': processing_jobs}
