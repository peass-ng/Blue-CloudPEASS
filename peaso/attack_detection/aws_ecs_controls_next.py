"""Normalize accepted ECS telemetry and task-protection changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_ecs_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'ecs.amazonaws.com'
            or name not in {'UpdateClusterSettings', 'UpdateTaskProtection'}
            or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    account, region = record.get('recipientAccountId'), record.get('awsRegion')
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return None
    if not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region):
        return None
    request, response = record.get('requestParameters'), record.get('responseElements')
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    cluster = request.get('cluster')
    valid_cluster = (isinstance(cluster, str)
                     and cluster.startswith(f'arn:aws:ecs:{region}:{account}:cluster/')
                     and bool(cluster.split('/')[-1]))
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or response.get('errorCode') or response.get('errorMessage'))
    settings = request.get('settings')
    disabled = (isinstance(settings, list) and any(isinstance(x, Mapping)
                and x.get('name') == 'containerInsights' and x.get('value') == 'disabled' for x in settings))
    returned_cluster = response.get('cluster')
    confirmed_disabled = (isinstance(returned_cluster, Mapping)
                          and returned_cluster.get('clusterArn') == cluster
                          and isinstance(returned_cluster.get('settings'), list)
                          and any(isinstance(x, Mapping) and x.get('name') == 'containerInsights'
                                  and x.get('value') == 'disabled' for x in returned_cluster['settings']))
    tasks = request.get('tasks')
    tasks = tasks if isinstance(tasks, list) else []
    task_ids = {x.rsplit('/', 1)[-1] for x in tasks if isinstance(x, str)
                and x.startswith(f'arn:aws:ecs:{region}:{account}:task/')}
    protected = response.get('protectedTasks')
    protected_ids = {x['taskArn'].rsplit('/', 1)[-1] for x in protected if isinstance(x, Mapping)
                     and isinstance(x.get('taskArn'), str) and x.get('protectionEnabled') is True} if isinstance(protected, list) else set()
    protection_confirmed = (request.get('protectionEnabled') is True and bool(task_ids)
                            and task_ids <= protected_ids and response.get('failures') == [])
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': name, 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': account, 'actor.id': actor.get('arn'), 'target.id': cluster if valid_cluster else None,
            'request.ecs_container_insights_disabled': name == 'UpdateClusterSettings'
                and valid_cluster and disabled and confirmed_disabled and not failed,
            'request.ecs_task_protection_enabled': name == 'UpdateTaskProtection'
                and valid_cluster and protection_confirmed and not failed}
