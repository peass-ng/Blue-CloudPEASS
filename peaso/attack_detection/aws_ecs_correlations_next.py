"""Correlate dormant ECS services with task revisions that add a container."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def correlate_aws_ecs_dormant_sidecar(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    events = []
    for record in records:
        name = record.get('eventName')
        if (record.get('eventSource') != 'ecs.amazonaws.com'
                or name not in {'RegisterTaskDefinition', 'CreateService', 'UpdateService'}
                or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
                or record.get('managementEvent') is not True or record.get('readOnly') is not False
                or record.get('errorCode') or record.get('errorMessage')):
            continue
        account, region = record.get('recipientAccountId'), record.get('awsRegion')
        request, response = record.get('requestParameters'), record.get('responseElements')
        when = _when(record.get('eventTime'))
        if (not isinstance(account, str) or not re.fullmatch(r'\d{12}', account)
                or not isinstance(region, str) or not isinstance(request, Mapping)
                or not isinstance(response, Mapping) or when is None):
            continue
        events.append((when, {'RegisterTaskDefinition': 0, 'CreateService': 1, 'UpdateService': 2}[name],
                       account, region, record))
    events.sort(key=lambda x: x[:4])
    definitions: dict[str, tuple[datetime, str, int, set[str], Mapping[str, Any]]] = {}
    dormant: dict[tuple[str, str, str, str], tuple[datetime, str, Mapping[str, Any]]] = {}
    matches = []
    for when, _, account, region, event in events:
        name, request, response = event['eventName'], event['requestParameters'], event['responseElements']
        if name == 'RegisterTaskDefinition':
            task = response.get('taskDefinition')
            if not isinstance(task, Mapping) or task.get('status') != 'ACTIVE':
                continue
            arn, family, revision = task.get('taskDefinitionArn'), task.get('family'), task.get('revision')
            prefix = f'arn:aws:ecs:{region}:{account}:task-definition/'
            if (not isinstance(arn, str) or not arn.startswith(prefix)
                    or not isinstance(family, str) or not family or type(revision) is not int
                    or arn != prefix + family + ':' + str(revision)
                    or request.get('family') != family):
                continue
            containers = request.get('containerDefinitions')
            if not isinstance(containers, list):
                continue
            names = {x.get('name') for x in containers if isinstance(x, Mapping)
                     and isinstance(x.get('name'), str) and x.get('name')}
            if len(names) != len(containers) or not names:
                continue
            definitions[arn] = (when, family, revision, names, event)
            continue
        cluster = request.get('cluster')
        service_name = request.get('serviceName') if name == 'CreateService' else request.get('service')
        if (not isinstance(cluster, str) or not cluster.startswith(f'arn:aws:ecs:{region}:{account}:cluster/')
                or not isinstance(service_name, str) or not service_name):
            continue
        service = response.get('service')
        if (not isinstance(service, Mapping) or service.get('clusterArn') != cluster
                or service.get('serviceName') != service_name or service.get('status') != 'ACTIVE'):
            continue
        key = (account, region, cluster, service_name)
        if name == 'CreateService':
            old_arn = request.get('taskDefinition')
            if (request.get('desiredCount') == 0 and service.get('desiredCount') == 0
                    and old_arn == service.get('taskDefinition') and old_arn in definitions):
                dormant[key] = (when, old_arn, event)
            continue
        prior = dormant.get(key)
        if prior is None or when - prior[0] > timedelta(hours=1):
            continue
        new_arn = request.get('taskDefinition')
        if (type(request.get('desiredCount')) is not int or request['desiredCount'] <= 0
                or service.get('desiredCount') != request['desiredCount']
                or service.get('taskDefinition') != new_arn or new_arn not in definitions):
            continue
        old, new = definitions[prior[1]], definitions[new_arn]
        added = new[3] - old[3]
        if old[1] != new[1] or new[2] <= old[2] or not added:
            continue
        actor = event.get('userIdentity')
        actor = actor if isinstance(actor, Mapping) else {}
        matches.append({'cloud.provider': 'aws', 'event.source': 'ecs.amazonaws.com',
                        'event.name': 'UpdateService', 'event.outcome': 'success',
                        'event.id': event.get('eventID'), 'event.time': event.get('eventTime'),
                        'account.id': account, 'actor.id': actor.get('arn'), 'target.id': service.get('serviceArn'),
                        'request.ecs_dormant_service_sidecar_activated': True,
                        'correlation_evidence': {'create_service_event_id': prior[2].get('eventID'),
                                                 'new_task_definition_event_id': new[4].get('eventID'),
                                                 'added_containers': sorted(added)}})
    return matches
