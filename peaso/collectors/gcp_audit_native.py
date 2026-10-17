"""Private opt-in GCP audit evidence adapter; no default scan or cloud call on import.

Integrate by adding audit_log to the explicit planner selector only. The parent
collector supplies cached, budgeted Transport.request, pagination and envelopes.
"""
from __future__ import annotations
from datetime import datetime, timezone
from peaso.collectors.gcp import GCPCollector, ReadError

CLASSES = frozenset({'activity', 'data_access', 'system_event', 'policy'})
URL = 'https://logging.googleapis.com/v2/entries:list'
DETECTOR_METHODS = (
    'google.cloud.osconfig.v1.OsConfigZonalService.GetInventory',
    'google.cloud.osconfig.v1alpha.OsConfigZonalService.GetInventory',
    'v1.compute.regions.list',
    'v1.compute.zones.list',
    'google.iam.admin.v1.CreateServiceAccount',
    'google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger',
    'google.cloud.scheduler.v1.CloudScheduler.CreateJob',
)


def _instant(value):
    if not isinstance(value, str):
        raise ValueError('audit window requires RFC3339 strings')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('invalid audit window') from exc
    if result.tzinfo is None:
        raise ValueError('audit window requires timezone')
    return result.astimezone(timezone.utc)


def validate_audit_options(provider, options):
    """Pure, bounded opt-in audit declaration shared by API intake and collector."""
    if not isinstance(options, dict):
        raise ValueError('audit options must be an object')
    inventories=options.get('inventories', [])
    audit_fields={'audit_window', 'audit_detection_policy'} & set(options)
    if not audit_fields and (not isinstance(inventories,list) or 'audit_log' not in inventories):
        return None
    if provider!='gcp':
        raise ValueError('audit_log is GCP-only')
    if (not isinstance(inventories,list) or
        any(not isinstance(x,str) for x in inventories) or
        inventories.count('audit_log')!=1):
        raise ValueError('audit_log requires one explicit inventory selector')
    window=options.get('audit_window')
    if not isinstance(window,dict) or set(window)!={'start','end','classes'}:
        raise ValueError('audit_log requires exact audit_window start/end/classes')
    start,end=_instant(window['start']),_instant(window['end'])
    if not start<end or (end-start).total_seconds()>86400 or end>datetime.now(timezone.utc):
        raise ValueError('audit window must be a past interval of at most 24 hours')
    classes=window['classes']
    if (not isinstance(classes,list) or not classes or len(classes)>len(CLASSES) or
        any(not isinstance(x,str) or x not in CLASSES for x in classes) or
        len(classes)!=len(set(classes))):
        raise ValueError('audit classes must be an explicit nonempty subset')
    for key,maximum in (('max_pages',100),('max_calls',1000),('max_resources',100000)):
        value=options.get(key)
        if type(value) is not int or not 1<=value<=maximum:
            raise ValueError('audit selection requires bounded '+key)
    policy=options.get('audit_detection_policy',{})
    if not isinstance(policy,dict) or set(policy)-{'approved_identity_admins','approved_automation_admins','approved_list_rate'}:
        raise ValueError('invalid audit detection policy')
    if 'approved_list_rate' in policy and (type(policy['approved_list_rate']) is not int or not 0<=policy['approved_list_rate']<=100000):
        raise ValueError('approved_list_rate must be an explicit integer between 0 and 100000')
    for key,value in policy.items():
        if key=='approved_list_rate':continue
        if (not isinstance(value,list) or len(value)>1000 or
            any(not isinstance(v,str) or not 0<len(v)<=320 or v!=v.strip() or
                any(ord(char)<32 for char in v) for v in value) or
            len(value)!=len(set(value))):
            raise ValueError('invalid audit allowlist')
    return {'window':{'start':start.isoformat(),'end':end.isoformat(),'classes':sorted(classes)},
            'policy':policy}


class AuditGCPCollector(GCPCollector):
    def __init__(self, connector, requirements=None, *, transport=None):
        options = connector.get('options') or {}
        selected = 'audit_log' in (requirements or ()) and 'audit_log' in options.get('inventories', [])
        ordinary = None if requirements is None else [kind for kind in requirements if kind != 'audit_log']
        # The public collector does not support audit_log; strip only this explicit
        # selection before entering its normal planner, then add our private job.
        copied_options = dict(options)
        if 'inventories' in copied_options:
            copied_options['inventories'] = [kind for kind in copied_options['inventories'] if kind != 'audit_log']
        copied = {**connector, 'options': copied_options}
        super().__init__(copied, ordinary, transport=transport)
        self.audit_selected = selected
        if not selected:
            return
        parsed=validate_audit_options('gcp',options)
        self.audit_window=parsed['window']
        self.audit_policy=parsed['policy']
        self.wanted.add('audit_log')
        self.needed.add('audit_log')

    def scope_jobs(self, scope):
        jobs = super().scope_jobs(scope)
        if not self.audit_selected or not scope.startswith('projects/'):
            return jobs
        window = self.audit_window
        terms = ' OR '.join(f'log_id("cloudaudit.googleapis.com/{name}")' for name in window['classes'])
        methods = ' OR '.join(f'protoPayload.methodName="{name}"' for name in DETECTOR_METHODS)
        expression = f'timestamp >= "{window["start"]}" AND timestamp < "{window["end"]}" AND ({terms}) AND ({methods})'
        body = {'resourceNames': [scope], 'filter': expression, 'orderBy': 'timestamp asc', 'pageSize': min(self.page_size, 1000)}
        def project_only(row):
            if not isinstance(row, dict):
                raise ReadError('malformed', 'malformed_audit_entry')
            payload = row.get('protoPayload')
            if not isinstance(payload, dict):
                raise ReadError('malformed', 'malformed_audit_payload')
            # Strict projection: never retain request/response bodies or tokens.
            auth, status, metadata = payload.get('authenticationInfo'), payload.get('status'), payload.get('requestMetadata')
            log_name, insert_id = row.get('logName'), row.get('insertId')
            identity = f'{log_name}#{insert_id}' if isinstance(log_name, str) and isinstance(insert_id, str) else None
            return {'name': identity, 'insertId': insert_id, 'timestamp': row.get('timestamp'),
                    'logName': row.get('logName'), 'resource': {'type': (row.get('resource') or {}).get('type'),
                        'labels': {'project_id': ((row.get('resource') or {}).get('labels') or {}).get('project_id')}},
                    'protoPayload': {'@type': payload.get('@type'), 'serviceName': payload.get('serviceName'),
                        'resourceName': payload.get('resourceName'), 'methodName': payload.get('methodName'),
                        'authenticationInfo': {'principalEmail': auth.get('principalEmail') if isinstance(auth, dict) else None},
                        'status': {'code': status.get('code') if isinstance(status, dict) else None},
                        'requestMetadata': {'callerIp': metadata.get('callerIp') if isinstance(metadata, dict) else None}}}
        def fetch():
            yield from self.pages(URL, scope, key='entries', method='POST', page_size_key=None,
                body=body, transform=project_only)
        jobs.append(('audit_log', scope, 'logging', fetch))
        return jobs

    def finish(self):
        if self.audit_selected:
            for (kind, scope), env in self.collections.items():
                if kind == 'audit_log':
                    env['audit_coverage'] = {**self.audit_window, 'all_pages': env['status'] in ('collected', 'empty'),
                        'logclass_routing_retention_verified': False,
                        'absence_proves_no_event': False, 'detector_methods': list(DETECTOR_METHODS), 'source_requests': env['source_requests']}
        snapshot = super().finish()
        if self.audit_selected:
            from peaso.snapshot import make_snapshot
            snapshot = make_snapshot('gcp', snapshot['scopes'], snapshot['collections'],
                created_at=snapshot['created_at'],
                metadata={**snapshot['metadata'], 'audit_detection_policy': self.audit_policy})
        return snapshot


def collect_selected(connector, requirements, *, transport=None):
    return AuditGCPCollector(connector, requirements, transport=transport).collect()
