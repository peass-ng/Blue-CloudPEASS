"""Private offline candidate for two exact-method signed audit predicates.

The other three are held: T1110 lacks a documented authentication-event
classifier; T1490 requires request payload not retained by the safe producer;
T1651 lacks service-specific exact method names. Five rate predicates use
permission names rather than documented AuditLog.methodName values; T1648
does too. No registry import side effect.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
import re
from peaso.checks import CHECKS, register, result, unknown
from peaso.checks.facts import Unavailable, memoized

METHODS = {
 'gcp_logging_detect_t1136': {'google.iam.admin.v1.CreateServiceAccount'},
 'gcp_logging_detect_t1546': {'google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger','google.cloud.scheduler.v1.CloudScheduler.CreateJob'},
}
SERVICES = {'google.iam.admin.v1.CreateServiceAccount':'iam.googleapis.com',
 'google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger':'cloudbuild.googleapis.com',
 'google.cloud.scheduler.v1.CloudScheduler.CreateJob':'cloudscheduler.googleapis.com'}
ALLOW = {'gcp_logging_detect_t1136':'approved_identity_admins',
 'gcp_logging_detect_t1546':'approved_automation_admins'}
ELIGIBLE = frozenset(ALLOW)
SPEC_SHA256 = {
 'gcp_logging_detect_t1136': 'e859d6be906ef8bce5f3bdf65201c2c2e286efea9213e148be3457278baaf05d',
 'gcp_logging_detect_t1546': 'eb87cb4e5a61ed26915d102d308e686522260728d902d71c547a084bb594a06d',
}


def instant(text):
    if not isinstance(text,str): raise Unavailable('timestamp missing')
    try: value=datetime.fromisoformat(text.replace('Z','+00:00'))
    except ValueError as exc: raise Unavailable('timestamp malformed') from exc
    if value.tzinfo is None: raise Unavailable('timestamp lacks timezone')
    return value.astimezone(timezone.utc)


def read_scope(index):
    context=index.get('context')
    if not isinstance(context,dict) or context.get('provider')!='gcp':
        raise Unavailable('GCP context missing')
    scope=context.get('scope')
    if not isinstance(scope,str) or not re.fullmatch(r'projects/[A-Za-z0-9][A-Za-z0-9._-]*',scope):
        raise Unavailable('project scope missing')
    collections=index.get('collections',{}).get('audit_log',[])
    if len(collections)!=1: raise Unavailable('audit collection missing or ambiguous')
    env=collections[0]
    if env.get('scope')!=scope or env.get('type')!='audit_log': raise Unavailable('foreign audit collection')
    if env.get('status') not in ('collected','empty'): raise Unavailable('audit collection unavailable')
    coverage=env.get('audit_coverage')
    if not isinstance(coverage,dict) or coverage.get('all_pages') is not True:
        raise Unavailable('audit page coverage missing')
    start,end=instant(coverage.get('start')),instant(coverage.get('end'))
    if start>=end or (end-start).total_seconds()>86400: raise Unavailable('audit window invalid')
    classes=coverage.get('classes')
    if not isinstance(classes,list) or not classes: raise Unavailable('audit class selection missing')
    rows=env.get('items')
    if not isinstance(rows,list) or (env['status']=='empty') != (len(rows)==0):
        raise Unavailable('audit rows malformed')
    project=scope.split('/',1)[1]
    events=[]; seen=set(); by_method=defaultdict(list); by_identity={}
    for row in rows:
        if not isinstance(row,dict): raise Unavailable('audit row malformed')
        insert_id=row.get('insertId')
        if not isinstance(insert_id,str) or not insert_id:
            raise Unavailable('audit entry identity missing')
        log=row.get('logName')
        if not isinstance(log,str) or not log.startswith(scope+'/logs/cloudaudit.googleapis.com%2F'):
            raise Unavailable('foreign audit log')
        identity=(log,insert_id)
        if identity in seen: raise Unavailable('audit entry identity duplicated')
        seen.add(identity)
        logclass=log.rsplit('%2F',1)[-1]
        if logclass not in classes: raise Unavailable('audit class outside selector')
        resource=row.get('resource')
        if not isinstance(resource,dict) or not isinstance(resource.get('type'),str) or not resource['type']:
            raise Unavailable('foreign audit resource')
        labels=resource.get('labels')
        if not isinstance(labels,dict) or labels.get('project_id') not in (None,project):
            raise Unavailable('foreign audit resource')
        ts=instant(row.get('timestamp'))
        if not start<=ts<end: raise Unavailable('event outside audit window')
        # A redacted or incomplete event is unknown on its own identity. It
        # must not suppress a different, fully evidenced event in this scope.
        try:
            payload=row.get('protoPayload')
            if not isinstance(payload,dict): raise Unavailable('audit payload missing')
            if payload.get('@type')!='type.googleapis.com/google.cloud.audit.AuditLog':
                raise Unavailable('audit payload type unverified')
            method=payload.get('methodName'); auth=payload.get('authenticationInfo'); status=payload.get('status')
            if not isinstance(method,str) or not isinstance(auth,dict) or not isinstance(status,dict):
                raise Unavailable('method, authentication or status unavailable')
            principal=auth.get('principalEmail'); code=status.get('code')
            if not isinstance(principal,str) or not principal or type(code) is not int or code<0:
                raise Unavailable('principal or status redacted or malformed')
            event=(ts,method,principal,code,row)
            events.append(event); by_method[method].append(event)
            by_identity[identity]=(row,event,None)
        except Unavailable as exc:
            by_identity[identity]=(row,None,str(exc))
    metadata=context.get('metadata',{})
    if not isinstance(metadata,dict): raise Unavailable('audit metadata malformed')
    policy=metadata.get('audit_detection_policy',{})
    if not isinstance(policy,dict): raise Unavailable('audit policy malformed')
    return context,coverage,policy,events,by_method,by_identity


def evaluate(check_id,item,index):
    if check_id not in ELIGIBLE: return unknown('signed predicate held for missing semantics')
    try:
        context,coverage,policy,events,by_method,by_identity=memoized(index,'gcp-audit-v1',lambda:read_scope(index))
        if not isinstance(item,dict): raise Unavailable('audit event missing')
        identity=(item.get('logName'),item.get('insertId'))
        parsed=by_identity.get(identity)
        if parsed is None or parsed[0]!=item: raise Unavailable('audit event absent from scoped collection')
        _,event,reason=parsed
        if reason is not None: raise Unavailable(reason)
        approved=policy.get(ALLOW[check_id])
        if (not isinstance(approved,list) or
            any(not isinstance(x,str) or not x for x in approved) or
            len(approved)!=len(set(approved))):
            raise Unavailable('approved principal roster unavailable')
        _,method,principal,code,row=event
        if method not in METHODS[check_id] or row['protoPayload'].get('serviceName')!=SERVICES.get(method):
            return unknown('event is unrelated to signed method and service')
        if code != 0: return unknown('event is not a successful operation')
        kind=row['resource']['type']
        if check_id.endswith('t1136') and kind!='service_account':
            raise Unavailable('service-account resource type mismatch')
        if method=='google.cloud.scheduler.v1.CloudScheduler.CreateJob' and kind!='audited_resource':
            raise Unavailable('scheduler resource type mismatch')
        return result(principal not in approved,principal=principal,method=method,
            event_id=row['insertId'],evaluated_resource_type=kind,
            semantics='this observed event only; no global absence assertion')
    except Unavailable as exc:
        return unknown(str(exc))


def install(specs):
    """Private opt-in registration with signed metadata, leaving public registry untouched on disk."""
    for cid in sorted(ELIGIBLE):
        spec=specs[cid]
        if any(c.id==cid for c in CHECKS): raise ValueError('candidate already registered: '+cid)
        @register(cid,'gcp','hardening','audit_log',spec['title'],spec['severity'],'CM-6',
            spec['remediation_hint'],dependencies=['audit_log'],target='resource')
        def callback(item,index,_cid=cid):
            return evaluate(_cid,item,index)
        callback.proposed_spec_sha256 = SPEC_SHA256[cid]
        CHECKS[-1].evaluate.proposed_spec_sha256 = SPEC_SHA256[cid]
        # Engine category is a supported selector; authored threat_detection
        # stays in the signed companion, without falsely changing engine schema.
