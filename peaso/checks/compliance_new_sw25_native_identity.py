"""Narrow native guest-review proof over actual Graph instances and decisions."""
from __future__ import annotations
from datetime import datetime,timedelta,timezone
import re
from urllib.parse import urlsplit,parse_qs
from . import result,unknown
from .facts import Unavailable,get,list_of_objects
from .compliance_new_sw25_facts import MONTHLY_ID,REGULAR_ID,_rows,_scope,_policy,_date,_now,_strings

GUID=r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
ADAPTER='graph-access-reviews-native-v1'


def _group(scope,groups):
    if not isinstance(scope,dict) or scope.get('@odata.type')!='#microsoft.graph.accessReviewQueryScope' or scope.get('queryType')!='MicrosoftGraph' or scope.get('queryRoot') is not None:
        raise Unavailable('native group review scope unsupported')
    if any(k not in ('@odata.type','queryType','queryRoot','query') and v not in (None,[],{}) for k,v in scope.items()):
        raise Unavailable('unmodeled native review scope')
    query=get(scope,'query',str);url=urlsplit(query)
    match=re.fullmatch(r'/(?:v1\.0/)?groups/('+GUID+r')/(?:members|transitiveMembers)(?:/microsoft\.graph\.user)?/?',url.path,re.I)
    params=parse_qs(url.query,keep_blank_values=True)
    if url.scheme or url.netloc or url.fragment or not match or set(params)-{'$count','$filter'}:
        raise Unavailable('native group scope query unresolved')
    if '$count' in params and params['$count']!=['true']:
        raise Unavailable('native group count semantics unresolved')
    if '$filter' in params and params['$filter'] not in (["(userType eq 'Guest')"],["userType eq 'Guest'"]):
        raise Unavailable('native group filter unsupported')
    group=groups.get(match[1].casefold())
    if group is None or 'DynamicMembership' in _strings(get(group,'groupTypes',list)):
        raise Unavailable('review group identity or dynamic membership unresolved')
    return match[1].casefold()


def _schedule(definition,instances,now,monthly):
    settings=get(definition,'reviewSettings',dict);recurrence=get(settings,'recurrence',dict)
    pattern=get(recurrence,'pattern',dict);kind=get(pattern,'type',str);interval=get(pattern,'interval',int)
    if type(interval) is not int or not 1<=interval<=3650:
        raise Unavailable('native recurrence interval unresolved')
    period=interval*(1 if kind=='daily' else 7 if kind=='weekly' else 31 if kind=='absoluteMonthly' else 0)
    if not period or monthly and not (kind=='absoluteMonthly' and interval==1 or kind in ('daily','weekly') and period<=28):
        raise Unavailable('native recurrence cadence unsupported')
    if kind=='absoluteMonthly' and (type(pattern.get('dayOfMonth')) is not int or not 1<=pattern['dayOfMonth']<=28):
        raise Unavailable('monthly calendar boundary unsupported')
    if kind=='weekly' and (not isinstance(pattern.get('daysOfWeek'),list) or len(pattern['daysOfWeek'])!=1):
        raise Unavailable('weekly recurrence day partition unresolved')
    recurrence_range=get(recurrence,'range',dict)
    if recurrence_range.get('recurrenceTimeZone') not in (None,'UTC','Etc/UTC'):
        raise Unavailable('review recurrence timezone unresolved')
    started=_date(get(recurrence_range,'startDate',str)+'T00:00:00Z')
    range_type=get(recurrence_range,'type',str)
    if range_type not in ('noEnd','endDate') or started>now:
        raise Unavailable('review active recurrence range unresolved')
    if range_type=='endDate' and _date(get(recurrence_range,'endDate',str)+'T23:59:59Z')<now:
        raise Unavailable('review schedule is no longer active')
    duration=get(settings,'instanceDurationInDays',int)
    if type(duration) is not int or not 1<=duration<=366:
        raise Unavailable('native review duration unresolved')
    due=[]
    for instance in instances:
        begin,end=_date(get(instance,'startDateTime',str)),_date(get(instance,'endDateTime',str))
        if begin<started or end<=begin or end-begin>timedelta(days=duration):
            raise Unavailable('native instance chronology unresolved')
        if kind=='absoluteMonthly' and begin.day!=pattern['dayOfMonth']:
            raise Unavailable('native instance does not match monthly boundary')
        if kind=='weekly' and begin.strftime('%A').casefold()!=str(pattern['daysOfWeek'][0]).casefold():
            raise Unavailable('native instance does not match weekly day')
        if get(instance,'status',str) not in ('Initializing','NotStarted','Starting','InProgress','Completing','Completed','AutoReviewing','AutoReviewed'):
            raise Unavailable('native review instance status unresolved')
        if end<=now:due.append((begin,end,instance))
    due.sort(key=lambda r:r[0])
    if not due or now-due[-1][1]>timedelta(days=period):
        raise Unavailable('latest scheduled due review boundary unresolved')
    if any(b[0]-a[0]>timedelta(days=period) or b[0]<=a[0] for a,b in zip(due,due[1:])):
        raise Unavailable('native recurring instance history has a gap')
    return due[-1:] if monthly else due


def native_guest_reviews(cid,index):
    envelopes=index.get('collections',{}).get('access_review_subject',[])
    if not any(e.get('_provenance',{}).get('subject_model')=='directory_users' and e.get('_provenance',{}).get('adapter')==ADAPTER for e in envelopes):return None
    if cid not in (MONTHLY_ID,REGULAR_ID):
        return unknown('Native directory-user subjects do not resolve effective directory role/PIM assignments')
    metadata=get(index,'context.metadata',dict)
    if 'sw25_policy' in metadata:
        policy=_policy(index,cid)
    else:
        root=get(metadata,'compliance_policy.sw25',dict)
        if get(root,'status',str)!='collected' or get(root,'scope',str).casefold()!=_scope(index).casefold():
            raise Unavailable('guest review owner policy scope unresolved')
        checks=get(root,'checks',dict);policy=checks.get(cid)
        if not isinstance(policy,dict):raise Unavailable('guest review owner policy unavailable')
    now=_now(index);age=31 if cid==MONTHLY_ID else get(policy,'maxReviewAgeDays',int)
    if type(age) is not int or not 1<=age<=3660:raise Unavailable('guest review age invalid')
    since=now-timedelta(days=age)
    subjects=_rows(index,'access_review_subject',graph=True)
    applicable=[]
    for subject in subjects:
        if get(subject,'userType',str) not in ('Guest','Member'):
            raise Unavailable('native directory principal type unresolved')
        if not re.fullmatch(GUID,get(subject,'id',str),re.I) or get(subject,'principalId',str).casefold()!=subject['id'].casefold():
            raise Unavailable('native directory principal identity ambiguous')
        if 'createdDateTime' in subject and _date(get(subject,'createdDateTime',str))>now:
            raise Unavailable('native guest creation time is future dated')
        enabled=get(subject,'accountEnabled',bool)
        if subject['userType']=='Guest' and (enabled or cid==REGULAR_ID):applicable.append(subject)
    if not applicable:return 'NOT_APPLICABLE',{'reason':'Complete native directory roster has no applicable guest users'}
    definitions=_rows(index,'access_review_definition',graph=True)
    instances=_rows(index,'access_review_instance',graph=True)
    decisions=_rows(index,'access_review_decision',graph=True)
    groups={r['id'].casefold():r for r in _rows(index,'directory_group',graph=True)}
    definitions_by_id={r['id']:r for r in definitions};instances_by_id={r['id']:r for r in instances}
    if any(get(r,'definitionId',str) not in definitions_by_id for r in instances) or any(get(r,'instanceId',str) not in instances_by_id for r in decisions):
        raise Unavailable('native review child belongs to another parent')
    supported=[];unresolved=any(not isinstance(d.get('principal'),dict) or not re.fullmatch(GUID,str(d['principal'].get('id','')),re.I) for d in decisions)
    for definition in definitions:
        try:
            if get(definition,'stageCount',int)!=0:
                raise Unavailable('native multistage review semantics unresolved')
            if get(definition,'status',str) not in ('Initializing','NotStarted','Starting','InProgress','Completing','Completed','AutoReviewing','AutoReviewed'):
                raise Unavailable('native definition status unresolved')
            if definition.get('instanceEnumerationScope') is not None:raise Unavailable('enumerated review scope unsupported')
            gid=_group(get(definition,'scope',dict),groups)
            children=[r for r in instances if r['definitionId']==definition['id']]
            windows=_schedule(definition,children,now,cid==MONTHLY_ID)
            for begin,end,instance in windows:
                if instance.get('scope') is not None and _group(instance['scope'],groups)!=gid:
                    raise Unavailable('native instance scope differs from definition')
            supported.append((gid,windows))
        except Unavailable:unresolved=True
    failures=[];uncertain=[];reviewed=[]
    for subject in applicable:
        uid=subject['id'].casefold();matched=False;pending=unresolved;due_begin=since
        for gid,windows in supported:
            for begin,end,instance in reversed(windows):
                due_begin=max(due_begin,begin)
                if instance['status']!='Completed':continue
                matches=[d for d in decisions if d['instanceId']==instance['id'] and isinstance(d.get('principal'),dict) and str(d['principal'].get('id','')).casefold()==uid]
                if len(matches)>1:pending=True;continue
                if not matches:continue
                d=matches[0]
                try:
                    # Native group decisions commonly have resource:null; the
                    # fixed definition/instance scope and fetched child path bind them.
                    if d.get('resource') is not None and get(d,'resource.id',str).casefold()!=gid:
                        raise Unavailable('review resource identity unresolved')
                    state=get(d,'decision',str)
                    if state=='NotReviewed':continue
                    if state not in ('Approve','Deny','DontKnow'):raise Unavailable('unknown native review decision')
                    at=_date(get(d,'reviewedDateTime',str))
                    if not re.fullmatch(GUID,get(d,'reviewedBy.id',str),re.I) or get(d,'reviewedBy.id',str)=='00000000-0000-0000-0000-000000000000':raise Unavailable('native reviewer identity unresolved')
                    if at>now or at<begin or at>end:
                        raise Unavailable('native decision chronology unresolved')
                    if 'createdDateTime' in subject and at<_date(get(subject,'createdDateTime',str)):
                        raise Unavailable('native review predates guest principal creation')
                    if at>=since:matched=True;reviewed.append(uid);break
                except Unavailable:pending=True
            if matched:break
        if matched:continue
        try:created=_date(get(subject,'createdDateTime',str))
        except Unavailable:created=now
        if pending or created>due_begin:uncertain.append(uid)
        else:failures.append(uid)
    if failures:return result(True,unreviewed_guest_ids=failures,uncertain_guest_count=len(uncertain))
    if uncertain:return unknown('Guest review scope, schedule, principal or chronology incomplete',uncertain_guest_count=len(uncertain))
    return result(False,reviewed_guest_count=len(set(reviewed)),native_timestamp='decision.reviewedDateTime',native_completed_state='Completed')
