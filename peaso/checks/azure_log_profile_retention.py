"""Private legacy Monitor log-profile retention predicate; no cloud calls."""
from __future__ import annotations
import re
from peaso.checks import register, result, unknown
from peaso.checks.facts import Unavailable, complete_items, get, list_of_objects, memoized

CHECK_ID='azure.gap.monitor_log_profile_retention_365_days'
SPEC_SHA256='79ba51c47bda8b66e9a9b95854be99025fb8e45c83a88b1b0b934bf89e4105d1'


def _profiles(index):
    ctx=get(index,'context',dict)
    if get(ctx,'provider',str)!='azure':raise Unavailable('foreign provider')
    scope=get(ctx,'scope',str).casefold()
    if not re.fullmatch(r'/subscriptions/[0-9a-f-]{36}',scope):raise Unavailable('subscription scope unavailable')
    def build():
        envelopes=get(index,'collections',dict).get('monitor_log_profile')
        if not isinstance(envelopes,list) or len(envelopes)!=1:raise Unavailable('missing or ambiguous log profile inventory')
        env=envelopes[0]
        if not isinstance(env,dict):raise Unavailable('malformed log profile envelope')
        if (env.get('type')!='monitor_log_profile' or str(env.get('scope','')).casefold()!=scope or
            env.get('status') not in ('collected','empty')):
            raise Unavailable('incomplete or foreign log profile inventory')
        rows=list_of_objects(get(env,'items',list))
        if (env['status']=='empty')!=(not rows) or sorted(rows,key=lambda r:r.get('id',''))!=sorted(complete_items(index,'monitor_log_profile'),key=lambda r:r.get('id','')):
            raise Unavailable('inventory/projection mismatch')
        seen=set()
        for row in rows:
            rid=get(row,'id',str).casefold()
            if not re.fullmatch(re.escape(scope)+r'/providers/microsoft\.insights/logprofiles/[^/?#]+',rid):
                raise Unavailable('foreign or malformed log profile ID')
            if rid in seen:raise Unavailable('duplicate log profile identity')
            seen.add(rid)
            if get(row,'type',str).casefold() not in ('microsoft.insights/logprofiles',''):
                raise Unavailable('wrong log profile native type')
        return rows
    return memoized(index,('azure_log_profile',scope),build)


@register(CHECK_ID,'azure','hardening','monitor_log_profile','Legacy Monitor log profiles retain logs at least 365 days','medium','AU-11',
          'Review the legacy log profile retention and migrate to supported Diagnostic Settings.',target='scope',dependencies=('monitor_log_profile',))
def retention(item,index):
    rows=_profiles(index)
    if not rows:return 'NOT_APPLICABLE',{'reason':'No legacy Monitor log profile in complete subscription inventory'}
    failing=[];unresolved=[]
    for row in rows:
        rid=row['id']
        try:
            enabled=get(row,'properties.retentionPolicy.enabled',bool)
            days=get(row,'properties.retentionPolicy.days',int)
            if days<0:raise Unavailable('invalid retention day count')
            if enabled and 1<=days<365:
                failing.append(rid)
            elif enabled and days>=365:
                pass
            elif days==0:
                # No producer verifies destination retention yet. The ARM
                # field alone cannot establish the signed unlimited case.
                unresolved.append(rid)
            else:
                unresolved.append(rid)
        except Unavailable:
            unresolved.append(rid)
    if failing:return result(True,short_retention_profile_ids=sorted(failing))
    if unresolved:return unknown('legacy retention or destination retention unresolved',profile_ids=sorted(set(unresolved)))
    return result(False,profile_count=len(rows))
