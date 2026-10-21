"""Exact API-only audit declaration parser; no native collector import or I/O."""
from datetime import datetime, timezone

CLASSES = frozenset({'activity', 'data_access', 'system_event', 'policy'})

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
