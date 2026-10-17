"""Only owner requirements; native observations can never enter this schema."""
import copy
import re

CHECK = 'azure.cis.monitor_resource_logging_services_support_it'
SUB = r'/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
SEG = r'[^/?#%\s\\]+'
ARM_ID = SUB+r'/resourceGroups/'+SEG+r'/providers/'+SEG+r'(?:/'+SEG+r'/'+SEG+r')+'


def normalize(options):
    parent = options.get('compliance_parameters', {})
    if not isinstance(parent, dict):
        raise ValueError('invalid compliance parameters')
    if 'azure_resource_logging' not in parent:
        return None
    raw = parent['azure_resource_logging']
    if (not isinstance(raw, dict) or set(raw) != {'scope','status','resources'}
            or not isinstance(raw['scope'], str) or not re.fullmatch(SUB,raw['scope'],re.I)
            or raw['status'] != 'collected' or not isinstance(raw['resources'],list)
            or len(raw['resources']) > 1000):
        raise ValueError('invalid diagnostic owner requirements')
    seen = set()
    for row in raw['resources']:
        if (not isinstance(row,dict) or set(row) != {'resourceId','requiredCategories','requiredCategoryGroups','approvedSinkIds','minRetentionDays'}
                or not isinstance(row['resourceId'],str) or not re.fullmatch(ARM_ID,row['resourceId'],re.I)
                or any(ord(c)<=32 or ord(c)==127 for c in row['resourceId'])
                or not row['resourceId'].casefold().startswith(raw['scope'].casefold()+'/')
                or row['resourceId'].casefold() in seen or type(row['minRetentionDays']) is not int
                or not 0 < row['minRetentionDays'] <= 4383):
            raise ValueError('invalid diagnostic resource requirement')
        seen.add(row['resourceId'].casefold())
        for field in ('requiredCategories','requiredCategoryGroups','approvedSinkIds'):
            values=row[field]
            if (not isinstance(values,list) or len(values)>1000
                    or any(not isinstance(v,str) or not v or len(v)>2048 or v.strip()!=v or any(ord(c)<=32 or ord(c)==127 for c in v) for v in values)
                    or len(values)!=len(set(values))):
                raise ValueError('invalid diagnostic requirement list')
        if not row['approvedSinkIds'] or not (row['requiredCategories'] or row['requiredCategoryGroups']):
            raise ValueError('diagnostic requirement has no category or sink')
        for sink in row['approvedSinkIds']:
            if not re.fullmatch(ARM_ID,sink,re.I) or not sink.casefold().startswith(raw['scope'].casefold()+'/'):
                raise ValueError('foreign approved diagnostic sink')
        for value in [row['resourceId'],*row['approvedSinkIds']]:
            if any(part in ('.','..')for part in value.split('/')):
                raise ValueError('diagnostic identity traversal')
    return copy.deepcopy(raw)


def owner_policy(options, scopes):
    raw = normalize(options)
    if raw is not None and raw['scope'].casefold() not in {scope.casefold()for scope in scopes}:
        raise ValueError('diagnostic approval outside selected subscriptions')
    return {CHECK:raw} if raw is not None else {}
