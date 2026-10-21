"""Native ARM custom-role consumer source contracts; no collector imports."""
from copy import deepcopy
import re
from urllib.parse import urlsplit,parse_qs
from peaso.azure_unused_iam_contract import guid

ARM='https://management.azure.com'
KIND='azure_unused_arm_role_evidence'
META='azure_unused_arm_roles'
SCHEMA='azure-unused-arm-role-evidence-v1'
GUID=r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
MG='/providers/microsoft.management/managementgroups/'
REPORTS={'assignments':('roleAssignments','2022-04-01'),
         'assignment_schedules':('roleAssignmentSchedules','2020-10-01'),
         'eligibility_schedules':('roleEligibilitySchedules','2020-10-01')}
MAX_ROWS=100000


def scope(value,root=False):
    if (not isinstance(value,str) or re.search(r'[\s?#%\\*]',value) or any(x in ('.','..','') for x in value.split('/')[1:])):
        if root and value=='/':return '/'
        raise ValueError('native ARM scope is malformed')
    value=value.casefold()
    if root and value=='/':return value
    if re.fullmatch(re.escape(MG)+r'[a-z0-9_.()-]+',value):return value
    if re.fullmatch('/subscriptions/'+GUID+r'(?:/resourcegroups/[^/]+(?:/providers/[^/]+(?:/[^/]+/[^/]+)+)?|/providers/[^/]+(?:/[^/]+/[^/]+)+)?',value):return value
    raise ValueError('native ARM scope is unsupported')


def subscription(value):
    match=re.match(r'(/subscriptions/'+GUID+')(?:/|$)',scope(value))
    return match[1] if match else None


def role_id(value):
    match=re.fullmatch(r'(.*)/providers/microsoft.authorization/roledefinitions/('+GUID+')',value.casefold()) if isinstance(value,str) else None
    if not match:raise ValueError('native ARM role reference is malformed')
    scope(match[1] or '/',root=True)
    return guid(match[2])


def path(sc,name):
    endpoint,version=REPORTS[name]
    return sc.rstrip('/')+'/providers/Microsoft.Authorization/'+endpoint,version


def validate_read(url,expected,version,*,audience=ARM,body=None):
    parsed=urlsplit(url);query=parse_qs(parsed.query,keep_blank_values=True)
    if (body is not None or audience!=ARM or parsed.scheme!='https' or parsed.netloc!='management.azure.com' or parsed.fragment
            or parsed.path.casefold()!=expected.casefold() or query.get('api-version')!=[version]
            or any(key not in ('api-version','$skiptoken','$skipToken','$top') for key in query)
            or any(len(values)!=1 or not values[0] for values in query.values())
            or '$top' in query and (not query['$top'][0].isdigit() or int(query['$top'][0])<1)):
        raise ValueError('unfiltered native ARM consumer source changed')


def project(name,row,queried_scope):
    endpoint,_=REPORTS[name]
    if not isinstance(row,dict) or not isinstance(row.get('properties'),dict):raise ValueError('native ARM consumer is malformed')
    identity=row.get('id');props=row['properties']
    match=re.fullmatch(r'(.*)/providers/microsoft.authorization/'+endpoint.casefold()+'/('+GUID+')',identity.casefold()) if isinstance(identity,str) else None
    if not match or str(row.get('type','')).casefold()!='microsoft.authorization/'+endpoint.casefold():raise ValueError('native ARM consumer identity is malformed')
    name=row.get('name',match[2])
    if not isinstance(name,str) or name.casefold()!=match[2]:raise ValueError('native ARM consumer name differs from ID')
    declared=scope(props.get('scope'),root=True)
    if scope(match[1] or '/',root=True)!=declared:raise ValueError('native ARM consumer ID parent differs from its scope')
    owner=subscription(queried_scope)
    if declared.startswith('/subscriptions/') and owner and subscription(declared)!=owner:
        raise ValueError('native ARM consumer is outside requested subscription')
    role_id(props.get('roleDefinitionId'));guid(props.get('principalId'))
    fields=('scope','roleDefinitionId','principalId','principalType','condition','conditionVersion','status','startDateTime','endDateTime','memberType')
    return {'id':identity,'type':row['type'],'properties':{key:deepcopy(props[key]) for key in fields if key in props}}


def required_types(wanted):return {'role_definition'} if KIND in wanted else set()
