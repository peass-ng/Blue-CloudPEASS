"""Pure normative approvals for Sentinel reviews and static severity criteria."""
import copy
from datetime import datetime,timezone,timedelta
import json
import re

_SCOPE=re.compile(r'/subscriptions/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',re.I)
_NAME=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
_CLASSIFICATIONS={'TruePositive','FalsePositive','BenignPositive','Undetermined'}
_PRIORITIES={'High','Medium','Low','Informational'}


def _instant(value):
    if not isinstance(value,str)or len(value)>64:raise ValueError('invalid incident review time')
    try:value=datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError:raise ValueError('invalid incident review time')from None
    if value.tzinfo is None or value.utcoffset()is None:raise ValueError('incident review needs timezone')
    try:return value.astimezone(timezone.utc)
    except(OverflowError,ValueError):raise ValueError('invalid incident review time')from None


def _choice_list(value,allowed):
    if (not isinstance(value,list)or not 1<=len(value)<=len(allowed)
        or any(not isinstance(v,str)or v not in allowed for v in value)or len(set(value))!=len(value)):
        raise ValueError('invalid or duplicate incident approval criteria')


_UUID=r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
_SEGMENT=r'[^/\\?#%\x00-\x20\x7f]+'
_GROUP=r'[^/\\?#%\x00-\x20\x7f]{1,90}'
_MG=r'/providers/Microsoft\.Management/managementGroups/'+_SEGMENT
_SUB=r'/subscriptions/'+_UUID
_RESOURCE=_SUB+r'/resourceGroups/'+_GROUP+r'/providers/'
_CRITERIA={'incident_review','vulnerability_severity_criteria',
           'acr_max_untagged_days','later_stage_deployment_limit','max_registry_scan_age_seconds',
           'registry_vulnerability_assessment_key','approved_cosmos_workspaces',
           'required_role_assignments','approved_key_algorithms','sensitive_dashboard_ids',
           'approved_dashboard_viewers','approved_peer_ids'}
_MAX_INTEGER=2**53-1


def _integer(value,minimum):
    if type(value)is not int or not minimum<=value<=_MAX_INTEGER:
        raise ValueError('invalid bounded SW32 integer criterion')


def _identity(value,pattern):
    if (not isinstance(value,str)or not 1<=len(value)<=2048
        or any(part in {'.','..'}for part in value.split('/'))
        or not re.fullmatch(pattern,value,re.I)):
        raise ValueError('invalid SW32 approved identity')


def _identities(value,pattern,*,nonempty=False):
    if not isinstance(value,list)or not int(nonempty)<=len(value)<=256:
        raise ValueError('invalid bounded SW32 approval list')
    for entry in value:_identity(entry,pattern)
    if len({entry.casefold()for entry in value})!=len(value):
        raise ValueError('duplicate SW32 approved identity')


def _assignment_scope(value,subscription):
    # Management-group applicability is normative, never proof of ancestry or RBAC coverage.
    if isinstance(value,str)and re.fullmatch(_MG,value,re.I):
        _identity(value,_MG)
        return
    _identity(value,_SUB+r'(?:/'+_SEGMENT+r')*')
    parts=value.split('/')[3:]
    if value.split('/')[2].casefold()!=subscription.split('/')[2].casefold():
        raise ValueError('foreign SW32 required assignment scope')
    if parts and parts[0].casefold()=='resourcegroups':
        if len(parts)<2:raise ValueError('incomplete required assignment resource group')
        _identity(parts[1],_GROUP)
        parts=parts[2:]
    while parts:
        if parts[0].casefold()!='providers':raise ValueError('invalid required assignment ARM scope')
        boundary=next((i for i,part in enumerate(parts[1:],1)if part.casefold()=='providers'),len(parts))
        segment=parts[1:boundary]
        if (len(segment)<3 or len(segment)%2!=1
            or not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+',segment[0])):
            raise ValueError('invalid required assignment resource identity')
        parts=parts[boundary:]


def _normative_extensions(value,scope):
    for key,minimum in (('acr_max_untagged_days',1),('later_stage_deployment_limit',0),('max_registry_scan_age_seconds',1)):
        if key in value:_integer(value[key],minimum)
    if 'registry_vulnerability_assessment_key'in value:
        if not isinstance(value['registry_vulnerability_assessment_key'],str)or not _NAME.fullmatch(value['registry_vulnerability_assessment_key']):
            raise ValueError('invalid expected registry assessment selector')
    for key,kind in (('approved_cosmos_workspaces',r'Microsoft\.OperationalInsights/workspaces'),
                     ('sensitive_dashboard_ids',r'Microsoft\.Portal/dashboards'),
                     ('approved_peer_ids',r'Microsoft\.Network/virtualNetworks')):
        if key in value:_identities(value[key],_RESOURCE+kind+'/'+_SEGMENT)
    if 'approved_dashboard_viewers'in value:_identities(value['approved_dashboard_viewers'],_UUID)
    if 'required_role_assignments'in value:
        rows=value['required_role_assignments']
        if not isinstance(rows,list)or len(rows)>256:raise ValueError('invalid required assignment list')
        seen=set()
        for row in rows:
            if not isinstance(row,dict)or set(row)!={'principalId','roleDefinitionId','scope'}:
                raise ValueError('unsupported required role assignment criterion')
            _identity(row['principalId'],_UUID)
            # Role definition IDs can be root, subscription or management-group scoped.
            _identity(row['roleDefinitionId'],r'(?:'+_SUB+'|'+_MG+r')?/providers/Microsoft\.Authorization/roleDefinitions/'+_UUID)
            _assignment_scope(row['scope'],scope)
            identity=tuple(row[key].casefold()for key in ('principalId','roleDefinitionId','scope'))
            if identity in seen:raise ValueError('duplicate required role assignment criterion')
            seen.add(identity)
    if 'approved_key_algorithms'in value:
        policy=value['approved_key_algorithms']
        if (not isinstance(policy,dict)or set(policy)!={'industry_standard_confirmed','minimum_rsa_bits','approved_ec_curves'}
            or policy['industry_standard_confirmed']is not True):
            raise ValueError('unsupported or unapproved key algorithm criteria')
        _integer(policy['minimum_rsa_bits'],2048)
        curves=policy['approved_ec_curves']
        _identities(curves,r'P-(?:256|256K|384|521)',nonempty=True)


def normalize_sw32(value,expected_scope=None):
    """Return approved criteria only. Never accept findings, provenance or coverage."""
    if not isinstance(value,dict)or set(value)-({'status','scope'}|_CRITERIA):
        raise ValueError('unsupported SW32 policy field')
    try:size=len(json.dumps(value,allow_nan=False))
    except(TypeError,ValueError,RecursionError):raise ValueError('invalid SW32 policy')from None
    scope=value.get('scope')
    if (size>50000 or value.get('status')!='collected'or not isinstance(scope,str)or not _SCOPE.fullmatch(scope)
        or not set(value).intersection(_CRITERIA)):
        raise ValueError('SW32 policy needs an exact subscription and explicit criteria')
    if expected_scope is not None and (not isinstance(expected_scope,str)or scope.casefold()!=expected_scope.casefold()):
        raise ValueError('foreign SW32 approval scope')
    if 'incident_review'in value:
        review=value['incident_review']
        if not isinstance(review,dict)or set(review)!={'start','end','approved','allowed_classifications','allowed_priorities'}or review['approved']is not True:
            raise ValueError('unsupported or unapproved incident review')
        start,end=_instant(review['start']),_instant(review['end'])
        if not start<end<=datetime.now(timezone.utc)or end-start>timedelta(days=366):
            raise ValueError('incident review window is future, reversed or too large')
        _choice_list(review['allowed_classifications'],_CLASSIFICATIONS)
        _choice_list(review['allowed_priorities'],_PRIORITIES)
    if 'vulnerability_severity_criteria'in value:
        criteria=value['vulnerability_severity_criteria']
        if (not isinstance(criteria,dict)or set(criteria)!={'approved','version','expectedSeverityByAssessmentName'}
            or criteria['approved']is not True or not isinstance(criteria['version'],str)
            or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}',criteria['version'])):
            raise ValueError('unsupported or unapproved static severity criteria')
        mapping=criteria['expectedSeverityByAssessmentName']
        if (not isinstance(mapping,dict)or not 1<=len(mapping)<=256
            or len({k.casefold() for k in mapping if isinstance(k,str)})!=len(mapping)
            or any(not isinstance(k,str)or not _NAME.fullmatch(k)or not isinstance(v,str)or v not in {'Low','Medium','High'}for k,v in mapping.items())):
            raise ValueError('invalid approved assessment severity map')
    _normative_extensions(value,scope)
    return copy.deepcopy(value)
