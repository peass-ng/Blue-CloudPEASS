"""Normative obligations for native AWS Budgets stop-action configuration."""
import copy,math,re
from datetime import datetime,timezone

STATUSES={'STANDBY','PENDING','EXECUTION_IN_PROGRESS','EXECUTION_SUCCESS','EXECUTION_FAILURE','REVERSE_IN_PROGRESS','REVERSE_SUCCESS','REVERSE_FAILURE','RESET_IN_PROGRESS','RESET_FAILURE'}
FIELDS={'ActionSubType','Region','InstanceIds','ExecutionRoleArn','ActionThreshold','NotificationType','ApprovalModel'}


def timestamp(value):
    if not isinstance(value,str):raise ValueError('timestamp required')
    dt=datetime.fromisoformat(value.replace('Z','+00:00'))
    if dt.utcoffset()is None:raise ValueError('timestamp timezone required')
    return dt.astimezone(timezone.utc)


def definition(value,account,partition=None):
    if not isinstance(value,dict)or set(value)!=FIELDS:raise ValueError('exact stop obligation required')
    subtype=value['ActionSubType'];ids=value['InstanceIds'];region=value['Region']
    if subtype not in {'STOP_EC2_INSTANCES','STOP_RDS_INSTANCES'}:raise ValueError('unsupported stop subtype')
    if not isinstance(region,str)or not re.fullmatch(r'[a-z]{2,4}(?:-[a-z]+)+-[0-9]',region):raise ValueError('invalid stop Region')
    pattern=r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})'if subtype=='STOP_EC2_INSTANCES'else r'[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    if not isinstance(ids,list)or not 1<=len(ids)<=100 or any(not isinstance(i,str)or not re.fullmatch(pattern,i)for i in ids)or len(set(ids))!=len(ids):raise ValueError('invalid stop targets')
    execution(value,account,partition)
    return copy.deepcopy(value)


def execution(value,account,partition=None):
    role=value['ExecutionRoleArn']
    m=re.fullmatch(r'arn:(aws(?:-[a-z0-9-]+)?):iam::'+re.escape(account)+r':role/(?:[!-~]+/)?[\w+=,.@-]+',role)if isinstance(role,str)else None
    if not m or partition is not None and m.group(1)!=partition:raise ValueError('foreign execution role')
    if value['NotificationType']not in {'ACTUAL','FORECASTED'}or value['ApprovalModel']not in {'AUTOMATIC','MANUAL'}:raise ValueError('unsupported trigger/approval')
    th=value['ActionThreshold']
    if not isinstance(th,dict)or set(th)!={'ActionThresholdType','ActionThresholdValue'}or th['ActionThresholdType']not in {'PERCENTAGE','ABSOLUTE_VALUE'}or type(th['ActionThresholdValue'])not in(int,float)or not math.isfinite(th['ActionThresholdValue'])or th['ActionThresholdValue']<=0:raise ValueError('invalid trigger threshold')


def normalize_value(raw):
    fields={'scope','status','authorized_by','document_id','observed_at','expires_at','budgets'}
    if not isinstance(raw,dict)or set(raw)!=fields or raw['status']!='collected'or not isinstance(raw['scope'],str)or not re.fullmatch(r'[0-9]{12}/global',raw['scope']):raise ValueError('invalid budget stop review')
    for key in('authorized_by','document_id'):
        v=raw[key]
        if not isinstance(v,str)or not 0<len(v)<=512 or v.strip()!=v or any(ord(c)<32 for c in v):raise ValueError('review identity required')
    if timestamp(raw['observed_at'])>=timestamp(raw['expires_at']):raise ValueError('invalid review window')
    budgets=raw['budgets']
    if not isinstance(budgets,dict)or not 1<=len(budgets)<=100:raise ValueError('explicit reviewed budgets required')
    for name,value in budgets.items():
        if not isinstance(name,str)or not 1<=len(name)<=100 or any(c in name for c in(':','\\'))or '/action/'in name or any(ord(c)<32 for c in name):raise ValueError('invalid reviewed budget name')
        definition(value,raw['scope'].split('/')[0])
    return copy.deepcopy(raw)


def normalize(options):
    params=options.get('compliance_parameters',{})
    if not isinstance(params,dict):raise ValueError('invalid compliance parameters')
    return normalize_value(params['aws_budget_stop'])if'aws_budget_stop'in params else None
