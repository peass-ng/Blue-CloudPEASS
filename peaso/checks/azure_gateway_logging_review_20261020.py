"""Unregistered AppGateway HTTP-log applicability/source successor proposal.

No registry change. L4 LoadBalancer health logging is a distinct contract.
"""
from ._bulk_pending_compliance_new_sw33 import _rows,_arm_id,_objects
from .facts import get,Unavailable
from . import result

CHECK='azure_application_gateway_app_http_logs_enabled_2de0361'
SUPPORTING_COLLECTIONS=('diagnostic_setting','diagnostic_category','log_analytics_workspace','storage_account')
DEPENDENCIES=('application_gateway',*SUPPORTING_COLLECTIONS)
EMPTY_APPLICABILITY_DEPENDENCIES=('application_gateway',)
DESCRIPTION='Application Gateway declares HTTP access-log export to an inventoried Log Analytics workspace or storage account. This checks configuration; log production, destination authorization and delivery are not measured.'


def evaluate(item,index):
    resources=_rows(index,'application_gateway')
    if not resources:
        return 'NOT_APPLICABLE',{'reason':'Complete native selected scope contains no Application Gateway; Layer4 LoadBalancer HTTP logs are outside this contract.'}
    settings=_rows(index,'diagnostic_setting');categories=_rows(index,'diagnostic_category')
    destinations={get(row,'id',str).casefold()for kind in('log_analytics_workspace','storage_account')for row in _rows(index,kind)}
    by_parent={}
    for category in categories:
        parent=_arm_id(get(category,'resourceId',str));by_parent.setdefault(parent,[]).append(category)
    missing=[]
    for resource in resources:
        rid=_arm_id(get(resource,'id',str))
        supported={get(c,'name',str)for c in by_parent.get(rid,[])if get(c,'categoryType',str)=='Logs'and get(c,'name',str)=='ApplicationGatewayAccessLog'}
        if not supported:raise Unavailable('Native Application Gateway access-log category resolution unavailable')
        good=False
        for setting in settings:
            sid=get(setting,'id',str).casefold();prefix=rid+'/providers/microsoft.insights/diagnosticsettings/'
            if not sid.startswith(prefix):continue
            if '/'in sid[len(prefix):]or get(setting,'parent_id',str).casefold()!=rid:raise Unavailable('Foreign native gateway diagnostic child')
            props=get(setting,'properties',dict)
            target=[_arm_id(get(props,f,str))for f in('workspaceId','storageAccountId')if f in props]
            enabled={get(log,'category',str)for log in _objects(props,'logs')if get(log,'enabled',bool)}
            if supported&enabled and any(x in destinations for x in target):good=True
        if not good:missing.append(rid)
    return result(bool(missing),resources_without_access_log_export=missing,semantics='Declared Application Gateway access-log export only; LoadBalancer health events and delivery are separate.')
