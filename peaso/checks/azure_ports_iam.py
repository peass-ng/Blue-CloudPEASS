"""Declared role/tenant policy predicates do not compute effective privilege or chains."""
from . import register,result
from .facts import get,list_of_objects,complete_items,Unavailable
from .fixtures import CASES
from .azure_ports_directory import _tenant

CHECK_IDS=[]
SOURCE_QUERIES={}

cid='azure.port.iam_no_custom_subscription_owner_roles_created'
CHECK_IDS.append(cid);SOURCE_QUERIES['iam_no_custom_subscription_owner_roles_created']=cid
@register(cid,'azure','hardening','role_definition','Selected subscription custom-role definitions contain no literal wildcard control-plane action','medium','AC-6',
          'Review the declared Actions/NotActions and separate assignments, conditions and data-plane permissions; this check does not call exclusions a deny or infer effective Owner.',target='scope',dependencies=['role_definition'])
def wildcard(item,index):
    scope=get(item,'scope',str)
    if not scope.startswith('/subscriptions/') or len(scope.strip('/').split('/'))!=2:
        return 'NOT_APPLICABLE',{'reason':'Source predicate requires subscription scope'}
    envelopes=index.get('collections',{}).get('role_definition',[])
    if any(not isinstance(e,dict) or get(e,'scope',str).casefold()!=scope.casefold() for e in envelopes):
        raise Unavailable('Role-definition dependency was not captured at the selected subscription scope')
    matches=[]
    for role in complete_items(index,'role_definition'):
        identity=get(role,'id',str)
        if '/providers/microsoft.authorization/roledefinitions/' not in identity.casefold():
            raise Unavailable('Malformed role-definition identity')
        role_type=get(role,'properties.roleType',str)
        if role_type not in ('CustomRole','BuiltInRole'):raise Unavailable('Unrecognized role definition type')
        if role_type!='CustomRole':continue
        for permission in list_of_objects(get(role,'properties.permissions',list)):
            actions=get(permission,'actions',list)
            if any(not isinstance(action,str) for action in actions):raise Unavailable('Malformed role actions')
            if any(action in ('*','*:*') for action in actions):matches.append(identity)
    return result(bool(matches),role_ids=sorted(set(matches)),semantics='Literal declared control-plane action only; NotActions remain exclusions, DataActions/assignments/conditions/effective access separate')
_ROLE='/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/role'
def _role(actions):return {'id':_ROLE,'properties':{'roleType':'CustomRole','permissions':[{'actions':actions,'notActions':['Microsoft.Authorization/*'],'dataActions':[],'notDataActions':[]}]}}
def _index(rows):return {'role_definition':[{'data':row} for row in rows],'collections':{'role_definition':[{'scope':'/subscriptions/sub','status':'collected' if rows else 'empty'}]}}
CASES[cid]={'pass':{'scope':'/subscriptions/sub'},'fail':{'scope':'/subscriptions/sub'},'pass_index':_index([_role(['Microsoft.Compute/virtualMachines/read'])]),'fail_index':_index([_role(['*'])])}

cid='azure.port.iam_subscription_tenant_transfer_restricted'
CHECK_IDS.append(cid);SOURCE_QUERIES['iam_subscription_tenant_transfer_restricted']=cid
@register(cid,'azure','hardening','subscription_tenant_policy','Tenant policy blocks subscription transfers both into and out of tenant','medium','AC-4','Review both declared tenant-transfer block flags; no subscription is moved or policy modified.')
def transfers(item,index):
    tenant=_tenant(item,index)
    incoming=get(item,'properties.blockSubscriptionsIntoTenant',bool)
    leaving=get(item,'properties.blockSubscriptionsLeavingTenant',bool)
    return result(not(incoming and leaving),tenant_id=tenant,block_into=incoming,block_leaving=leaving,semantics='Declared global flags; allowlisted exceptions and operational transfer state are separate')
CASES[cid]={'pass':{'_provenance':{'tenant_id':'tenant'},'properties':{'blockSubscriptionsIntoTenant':True,'blockSubscriptionsLeavingTenant':True}},'fail':{'_provenance':{'tenant_id':'tenant'},'properties':{'blockSubscriptionsIntoTenant':True,'blockSubscriptionsLeavingTenant':False}}}


cid='azure.port.iam_user_access_administrator_role_restricted'
CHECK_IDS.append(cid);SOURCE_QUERIES['iam_user_access_administrator_role_restricted']=cid
@register(cid,'azure','hardening','role_assignment','Assignment does not refer to a definition named User Access Administrator','medium','AC-6','Review the exact assignment/definition and condition scope; no grants, exclusion semantics or effective authority are computed.',dependencies=['role_assignment','role_definition'])
def named_access_admin(item,index):
    rid=get(item,'properties.roleDefinitionId',str)
    roles=[role for role in complete_items(index,'role_definition') if get(role,'id',str).casefold()==rid.casefold()]
    if len(roles)!=1:raise Unavailable('Assignment definition is missing or ambiguous')
    name=get(roles[0],'properties.roleName',str)
    if name!='User Access Administrator':return result(False,role_name=name,semantics='Known nonmatching definition does not satisfy source risk selector')
    return result(True,role_definition_id=rid,role_name=name,semantics='Exact source declaration selector; assignment conditions/NotActions/effective permissions remain separate')
_DEF='/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/definition'
def _definitions(name):return {'role_definition':[{'data':{'id':_DEF,'properties':{'roleName':name}}}],'collections':{'role_definition':[{'scope':'/subscriptions/sub','status':'collected'}]}}
CASES[cid]={'pass':{'properties':{'roleDefinitionId':_DEF}},'fail':{'properties':{'roleDefinitionId':_DEF}},'pass_index':_definitions('Reader'),'fail_index':_definitions('User Access Administrator')}
