"""Tenant policy value requirements use verified captured tenant context and no defaults."""
from . import register, result
from .facts import get, list_of_objects, complete_items, Unavailable
from .fixtures import CASES
from .azure_ports_directory import _tenant

CHECK_IDS=[]
SOURCE_QUERIES={}


def _policy(query,name,kind,good,bad):
    cid='azure.port.'+query
    CHECK_IDS.append(cid);SOURCE_QUERIES[query]=cid
    @register(cid,'azure','hardening','directory_setting','Captured tenant setting '+name+' meets the pinned baseline','medium','AC-3',
              'Review the named administrative policy value and its availability; no settings, licenses or consent are changed.',target='scope',dependencies=['directory_setting'])
    def evaluate(item,index):
        scope=get(item,'scope',str)
        if not scope.startswith('/tenants/'):
            return 'NOT_APPLICABLE',{'reason':'Administrative setting baseline requires a tenant scope'}
        tenant=scope.removeprefix('/tenants/')
        matches=[]
        for row in complete_items(index,'directory_setting'):
            if _tenant(row,{'context':{'scope':scope,'metadata':{'tenant_id':tenant}}})!=tenant:
                raise Unavailable('Foreign tenant administrative setting')
            for entry in list_of_objects(get(row,'values',list)):
                if get(entry,'name',str)==name:
                    matches.append(get(entry,'value',str))
        if len(matches)!=1:
            raise Unavailable('Required administrative policy value missing or ambiguous')
        raw=matches[0]
        if kind=='bool':
            if raw.lower() not in ('true','false'):
                raise Unavailable('Malformed administrative boolean policy')
            value=raw.lower()=='true'
        else:
            if not raw.isdigit():raise Unavailable('Malformed administrative integer policy')
            value=int(raw)
            if value<1:raise Unavailable('Administrative threshold/duration must be positive')
        return result(not good(value),setting=name,configured=value,semantics='Explicit named policy metadata; effective enforcement and policy/native constraints remain separate')
    def fixture(value):
        return {'collections':{'directory_setting':[{'scope':'/tenants/tenant','status':'collected'}]},'directory_setting':[{'data':{'id':'policy','values':[{'name':name,'value':value}],'_provenance':{'tenant_id':'tenant'}}}]}
    CASES[cid]={'pass':{'scope':'/tenants/tenant'},'fail':{'scope':'/tenants/tenant'},'pass_index':fixture(str(good.value).lower()),'fail_index':fixture(str(bad).lower())}


class _Condition:
    def __init__(self,value,test):self.value,self.test=value,test
    def __call__(self,value):return self.test(value)


_policy('ad_m365_group_creation_disabled','EnableGroupCreation','bool',_Condition(False,lambda value:not value),True)
_policy('ad_custom_banned_password_enforced','EnableBannedPasswordCheck','bool',_Condition(True,lambda value:value),False)
_policy('ad_account_duration_min_60_seconds','LockoutDurationInSeconds','int',_Condition(60,lambda value:value>=60),59)
_policy('ad_account_lockout_threshold_max_10','LockoutThreshold','int',_Condition(10,lambda value:value<=10),11)


cid='azure.port.iam_user_not_allowed_to_create_tenants'
CHECK_IDS.append(cid);SOURCE_QUERIES['iam_user_not_allowed_to_create_tenants']=cid
@register(cid,'azure','hardening','directory_authorization_policy','Tenant default user role cannot create tenants','medium','AC-3','Review the default role flag and explicit Tenant Creator assignments separately; no policy or role assignment is changed.')
def create_tenants(item,index):
    tenant=_tenant(item,index)
    enabled=get(item,'defaultUserRolePermissions.allowedToCreateTenants',bool)
    return result(enabled,tenant_id=tenant,default_user_tenant_creation_allowed=enabled,semantics='Default role only; explicit Tenant Creator grants remain separate')
CASES[cid]={'pass':{'_provenance':{'tenant_id':'tenant'},'defaultUserRolePermissions':{'allowedToCreateTenants':False}},'fail':{'_provenance':{'tenant_id':'tenant'},'defaultUserRolePermissions':{'allowedToCreateTenants':True}}}


cid='azure.port.ad_user_mfa_registered'
CHECK_IDS.append(cid);SOURCE_QUERIES['ad_user_mfa_enabled']=cid
@register(cid,'azure','hardening','user_registration_detail','Named user registration report declares MFA registration','medium','IA-2','Review registration and separate Conditional Access enforcement; no authentication method or MFA configuration is changed.')
def registered(item,index):
    tenant=_tenant(item,index)
    upn=get(item,'userPrincipalName')
    if upn is None:return 'NOT_APPLICABLE',{'reason':'Pinned source excludes registration rows without a principal name'}
    if not isinstance(upn,str) or not upn:raise Unavailable('Malformed user registration principal name')
    value=get(item,'isMfaRegistered',bool)
    return result(not value,tenant_id=tenant,mfa_registered=value,semantics='Registration report flag only; capability/default auth strength and required MFA are separate')
CASES[cid]={'pass':{'_provenance':{'tenant_id':'tenant'},'userPrincipalName':'user@example.invalid','isMfaRegistered':True},'fail':{'_provenance':{'tenant_id':'tenant'},'userPrincipalName':'user@example.invalid','isMfaRegistered':False}}
