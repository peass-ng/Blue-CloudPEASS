"""Reviewed Azure pending predicates over complete read-only ARM facts.

The native hardening category represents signed encryption/logging/recovery controls;
the signed category and exact requirement edges are retained by the companion.
"""
from __future__ import annotations

import re
from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, memoized

SPECS = {'azure.cis.enforce_ssl_connection_mysql_server': ('mysql_single_server',
                                                   'encryption',
                                                   'medium',
                                                   "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL "
                                                   'Database Server',
                                                   'For each legacy MySQL Single Server, set SSL enforcement to Enabled in '
                                                   'Connection security; migrate to Flexible Server and require secure '
                                                   'transport where Single Server is retired.'),
 'azure.cis.legacy_infrastructure_double_encryption_postgresql_single_server': ('postgresql_single_server',
                                                                                'encryption',
                                                                                'high',
                                                                                "Ensure 'Infrastructure double encryption' "
                                                                                'for PostgreSQL Database Server is '
                                                                                "'Enabled'",
                                                                                'Migrate legacy PostgreSQL Single Server to '
                                                                                'Flexible Server with infrastructure '
                                                                                'encryption enabled; for existing Single '
                                                                                'Server, use ARM server settings if the '
                                                                                'service still permits changes.'),
 'azure.cis.mysql_single_audit_log_enabled': ('mysql_single_server',
                                              'logging',
                                              'medium',
                                              "Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL "
                                              'Database Server',
                                              'For each legacy MySQL Single Server, set audit_log_enabled to ON in Server '
                                              'parameters, or migrate to Flexible Server and configure its audit logs.'),
 'azure.cis.postgresql_single_connection_throttling': ('postgresql_single_server',
                                                       'hardening',
                                                       'medium',
                                                       "Ensure server parameter 'connection_throttling' is set to 'ON' for "
                                                       'PostgreSQL Database Server',
                                                       'For any remaining PostgreSQL Single Server, set '
                                                       'connection_throttling=ON through server parameters, then migrate '
                                                       'the retired server to Flexible Server.'),
 'azure.cis.postgresql_single_log_checkpoints': ('postgresql_single_server',
                                                 'hardening',
                                                 'medium',
                                                 "Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL "
                                                 'Database Server',
                                                 'For each legacy PostgreSQL Single Server, open Server parameters and set '
                                                 'log_checkpoints to ON.'),
 'azure.cis.postgresql_single_log_connections': ('postgresql_single_server',
                                                 'hardening',
                                                 'medium',
                                                 'Legacy PostgreSQL single server logs connections',
                                                 'Azure portal > legacy Azure Database for PostgreSQL server > Server '
                                                 'parameters: set log_connections to ON, save, and migrate retired Single '
                                                 'Server where possible.'),
 'azure.cis.postgresql_single_log_disconnections': ('postgresql_single_server','hardening','medium',
    'Enable PostgreSQL Single Server disconnection logging',
    'Set legacy PostgreSQL Single Server log_disconnections to on in server parameters.'),
 'azure.cis.mysql_single_audit_log_events_connection': ('mysql_single_server','logging','medium',
    'Legacy MySQL single server audits connection events',
    'Enable audit_log_enabled and include the exact CONNECTION event in audit_log_events.'),
 'azure.cis.postgresql_single_no_azure_services_rule': ('postgresql_single_server','hardening','medium',
    "Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled",
    'Remove the 0.0.0.0 Azure services sentinel firewall rule from legacy PostgreSQL Single Server.'),
 'azure.cis.postgresql_single_log_retention_days': ('postgresql_single_server',
                                                    'recovery',
                                                    'medium',
                                                    "Ensure Server Parameter 'log_retention_days' is greater than 3 days "
                                                    'for PostgreSQL Database Server',
                                                    'Set PostgreSQL Single Server parameter log_retention_days to 4 or more '
                                                    'in Server parameters or az postgres server configuration set.'),
 'azure.cis.postgresql_single_ssl_enforcement': ('postgresql_single_server',
                                                 'encryption',
                                                 'medium',
                                                 'Legacy PostgreSQL single server enforces SSL',
                                                 'Azure portal > Azure Database for PostgreSQL Single Server > Connection '
                                                 'security: Set sslEnforcement to Enabled on the legacy server.'),
 'azure.cis.public_network_access_should_mariadb_servers': ('mariadb_server',
                                                            'network',
                                                            'high',
                                                            'Public network access should be disabled for MariaDB servers',
                                                            'For legacy MariaDB, disable Public network access in '
                                                            'Connection security where supported; otherwise migrate to a '
                                                            'service with private networking.'),
 'azure.gap.monitor_log_cluster_infrastructure_encryption_enabled': ('log_analytics_cluster',
                                                                     'encryption',
                                                                     'medium',
                                                                     'Enable infrastructure encryption for Log Analytics '
                                                                     'clusters',
                                                                     'Azure portal > Log Analytics dedicated clusters: '
                                                                     'enable infrastructure encryption where supported, or '
                                                                     'create a double-encrypted replacement cluster and '
                                                                     'move linked workspaces.'),
 'azure_firewall_policy_1_2_8_42_cacbd9e': ('web_application_firewall_policy',
                                            'network',
                                            'high',
                                            'Configure effective WAF policy rules',
                                            'In the WAF policy, enable the policy, use Prevention mode, enable a managed '
                                            'rule set or a blocking custom rule without blanket exclusions, and verify '
                                            'attachment.'),
 'azure_firewall_policy_1_2_8_24_cc7cb8a': ('firewall_policy','network','medium',
    'Firewall Policy contains at least one rule',
    'Add at least one rule to each fully enumerated Firewall Policy Rule Collection Group.')}


def _scope(index):
    context=get(index,'context',dict)
    if get(context,'provider',str)!='azure':raise Unavailable('Azure provider mismatch')
    scope=get(context,'scope',str)
    if not re.fullmatch(r'/subscriptions/[A-Za-z0-9._-]{1,128}',scope,re.I):
        raise Unavailable('Azure subscription scope unavailable')
    return context,scope


def _rows(index,kind):
    _,scope=_scope(index)
    def build():
        pages=get(index,'collections',dict).get(kind)
        if not isinstance(pages,list) or not pages or any(not isinstance(p,dict) or p.get('type')!=kind or p.get('scope','').casefold()!=scope.casefold() or p.get('status') not in ('collected','empty') for p in pages):
            raise Unavailable('complete Azure collection unavailable: '+kind)
        rows=complete_items(index,kind)
        wrappers=index.get(kind,[])
        if not isinstance(wrappers,list):raise Unavailable('malformed Azure projection')
        if any(not isinstance(w,dict) or w.get('provider') not in (None,'azure') or w.get('type')!=kind or w.get('scope','').casefold()!=scope.casefold() for w in wrappers):
            raise Unavailable('foreign Azure projection')
        if rows!=[r for p in pages for r in p.get('items',[])]:
            raise Unavailable('Azure collection and projection differ')
        identities=[get(r,'id',str).casefold() for r in rows]
        if len(set(identities))!=len(identities) or any(not i.startswith(scope.casefold()+'/') for i in identities):
            raise Unavailable('foreign or duplicate Azure resource identity')
        return rows
    return memoized(index,('batch_azure_rows',kind),build)


def _member(item,index,kind):
    identity=get(item,'id',str).casefold()
    def build():return {get(row,'id',str).casefold():row for row in _rows(index,kind)}
    member_map=memoized(index,('batch_azure_member',kind),build)
    if identity not in member_map or member_map[identity]!=item:raise Unavailable('Azure resource not in scoped inventory')
    return identity


def _full(item):
    provenance=get(item,'_provenance',dict)
    if provenance.get('representation')!='full' or provenance.get('read_only') is not True or provenance.get('source_operation','').casefold()!='get':
        raise Unavailable('complete authoritative GET unavailable')


def _waf(item,index):
    identity=_member(item,index,'web_application_firewall_policy');_full(item)
    props=get(item,'properties',dict)
    custom=list_of_objects(get(props,'customRules',list)) if 'customRules' in props or 'customRules' in props.get('_coverage',{}) else []
    managed=get(props,'managedRules',dict) if 'managedRules' in props or 'managedRules' in props.get('_coverage',{}) else {}
    sets=list_of_objects(get(managed,'managedRuleSets',list)) if 'managedRuleSets' in managed or 'managedRuleSets' in managed.get('_coverage',{}) else []
    for row in custom:
        if not get(row,'name',str):raise Unavailable('WAF custom rule identity missing')
    for row in sets:
        if not get(row,'ruleSetType',str) or not get(row,'ruleSetVersion',str):raise Unavailable('WAF managed rule-set identity missing')
    return result(not(custom or sets),policy_id=identity,custom_rule_count=len(custom),managed_rule_set_count=len(sets),semantics='structural rule presence only')


def _server_enum(item,index,kind,path,good='Enabled'):
    identity=_member(item,index,kind);_full(item)
    value=get(item,path,str)
    if value not in ('Enabled','Disabled'):return unknown('unrecognized Azure server enum',resource_id=identity)
    return result(value!=good,resource_id=identity,configured=value)


def _config(item,index,kind,name,good,bad,missing_fail=False,numeric=False):
    identity=_member(item,index,kind);_full(item)
    coverage=get(item,'_coverage.configurations',dict)
    if get(coverage,'status',str) not in ('collected','empty'):
        raise Unavailable('configuration list incomplete')
    rows=list_of_objects(get(item,'configurations',list))
    selected=[r for r in rows if get(r,'name',str).casefold()==name.casefold()]
    if len(selected)>1:raise Unavailable('duplicate configuration name')
    if not selected:
        if missing_fail:return result(True,resource_id=identity,configuration=name,reason='confirmed absent')
        return unknown('named configuration absent',resource_id=identity,configuration=name)
    row=selected[0]
    if get(row,'id',str).casefold()!=identity+'/configurations/'+name.casefold():
        raise Unavailable('configuration belongs to foreign server')
    value=get(row,'properties.value',str)
    if numeric:
        if not re.fullmatch(r'[0-9]+',value):return unknown('configuration value not a decimal integer')
        number=int(value)
        return result(number<4,resource_id=identity,configuration=name,value=number)
    normalized=value.upper() if good == 'ON' and bad == 'OFF' else value
    if normalized not in (good,bad):return unknown('unrecognized configuration value',resource_id=identity,configuration=name)
    return result(normalized==bad,resource_id=identity,configuration=name,value=value)


def _double_encryption(item,index):
    identity=_member(item,index,'log_analytics_cluster');_full(item)
    enabled=get(item,'properties.isDoubleEncryptionEnabled',bool)
    return result(not enabled,resource_id=identity,is_double_encryption_enabled=enabled)


def _firewall_policy(item,index):
    identity=_member(item,index,'firewall_policy');_full(item)
    coverage=get(item,'_coverage.ruleCollectionGroups',dict)
    if get(coverage,'status',str) not in ('collected','empty'):
        raise Unavailable('rule collection groups incomplete')
    groups=list_of_objects(get(item,'ruleCollectionGroups',list))
    if not groups:return 'NOT_APPLICABLE',{'policy_id':identity,'reason':'no rule collection group'}
    bad=[]
    for group in groups:
        gid=get(group,'id',str).casefold()
        if not gid.startswith(identity+'/rulecollectiongroups/') or get(group,'parent_id',str).casefold()!=identity:
            raise Unavailable('foreign rule collection group')
        provenance=get(group,'_provenance',dict)
        if provenance.get('representation')!='full' or provenance.get('read_only') is not True or provenance.get('source_operation')!='get_rule_collection_group':
            raise Unavailable('full rule collection group GET missing')
        collections=list_of_objects(get(group,'properties.ruleCollections',list))
        if not any(list_of_objects(get(row,'rules',list)) for row in collections):bad.append(gid)
    return result(bool(bad),policy_id=identity,empty_group_ids=bad)


def _mysql_connection_events(item,index):
    identity=_member(item,index,'mysql_single_server');_full(item)
    coverage=get(item,'_coverage.configurations',dict)
    if get(coverage,'status',str) not in ('collected','empty'):
        raise Unavailable('MySQL configuration list incomplete')
    rows=list_of_objects(get(item,'configurations',list))
    by_name={}
    for row in rows:
        name=get(row,'name',str).casefold()
        if name in by_name:raise Unavailable('duplicate MySQL configuration')
        if get(row,'id',str).casefold()!=identity+'/configurations/'+name:
            raise Unavailable('foreign MySQL configuration')
        by_name[name]=row
    enabled=by_name.get('audit_log_enabled')
    events=by_name.get('audit_log_events')
    if enabled is None or events is None:
        return result(True,resource_id=identity,missing_required_configuration=True)
    state=get(enabled,'properties.value',str).upper()
    if state not in ('ON','OFF'):
        return unknown('unrecognized MySQL audit enabled value')
    value=get(events,'properties.value',str)
    tokens=[part.strip().upper() for part in value.split(',')]
    if any(not part or not re.fullmatch(r'[A-Z_]+',part) for part in tokens):
        return unknown('malformed MySQL audit event list')
    return result(state!='ON' or 'CONNECTION' not in tokens,
                  resource_id=identity,audit_enabled=state,connection_token_present='CONNECTION' in tokens)


def _postgres_azure_services(item,index):
    identity=_member(item,index,'postgresql_single_server');_full(item)
    coverage=get(item,'_coverage.firewallRules',dict)
    # Inspect already observed child rows before the partial-page guard: an exact
    # sentinel proves FAIL, while absence from a partial list never proves PASS.
    rows=list_of_objects(item.get('firewallRules',[]))
    bad=[];malformed=False
    for row in rows:
        try:
            rid=get(row,'id',str).casefold()
            start=get(row,'properties.startIpAddress',str)
            end=get(row,'properties.endIpAddress',str)
        except Unavailable:
            malformed=True;continue
        if not rid.startswith(identity+'/firewallrules/'):
            malformed=True;continue
        if start==end=='0.0.0.0':bad.append(rid)
        elif not start or not end:malformed=True
    if bad:return result(True,resource_id=identity,azure_services_rule_ids=bad)
    if get(coverage,'status',str) not in ('collected','empty') or malformed:
        raise Unavailable('PostgreSQL firewall-rule inventory incomplete or malformed')
    return result(False,resource_id=identity,azure_services_rule_ids=[])


EVALUATORS={
 'azure_firewall_policy_1_2_8_42_cacbd9e':_waf,
 'azure.cis.enforce_ssl_connection_mysql_server':lambda item,index:_server_enum(item,index,'mysql_single_server','properties.sslEnforcement'),
 'azure.cis.postgresql_single_ssl_enforcement':lambda item,index:_server_enum(item,index,'postgresql_single_server','properties.sslEnforcement'),
 'azure.cis.public_network_access_should_mariadb_servers':lambda item,index:_server_enum(item,index,'mariadb_server','properties.publicNetworkAccess','Disabled'),
 'azure.cis.legacy_infrastructure_double_encryption_postgresql_single_server':lambda item,index:_server_enum(item,index,'postgresql_single_server','properties.infrastructureEncryption'),
 'azure.cis.postgresql_single_connection_throttling':lambda item,index:_config(item,index,'postgresql_single_server','connection_throttling','ON','OFF',missing_fail=True),
 'azure.cis.postgresql_single_log_checkpoints':lambda item,index:_config(item,index,'postgresql_single_server','log_checkpoints','ON','OFF',missing_fail=True),
 'azure.cis.postgresql_single_log_connections':lambda item,index:_config(item,index,'postgresql_single_server','log_connections','ON','OFF'),
 'azure.cis.postgresql_single_log_disconnections':lambda item,index:_config(item,index,'postgresql_single_server','log_disconnections','ON','OFF'),
 'azure.cis.mysql_single_audit_log_events_connection':_mysql_connection_events,
 'azure.cis.postgresql_single_no_azure_services_rule':_postgres_azure_services,
 'azure.cis.postgresql_single_log_retention_days':lambda item,index:_config(item,index,'postgresql_single_server','log_retention_days',None,None,numeric=True),
 'azure.cis.mysql_single_audit_log_enabled':lambda item,index:_config(item,index,'mysql_single_server','audit_log_enabled','ON','OFF'),
 'azure.gap.monitor_log_cluster_infrastructure_encryption_enabled':_double_encryption,
 'azure_firewall_policy_1_2_8_24_cc7cb8a':_firewall_policy,
}
for _id,(_kind,_signed_category,_severity,_title,_remediation) in SPECS.items():
    _native_category=_signed_category if _signed_category in ('network','hardening','exposure','least_privilege') else 'hardening'
    @register(_id,'azure',_native_category,_kind,_title,_severity,'CM-6',_remediation,dependencies=[_kind])
    def _evaluate(item,index,_id=_id):
        return EVALUATORS[_id](item,index)
    _evaluate.__name__=_id.replace('.','_')
