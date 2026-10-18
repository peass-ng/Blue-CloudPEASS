"""Literal reviewed flexible-server parameters are distinct from broad TLS/event-list baselines."""
from ipaddress import IPv4Address
from . import register,result
from .facts import get,list_of_objects,Unavailable
from .fixtures import CASES
CHECK_IDS=[]
SOURCE_QUERIES={}
PARAMETERS={
'postgres_sql_flexible_server_ssl_enabled':('postgresql_flexible_server','require_secure_transport','on','off'),
'postgres_flexible_server_log_checkpoints_on':('postgresql_flexible_server','log_checkpoints','on','off'),
'postgres_flexible_server_connection_throttling_on':('postgresql_flexible_server','connection_throttle.enable','on','off'),
'postgres_flexible_server_log_retention_days_3':('postgresql_flexible_server','logfiles.retention_days','4','3'),
'mysql_flexible_server_ssl_enabled':('mysql_flexible_server','require_secure_transport','ON','OFF'),
'mysql_flexible_server_min_tls_1_2':('mysql_flexible_server','tls_version','TLSv1.2,TLSv1.3','TLSv1.2'),
'mysql_flexible_server_audit_logging_enabled':('mysql_flexible_server','audit_log_enabled','ON','OFF'),
'mysql_flexible_server_audit_logging_events_connection_set':('mysql_flexible_server','audit_log_events','CONNECTION','CONNECTION,DDL'),
}


def _register(query,spec):
    kind,name,good,bad=spec;cid='azure.port.'+query
    CHECK_IDS.append(cid);SOURCE_QUERIES[query]=cid
    @register(cid,'azure','hardening',kind,'Flexible server '+name+' meets literal reviewed value '+good,'medium','CM-6','Review this parameter and service/version availability; no SQL connections, parameter updates or probes are made.',dependencies=[kind])
    def evaluate(item,index):
        rows=[row for row in list_of_objects(get(item,'configurations',list)) if get(row,'name',str)==name]
        if len(rows)!=1:raise Unavailable('Required flexible parameter missing or ambiguous; version/native constraint context unavailable')
        value=get(rows[0],'properties.value',str)
        if name=='logfiles.retention_days':
            if not value.isdigit():raise Unavailable('Malformed retention parameter')
            failed=int(value)<=3
        else:failed=value!=good
        return result(failed,parameter=name,configured=value,semantics='Exact source string/numeric baseline; TLS1.2-only/multiple audit events differ from pinned equality and are not broadly merged')
    def fixture(value):return {'configurations':[{'name':name,'properties':{'value':value}}]}
    CASES[cid]={'pass':fixture(good),'fail':fixture(bad)}
for _q,_s in PARAMETERS.items():_register(_q,_s)

cid='azure.port.postgres_flexible_server_allow_access_to_azure_services_disabled'
CHECK_IDS.append(cid);SOURCE_QUERIES['postgres_flexible_server_allow_access_to_azure_services_disabled']=cid
@register(cid,'azure','hardening','postgresql_flexible_server','PostgreSQL flexible firewall declares no zero start/end address','medium','SC-7','Review exact declared firewall intervals and separate public-network mode; no database or network connection is attempted.')
def firewall(item,index):
    rows=list_of_objects(get(item,'firewallRules',list));hits=[]
    for row in rows:
        start,end=get(row,'properties.startIpAddress',str),get(row,'properties.endIpAddress',str)
        try:
            if IPv4Address(start)>IPv4Address(end):raise ValueError('Reversed firewall interval')
        except ValueError as exc:
            raise Unavailable('Malformed IPv4 firewall interval') from exc
        if start=='0.0.0.0' or end=='0.0.0.0':hits.append(row.get('id') or row.get('name'))
    return result(bool(hits),declared_rules=hits,semantics='Exact source start ORend sentinel, even when publicnetwork isdisabled; no effective reachability claim')
CASES[cid]={'pass':{'firewallRules':[]},'fail':{'firewallRules':[{'name':'r','properties':{'startIpAddress':'0.0.0.0','endIpAddress':'10.0.0.1'}}]}}
