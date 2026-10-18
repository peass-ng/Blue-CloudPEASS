"""Read-only native EFS, EMR and SQL encryption joins with complete inventories."""
from collections import Counter
from ipaddress import ip_address
from pathlib import Path
import json
import re
from . import register,result,unknown
from .facts import Unavailable,complete_items,get,list_of_objects,optional

SPECS=json.loads(Path(__file__).with_suffix('.json').read_text())
EMR_IDS={i for i in SPECS if 'emr'in i}
PRIMARY_IDS={'aws_fedramp_emr_master_no_public_ip'}


def rows(index,kind):
    context=get(index,'context',dict);scope=get(context,'scope',str)
    envs=get(index,'collections',dict).get(kind)
    if not isinstance(envs,list)or len(envs)!=1:raise Unavailable('scoped inventory missing or ambiguous: '+kind)
    env=envs[0]
    if get(env,'scope',str).casefold()!=scope.casefold() or get(env,'type',str)!=kind:raise Unavailable('foreign inventory')
    native=list_of_objects(get(env,'items',list));observed=complete_items(index,kind)
    encode=lambda row:json.dumps(row,sort_keys=True,separators=(',',':'))
    if Counter(map(encode,native))!=Counter(map(encode,observed)):raise Unavailable('native inventory projection differs')
    wrapped=optional(index,kind,[],list)
    if len(wrapped)!=len(native)or any(get(w,'scope',str).casefold()!=scope.casefold()or get(w,'type',str)!=kind for w in wrapped):raise Unavailable('foreign native wrapper')
    return observed


def aws_scope(index):
    context=get(index,'context',dict);scope=get(context,'scope',str)
    if get(context,'provider',str)!='aws' or not re.fullmatch(r'[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]',scope):raise Unavailable('AWS regional account authority missing')
    account,region=scope.split('/')
    if get(context,'Account',str)!=account:raise Unavailable('AWS account mismatch')
    return account,region


def subject(item,index,kind,identity):
    ident=get(item,identity,str);inventory=rows(index,kind)
    ids=[get(row,identity,str)for row in inventory]
    if len(ids)!=len(set(ids))or ids.count(ident)!=1 or inventory[ids.index(ident)]!=item:raise Unavailable('subject missing, duplicated or inconsistent')
    return ident


def efs_root(item,index):
    account,region=aws_scope(index);arn=subject(item,index,'efs_access_point','AccessPointArn')
    if not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):elasticfilesystem:'+re.escape(region)+':'+account+r':access-point/fsap-[0-9a-f]+',arn):raise Unavailable('foreign EFS access point')
    provenance=get(item,'_provenance',dict)
    if provenance.get('operation')!='efs:DescribeAccessPoints' or provenance.get('root_directory_representation_complete')is not True:raise Unavailable('root directory field completeness unproven')
    root=optional(item,'RootDirectory',{},dict);path=optional(root,'Path','',str)
    if path in ('','/'):return result(True,access_point_arn=arn,root_path=path)
    if not path.startswith('/')or any(segment in ('.','..')for segment in path.split('/'))or '//'in path:raise Unavailable('root path is not a canonical absolute directory')
    return result(False,access_point_arn=arn,root_path=path,semantics='Configured root directory only; mount access and tenant isolation assessed separately')


def emr(item,index,primary=False):
    account,region=aws_scope(index);arn=subject(item,index,'emr_cluster','ClusterArn')
    ident=get(item,'Id',str)
    if arn!=f'arn:aws:elasticmapreduce:{region}:{account}:cluster/{ident}':
        if not any(arn==f'arn:{p}:elasticmapreduce:{region}:{account}:cluster/{ident}'for p in ('aws-cn','aws-us-gov')):raise Unavailable('foreign EMR cluster')
    state=get(item,'Status.State',str)
    if state not in ('RUNNING','WAITING'):
        if state in ('STARTING','BOOTSTRAPPING','TERMINATING','TERMINATED','TERMINATED_WITH_ERRORS'):return 'NOT_APPLICABLE',{'reason':'cluster is not running or waiting'}
        raise Unavailable('unrecognized EMR state')
    masters=get(item,'MasterInstances',dict)
    if get(masters,'complete',bool)is not True:raise Unavailable('master instance pagination incomplete')
    master_rows=list_of_objects(get(masters,'items',list));ids=[get(row,'Ec2InstanceId',str)for row in master_rows]
    if not ids or len(ids)!=len(set(ids))or any(not re.fullmatch(r'i-[0-9a-f]+',i)for i in ids):raise Unavailable('invalid master instance identities')
    if primary:
        selected=get(masters,'PrimaryEc2InstanceId',str)
        if selected not in ids:raise Unavailable('primary node unresolved')
        ids=[selected]
    instances=rows(index,'instance');by_id={get(row,'InstanceId',str):row for row in instances}
    if len(by_id)!=len(instances):raise Unavailable('duplicate EC2 instance')
    public=[];unresolved=[]
    for ident in ids:
        instance=by_id.get(ident)
        if instance is None:unresolved.append(ident);continue
        try:
            state=get(instance,'State.Name',str)
            if state not in ('running','pending','stopping','stopped'):raise Unavailable('instance state unresolved')
            enis=list_of_objects(get(instance,'NetworkInterfaces',list))
            if not enis:raise Unavailable('ENI inventory missing')
            ipv4=optional(instance,'PublicIpAddress',None)
            candidates=[] if ipv4 is None else [(ipv4,4)]
            for eni in enis:
                association=optional(eni,'Association',{},dict)
                address=optional(association,'PublicIp',None)
                if address is not None:candidates.append((address,4))
                candidates.extend((get(row,'Ipv6Address',str),6)for row in list_of_objects(optional(eni,'Ipv6Addresses',[],list)))
            for address,version in candidates:
                try:ip=ip_address(address)
                except (ValueError,TypeError)as exc:raise Unavailable('invalid master IP address')from exc
                if ip.version!=version:raise Unavailable('wrong IP address family')
                if version==4 or ip.is_global:public.append({'instance_id':ident,'address':str(ip)})
        except Unavailable:unresolved.append(ident)
    if public:return result(True,cluster_arn=arn,public_master_addresses=public,unresolved_master_instances=unresolved)
    if unresolved:return unknown('Master EC2 facts incomplete',unresolved_master_instances=unresolved)
    return result(False,cluster_arn=arn,master_instances_checked=ids)


def sql_tde(item,index):
    context=get(index,'context',dict);scope=get(context,'scope',str)
    if get(context,'provider',str)!='azure' or not re.fullmatch(r'/subscriptions/[^/]+',scope,re.I)or get(item,'scope',str).casefold()!=scope.casefold():raise Unavailable('subscription authority missing')
    failures=[];unresolved=[];unavailable_inventories=[];applicable=0
    for kind,tde_kind in [('sql_database_inventory','sql_tde_inventory'),('managed_instance_database','managed_instance_tde')]:
        try:
            databases=rows(index,kind);encryptions=rows(index,tde_kind)
            pairs={}
            for encryption in encryptions:
                parent=get(encryption,'parent_id',str).casefold();rid=get(encryption,'id',str).casefold()
                if not parent.startswith(scope.casefold()+'/')or rid not in (parent,parent+'/transparentdataencryption/current'):raise Unavailable('foreign TDE child')
                if parent in pairs:raise Unavailable('duplicate current TDE child')
                pairs[parent]=encryption
            ids=[get(db,'id',str).casefold()for db in databases]
            parent_type='servers'if kind=='sql_database_inventory'else'managedInstances'
            pattern=re.escape(scope)+r'/resourceGroups/[^/?#%]+/providers/Microsoft.Sql/'+parent_type+r'/[^/?#%]+/databases/[^/?#%]+'
            if (len(ids)!=len(set(ids))or any(not re.fullmatch(pattern,rid,re.I)or any(part in ('.','..')for part in rid.split('/'))for rid in ids)):
                raise Unavailable('foreign or duplicate database')
            if not set(pairs)<=set(ids):raise Unavailable('orphan encryption child')
        except Unavailable:
            unavailable_inventories.extend((kind,tde_kind))
            continue
        for rid in ids:
            if kind=='sql_database_inventory'and rid.rsplit('/',1)[-1]=='master':continue
            applicable+=1
            try:state=get(pairs[rid],'properties.state',str)
            except (KeyError,Unavailable):unresolved.append(rid);continue
            if state=='Disabled':failures.append(rid)
            elif state!='Enabled':unresolved.append(rid)
    if failures:return result(True,disabled_database_ids=failures,unresolved_database_ids=unresolved,unavailable_inventories=unavailable_inventories)
    if unresolved or unavailable_inventories:return unknown('Current database encryption state incomplete',unresolved_database_ids=unresolved,unavailable_inventories=unavailable_inventories)
    if not applicable:return 'NOT_APPLICABLE',{'reason':'complete empty user database inventories'}
    return result(False,encrypted_database_count=applicable)


for ident,spec in SPECS.items():
    if ident in EMR_IDS:
        def callback(item,index,ident=ident):return emr(item,index,ident in PRIMARY_IDS)
        deps=['emr_cluster','instance'];target='resource'
    elif ident.startswith('aws_'):
        callback=efs_root;deps=['efs_access_point'];target='resource'
    else:callback=sql_tde;deps=['sql_database_inventory','sql_tde_inventory','managed_instance_database','managed_instance_tde'];target='scope'
    register(ident,spec['provider'],'hardening',spec['resource_kind'],spec['title'],spec['severity'],'CM-6',spec['remediation_hint'],dependencies=deps,target=target,allow_incomplete_failure=ident=='azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5')(callback)
from .fixtures import CASES
CASES.update(json.loads(Path(__file__).with_name('native_storage_compute_fixtures.json').read_text()))
