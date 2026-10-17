"""Owner-approved grouping, with capacity and placements from actual native APIs."""
from __future__ import annotations
import copy
import re

SPECS={'recovery_group':('ec2','describe_instances','Reservations[].Instances[]'),
       'capacity_group':('autoscaling','describe_auto_scaling_groups','AutoScalingGroups')}
NATIVE_IDS={'recovery_group':'id','capacity_group':'id'}
READ_ACTIONS={('ec2','describe_instances'),('rds','describe_db_instances'),('autoscaling','describe_auto_scaling_groups')}
KEY='operational_groups'
_SCOPE=re.compile(r'[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]+')
_LABEL=re.compile(r'[A-Za-z0-9_.-]{1,128}')

def normalize(options):
    parameters=options.get('compliance_parameters',{})
    if not isinstance(parameters,dict):raise ValueError('compliance parameters must be an object')
    if KEY not in parameters:return None
    value=parameters[KEY]
    if not isinstance(value,dict)or not value or set(value)-{'recovery_groups','capacity_groups'}:
        raise ValueError('invalid operational group owner policy fields')
    out={}
    for field,rows in value.items():
        if not isinstance(rows,list)or not 1<=len(rows)<=1000:raise ValueError('approved operational groups must be nonempty')
        seen=set();sources=set();selected=[]
        for row in rows:
            required={'scope','id','members'}if field=='recovery_groups'else{'scope','id','autoscaling_group_arn','minimum_capacity','capacity_unit'}
            if not isinstance(row,dict)or set(row)!=required:raise ValueError('invalid operational group owner row')
            scope,ident=row['scope'],row['id']
            if not isinstance(scope,str)or not _SCOPE.fullmatch(scope)or not isinstance(ident,str)or not _LABEL.fullmatch(ident)or(scope,ident)in seen:
                raise ValueError('invalid duplicate operational group owner identity')
            seen.add((scope,ident))
            if field=='recovery_groups':
                members=row['members'];ids=set()
                if not isinstance(members,list)or not 1<=len(members)<=10000:raise ValueError('approved recovery member list empty')
                for member in members:
                    if not isinstance(member,dict)or set(member)!={'kind','id'}:raise ValueError('invalid recovery member fields')
                    kind,mid=member['kind'],member['id']
                    pattern=r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})'if kind=='instance'else r'[A-Za-z][A-Za-z0-9-]{0,62}'if kind=='rds_instance'else None
                    if not pattern or not isinstance(mid,str)or not re.fullmatch(pattern,mid)or(kind,mid)in ids:raise ValueError('invalid duplicate recovery member')
                    ids.add((kind,mid))
            else:
                arn=row['autoscaling_group_arn'];account,region=scope.split('/')
                if not isinstance(arn,str)or not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:autoscaling:'+re.escape(region)+':'+account+r':autoScalingGroup:[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}:autoScalingGroupName/[\x21-\x39\x3b-\x7e]{1,255}',arn)or arn in sources:
                    raise ValueError('invalid duplicate approved Auto Scaling source')
                sources.add(arn)
                if type(row['minimum_capacity'])is not int or not 1<=row['minimum_capacity']<=2147483647 or row['capacity_unit']not in('units','vcpu','memory-mib'):
                    raise ValueError('invalid approved capacity minimum or unit')
            selected.append(copy.deepcopy(row))
        out[field]=selected
    return out

def _result(rows=(),status=None,code=None):
    from .aws import ReadResult
    rows=list(rows)
    return ReadResult(rows,status or('collected'if rows else'empty'),{'code':code}if code else None)

def _policy(requests,key,account,region):
    policy=getattr(requests,'operational_groups_policy',None)
    if not isinstance(policy,dict):return None
    rows=[row for row in policy.get(key,[])if row['scope']==account+'/'+region]
    return rows or None

def _failed(read,code):
    return _result([],read.status if read.status not in('collected','empty')else'malformed',(read.error or{}).get('code',code))

def _inventory(read,field,account,region,partition):
    if read.status not in('collected','empty'):raise ValueError('incomplete operational native inventory')
    rows={}
    for row in read.items:
        if not isinstance(row,dict)or not isinstance(row.get(field),str)or row[field]in rows:raise ValueError('malformed duplicate operational native identity')
        for name in('DBInstanceArn','AutoScalingGroupARN'):
            if name in row:
                arn=row[name]
                if not isinstance(arn,str)or not arn.startswith('arn:'+partition+':')or ':'+region+':'+account+':'not in arn:raise ValueError('foreign operational native resource')
        rows[row[field]]=row
    return rows

def recovery_group(requests,session,region,account):
    policy=_policy(requests,'recovery_groups',account,region)
    if policy is None:return _result([],'not_collected','approved_recovery_groups_unavailable')
    ec2=requests.pages(session,'ec2',region,'describe_instances','Reservations[].Instances[]')
    if ec2.status not in('collected','empty'):return _failed(ec2,'recovery_ec2_inventory_incomplete')
    rds=requests.pages(session,'rds',region,'describe_db_instances','DBInstances')
    if rds.status not in('collected','empty'):return _failed(rds,'recovery_rds_inventory_incomplete')
    partition=session.get_partition_for_region(region)
    try:
        inventories={'instance':_inventory(ec2,'InstanceId',account,region,partition),'rds_instance':_inventory(rds,'DBInstanceIdentifier',account,region,partition)}
        out=[]
        for group in policy:
            source_ids=[]
            for member in group['members']:
                row=inventories[member['kind']].get(member['id'])
                if row is None:raise ValueError('approved recovery member placement unavailable')
                if member['kind']=='instance':
                    state=row.get('State',{}).get('Name');zone=row.get('Placement',{}).get('AvailabilityZone')
                    if state not in('pending','running','shutting-down','terminated','stopping','stopped'):raise ValueError('unrecognized recovery instance state')
                    active=state=='running'
                else:
                    state=row.get('DBInstanceStatus');zone=row.get('AvailabilityZone')
                    if state not in('available','creating','deleting','modifying','stopped','stopping','starting','failed','inaccessible-encryption-credentials'):raise ValueError('unrecognized recovery database state')
                    active=state=='available'
                if active and(not isinstance(zone,str)or not re.fullmatch(re.escape(region)+r'[a-z]',zone)):raise ValueError('foreign or unsupported recovery availability zone')
                source_ids.append(member['id'])
            out.append({'id':group['id'],'Members':[{'Kind':m['kind'],'Id':m['id']}for m in group['members']],
                        '_provenance':{'source':'approved_owner_grouping','read_only':True,'source_operations':['ec2:DescribeInstances','rds:DescribeDBInstances'],'source_ids':source_ids}})
        return _result(out)
    except (TypeError,ValueError):return _result([],'malformed','native_recovery_members_unresolved')

def capacity_group(requests,session,region,account):
    policy=_policy(requests,'capacity_groups',account,region)
    if policy is None:return _result([],'not_collected','approved_capacity_groups_unavailable')
    read=requests.pages(session,'autoscaling',region,'describe_auto_scaling_groups','AutoScalingGroups')
    if read.status not in('collected','empty'):return _failed(read,'capacity_asg_inventory_incomplete')
    partition=session.get_partition_for_region(region)
    try:
        inventory=_inventory(read,'AutoScalingGroupARN',account,region,partition);out=[]
        for group in policy:
            arn=group['autoscaling_group_arn'];row=inventory.get(arn)
            if row is None:raise ValueError('approved capacity source unavailable')
            name=row.get('AutoScalingGroupName')
            if not isinstance(name,str)or arn.split(':autoScalingGroupName/',1)[-1]!=name:raise ValueError('capacity source name differs')
            if row.get('Status')not in(None,''):raise ValueError('Auto Scaling source deletion in progress')
            unit=row.get('DesiredCapacityType','units')  # Documented service default, not observed runtime capacity.
            if unit!=group['capacity_unit']:raise ValueError('approved capacity unit differs')
            capacity=row.get('DesiredCapacity');zones=row.get('AvailabilityZones')
            if type(capacity)is not int or capacity<0 or not isinstance(zones,list)or not zones or any(not isinstance(z,str)or not re.fullmatch(re.escape(region)+r'[a-z]',z)for z in zones)or len(zones)!=len(set(zones)):raise ValueError('capacity native fields invalid')
            out.append({'id':group['id'],'DocumentedMinimum':group['minimum_capacity'],'ConfiguredCapacity':capacity,'AvailabilityZones':list(zones),
                        'CapacityUnit':unit,'AutoScalingGroupARN':arn,'_provenance':{'read_only':True,'source_operation':'autoscaling:DescribeAutoScalingGroups',
                        'native_field_mapping':{'ConfiguredCapacity':'DesiredCapacity','AvailabilityZones':'AvailabilityZones'},'minimum_source':'approved_owner_policy','capacity_semantics':'configured_desired_capacity'}})
        return _result(out)
    except (TypeError,ValueError):return _result([],'malformed','native_capacity_group_unresolved')

FETCHERS={'recovery_group':recovery_group,'capacity_group':capacity_group}
