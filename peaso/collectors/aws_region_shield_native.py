"""Native enabled-region state and exact Shield protection metric locations."""
from __future__ import annotations

import re

SPECS = {'aws_region': ('ec2','describe_regions','Regions'),
         'shield_protection_region': ('shield','list_protections','Protections')}
NATIVE_IDS = {'aws_region':'RegionName','shield_protection_region':'ResourceArn'}
READ_ACTIONS = {('ec2','describe_regions'),('shield','list_protections')}
_OK = ('collected','empty')
_REGION = r'[a-z]{2}(?:-[a-z]+)+-[0-9]+'
_UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'


def _result(rows=(),status=None,code=None):
    from .aws import ReadResult
    rows=list(rows)
    return ReadResult(rows,status or ('collected'if rows else'empty'),{'code':code}if code else None)


def _failed(read,code):
    return _result([],read.status if read.status not in _OK else'malformed',(read.error or {}).get('code',code))


def _match(pattern,value):
    return isinstance(value,str) and re.fullmatch(pattern,value) is not None


def aws_region(requests,session,region,account):
    from .aws_facts_cb_ca import _home
    if not _match(_REGION,region) or not _match(r'[0-9]{12}',account):
        return _result([], 'malformed','aws_region_scope_invalid')
    partition=session.get_partition_for_region(region)
    read=requests.pages(session,'ec2',_home(region,'us-east-1'),'describe_regions','Regions',AllRegions=True)
    if read.status not in _OK:return _failed(read,'aws_region_inventory_incomplete')
    seen=set();current=None
    for native in read.items:
        if not isinstance(native,dict):return _result([], 'malformed','aws_region_identity_invalid')
        name,status=native.get('RegionName'),native.get('OptInStatus')
        if (not _match(_REGION,name) or name in seen or session.get_partition_for_region(name)!=partition
                or status not in ('opt-in-not-required','opted-in','not-opted-in')):
            return _result([], 'malformed','aws_region_identity_or_opt_in_invalid')
        seen.add(name)
        if name==region:current=native
    if current is None:return _result([], 'not_collected','aws_region_requested_region_unresolved')
    return _result([{'id':f'{account}/{region}/region','AccountId':account,'Region':region,'RegionName':region,
                     'Enabled':current['OptInStatus']in('opt-in-not-required','opted-in'),'OptInStatus':current['OptInStatus'],
                     '_provenance':{'source_operation':'DescribeRegions','read_only':True,'all_regions_requested':True,
                                    'enumeration_complete':True,'requested_region_identity_verified':True}}])


def _metric_region(arn,partition,account,session):
    if not isinstance(arn,str):return None
    parts=arn.split(':',5)
    if len(parts)!=6 or parts[:2]!=['arn',partition]:return None
    _,_,service,region,owner,resource=parts
    if service=='elasticloadbalancing':
        if (owner!=account or not _match(_REGION,region) or session.get_partition_for_region(region)!=partition
                or not _match(r'loadbalancer/(?:app/[^/]+/[a-zA-Z0-9]+|net/[^/]+/[a-zA-Z0-9]+|[^/]+)',resource)):return None
        return region
    if service=='ec2':
        if (owner!=account or not _match(_REGION,region) or session.get_partition_for_region(region)!=partition
                or not _match(r'eip-allocation/eipalloc-[a-z0-9]+',resource)):return None
        return region
    # AWS documents Shield CloudFront/Route 53 metrics in us-east-1.
    # Global Accelerator has an account-global ARN but no region in this proof;
    # do not guess its Shield metric location or silently omit its protection.
    if partition=='aws' and not region:
        if service=='cloudfront' and owner==account and _match(r'distribution/[A-Z0-9]+',resource):return 'us-east-1'
        if service=='route53' and not owner and _match(r'hostedzone/[A-Z0-9]+',resource):return 'us-east-1'
    return None


def shield_protection_region(requests,session,region,account):
    from .aws_facts_cb_ca import _home
    if not _match(_REGION,region) or not _match(r'[0-9]{12}',account):
        return _result([], 'malformed','shield_protection_scope_invalid')
    partition=session.get_partition_for_region(region)
    # Same exact API arguments/projection as the existing global parent, sharing
    # scan cache entries. Retain failures rather than treating NotFound as empty.
    read=requests.pages(session,'shield',_home(region,'us-east-1'),'list_protections',
                        'Protections[].{Id: Id, Name: Name, ResourceArn: ResourceArn, ProtectionArn: ProtectionArn, HealthCheckIds: HealthCheckIds}')
    if read.status not in _OK:return _failed(read,'shield_protection_inventory_incomplete')
    rows=[];seen_ids=set();seen_resources=set()
    for native in read.items:
        if not isinstance(native,dict):return _result([], 'malformed','shield_protection_identity_invalid')
        ident,arn=native.get('Id'),native.get('ResourceArn')
        if not _match(_UUID,ident) or not isinstance(arn,str) or ident in seen_ids or arn in seen_resources:
            return _result([], 'malformed','shield_protection_duplicate_or_invalid')
        protection_arn=f'arn:{partition}:shield::{account}:protection/{ident}'
        if native.get('ProtectionArn')not in(None,protection_arn):
            return _result([], 'malformed','shield_protection_owner_mismatch')
        metric_region=_metric_region(arn,partition,account,session)
        if metric_region is None:return _result([], 'not_collected','shield_resource_metric_region_unresolved')
        seen_ids.add(ident);seen_resources.add(arn)
        if metric_region!=region:continue
        rows.append({'id':arn,'AccountId':account,'Region':region,'ResourceArn':arn,'SourceRegion':metric_region,
                     'ProtectionId':ident,**({'ProtectionArn':protection_arn}if native.get('ProtectionArn')is not None else{}),
                     '_provenance':{'source_operation':'ListProtections','read_only':True,'account_enumeration_complete':True,
                       'metric_region_basis':'documented_global_us_east_1'if not arn.split(':',5)[3]else'protected_resource_arn_region',
                       'global_control_plane_region':_home(region,'us-east-1')}})
    return _result(rows)


FETCHERS = {'aws_region':aws_region,'shield_protection_region':shield_protection_region}
