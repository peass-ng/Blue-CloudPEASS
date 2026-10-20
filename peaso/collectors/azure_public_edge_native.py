"""Bounded native public-edge joins; unsupported route/product evidence stays absent."""
from copy import deepcopy
import re

NATIVE_TYPES = ('frontdoor_profile', 'public_edge_binding')
PARENTS = {'application_gateway', 'load_balancer', 'public_ip', 'frontdoor'}
TYPES = {'application_gateway':'Microsoft.Network/applicationGateways',
         'load_balancer':'Microsoft.Network/loadBalancers',
         'public_ip':'Microsoft.Network/publicIPAddresses',
         'frontdoor':'Microsoft.Network/frontDoors', 'frontdoor_profile':'Microsoft.Cdn/profiles'}
VERSIONS = {'frontdoor':'2021-06-01', 'frontdoor_profile':'2025-04-15'}
AFD_SKUS = {'Standard_AzureFrontDoor','Premium_AzureFrontDoor'}
OTHER_SKUS = {'Standard_Microsoft','Standard_Akamai','Standard_Verizon','Premium_Verizon',
              'Standard_ChinaCdn','StandardPlus_ChinaCdn','StandardPlus_955BandWidth_ChinaCdn'}


def required_types(wanted):
    return set(PARENTS) if set(wanted).intersection(NATIVE_TYPES) else set()


def _identity(row, scope, kind):
    rid = row.get('id') if isinstance(row,dict) else None
    pattern = re.escape(scope) + r'/resourceGroups/[^/?#%\\\x00-\x1f]+/providers/' + re.escape(TYPES[kind]) + r'/[^/?#%\\\x00-\x1f]+'
    if (not isinstance(rid,str) or not re.fullmatch(pattern,rid,re.I)
            or not isinstance(row.get('type'),str) or row['type'].casefold()!=TYPES[kind].casefold()
            or row.get('name','').casefold()!=rid.rsplit('/',1)[1].casefold()):
        raise ValueError('Public-edge native identity mismatch')
    return rid.casefold()


def _get(reader, request, source, scope, kind):
    from .azure import ARM, _metadata_only
    rid = _identity(source,scope,kind)
    version = VERSIONS.get(kind,'2023-09-01')
    raw = reader.call(request,ARM+source['id']+'?api-version='+version)
    if _identity(raw,scope,kind)!=rid or not isinstance(raw.get('properties'),dict):
        raise ValueError('Public-edge GET identity/properties mismatch')
    if not isinstance(raw.get('etag'),str) or not raw['etag'] or len(raw['etag'])>1024:
        raise ValueError('Public-edge native ETag missing')
    # Reader.call is raw: use the existing metadata sanitizer before storage.
    result=_metadata_only(raw)
    result['_provenance']={'source_operation':TYPES[kind]+':GET','representation':'full',
                           'read_only':True,'api_version':version}
    return result


def _profiles(reader, request, scope):
    from .azure import ARM,AzureReadError
    rows=[];seen=set()
    for page in reader.pages(request,ARM+scope+'/providers/Microsoft.Cdn/profiles?api-version=2025-04-15'):
        for summary in page:
            rid=_identity(summary,scope,'frontdoor_profile')
            if rid in seen:raise ValueError('Duplicate CDN/Front Door profile')
            seen.add(rid)
            if reader.budget.max_items is not None and reader.total+len(seen)>reader.budget.max_items:
                raise AzureReadError('resource_limit')
            current=_get(reader,request,summary,scope,'frontdoor_profile')
            sku=current.get('sku',{}).get('name')
            if sku in AFD_SKUS:rows.append(current)
            elif sku not in OTHER_SKUS:raise ValueError('Unknown CDN profile product')
    return rows


def _binding(resource,kind,scope,ips):
    rid=_identity(resource,scope,kind)
    fronts=[]
    if kind=='public_ip':fronts=[resource['id']]
    elif kind in {'application_gateway','load_balancer'}:
        configs=resource['properties'].get('frontendIPConfigurations')
        if not isinstance(configs,list):raise ValueError('Native frontend universe unavailable')
        seen=set()
        for config in configs:
            fid=config.get('id') if isinstance(config,dict) else None
            if (not isinstance(fid,str) or not re.fullmatch(re.escape(rid)+r'/frontendIPConfigurations/[^/?#%\\\x00-\x1f]+',fid,re.I)
                    or fid.casefold() in seen or not isinstance(config.get('properties'),dict)):
                raise ValueError('Native frontend identity unavailable')
            seen.add(fid.casefold());props=config['properties']
            reference=props.get('publicIPAddress')
            if reference is not None:
                ip=reference.get('id') if isinstance(reference,dict) else None
                if not isinstance(ip,str) or ip.casefold() not in ips:
                    raise ValueError('Public frontend exact IP join unavailable')
                fronts.append(fid)
    else:
        raise ValueError('Front Door endpoint/WAF/product joins not yet implemented')
    binding={'id':resource['id']+'/public-edge-binding','resource_id':resource['id'],
             'resource_kind':kind,'resource_etag':resource['etag'],'public':bool(fronts),
             'public_frontend_ids':fronts,'_coverage':{'frontends':{
                 'status':'collected' if fronts else 'empty','parent_id':rid}},
             '_provenance':{'source_operation':'Azure.publicEdgeProtection:resolve',
                            'representation':'full','read_only':True,
                            'api_version':resource['_provenance']['api_version'],
                            'source_resource_etag':resource['etag']}}
    # Public gateways require complete effective listener/rule WAF precedence.
    # Do not synthesize it from a gateway-wide firewallPolicy property.
    if kind=='application_gateway' and fronts:
        binding['_coverage']['effective_waf']={'status':'not_collected','parent_id':rid}
    return binding


def collect(reader,request,scopes,wanted):
    active=set(wanted).intersection(NATIVE_TYPES)
    if not active:return
    from .azure import _safe_error,AzureReadError
    for scope in scopes:
        status='collected';error=None;profiles=[];bindings=[];updates=[];supporting={}
        try:
            from .azure import ARM
            native={};sources={}
            for kind in PARENTS:
                matches=[c for c in reader.collections if c['type']==kind and c['scope'].casefold()==scope.casefold()]
                if len(matches)!=1 or matches[0]['status'] not in {'collected','empty'}:
                    raise ValueError('Complete native edge parent inventory required')
                source=matches[0]
                if any(source.get(k) for k in ('nextLink','@odata.nextLink','continue')) or (source['status']=='empty')!= (not source['items']):
                    raise ValueError('Native edge parent paging/status contradictory')
                rows=[];seen=set()
                for item in source['items']:
                    rid=_identity(item,scope,kind)
                    if rid in seen:raise ValueError('Duplicate public-edge native parent')
                    seen.add(rid);rows.append(_get(reader,request,item,scope,kind))
                # Generic Reader inventories deduplicate some native LISTs. A
                # second bounded native enumeration proves the exact universe
                # and rejects duplicates before building protection bindings.
                listed=set()
                version=VERSIONS.get(kind,'2023-09-01')
                for page in reader.pages(request,ARM+scope+'/providers/'+TYPES[kind]+'?api-version='+version):
                    for summary in page:
                        current_id=_identity(summary,scope,kind)
                        if current_id in listed:raise ValueError('Duplicate native public-edge LIST identity')
                        listed.add(current_id)
                        if reader.budget.max_items is not None and reader.total+len(listed)>reader.budget.max_items:
                            raise AzureReadError('resource_limit')
                if listed!=seen:raise ValueError('Native public-edge membership changed between captures')
                native[kind]=rows;sources[kind]=source
            profiles=_profiles(reader,request,scope);native['frontdoor_profile']=profiles
            from .azure_public_edge_config_20261020 import resolve
            bindings,supporting=resolve(reader,request,native,scope,_binding)
            # Existing complete native inventories keep their own universe.
            # Referenced GETs must agree with their membership, never create
            # duplicate collection tuples or silently expand an empty roster.
            support_updates=[]
            for support_kind,rows in list(supporting.items()):
                existing=[c for c in reader.collections if c['type']==support_kind and c['scope'].casefold()==scope.casefold()]
                if not rows or not existing:
                    continue
                if len(existing)!=1 or existing[0]['status']not in('collected','empty'):
                    raise ValueError('referenced edge inventory incomplete or ambiguous')
                current={row['id'].casefold():row for row in existing[0]['items']}
                if len(current)!=len(existing[0]['items']) or any(row['id'].casefold()not in current for row in rows):
                    raise ValueError('edge GET contradicts complete native supporting inventory')
                updated={**current,**{row['id'].casefold():row for row in rows}}
                support_updates.append((existing[0],list(updated.values())))
                supporting.pop(support_kind)
            if reader.budget.max_items is not None and reader.total+len(profiles)+len(bindings)+sum(map(len,supporting.values()))>reader.budget.max_items:
                raise AzureReadError('resource_limit')
            updates=[(sources[kind],rows)for kind,rows in native.items()if kind in sources]+support_updates
        except Exception as exc:
            status,error=_safe_error(exc)
            if getattr(exc,'code','')=='partial_native_edge_inventory':status='partial'
            if status in {'collected','empty'}:status='unknown'
            profiles=[];bindings=[];updates=[];supporting={}
        # Commit source GETs only after the whole native join succeeds.
        for source,rows in updates:
            source['items']=rows
        # These are exact referenced resources, not discovery of all policies.
        # The signed public-edge consumer joins each reference by native ID.
        for kind,rows in supporting.items():
            if not rows:
                continue
            env={'type':kind,'scope':scope,'service':'Microsoft.Network','status':'collected',
                 'items':rows,'reference_inventory':'public_edge_binding',
                 'source_operation':'Peasso.public_edge_config.native_reference_gets'}
            reader.collections.append(env);reader.total+=len(rows)
            reader.progress(scope=scope,settled=env)
        for kind,rows in [('frontdoor_profile',profiles),('public_edge_binding',bindings)]:
            if kind not in active:continue
            env={'type':kind,'scope':scope,'service':'Microsoft.Network','status':status if error else 'collected' if rows else 'empty','items':rows}
            if error:env['error']=error
            reader.collections.append(env);reader.total+=len(rows);reader.progress(scope=scope,settled=env)
