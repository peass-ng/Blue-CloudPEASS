"""Peasso-derived public-edge configuration joins from bounded native GET/LIST.

No packet, HTTP backend, mitigation, WAF rule execution or origin bypass probe.
Legacy resolver labels below name internal normalization, never provider APIs.
"""
from copy import deepcopy
import re

ARM='https://management.azure.com'
DDOS_SOURCE='https://learn.microsoft.com/en-us/azure/frontdoor/billing'
CLASSIC_DDOS_SOURCE='https://learn.microsoft.com/en-us/azure/web-application-firewall/shared/application-ddos-protection'
UUID=r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
SEG=r'[^/?#%\\\x00-\x20]+'


def _arm(value,scope,typ=None):
    suffix=SEG+'(?:/'+SEG+')+'
    if typ:
        parts=typ.split('/')
        suffix=re.escape(parts[0])+''.join('/'+re.escape(t)+'/'+SEG for t in parts[1:])
    if (not isinstance(value,str) or any(x in ('.','..')for x in value.split('/'))
            or re.fullmatch(re.escape(scope)+'/resourceGroups/'+SEG+'/providers/'+suffix,value,re.I)is None):
        raise ValueError('foreign or malformed public-edge ARM reference')
    return value.casefold()


def _children(parent,field):
    rows=parent['properties'].get(field)
    if not isinstance(rows,list):raise ValueError('native declared child inventory missing: '+field)
    out={}
    for row in rows:
        rid=row.get('id')if isinstance(row,dict)else None
        if (not isinstance(rid,str)or re.fullmatch(re.escape(parent['id'])+'/'+field+'/'+SEG,rid,re.I)is None
                or rid.casefold()in out or not isinstance(row.get('properties'),dict)):
            raise ValueError('foreign, duplicate or malformed native edge child')
        if 'name'in row and str(row['name']).casefold()not in(rid.rsplit('/',1)[-1].casefold(),'/'.join(re.split('/providers/',rid,flags=re.I)[-1].split('/')[2::2]).casefold()):
            raise ValueError('native edge child name mismatch')
        if 'type'in row:
            parts=re.split('/providers/',rid,flags=re.I)[-1].split('/')
            if str(row['type']).casefold()!='/'.join([parts[0],*parts[1::2]]).casefold():raise ValueError('native edge child type mismatch')
        out[rid.casefold()]=row
    return out


def _reference(props,field,scope,typ):
    value=props.get(field)
    if value is None:return None
    if not isinstance(value,dict):raise ValueError('malformed policy reference')
    return _arm(value.get('id'),scope,typ)


def _gateway(resource,binding,scope):
    props=resource['properties'];kind='Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'
    global_policy=_reference(props,'firewallPolicy',scope,kind)
    if global_policy is None and props.get('webApplicationFirewallConfiguration') is not None:
        inline=props['webApplicationFirewallConfiguration']
        if not isinstance(inline,dict):raise ValueError('malformed native inline WAF configuration')
        global_policy={'source':'inline','parent_id':resource['id'],
                       'native_field':'properties.webApplicationFirewallConfiguration',
                       'configuration':deepcopy(inline),
                       'source_resource_etag':resource['etag']}
    fronts=_children(resource,'frontendIPConfigurations');ports=_children(resource,'frontendPorts')
    listeners=_children(resource,'httpListeners');rules=_children(resource,'requestRoutingRules')
    maps=_children(resource,'urlPathMaps')if'urlPathMaps'in props else{}
    public={x.casefold()for x in binding['public_frontend_ids']};policies=[];paths=[]
    used=set()
    for lid,listener in listeners.items():
        lp=listener['properties'];fid=lp.get('frontendIPConfiguration',{}).get('id');portid=lp.get('frontendPort',{}).get('id')
        if not isinstance(fid,str)or fid.casefold()not in fronts or not isinstance(portid,str)or portid.casefold()not in ports:raise ValueError('listener frontend/port exact join unresolved')
        port=ports[portid.casefold()]['properties'].get('port');protocol=lp.get('protocol')
        if type(port)is not int or not 1<=port<=65535 or protocol not in('Http','Https'):raise ValueError('unsupported declared public listener protocol/port')
        if fid.casefold()not in public:continue
        selected=[r for r in rules.values()if str(r['properties'].get('httpListener',{}).get('id','')).casefold()==lid]
        if len(selected)!=1:raise ValueError('public listener routing rule missing or ambiguous')
        rule=selected[0];rp=rule['properties'];used.add(rule['id'].casefold())
        if rp.get('rewriteRuleSet')is not None:raise ValueError('dynamic gateway rewrite precedence unsupported')
        policy=_reference(lp,'firewallPolicy',scope,kind)or global_policy
        route_policies=[policy]
        if rp.get('ruleType')=='PathBasedRouting':
            mid=rp.get('urlPathMap',{}).get('id')
            if not isinstance(mid,str)or mid.casefold()not in maps:raise ValueError('public route path map unresolved')
            pathmap=maps[mid.casefold()];mp=pathmap['properties']
            if mp.get('defaultRewriteRuleSet')is not None:raise ValueError('dynamic path map rewrite unsupported')
            pathrows=mp.get('pathRules')
            if not isinstance(pathrows,list):raise ValueError('native path rules missing')
            seen=set()
            for path in pathrows:
                pid=path.get('id')if isinstance(path,dict)else None;pp=path.get('properties')if isinstance(path,dict)else None
                if (not isinstance(pid,str)or re.fullmatch(re.escape(pathmap['id'])+'/pathRules/'+SEG,pid,re.I)is None
                        or pid.casefold()in seen or not isinstance(pp,dict)or not isinstance(pp.get('paths'),list)or not pp['paths']
                        or any(not isinstance(p,str)or not p.startswith('/')for p in pp['paths'])):raise ValueError('foreign or malformed native WAF path rule')
                if pp.get('rewriteRuleSet')is not None:raise ValueError('dynamic path rewrite unsupported')
                seen.add(pid.casefold());route_policies.append(_reference(pp,'firewallPolicy',scope,kind)or policy)
        elif rp.get('ruleType')!='Basic':raise ValueError('unknown gateway routing rule type')
        policies.extend(route_policies)
        paths.append({'listener_id':listener['id'],'frontend_id':fronts[fid.casefold()]['id'],'frontend_port_id':ports[portid.casefold()]['id'],'port':port,'protocol':protocol,'routing_rule_id':rule['id'],'configured_waf_policy_ids':route_policies})
    if not paths:raise ValueError('public gateway has no bounded declared HTTP listener paths')
    # A dangling/foreign listener reference must not disappear from coverage.
    if any(str(r['properties'].get('httpListener',{}).get('id','')).casefold()not in listeners for r in rules.values()):raise ValueError('foreign native routing-rule listener')
    binding['declared_http_paths']=paths
    return policies


def resolve(reader,request,native,scope,base_binding):
    """Return exact native-derived bindings plus referenced configuration reads."""
    if re.fullmatch('/subscriptions/'+UUID,scope,re.I)is None:raise ValueError('invalid selected subscription')
    from .azure import _metadata_only
    cache={};receipts=[];supports={'waf_policy':{},'vnet':{},'ddos_plan':{}}
    def read(rid,typ,version,operation):
        key=_arm(rid,scope,typ)
        if(key,version)not in cache:
            if reader.budget.max_items is not None and reader.total+len(cache)>=reader.budget.max_items:
                from .azure import AzureReadError
                raise AzureReadError('resource_limit')
            raw=reader.call(request,ARM+rid+'?api-version='+version)
            if (not isinstance(raw,dict)or _arm(raw.get('id'),scope,typ)!=key
                    or str(raw.get('type','')).casefold()!=typ.casefold()or not isinstance(raw.get('properties'),dict)
                    or 'name'in raw and str(raw['name']).casefold() not in (rid.rsplit('/',1)[-1].casefold(),'/'.join(re.split('/providers/',rid,flags=re.I)[-1].split('/')[2::2]).casefold())):
                raise ValueError('referenced native edge GET identity/type mismatch')
            row=_metadata_only(raw)
            row['_provenance']={'read_only':True,'representation':'full','api_version':version,'source_operation':operation,'request_path':rid,'native_http_method':'GET'}
            cache[key,version]=row;receipts.append({'method':'GET','path':rid,'api_version':version,'native_operation':operation})
        return cache[key,version]
    def list_rows(parent,segment,typ,version):
        seen={}
        try:
            for page in reader.pages(request,ARM+parent+'/'+segment+'?api-version='+version):
                for raw in page:
                    rid=raw.get('id')if isinstance(raw,dict)else None
                    if not isinstance(rid,str)or re.fullmatch(re.escape(parent+'/'+segment+'/')+SEG,rid,re.I)is None:raise ValueError('foreign native edge list child')
                    if rid.casefold()in seen:raise ValueError('duplicate native edge list child')
                    seen[rid.casefold()]=read(rid,typ,version,typ+':GET')
        except Exception:
            if seen:
                from .azure import AzureReadError
                raise AzureReadError('partial_native_edge_inventory') from None
            raise
        receipts.append({'method':'GET','path':parent+'/'+segment,'api_version':version,'native_operation':typ+':LIST'})
        return list(seen.values())
    def waf(pid):
        if pid is None:return
        typ='Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'if'/applicationgatewaywebapplicationfirewallpolicies/'in pid else'Microsoft.Network/frontDoorWebApplicationFirewallPolicies'
        version='2024-05-01'if'ApplicationGateway'in typ else'2022-05-01'
        row=deepcopy(read(pid,typ,version,typ+':GET'))
        # Existing signed consumer uses a legacy internal normalizer label.
        row['_provenance'].update(source_operation='Azure.WAF:GET',native_source_operation=typ+':GET',derived_by='Peasso.azure_public_edge_config_20261020')
        supports['waf_policy'][pid]=row
    ips={r['id'].casefold()for r in native['public_ip']};bindings=[]
    for kind,rows in native.items():
        for resource in rows:
            rid=resource['id'].casefold()
            if kind in('frontdoor','frontdoor_profile'):
                if kind=='frontdoor':
                    endpoints=list(_children(resource,'frontendEndpoints').values());rules=list(_children(resource,'routingRules').values())
                    policies=[]
                    for ep in endpoints:
                        eid=ep['id'].casefold();selected=[r for r in rules if r['properties'].get('enabledState')=='Enabled'and any(str(ref.get('id','')).casefold()==eid for ref in r['properties'].get('frontendEndpoints',[]))]
                        if not selected:raise ValueError('classic Front Door route universe unresolved')
                        policies.append(_reference(ep['properties'],'webApplicationFirewallPolicyLink',scope,'Microsoft.Network/frontDoorWebApplicationFirewallPolicies'))
                    doc=CLASSIC_DDOS_SOURCE
                else:
                    sku=resource.get('sku',{}).get('name')
                    if sku not in('Standard_AzureFrontDoor','Premium_AzureFrontDoor'):raise ValueError('unsupported Front Door product DDoS mapping')
                    endpoints=list_rows(resource['id'],'afdEndpoints','Microsoft.Cdn/profiles/afdEndpoints','2025-04-15')
                    domains=list_rows(resource['id'],'customDomains','Microsoft.Cdn/profiles/customDomains','2025-04-15')
                    domains={d['id'].casefold():d for d in domains}
                    security=list_rows(resource['id'],'securityPolicies','Microsoft.Cdn/profiles/securityPolicies','2025-04-15')
                    policies=[]
                    for ep in endpoints:
                        routes=list_rows(ep['id'],'routes','Microsoft.Cdn/profiles/afdEndpoints/routes','2025-04-15')
                        if not routes:raise ValueError('AFD route declaration universe empty')
                        for route in routes:
                            rp=route['properties']
                            if rp.get('enabledState')not in('Enabled','Disabled'):raise ValueError('AFD route state unresolved')
                            if rp['enabledState']=='Disabled':continue
                            # Native WAF evaluates incoming requests before AFD rule sets.
                            # Their presence alone cannot bypass this association proof.
                            protocols=rp.get('supportedProtocols')
                            if not isinstance(protocols,list)or not protocols or any(p not in('Http','Https')for p in protocols):raise ValueError('AFD declared protocols unresolved')
                            members=rp.get('customDomains')
                            if not isinstance(members,list):raise ValueError('AFD custom-domain declaration missing')
                            targets=[]
                            for member in members:
                                mid=member.get('id')if isinstance(member,dict)else None
                                if not isinstance(mid,str)or mid.casefold()not in domains:raise ValueError('AFD foreign custom-domain join')
                                targets.append(mid.casefold())
                            if rp.get('linkToDefaultDomain')=='Enabled':targets.append(ep['id'].casefold())
                            elif rp.get('linkToDefaultDomain')!='Disabled':raise ValueError('AFD default-domain link unresolved')
                            if not targets:raise ValueError('AFD route has no declared domain')
                            for target in targets:
                                candidates=[]
                                for sp in security:
                                    params=sp['properties'].get('parameters')
                                    if not isinstance(params,dict)or params.get('type')!='WebApplicationFirewall':raise ValueError('unknown AFD security policy type')
                                    associations=params.get('associations')
                                    if not isinstance(associations,list):raise ValueError('AFD WAF associations missing')
                                    for association in associations:
                                        if not isinstance(association,dict)or not isinstance(association.get('domains'),list):raise ValueError('AFD malformed WAF association')
                                        if any(str(d.get('id','')).casefold()==target for d in association['domains']):
                                            if association.get('patternsToMatch')!=['/*']:raise ValueError('partial AFD WAF path precedence unsupported')
                                            candidates.append(_reference(params,'wafPolicy',scope,'Microsoft.Network/frontDoorWebApplicationFirewallPolicies'))
                                if len(candidates)>1:raise ValueError('ambiguous AFD WAF association')
                                policies.append(candidates[0]if candidates else None)
                    doc=DDOS_SOURCE
                    resource['endpoints']=endpoints;resource.setdefault('_coverage',{})['endpoints']={'status':'collected'if endpoints else'empty','parent_id':rid}
                fronts=[e['id']for e in endpoints]
                binding={'id':resource['id']+'/public-edge-binding','resource_id':resource['id'],'resource_kind':kind,'resource_etag':resource['etag'],'public':bool(fronts),'public_frontend_ids':fronts,'_coverage':{'frontends':{'status':'collected'if fronts else'empty','parent_id':rid}},'_provenance':{'source_operation':'Azure.publicEdgeProtection:resolve','representation':'full','read_only':True,'api_version':resource['_provenance']['api_version']}}
                binding['ddos']={'resource_id':rid,'state':'Protected','mapping_ref':doc,'evidence_ref':resource['id']+'@'+resource['etag']}
                binding['_coverage']['ddos']={'status':'collected','parent_id':rid}
                if fronts and not policies:raise ValueError('Front Door declared WAF path set empty')
            else:
                binding=base_binding(resource,kind,scope,ips);policies=[]
                if kind=='application_gateway'and binding['public']:policies=_gateway(resource,binding,scope)
                if kind=='public_ip'and resource['properties'].get('ddosSettings',{}).get('protectionMode')=='VirtualNetworkInherited':
                    vnets=set()
                    for gateway in native['application_gateway']:
                        front=list(_children(gateway,'frontendIPConfigurations').values())
                        if not any(str(f['properties'].get('publicIPAddress',{}).get('id','')).casefold()==rid for f in front):continue
                        for conf in _children(gateway,'gatewayIPConfigurations').values():
                            subnet=conf['properties'].get('subnet',{}).get('id')
                            if not isinstance(subnet,str)or re.fullmatch(re.escape(scope)+'/resourceGroups/'+SEG+'/providers/Microsoft.Network/virtualNetworks/'+SEG+'/subnets/'+SEG,subnet,re.I)is None:raise ValueError('inherited gateway VNet identity unresolved')
                            vnets.add(subnet.rsplit('/',2)[0].casefold())
                    if len(vnets)!=1:raise ValueError('public IP inherited VNet association missing or ambiguous')
                    vid=next(iter(vnets));vnet=read(vid,'Microsoft.Network/virtualNetworks','2023-09-01','Microsoft.Network/virtualNetworks:GET');supports['vnet'][vid]=vnet
                    plan=_reference(vnet['properties'],'ddosProtectionPlan',scope,'Microsoft.Network/ddosProtectionPlans')
                    if plan:supports['ddos_plan'][plan]=read(plan,'Microsoft.Network/ddosProtectionPlans','2023-09-01','Microsoft.Network/ddosProtectionPlans:GET')
                    binding.update(inherited_vnet_id=vid,vnet_association_evidence_ref=resource['id']+'@'+resource['etag']);binding['_coverage']['inherited_vnet']={'status':'collected','parent_id':rid}
                if kind=='public_ip'and resource['properties'].get('ddosSettings',{}).get('protectionMode')=='Enabled':
                    plan=_reference(resource['properties']['ddosSettings'],'ddosProtectionPlan',scope,'Microsoft.Network/ddosProtectionPlans')
                    if plan:supports['ddos_plan'][plan]=read(plan,'Microsoft.Network/ddosProtectionPlans','2023-09-01','Microsoft.Network/ddosProtectionPlans:GET')
            if kind in('application_gateway','frontdoor','frontdoor_profile')and binding['public']:
                for pid in policies:
                    if not isinstance(pid,dict):waf(pid)
                inline=any(isinstance(pid,dict)for pid in policies)
                binding['declared_waf_selections']=deepcopy(policies)
                binding['effective_waf_policy_ids']=list(dict.fromkeys(pid for pid in policies if not isinstance(pid,dict)))
                binding['waf_linkage_evidence_ref']=resource['id']+'@'+resource['etag']
                binding['_coverage']['effective_waf']={'status':'not_collected'if inline else'collected','parent_id':rid}
                if inline:binding['_coverage']['inlineWafConfiguration']={'status':'collected','parent_id':rid}
            binding['_provenance'].update(derived_by='Peasso.azure_public_edge_config_20261020',native_source_operation=resource['_provenance']['source_operation'],native_request_path=resource['id'])
            bindings.append(binding)
    # Only completed real reads form the final source-receipt closure.
    for b in bindings:b['_provenance']['native_supporting_reads']=deepcopy(receipts)
    return bindings,{k:list(v.values())for k,v in supports.items()}
