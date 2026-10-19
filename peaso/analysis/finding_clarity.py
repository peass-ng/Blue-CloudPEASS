"""Short presentation of the six non-path analysis projections."""
HOW = {
    'analysis.grant_review': 'Classifies each declared Allow grant using the bundled permission-risk catalog; it does not calculate complete effective access.',
    'analysis.inactive_identity': 'Reports an explicit zero activity count in the collected usage window; missing activity is not proof that an identity is unused.',
    'analysis.principal_exposure': 'Classifies declared principals against the scanned scopes and collected organization membership, retaining restrictive conditions and attribution gaps.',
    'analysis.network_review': 'Finds Internet-wide allow rules in security groups, firewalls, NSGs or NetworkPolicies; it does not establish an endpoint path.',
    'analysis.coverage': 'Reports missing, denied or malformed inventory required by the identity analysis.',
    'analysis.federated_trust': 'Checks OIDC trust declarations for the required issuer, audience and subject restrictions; unresolved identity details remain undetermined.',
}
ACTION = {
    'analysis.grant_review': 'Remove unnecessary broad permissions; retain only the actions and resources the workload needs.',
    'analysis.inactive_identity': 'Confirm whether the identity is still needed before disabling its credentials or removing its permissions.',
    'analysis.principal_exposure': 'Keep public or external principals only where access is intended; restrict the granting policy or binding otherwise.',
    'analysis.network_review': 'Consider whether public access is needed; restrict unnecessary source networks or ports.',
    'analysis.coverage': 'Collect the named missing inventory or resolve its read-permission error before drawing a conclusion.',
    'analysis.federated_trust': 'Restrict the trust policy to the intended issuer, audience and subjects.',
}


def _web_ports(native):
    """Return only explicit TCP80/443 declarations; unrecognized rules retain risk."""
    if not isinstance(native,dict):
        return None
    if 'IpProtocol' in native:
        if native.get('IpProtocol') not in ('tcp','6'):
            return None
        a,b=native.get('FromPort'),native.get('ToPort')
        return [a] if type(a) is int and a==b and a in (80,443) else None
    if 'allowed' in native:
        entries=native['allowed']
        if not isinstance(entries,list) or not entries:return None
        ports=[]
        for entry in entries:
            if not isinstance(entry,dict) or entry.get('IPProtocol') not in ('tcp','6'):return None
            values=entry.get('ports')
            if not isinstance(values,list) or not values:return None
            for v in values:
                if v not in ('80','443','80-80','443-443'):return None
                ports.append(int(v.split('-')[0]))
        return ports
    props=native.get('properties',native)
    if not isinstance(props,dict):return None
    if 'destinationPortRange' in props or 'destinationPortRanges' in props:
        if props.get('protocol') not in ('Tcp','TCP','tcp'):return None
        values=props.get('destinationPortRanges') or [props.get('destinationPortRange')]
        if not isinstance(values,list) or not values or any(v not in ('80','443','80-80','443-443') for v in values):return None
        return [int(v.split('-')[0]) for v in values]
    if 'ports' in native:
        values=native['ports'];out=[]
        if not isinstance(values,list) or not values:return None
        for p in values:
            if not isinstance(p,dict) or p.get('protocol','TCP')!='TCP' or type(p.get('port')) is not int or p['port'] not in (80,443) or p.get('endPort',p['port'])!=p['port']:return None
            out.append(p['port'])
        return out
    return None


def network_priority(evidence, default='high'):
    rules=evidence.get('rules') if isinstance(evidence,dict) else None
    if not isinstance(rules,list) or not rules:return default
    ports=[_web_ports(row.get('native_rule')) if isinstance(row,dict) else None for row in rules]
    return 'medium' if all(ports) else default


def evidence_summary(finding):
    if not isinstance(finding,dict):return None
    cid=finding.get('check_id');e=finding.get('evidence');status=finding.get('status')
    if cid not in HOW or not isinstance(e,dict):return None
    if cid=='analysis.network_review' and isinstance(e.get('rules'),list) and e['rules']:
        def valid_rule(row):
            if not isinstance(row,dict) or not isinstance(row.get('native_rule'),dict):return False
            native=row['native_rule'];source=row.get('source')
            if not native:
                return isinstance(source,dict) and source.get('resource_type')=='networkpolicy' and isinstance(source.get('path'),str) and source['path'].startswith('spec.ingress[')
            props=native.get('properties',native)
            if 'IpProtocol' in native:
                protocol=native['IpProtocol']
                if protocol in ('tcp','udp','6','17'):
                    a,b=native.get('FromPort'),native.get('ToPort')
                    return type(a) is int and type(b) is int and 0<=a<=b<=65535
                return isinstance(protocol,str) and bool(protocol) and (protocol in ('icmp','icmpv6','-1') or protocol.isdigit())
            if 'allowed' in native:
                allowed=native['allowed']
                return isinstance(allowed,list) and bool(allowed) and all(isinstance(v,dict) and isinstance(v.get('IPProtocol'),str) and bool(v['IPProtocol']) for v in allowed)
            if isinstance(props,dict) and 'protocol' in props:return props['protocol'] in ('Tcp','TCP','tcp','Udp','UDP','udp','Icmp','ICMP','icmp','*')
            if 'ports' in native:
                return isinstance(native['ports'],list) and all(isinstance(v,dict) and v.get('protocol','TCP') in ('TCP','UDP','SCTP') and (type(v.get('port')) is int or isinstance(v.get('port'),str)) for v in native['ports'])
            return isinstance(native.get('from'),list) and all(isinstance(v,dict) for v in native['from'])
        def public_origin(row):
            # Reuse the native projection's public-source semantics rather than
            # interpreting a port declaration as evidence of public ingress.
            from .network import public_rules
            native=row['native_rule'];source=row.get('source')
            if 'IpProtocol' in native:kind,data='security_group',{'IpPermissions':[native]}
            elif 'allowed' in native:kind,data='firewall',native
            elif 'properties' in native or 'sourceAddressPrefix' in native or 'sourceAddressPrefixes' in native:
                kind,data='nsg',{'securityRules':[native]}
            elif 'ports' in native or 'from' in native or isinstance(source,dict) and source.get('resource_type')=='networkpolicy':
                kind,data='networkpolicy',{'spec':{'policyTypes':['Ingress'],'ingress':[native]}}
            else:return False
            try:return any(public_rules({'type':kind,'data':data}))
            except (AttributeError,TypeError,ValueError,KeyError):return False
        if not all(valid_rule(row) and public_origin(row) for row in e['rules']):return None
        ports=[_web_ports(x.get('native_rule')) if isinstance(x,dict) else None for x in e['rules']]
        if all(ports):
            names=', '.join('TCP/'+str(p) for p in sorted({p for group in ports for p in group}))
            return f'The collected rules allow Internet-wide sources on {names}; endpoint reachability is not established.'
        return 'The collected rules contain Internet-wide allow declarations; endpoint reachability is not established.'
    if cid=='analysis.inactive_identity':
        usage=e.get('usage')
        if isinstance(usage,dict) and usage.get('inactive_observation') is True:
            return 'No activity was recorded in the observed window; the identity may still be needed.'
    if cid=='analysis.grant_review' and isinstance(e.get('grants'),list) and e['grants']:
        grants=e['grants']
        if not all(isinstance(g,dict) and g.get('allowed_declaration') is True
                   and isinstance(g.get('native_grant'),(dict,str)) and bool(g['native_grant'])
                   and (g.get('broad') is True or g.get('severity') in ('high','critical')) for g in grants):return None
        n=len(grants)
        return f'The configuration declares {n} broad or high-impact permission grant'+('s' if n!=1 else '')+'; effective access is not established.'
    if cid=='analysis.coverage':
        if e.get('reason')=='malformed_native_fact':return 'A collected inventory record is malformed; the assessment remains undetermined.'
        gaps=e.get('gaps')
        if isinstance(gaps,list) and gaps:
            kinds=[x['type'] for x in gaps if isinstance(x,dict) and isinstance(x.get('type'),str)]
            if kinds:return 'Required inventory is incomplete: '+', '.join(kinds[:4])+('.' if len(kinds)<=4 else ', and other types.')
    from .provider_observed_evidence import evidence_summary as provider_summary
    observed=provider_summary(finding)
    if observed is not None:return observed
    if cid=='analysis.principal_exposure':
        entries=e.get('principals')
        if not isinstance(entries,list) or not entries or any(not isinstance(v,dict) for v in entries):return None
        public=[]
        for entry in entries:
            grant=entry.get('native_grant')
            if entry.get('classification')!='public' or not isinstance(grant,dict) or grant.get('Effect')!='Allow':continue
            principal=grant.get('Principal')
            candidates=[principal] if isinstance(principal,str) else list(principal.values()) if isinstance(principal,dict) else []
            values=[v for group in candidates for v in (group if isinstance(group,list) else [group])]
            if '*' in values:public.append(entry)
        if public:
            conditional=any(v.get('reason')=='public_conditional' or bool(v.get('restrictive_conditions')) for v in public)
            return 'The policy declares a public wildcard principal'+(' with limiting conditions recorded' if conditional else '')+'; effective access is not established.'
    if cid=='analysis.federated_trust':
        trusts=e.get('federated_trusts')
        if not isinstance(trusts,list) or not trusts or any(not isinstance(v,dict) for v in trusts):return None
        messages=[];reviewed=[]
        for trust in trusts:
            issuer,principal,problems=trust.get('issuer'),trust.get('federated_principal'),trust.get('problems')
            if not isinstance(issuer,str) or not issuer or len(issuer)>240 or any(c in issuer for c in '\n\r\x00') or not isinstance(principal,str):return None
            oidc=principal.startswith('arn:') and ':oidc-provider/' in principal and principal.split(':oidc-provider/',1)[1]==issuer
            cognito=principal==issuer=='cognito-identity.amazonaws.com'
            if not (oidc or cognito) or not isinstance(problems,list) or any(not isinstance(p,dict) for p in problems):return None
            codes=[p.get('code') for p in problems]
            if any(not isinstance(code,str) for code in codes):return None
            for code in codes:
                if code=='no_sub_condition' and oidc:messages.append('The OIDC trust for '+issuer+' has no positive subject restriction.')
                elif code=='wildcard_sub' and oidc:messages.append('The OIDC subject pattern leaves the tenant or repository owner unrestricted.')
                elif code=='no_aud_condition' and oidc:messages.append('The OIDC trust has no positive audience restriction.')
                elif code=='cognito_no_aud' and cognito:messages.append('The Cognito trust does not pin an identity-pool audience.')
                elif code=='cognito_unauthenticated' and cognito:messages.append('The trust condition includes unauthenticated Cognito identities.')
                else:return None
            reviewed.append(issuer)
        if messages:
            unique=list(dict.fromkeys(messages))
            return ' '.join(unique[:2])+(f' {len(unique)-2} additional restriction issues are recorded.' if len(unique)>2 else '')
        unique=list(dict.fromkeys(reviewed))
        return 'No checked subject or audience restriction issue is recorded for '+', '.join(unique[:2])+(f' and {len(unique)-2} other issuers' if len(unique)>2 else '')+'.'
    return None
