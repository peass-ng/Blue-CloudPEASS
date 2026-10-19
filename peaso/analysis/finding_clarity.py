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
        n=len(e['grants'])
        return f'The configuration declares {n} broad or high-impact permission grant'+('s' if n!=1 else '')+'; effective access is not established.'
    if cid=='analysis.coverage':
        gaps=e.get('gaps')
        if isinstance(gaps,list) and gaps:
            kinds=[x['type'] for x in gaps if isinstance(x,dict) and isinstance(x.get('type'),str)]
            if kinds:return 'Required inventory is incomplete: '+', '.join(kinds[:4])+('.' if len(kinds)<=4 else ', and other types.')
    # Principal and OIDC verdicts have distinct subcases; retain their recorded
    # reason rather than inventing one universal public-access observation.
    return None
