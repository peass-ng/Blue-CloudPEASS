"""Evidence-bound Lightsail public-port priority; no verdict changes."""

_LIGHTSAIL_PORTS={
    'aws.cb.lightsail.ssh_rdp_http_world_closed':frozenset({22,80,3389}),
    'aws.cb.lightsail.ssh_restricted':frozenset({22}),
    'aws.cb.lightsail.rdp_restricted':frozenset({3389}),
}


def contextual_severity(finding,default=None):
    if not isinstance(finding,dict):
        return default
    baseline=default if default is not None else finding.get('severity')
    if finding.get('provider')!='aws' or finding.get('status')!='FAIL':
        return baseline
    accepted=_LIGHTSAIL_PORTS.get(finding.get('check_id'))
    evidence=finding.get('evidence')
    if accepted is None or not isinstance(evidence,dict):
        return baseline
    ports=evidence.get('open_ports')
    if not isinstance(ports,list) or not ports or any(type(p) is not int or p not in accepted for p in ports):
        return baseline
    return 'medium' if set(ports)<={80} else 'high'
