"""Declared PSC/DNS configuration, never effective traffic or firewall certification."""
from collections import Counter
from datetime import timedelta
from ipaddress import IPv4Address
import json
from peaso.checks.facts import Unavailable, complete_items, get
from peaso.gcp_psc_policy import OPTION, instant, network_identity, normalize

CHECK_ID = 'gcp.network.private_service_connect_google_apis'


def rows(index, kind, scope):
    envelopes = index.get('collections', {}).get(kind, [])
    if len(envelopes) != 1:
        raise Unavailable('Complete project inventory unavailable: ' + kind)
    env = envelopes[0]
    if (env.get('scope') != scope or env.get('type') != kind or env.get('status') not in ('collected', 'empty') or
            env.get('coverage_status', env.get('status')) not in ('collected', 'empty')):
        raise Unavailable('Foreign or incomplete project inventory: ' + kind)
    native = get(env, 'items', list)
    observed = complete_items(index, kind)
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
    if (len(native) != len(observed) or (env['status'] == 'empty') != (not native) or
            Counter(map(encode, native)) != Counter(map(encode, observed))):
        raise Unavailable('Inventory projection or cardinality differs: ' + kind)
    wrappers = index.get(kind, [])
    if len(wrappers) != len(native) or any(row.get('scope') != scope or row.get('type') != kind or
                                         row.get('provider', 'gcp') != 'gcp' for row in wrappers):
        raise Unavailable('Foreign resource projection: ' + kind)
    return observed


def evaluate(item, index):
    from peaso.checks import unknown, result
    try:
        context = get(index, 'context', dict)
        scope = get(context, 'scope', str)
        if context.get('provider') != 'gcp' or get(item, 'scope', str) != scope:
            raise Unavailable('Project scope authority unavailable')
        policy = normalize(get(get(context, 'metadata', dict), OPTION, dict), [scope])
        now = instant(get(context, 'created_at', str));date = instant(policy['observed_at'])
        if date > now or now - date > timedelta(seconds=policy['max_age_seconds']):
            raise Unavailable('Owner PSC scope is stale or future dated')
        rules = rows(index, 'forwarding_rule', scope)
        records = rows(index, 'dns_record', scope)
        required = {network_identity(n) for n in policy['required_vpcs']}
        addresses = {network: set() for network in required}
        for rule in rules:
            target = rule.get('target')
            if target is None and isinstance(rule.get('backendService'), str):
                continue
            if not isinstance(target, str):
                raise Unavailable('Forwarding rule target is unresolved')
            if target not in ('all-apis', 'vpc-sc'):
                continue
            network = network_identity(get(rule, 'network', str))
            if network in required and target in ('all-apis', 'vpc-sc'):
                address = str(IPv4Address(get(rule, 'IPAddress', str)))
                addresses[network].add(address)
        missing, alternatives = [], []
        for network in sorted(required):
            if not addresses[network]:
                missing.append({'network': network, 'configuration': 'Google APIs PSC forwarding rule'})
                continue
            visible = [r for r in records if network_identity(get(r, 'network', str)) == network]
            for hostname in policy['required_google_api_hostnames']:
                exact = [r for r in visible if get(r, 'name', str).lower().rstrip('.') == hostname]
                a_records = [r for r in exact if get(r, 'type', str) == 'A']
                zones = {get(r, 'managed_zone', str) for r in a_records}
                if len(zones) > 1:
                    raise Unavailable('Several private zones declare the same DNS name')
                if not a_records and (any(get(r, 'type', str) == 'CNAME' for r in exact) or any(
                        get(r, 'name', str).startswith('*.') and hostname.endswith('.' + r['name'][2:].rstrip('.')) for r in visible)):
                    alternatives.append(hostname)
                    continue
                values = [v for r in a_records for v in get(r, 'rrdatas', list)]
                if any(not isinstance(v, str) for v in values):
                    raise Unavailable('DNS A-record address must be a native string')
                values = [str(IPv4Address(v)) for v in values]
                if not set(values) & addresses[network]:
                    missing.append({'network': network, 'configuration': hostname})
        evidence = {'scope': scope, 'source_ref': policy['source_ref'], 'missing_configuration': missing,
                    'semantics': 'declared endpoint and private DNS A-record configuration; traffic, DNS precedence and firewall enforcement are not measured'}
        if missing:
            return result(True, **evidence)
        if alternatives:
            return unknown('Wildcard or CNAME resolution needs additional DNS evidence', unresolved_names=alternatives, **evidence)
        return result(False, **evidence)
    except (Unavailable, ValueError, TypeError, KeyError) as exc:
        return unknown(str(exc))


def install():
    from peaso.checks import register
    register(CHECK_ID, 'gcp', 'network', 'forwarding_rule', 'Declared Google API PSC endpoints and private DNS A records match owner scope',
             'medium', 'SC-7', 'Create the required Google APIs PSC endpoint and private DNS A records; verify actual routing and firewall enforcement separately.',
             target='scope', dependencies=['forwarding_rule', 'dns_record'])(evaluate)

    from pathlib import Path
    from peaso.checks.fixtures import CASES
    CASES[CHECK_ID] = json.loads(Path(__file__).with_name('gcp_psc_fixtures.json').read_text())
