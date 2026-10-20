"""Assess declared public IPv4 breadth, separately from VNet declarations."""
from copy import deepcopy
from ipaddress import IPv4Network, collapse_addresses
import json
from pathlib import Path
from peaso.collectors.azure_acr_public_ip_review_20261020 import ARM, KIND, MARKER, MAX_RULES, VERSION, registry_id
from .facts import Unavailable

CHECK = 'azure.network.acr_public_ip_ranges_restricted'
TITLE = 'ACR public network rules do not allow every IPv4 address'
REMEDIATION = 'Disable public network access, or use default Deny with only the IPv4 ranges needed by registry clients. Review trusted Azure service bypass separately.'
DECLARATIONS = [dict(id=CHECK, provider='azure', category='network', kind='container_registry',
    finding_type='network', severity='medium', title=TITLE, remediation=REMEDIATION,
    dependencies=['container_registry', KIND], requirements=[], ui_group='Network',
    evidence_sentences=['This result assesses declared public IPv4 rules. Authentication, private routing and effective access were not tested.'])]


def _bound(item, index):
    ctx = index.get('context', {})
    scope = ctx.get('scope')
    if ctx.get('provider') != 'azure':
        raise Unavailable('Azure context unavailable')
    rid = registry_id(item.get('id'), scope)
    if str(item.get('type', '')).casefold() != 'microsoft.containerregistry/registries':
        raise Unavailable('native registry type unresolved')
    inventory = index.get('collections', {}).get(KIND, [])
    own = [c for c in inventory if c.get('scope', '').casefold() == scope.casefold()]
    if len(own) != 1 or own[0].get('status') != 'collected' or not isinstance(own[0].get('items'), list):
        raise Unavailable('complete native registry network inventory unavailable')
    seen, matches = set(), []
    for row in own[0]['items']:
        value = registry_id(row.get('id'), scope)
        if value.casefold() in seen:
            raise Unavailable('duplicate registry network identity')
        seen.add(value.casefold())
        if value.casefold() == rid.casefold():
            matches.append(row)
    if len(matches) != 1:
        raise Unavailable('native registry network identity missing')
    row = matches[0]
    meta = ctx.get('metadata', {})
    for obj in (item, own[0], row):
        for key in ('credential_context_id', 'customer_context_id'):
            value = meta.get(key)
            if not isinstance(value, str) or not value or obj.get('_provenance', {}).get(key) != value:
                raise Unavailable('registry capture context unresolved')
    parent = row.get('parent_id')
    if (not isinstance(parent, str) or parent.casefold() != rid.casefold()
            or str(row.get('type', '')).casefold() != 'microsoft.containerregistry/registries'
            or row.get(MARKER) != {'scope': scope, 'resource_id': parent, 'method': 'GET', 'api_version': VERSION,
                                  'request_uri': ARM+parent+'?api-version='+VERSION, 'complete': True}
            or row.get(MARKER, {}).get('complete') is not True
            or row.get('_provenance', {}).get('scope') != scope
            or row.get('_provenance', {}).get('read_only') is not True
            or row.get('_provenance', {}).get('source_operation') != 'Registries_Get'
            or row.get('_provenance', {}).get('api_version') != VERSION):
        raise Unavailable('registry GET source binding unresolved')
    props = row.get('properties')
    if not isinstance(props, dict) or props.get('provisioningState') != 'Succeeded':
        raise Unavailable('registry configuration not settled')
    return props


def evaluate(item, index):
    props = _bound(item, index)
    pna, bypass = props.get('publicNetworkAccess'), props.get('networkRuleBypassOptions')
    if pna not in ('Enabled', 'Disabled') or bypass not in ('None', 'AzureServices'):
        raise Unavailable('public access or trusted-service bypass declaration unavailable')
    evidence = {'public_network_access': pna, 'trusted_service_bypass': bypass,
                'criterion': 'declared_public_ipv4_union', 'effective_access': 'not_tested'}
    if pna == 'Disabled':
        return 'PASS', dict(evidence, observed='The registry declares public network access disabled. Trusted-service bypass is '+bypass+'; private connectivity and effective access were not tested.')
    nrs = props.get('networkRuleSet')
    if not isinstance(nrs, dict) or nrs.get('defaultAction') not in ('Allow', 'Deny'):
        raise Unavailable('network default action unavailable')
    if nrs['defaultAction'] == 'Allow':
        return 'FAIL', dict(evidence, default_action='Allow', allows_all_ipv4=True,
            observed='The registry declares public access with default Allow. Trusted-service bypass is '+bypass+'; authentication and effective access were not tested.')
    rules = nrs.get('ipRules')
    if (not isinstance(rules, list) or len(rules) > MAX_RULES or any(not isinstance(r, dict) for r in rules)):
        raise Unavailable('complete bounded IP rule inventory unavailable')
    networks = []
    for rule in rules:
        value = rule.get('value')
        if (rule.get('action') != 'Allow' or not isinstance(value, str) or not value or len(value) > 18
                or any(c not in '0123456789./' for c in value)):
            raise Unavailable('native IPv4 allow rule unsupported')
        try:
            network = IPv4Network(value, strict=False)
        except (ValueError, TypeError) as exc:
            raise Unavailable('native IPv4 allow rule malformed') from exc
        # Dotted netmask spellings are not the native CIDR contract.
        if '/' in value and not value.split('/')[1].isdigit():
            raise Unavailable('native prefix format unsupported')
        networks.append(network)
    collapsed = list(collapse_addresses(networks))
    failed = any(n.prefixlen == 0 for n in collapsed)
    evidence.update(default_action=nrs['defaultAction'], declared_ip_rules=len(rules),
                    collapsed_ipv4_ranges=[str(n) for n in collapsed], allows_all_ipv4=failed)
    observation = ('The registry declares public access from every IPv4 address.' if failed else
                   'The registry declares default Deny without IP rules covering every IPv4 address.')
    return ('FAIL' if failed else 'PASS'), dict(evidence, observed=observation+' Trusted-service bypass is '+bypass+'; authentication and effective access were not tested.')


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK for c in CHECKS):
        return
    register(CHECK, 'azure', 'network', 'container_registry', TITLE, 'medium', 'security_configuration',
             REMEDIATION, dependencies=['container_registry', KIND])(evaluate)
    path = Path(__file__).with_name('azure_acr_public_ip_review_20261020_fixtures.json')
    if path.exists():
        CASES[CHECK] = deepcopy(json.loads(path.read_text()).get(CHECK, {}))
