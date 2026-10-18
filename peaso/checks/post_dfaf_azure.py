"""Offline Azure predicates; inert until explicitly admitted by the integrator.

No registry writes, cloud calls, owner-policy inference, or cache dependencies.
"""
from __future__ import annotations
import re
from peaso.checks import result, unknown
from peaso.checks.facts import Unavailable, get, list_of_objects, memoized

WEBPUBSUB = 'azure.gap.web_pub_sub_private_link_used'
FIREWALL = 'azure_firewall_policy_1_2_8_23_59ad733'
DEPENDENCIES = {WEBPUBSUB: ('web_pubsub',), FIREWALL: ('firewall_policy',)}


def _scope(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'azure':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    if not re.fullmatch(r'/subscriptions/[A-Za-z0-9._-]{1,128}', scope, re.I):
        raise Unavailable('subscription scope unavailable')
    return scope.casefold()


def _inventory(index, kind, complete=True):
    scope = _scope(index)
    return memoized(index, ('post_dfaf_azure_inventory', scope, kind, complete),
                    lambda: _inventory_uncached(index, kind, complete))


def _inventory_uncached(index, kind, complete=True):
    scope = _scope(index)
    pages = get(index, 'collections', dict).get(kind)
    if not isinstance(pages, list) or not pages:
        raise Unavailable('inventory not collected: ' + kind)
    rows = []
    for page in pages:
        if not isinstance(page, dict) or page.get('type') != kind or get(page, 'scope', str).casefold() != scope:
            raise Unavailable('foreign inventory envelope')
        if page.get('status') not in (('collected', 'empty') if complete else ('collected', 'empty', 'partial')):
            raise Unavailable('inventory unavailable: ' + kind)
        items = list_of_objects(get(page, 'items', list))
        if (page.get('status') == 'empty') != (not items):
            raise Unavailable('inventory status contradicts items')
        rows.extend(items)
    wrappers = list_of_objects(get(index, kind, list))
    if any(w.get('provider') != 'azure' or w.get('type') != kind or get(w, 'scope', str).casefold() != scope for w in wrappers):
        raise Unavailable('foreign projection')
    if [get(w, 'data', dict) for w in wrappers] != rows:
        raise Unavailable('inventory/projection mismatch')
    ids = [get(row, 'id', str).casefold() for row in rows]
    if len(ids) != len(set(ids)) or any(not rid.startswith(scope + '/') for rid in ids):
        raise Unavailable('foreign or duplicate resource')
    return rows


def _members(index, kind, complete=True):
    scope = _scope(index)
    return memoized(index, ('post_dfaf_azure_members', scope, kind, complete),
                    lambda: {get(row, 'id', str).casefold(): row
                             for row in _inventory(index, kind, complete)})


def _member(item, index, kind, complete=True):
    identity = get(item, 'id', str).casefold()
    if _members(index, kind, complete).get(identity) != item:
        raise Unavailable('resource not in scoped inventory')
    return identity


def _coverage(item, field):
    coverage = get(item, '_coverage', dict)
    state = get(get(coverage, field, dict), 'status', str)
    if state not in ('collected', 'empty'):
        raise Unavailable('incomplete child inventory: ' + field)


def _full(item):
    provenance = get(item, '_provenance', dict)
    if provenance.get('representation') != 'full' or provenance.get('read_only') is not True or get(provenance, 'source_operation', str).casefold() != 'get':
        raise Unavailable('authoritative parent GET unavailable')


def webpubsub(item, index):
    identity = _member(item, index, 'web_pubsub')
    if not re.fullmatch(r'.+/providers/microsoft.signalrservice/webpubsub/[^/?#]+', identity):
        raise Unavailable('Web PubSub resource type mismatch')
    _coverage(item, 'privateEndpointConnections')
    children = list_of_objects(get(item, 'privateEndpointConnections', list))
    if (get(item, '_coverage.privateEndpointConnections.status', str) == 'empty') != (not children):
        raise Unavailable('connection coverage contradicts rows')
    seen = set()
    approved = []
    for child in children:
        cid = get(child, 'id', str).casefold()
        if not re.fullmatch(re.escape(identity) + r'/privateendpointconnections/[^/?#]+', cid) or cid in seen:
            raise Unavailable('foreign or duplicate connection')
        seen.add(cid)
        status = get(child, 'properties.privateLinkServiceConnectionState.status', str)
        if status not in ('Approved', 'Pending', 'Rejected', 'Disconnected'):
            raise Unavailable('unknown private endpoint connection status')
        if status == 'Approved':
            endpoint = get(child, 'properties.privateEndpoint.id', str)
            if not re.fullmatch(r'/subscriptions/[^/?#]+/resourcegroups/[^/?#]+/providers/microsoft.network/privateendpoints/[^/?#]+', endpoint, re.I):
                raise Unavailable('malformed private endpoint ARM ID')
            approved.append(cid)
    return result(not approved, resource_id=identity, approved_connection_ids=approved)


def _policy_chain(item, index):
    identity = _member(item, index, 'firewall_policy')
    policies = _members(index, 'firewall_policy')
    chain = []; seen = set(); current = identity
    while current:
        if current in seen or current not in policies:
            raise Unavailable('cyclic or uncollected base policy')
        seen.add(current); policy = policies[current]; _full(policy)
        if not re.fullmatch(r'.+/providers/microsoft.network/firewallpolicies/[^/?#]+', current):
            raise Unavailable('firewall policy resource type mismatch')
        chain.append(policy)
        props = get(policy, 'properties', dict)
        # basePolicy is an optional ARM subresource; omission on a full GET
        # establishes no inheritance. Explicit denied/malformed coverage does not.
        if 'basePolicy' in props or 'basePolicy' in props.get('_coverage', {}):
            base = get(props, 'basePolicy')
            if base is None:
                current = None
            elif isinstance(base, dict):
                current = get(base, 'id', str).casefold()
            else:
                raise Unavailable('malformed base policy')
        else:
            current = None
    return identity, chain


def firewall(item, index):
    identity, chain = _policy_chain(item, index)
    present = []; unresolved = False
    for policy in chain:
        pid = get(policy, 'id', str).casefold()
        try:
            _coverage(policy, 'ruleCollectionGroups')
            groups = list_of_objects(get(policy, 'ruleCollectionGroups', list))
            if (get(policy, '_coverage.ruleCollectionGroups.status', str) == 'empty') != (not groups):
                raise Unavailable('group coverage contradicts rows')
            seen = set()
            for group in groups:
                gid = get(group, 'id', str).casefold()
                provenance = get(group, '_provenance', dict)
                if not re.fullmatch(re.escape(pid) + r'/rulecollectiongroups/[^/?#]+', gid) or gid in seen or get(group, 'parent_id', str).casefold() != pid:
                    raise Unavailable('foreign or duplicate group')
                seen.add(gid)
                if provenance.get('representation') != 'full' or provenance.get('read_only') is not True or provenance.get('source_operation') != 'get_rule_collection_group' or get(provenance, 'parent_policy_id', str).casefold() != pid:
                    raise Unavailable('complete group GET unavailable')
                for collection in list_of_objects(get(group, 'properties.ruleCollections', list)):
                    kind = get(collection, 'ruleCollectionType', str)
                    if kind not in ('FirewallPolicyFilterRuleCollection', 'FirewallPolicyNatRuleCollection'):
                        raise Unavailable('unknown rule collection type')
                    rules = list_of_objects(get(collection, 'rules', list))
                    for rule in rules:
                        rule_type = get(rule, 'ruleType', str)
                        allowed = ('NetworkRule', 'ApplicationRule') if kind == 'FirewallPolicyFilterRuleCollection' else ('NatRule',)
                        if rule_type not in allowed or not get(rule, 'name', str):
                            raise Unavailable('unknown or incompatible rule type')
                    if rules:
                        present.append(gid)
        except Unavailable:
            unresolved = True
    # The signed predicate explicitly requires complete direct and inherited
    # inventory, including known rule types, before either final verdict.
    if unresolved:
        raise Unavailable('rule collection inventory incomplete or malformed')
    if present:
        return result(False, policy_id=identity, qualifying_group_ids=sorted(set(present)))
    return result(True, policy_id=identity, qualifying_group_ids=[])


EVALUATORS = {WEBPUBSUB: webpubsub, FIREWALL: firewall}


def evaluate(check_id, item, index):
    """Native-compatible exception boundary without mutating the registry."""
    try:
        return EVALUATORS[check_id](item, index)
    except Unavailable as exc:
        return unknown(str(exc))


def install():
    """Install exactly the two reviewed signed Azure predicates."""
    from . import register
    register('azure.gap.web_pub_sub_private_link_used', 'azure', 'network', 'web_pubsub', 'Web PubSub has an approved private endpoint', 'medium', 'azure-compliance.control.web_pub_sub_private_link_used', 'Web PubSub > Networking > Private endpoint connections: approve a private endpoint; disable public network access separately if policy requires it.', dependencies=DEPENDENCIES['azure.gap.web_pub_sub_private_link_used'])(EVALUATORS['azure.gap.web_pub_sub_private_link_used'])
    register('azure_firewall_policy_1_2_8_23_59ad733', 'azure', 'network', 'firewall_policy', 'Azure Firewall Policies contain configured rules', 'medium', '1.2.8.23', 'Add a filter or NAT rule collection containing an applicable rule to the policy or its effective base policy.', dependencies=DEPENDENCIES['azure_firewall_policy_1_2_8_23_59ad733'])(EVALUATORS['azure_firewall_policy_1_2_8_23_59ad733'])
