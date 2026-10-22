"""Add source facts to the existing gateway CIDR verdict without changing it."""

from __future__ import annotations

import sys


CHECK_ID = 'azure.other.gateway_api_cidr_allowlist'
_ORIGINAL = None


def _sw14():
    """Use the admitted SW14 module already loaded by bulk install."""
    module = sys.modules.get('peaso.checks._bulk_pending_compliance_new_sw14')
    if module is None:
        raise RuntimeError('admitted SW14 module is not installed')
    return module


def _rule_facts(policy, outside):
    """Return the enabled RemoteAddr rules that affect outside-approved sources."""
    sw14 = _sw14()
    remaining = list(outside)
    facts = []
    rules = sw14.list_of_objects(sw14.get(policy, 'properties.customRules', list))
    enabled = [rule for rule in rules
               if sw14._full_default(rule, 'state', 'Enabled', policy) == 'Enabled']
    for rule in sorted(enabled, key=lambda row: row['priority']):
        action = sw14.get(rule, 'action', str)
        if action == 'Log':
            continue
        matched = list(sw14._UNIVERSE)
        values = []
        for condition in sw14.list_of_objects(sw14.get(rule, 'matchConditions', list)):
            cidrs = sw14._strings(sw14.get(condition, 'matchValues', list))
            ranges = sw14._ranges(cidrs)
            negated = (sw14.get(condition, 'negationConditon', bool)
                       if 'negationConditon' in condition
                       else sw14.get(condition, 'negationCondition', bool))
            if negated:
                ranges = sw14._subtract(sw14._UNIVERSE, ranges)
            matched = sw14._intersection(matched, ranges)
            values.append({'cidrs': cidrs[:3], 'cidr_count': len(cidrs), 'negated': negated})
        if not sw14._intersection(remaining, matched):
            continue
        facts.append({'priority': sw14.get(rule, 'priority', int),
                      'action': action, 'remote_addr_matches': values})
        if action == 'Allow':
            break
        if action == 'Block':
            remaining = sw14._subtract(remaining, matched)
    return facts[:3]


def evaluate(item, index):
    """Preserve the signed decision and add the WAF settings behind it."""
    sw14 = _sw14()
    status, evidence = _ORIGINAL(item, index)
    if status not in {'PASS', 'FAIL'}:
        return status, evidence

    policies = sw14._primary(item, index, 'web_application_firewall_policy')
    paths = [path for path in sw14._attached_paths(item, index) if path['apiInScope']]
    approved_cidrs = sw14._strings(sw14._policy(index, 'approvedCidrs'))
    outside = sw14._subtract(sw14._UNIVERSE, sw14._ranges(approved_cidrs))
    by_id = {policy['id'].casefold(): policy for policy in policies}
    observed_paths = []
    for path in paths:
        policy_id = path['effectivePolicyId']
        fact = {'listener_id': path['listenerId'], 'route_id': path['routeId'],
                'effective_policy_id': policy_id}
        if policy_id is None:
            fact['decision'] = 'FAIL' if outside else 'UNKNOWN'
        else:
            policy = by_id[policy_id.casefold()]
            state, mode = sw14._policy_settings(policy)
            fact.update(policy_state=state, policy_mode=mode)
            fact['decision'] = sw14._remote_rules(policy, outside)
            if state == 'Enabled' and mode == 'Prevention':
                fact['remote_addr_rules'] = _rule_facts(policy, outside)
        observed_paths.append(fact)

    # A failing path remains visible even when the gateway has many listeners.
    if status == 'FAIL':
        observed_paths.sort(key=lambda fact: fact['decision'] != 'FAIL')
    enriched = dict(evidence)
    enriched.update(approved_cidrs=approved_cidrs[:3],
                    approved_cidr_count=len(approved_cidrs),
                    outside_approved_ranges_empty=not outside,
                    effective_paths=observed_paths[:3],
                    effective_path_count=len(paths))
    return status, enriched


def install():
    """Bind only the gateway rule used by the existing SW14 registry closure."""
    global _ORIGINAL
    sw14 = _sw14()
    current = sw14._RULES[CHECK_ID]
    if current is evaluate:
        return
    if _ORIGINAL is not None and current is not _ORIGINAL:
        raise RuntimeError('gateway CIDR evaluator changed before successor install')
    _ORIGINAL = current
    sw14._RULES[CHECK_ID] = evaluate
