"""Four configuration controls from the pinned Azure AI Services source review."""
from pathlib import Path
import json
import re
from peaso.collectors.azure_ai_services_native import KINDS, VERSION, account_id, child_id
from .facts import get, list_of_objects, Unavailable

PREFIX = 'azure.review.ai_services.'
CHECK_IDS = [PREFIX + name for name in KINDS]
REVIEW = {
    'audit_logging': ('hardening', 'medium', 'AI Services configures supported audit logs to a destination',
        'Enable the Audit category or a supported audit/allLogs group in a diagnostic setting. Configure a Log Analytics, Storage, Event Hub or partner destination. Verify ingestion separately.'),
    'managed_identity': ('least_privilege', 'medium', 'AI Services declares a managed identity',
        'Enable a system-assigned or user-assigned managed identity. Grant only the roles needed by the workload and review those role assignments separately.'),
    'outbound_restriction': ('hardening', 'medium', 'AI Services declares restricted outbound network access',
        'Enable restrictOutboundNetworkAccess for the supported account. Review allowedFqdnList for necessary destinations and verify workload compatibility.'),
    'prompt_shield': ('hardening', 'high', 'Text deployments explicitly configure blocking Prompt Shields',
        'Assign an explicit RAI policy to each supported text deployment. Enable the Jailbreak filter with source Prompt and blocking true. Review default or unsupported policies manually.'),
}
DECLARATIONS = [dict(id=PREFIX + name, provider='azure', category=category, kind=KINDS[name],
    finding_type={'audit_logging': 'logging', 'managed_identity': 'permissions', 'outbound_restriction': 'network', 'prompt_shield': 'workload_hardening'}[name], severity=severity, requirements=[], dependencies=[KINDS[name]],
    title=title, remediation=remediation, evidence_sentences=['The result describes collected ARM configuration. Runtime enforcement and event delivery were not tested.'])
    for name, (category, severity, title, remediation) in REVIEW.items()]


def _bound(item, index):
    ctx = index['context']
    if ctx.get('provider') != 'azure':
        raise Unavailable('Azure scope unavailable')
    scope = ctx.get('scope')
    if not isinstance(scope, str):
        raise Unavailable('subscription unavailable')
    rid = account_id(get(item, 'id', str), scope)
    proof = get(item, '_ai_services_native', dict)
    if (proof != {'scope': scope, 'account_id': rid, 'method': 'GET', 'api_version': VERSION, 'complete': True}
            or get(item, 'properties.provisioningState', str) != 'Succeeded'):
        raise Unavailable('complete account configuration unavailable')
    return rid


def _children(item, field, path):
    values = list_of_objects(get(item, field, list))
    seen = set()
    for row in values:
        ident = child_id(row, item['id'], path)
        if ident in seen:
            raise Unavailable('duplicate child identity')
        seen.add(ident)
    return values


def _answer(failed, observed, **evidence):
    return ('FAIL' if failed else 'PASS'), dict(observed=observed, **evidence)


def managed_identity(item, index):
    _bound(item, index)
    # A successful full GET can omit identity when no identity is assigned.
    identity = item.get('identity')
    if identity is None:
        return _answer(True, 'The account has no managed identity declaration. Role assignments were not assessed.', identity_type='None')
    mode = get(item, 'identity.type', str)
    if mode not in ('None', 'SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned'):
        raise Unavailable('unsupported identity type')
    return _answer(mode == 'None', 'The account declares ' + mode + ' identity. This does not establish least privilege.', identity_type=mode)


def outbound_restriction(item, index):
    _bound(item, index)
    enabled = get(item, 'properties.restrictOutboundNetworkAccess', bool)
    return _answer(not enabled, 'The account declares outbound network restrictions ' + ('enabled.' if enabled else 'disabled.') + ' Allowed destinations and actual traffic were not tested.', restrict_outbound_network_access=enabled)


def _sink(properties):
    found = False
    kinds = {'workspaceId': r'Microsoft\.OperationalInsights/workspaces', 'storageAccountId': r'Microsoft\.Storage/storageAccounts',
             'eventHubAuthorizationRuleId': r'Microsoft\.EventHub/namespaces/[^/]+/authorizationRules',
             'marketplacePartnerId': r'Microsoft\.([A-Za-z0-9.]+)/[A-Za-z0-9]+'}
    for field, kind in kinds.items():
        if field not in properties:
            continue
        value = properties[field]
        if value is None or value == '':
            continue
        if (not isinstance(value, str) or any(c in value for c in '?%#\\') or
                not re.fullmatch(r'/subscriptions/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/resourceGroups/[^/\s]+/providers/' + kind + r'/[^/\s]+', value, re.I)):
            raise Unavailable('malformed diagnostic destination')
        found = True
    return found


def audit_logging(item, index):
    _bound(item, index)
    settings = _children(item, 'diagnosticSettings', 'providers/Microsoft.Insights/diagnosticSettings')
    categories = _children(item, 'diagnosticCategories', 'providers/Microsoft.Insights/diagnosticSettingsCategories')
    audits = [c for c in categories if c['name'].casefold() == 'audit' and get(c, 'properties.categoryType', str) == 'Logs']
    if not audits:
        return 'UNKNOWN', {'observed': 'The complete category inventory does not expose a supported Audit log category. Audit logging applicability requires review.'}
    groups = get(audits[0], 'properties.categoryGroups', list) if 'categoryGroups' in audits[0]['properties'] else []
    if any(not isinstance(g, str) for g in groups):
        raise Unavailable('malformed category groups')
    groups = {g.casefold() for g in groups} & {'audit', 'alllogs'}
    enabled_count = 0
    for setting in settings:
        props = get(setting, 'properties', dict)
        sink = _sink(props)
        logs = list_of_objects(get(setting, 'properties.logs', list))
        for log in logs:
            enabled = get(log, 'enabled', bool)
            category, group = log.get('category'), log.get('categoryGroup')
            if ((category is not None and not isinstance(category, str)) or (group is not None and not isinstance(group, str))
                    or bool(category) == bool(group)):
                raise Unavailable('ambiguous log category selector')
            match = (category or '').casefold() == 'audit' or (group or '').casefold() in groups
            if enabled and match and sink:
                enabled_count += 1
    return _answer(not enabled_count, 'A diagnostic setting ' + ('enables' if enabled_count else 'does not enable') + ' supported Audit logs with a destination. Log delivery and retention were not tested.', qualifying_log_entries=enabled_count)


def prompt_shield(item, index):
    _bound(item, index)
    deployments = _children(item, 'deployments', 'deployments')
    policies = _children(item, 'raiPolicies', 'raiPolicies')
    by_name = {p['name'].casefold(): p for p in policies}
    results = []
    for deployment in deployments:
        props = get(deployment, 'properties', dict)
        if props.get('provisioningState') != 'Succeeded':
            results.append('UNKNOWN'); continue
        capabilities = props.get('capabilities')
        if (not isinstance(capabilities, dict) or not capabilities or any(not isinstance(k, str) or not isinstance(v, str) for k, v in capabilities.items())):
            results.append('UNKNOWN'); continue
        enabled = {k.casefold() for k, v in capabilities.items() if v.casefold() == 'true'}
        text, nontext = {'chatcompletion', 'completion', 'responses', 'assistants'}, {'embeddings', 'imagegenerations'}
        if enabled and enabled <= nontext:
            continue
        if not enabled & text:
            results.append('UNKNOWN'); continue
        name = props.get('raiPolicyName')
        if (not isinstance(name, str) or not name or name != name.strip() or '/' in name or name.casefold() not in by_name):
            results.append('UNKNOWN'); continue
        filters = list_of_objects(get(by_name[name.casefold()], 'properties.contentFilters', list))
        seen, blocking = set(), False
        for filt in filters:
            fname, source = get(filt, 'name', str), get(filt, 'source', str)
            if source not in ('Prompt', 'Completion'):
                raise Unavailable('unknown content filter source')
            key = (fname.casefold(), source.casefold())
            if key in seen:
                raise Unavailable('duplicate content filter')
            seen.add(key)
            active, block = get(filt, 'enabled', bool), get(filt, 'blocking', bool)
            if key == ('jailbreak', 'prompt') and active and block:
                blocking = True
        results.append('PASS' if blocking else 'FAIL')
    if 'FAIL' in results:
        return 'FAIL', {'observed': 'At least one supported text deployment explicitly references a policy without enabled blocking Jailbreak filtering on prompts. Actual prompt traffic was not tested.', 'deployment_results': results}
    if 'UNKNOWN' in results:
        return 'UNKNOWN', {'observed': 'A deployment capability, explicit RAI policy reference or policy could not be resolved. Unnamed default policies were not inferred.', 'deployment_results': results}
    if not results:
        return 'NOT_APPLICABLE', {'observed': 'The complete deployment inventory is empty or contains only explicitly supported non-text capabilities.'}
    return 'PASS', {'observed': 'All supported text deployments explicitly reference a policy with enabled blocking Jailbreak filtering on prompts. Actual prompt traffic was not tested.', 'deployment_results': results}


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    fixtures = Path(__file__).with_name('azure_ai_services_review_20261020_fixtures.json')
    fixtures = json.loads(fixtures.read_text()) if fixtures.exists() else {}
    for declaration in DECLARATIONS:
        cid = declaration['id']
        if any(c.id == cid for c in CHECKS):
            continue
        name = cid.removeprefix(PREFIX)
        register(cid, 'azure', declaration['category'], declaration['kind'], declaration['title'], declaration['severity'],
                 'security_configuration', declaration['remediation'], dependencies=declaration['dependencies'])(globals()[name])
        CASES[cid] = fixtures.get(cid, {})
