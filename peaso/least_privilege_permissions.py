"""Resolve complete collected high-impact grants and correctly scoped usage facts."""
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import re

from peaso.analysis.common import as_list, native_id
from peaso.analysis.iam import grants, permission_severity
from peaso.principal_exposure import canonical, RANK, _cluster


def _date(value):
    try:
        result = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except (ValueError, TypeError):
        return None


def _label(row):
    data = row.get('data', {})
    return str(data.get('RoleName') or data.get('UserName') or data.get('PolicyName') or data.get('GroupName')
        or data.get('displayName') or data.get('name') or data.get('Name')
        or data.get('FunctionName') or data.get('taskArn') or data.get('InstanceId')
        or data.get('metadata', {}).get('name') or row.get('native_id') or native_id(row))


def enrich(card, provider, resources, observed_at):
    """Never expand wildcards or infer individual action usage from service activity."""
    rows = [{**r, 'provider': provider} for r in resources if isinstance(r.get('data'), dict)]
    target = card['principal']
    now = _date(observed_at)
    permissions, unresolved = [], []
    principal_rows = []

    def same(value):
        return canonical(provider, value) == canonical(provider, target)

    def append(permission, severity, row, *, scope=None, source=None, resources=None, conditions=None, exclusions=None, usage_row=None):
        if severity not in {'high', 'critical'}:
            return
        entry = dict(permission=str(permission), severity=severity, scope=scope or row.get('scope', ''),
            source=source or _label(row), resources=resources or [], conditions=conditions, exclusions=exclusions or [])
        if usage_row is not None:
            services = usage_row['data'].get('ServicesLastAccessed', [])
            state = usage_row['data'].get('ServicesLastAccessedStatus', {})
            if state.get('collection_status') == 'collected':
                service = next((s for s in services if s.get('ServiceNamespace') == str(permission).split(':')[0]), None)
                if service and service.get('LastAuthenticated'):
                    entry.update(last_accessed=service['LastAuthenticated'], usage_basis='service')
        # Only an exact per-action provider observation can describe action usage.
        exact = [s for s in card.get('suggestions', []) if s.get('kind') == 'permission'
                 and s.get('value', '').casefold() == str(permission).casefold()
                 and s.get('confidence') == 'provider_recommendation' and s.get('last_accessed')]
        if exact:
            latest = max((_date(s['last_accessed']) for s in exact), default=None, key=lambda d: d or datetime.min.replace(tzinfo=timezone.utc))
            if latest:
                entry.update(last_accessed=latest.isoformat(), usage_basis='permission')
        accessed = _date(entry.get('last_accessed'))
        if now and accessed and accessed <= now:
            entry['days_since_last_access'] = (now - accessed).days
        else:
            for key in ('last_accessed', 'usage_basis'):
                entry.pop(key, None)
        if entry not in permissions:
            permissions.append(entry)

    def declared(row, *, source=None, scope=None, usage_row=None, extra_conditions=None):
        for grant in grants(row):
            if not grant.get('allowed_declaration'):
                continue
            native = grant.get('native_grant')
            grant_source = source or _label(row)
            inline = re.match(r'(UserPolicyList|RolePolicyList|GroupPolicyList|PolicySources)\[(\d+)\]', grant.get('path', ''))
            if inline:
                item = row['data'].get(inline[1], [])[int(inline[2])]
                name = item.get('PolicyName') or item.get('PolicyArn') or item.get('name')
                if name:
                    grant_source += ' → ' + str(name)
            if provider == 'aws' and isinstance(native, dict):
                if native.get('NotAction'):
                    append('All actions except ' + ', '.join(as_list(native['NotAction'])), grant['severity'], row,
                        scope=scope, source=grant_source, resources=as_list(native.get('Resource')),
                        conditions=native.get('Condition'), exclusions=as_list(native.get('NotResource')), usage_row=usage_row)
                for action in as_list(native.get('Action')):
                    if not isinstance(action, str):
                        continue
                    severity = permission_severity(provider, action) or ('high' if '*' in action else 'info')
                    append(action, severity, row, scope=scope, source=grant_source, resources=as_list(native.get('Resource')),
                        conditions=native.get('Condition'), exclusions=as_list(native.get('NotResource')), usage_row=usage_row)
            elif provider == 'gcp' and isinstance(native, str):
                append(native, grant['severity'], row, scope=scope, source=grant_source, conditions=extra_conditions)
            elif provider == 'azure' and isinstance(native, dict):
                for key, exclusion in (('actions', 'notActions'), ('dataActions', 'notDataActions')):
                    for action in as_list(native.get(key)):
                        if not isinstance(action, str) or any(fnmatchcase(action.lower(), str(x).lower()) for x in as_list(native.get(exclusion))):
                            continue
                        append(action, permission_severity(provider, action) or ('high' if '*' in action else 'info'), row,
                            scope=scope, source=grant_source, conditions=extra_conditions,
                            exclusions=as_list(native.get(exclusion)))
            elif provider == 'k8s' and isinstance(native, dict):
                from bluepeass.k8s_risks import PermissionKey, classify_permission
                for verb in as_list(native.get('verbs')):
                    for group in as_list(native.get('apiGroups', [''])):
                        for resource in as_list(native.get('resources')):
                            base, _, sub = resource.partition('/')
                            level, _ = classify_permission(PermissionKey(verb, group=group, resource=base,
                                subresource=sub, namespace=row['data'].get('metadata', {}).get('namespace', '')))
                            append(f'{verb} {group or "core"}/{resource}', level, row, scope=scope, source=grant_source,
                                resources=as_list(native.get('resourceNames')))
                    for url in as_list(native.get('nonResourceURLs')):
                        append(f'{verb} {url}', grant['severity'], row, scope=scope, source=grant_source)

    if provider == 'aws':
        account = target.split(':')[4] if target.startswith('arn:') and len(target.split(':')) > 4 else None
        scoped = [r for r in rows if account and r.get('scope', '').split('/')[0] == account]
        policies = {r['data'].get('Arn'): r for r in scoped if r['type'] == 'iam_policy'}
        groups = {r['data'].get('GroupName'): r for r in scoped if r['type'] == 'iam_group'}
        principal_rows = [r for r in scoped if r['type'] in {'iam_user', 'iam_role', 'iam_group'} and r['data'].get('Arn') == target]
        for principal in principal_rows:
            sources = [principal]
            sources.extend(groups[name] for name in as_list(principal['data'].get('GroupList')) if name in groups)
            for source in sources:
                declared(source, source=_label(source), usage_row=principal)
                for ref in source['data'].get('AttachedManagedPolicies', []):
                    policy = policies.get(ref.get('PolicyArn'))
                    if policy:
                        declared(policy, scope=source.get('scope'), source=f'{_label(source)} → {_label(policy)}', usage_row=principal)
                    else:
                        unresolved.append(ref.get('PolicyArn') or ref.get('PolicyName'))
    elif provider == 'gcp':
        definitions = {r['data'].get('name'): r for r in rows if r['type'] == 'iam_role'}
        for row in rows:
            data = row['data']; policy = data.get('iamPolicy', data.get('policy', data))
            if not isinstance(policy, dict):
                continue
            for binding in policy.get('bindings', []):
                if not any(same(m) for m in binding.get('members', [])):
                    continue
                definition = definitions.get(binding.get('role'))
                if definition:
                    declared(definition, scope=row.get('scope'), source=binding['role'], extra_conditions=binding.get('condition'))
                else:
                    unresolved.append(binding.get('role'))
    elif provider == 'azure':
        definitions = {str(r['data'].get('name', '')).rstrip('/').split('/')[-1].lower(): r for r in rows if r['type'] == 'role_definition'}
        for row in rows:
            props = row['data'].get('properties', {})
            if row['type'] != 'role_assignment' or not same(props.get('principalId')):
                continue
            definition = definitions.get(str(props.get('roleDefinitionId', '')).rstrip('/').split('/')[-1].lower())
            if definition:
                declared(definition, scope=props.get('scope') or row.get('scope'), source=definition['data'].get('properties', {}).get('roleName') or _label(definition), extra_conditions=props.get('condition'))
            else:
                unresolved.append(props.get('roleDefinitionId'))
    elif provider == 'k8s':
        roles = {(_cluster(r), r['type'], r['data'].get('metadata', {}).get('namespace', 'default'), r['data'].get('metadata', {}).get('name')): r
                 for r in rows if r['type'] in {'role', 'clusterrole'}}
        target_cluster = card['id'].split('|', 1)[0] if '|' in card['id'] else None
        for row in rows:
            if row['type'] not in {'rolebinding', 'clusterrolebinding'} or target_cluster and _cluster(row) != target_cluster:
                continue
            data = row['data']; namespace = data.get('metadata', {}).get('namespace', 'default')
            identities = [f"system:serviceaccount:{s.get('namespace', namespace)}:{s.get('name')}" if s.get('kind') == 'ServiceAccount' else s.get('name') for s in data.get('subjects', [])]
            if target not in identities:
                continue
            ref = data.get('roleRef', {}); kind = str(ref.get('kind', '')).lower()
            definition = roles.get((_cluster(row), kind, namespace if kind == 'role' else 'default', ref.get('name')))
            if definition:
                declared(definition, scope=row.get('scope'), source=f"{ref.get('kind')} {ref.get('name')}")
            else:
                unresolved.append(ref.get('name'))

    labels = {r['id']: _label(r) for r in rows if r.get('id')}
    exposures = []
    for entry in card.get('exposures', []):
        current = dict(entry)
        for field in ('resource', 'workload_resource', 'endpoint_resource'):
            key = 'resource_id' if field == 'resource' else field
            if current.get(key) in labels:
                current[field + '_label'] = labels[current[key]]
        exposures.append(current)
    identity_last_used = next((r['data'].get('RoleLastUsed', {}).get('LastUsedDate') for r in principal_rows if r['data'].get('RoleLastUsed', {}).get('LastUsedDate')), None)
    return dict(card, high_risk_permissions=sorted(permissions, key=lambda p: (RANK[p['severity']], p['permission'], p['scope'], p['source'])),
        permission_definitions_missing=sorted({str(x) for x in unresolved if x}), exposures=exposures,
        observed_at=observed_at, identity_last_used=identity_last_used)


def include_resolved_principals(provider, rows, cards):
    """Keep inherited AWS grants and collected GCP custom roles in the principal list."""
    from peaso.principal_exposure import increased

    def add(identity, source, definitions, label=None):
        levels = [grant['severity'] for definition in definitions for grant in grants(definition)
                  if grant.get('allowed_declaration') and grant.get('severity') in {'high', 'critical'}]
        if not identity or not levels:
            return
        key = canonical(provider, identity)
        item = cards.setdefault(key, dict(principal=identity, label=label or identity, scopes=[], exposures=[],
            base_severity='info', grant_reviews=[]))
        item['base_severity'] = min([item['base_severity'], *levels], key=RANK.get)
        item['severity'] = increased(item['base_severity'], item['exposures'])
        if source.get('scope', '') not in item['scopes']:
            item['scopes'].append(source.get('scope', ''))
        review = {'resource_id': source.get('id'), 'scope': source.get('scope', '')}
        if review not in item['grant_reviews']:
            item['grant_reviews'].append(review)

    if provider == 'aws':
        groups = {(r.get('scope', '').split('/')[0], r['data'].get('GroupName')): r for r in rows if r['type'] == 'iam_group'}
        policies = {(r.get('scope', '').split('/')[0], r['data'].get('Arn')): r for r in rows if r['type'] == 'iam_policy'}
        for row in rows:
            if row['type'] != 'iam_user':
                continue
            account = row.get('scope', '').split('/')[0]
            for name in row['data'].get('GroupList', []):
                group = groups.get((account, name))
                if group:
                    definitions = [group, *[policies[(account, p.get('PolicyArn'))] for p in group['data'].get('AttachedManagedPolicies', []) if (account, p.get('PolicyArn')) in policies]]
                    add(row['data'].get('Arn'), row, definitions, row['data'].get('UserName'))
    elif provider == 'gcp':
        roles = {r['data'].get('name'): r for r in rows if r['type'] == 'iam_role'}
        for row in rows:
            data = row['data']; policy = data.get('iamPolicy', data.get('policy', data))
            if not isinstance(policy, dict):
                continue
            for binding in policy.get('bindings', []):
                definition = roles.get(binding.get('role'))
                if definition:
                    for member in binding.get('members', []):
                        add(member, row, [definition])
    return cards
