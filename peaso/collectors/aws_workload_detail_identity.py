"""Bind workload detail responses to their requested resource identities."""
import re


def bind_workload_details(kind, items, account, region, partition):
    """Discard unbound detail payloads before consumers can claim their settings.

    Call after all ENRICHERS, before Lambda documented-omission normalization.
    This deliberately does not certify parent inventory or auxiliary joins.
    """
    recipes = {
        'codebuild_project': ('Configuration', 'projects', 'name', 'name', 'arn', 'codebuild', 'project/'),
        'ecs_task_definition': ('Definition', 'taskDefinition', 'taskDefinitionArn', 'taskDefinitionArn', 'taskDefinitionArn', 'ecs', 'task-definition/'),
        'ecs_cluster': ('Configuration', 'clusters', 'clusterArn', 'clusterArn', 'clusterArn', 'ecs', 'cluster/'),
        'eks_cluster': ('Cluster', 'cluster', 'name', 'name', 'arn', 'eks', 'cluster/'),
    }
    if kind not in recipes:
        return items
    wrapper, member, outer_key, name_key, arn_key, service, prefix = recipes[kind]
    base = f'arn:{partition}:{service}:{region}:{account}:'
    for item in items:
        detail = item.get(wrapper)
        if not isinstance(detail, dict) or detail.get('collection_status') != 'collected':
            continue
        native = detail if member is None else detail.get(member)
        valid = not detail.get('failures') and not detail.get('projectsNotFound')
        if member in {'projects', 'clusters'}:
            valid = valid and isinstance(native, list) and len(native) == 1
            native = native[0] if valid else None
        valid = valid and isinstance(native, dict)
        identity = item.get(outer_key)
        if kind in {'ecs_task_definition', 'ecs_cluster'}:
            pattern = re.escape(base + prefix) + (r'[A-Za-z0-9_-]+:[1-9][0-9]*' if kind == 'ecs_task_definition' else r'[A-Za-z0-9_-]+')
            valid = valid and isinstance(identity, str) and re.fullmatch(pattern, identity) is not None
            valid = valid and native.get(arn_key) == identity
        else:
            pattern = r'[A-Za-z0-9][A-Za-z0-9_-]{0,254}'
            valid = valid and isinstance(identity, str) and re.fullmatch(pattern, identity) is not None
            valid = valid and native.get(name_key) == identity and native.get(arn_key) == base + prefix + identity
        if not valid:
            item[wrapper] = {'collection_status': 'malformed', 'error': {'code': kind + '_detail_identity_mismatch'}}
    return items
