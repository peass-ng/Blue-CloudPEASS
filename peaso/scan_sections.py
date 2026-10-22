"""Data dependencies and durable completion markers for independent UI sections."""
from collections import defaultdict

SECTIONS = ('hardening', 'exposure', 'least_privilege', 'network', 'privesc', 'leaks', 'images')


def section_for(check):
    identifier, kind = check.id.lower(), check.kind.lower()
    if 'image' in kind and any(word in kind for word in ('vulnerabil', 'cve')):
        return 'images'
    if ('secret_indicators' in identifier or identifier == 'aws_cis_ec2_userdata_embedded_secrets'):
        return 'leaks'
    return check.category if check.category in SECTIONS else 'hardening'


def dependencies(native, analyzed, requirements, privesc, planned):
    needed = defaultdict(set)
    for check in native:
        needed[section_for(check)].update({check.kind} | set(check.dependencies))
    for check in analyzed:
        section = check['category']
        if section in SECTIONS:
            needed[section].update(requirements.get(section, ()))
    for section in ('network', 'least_privilege'):
        if section in requirements:
            needed[section].update(requirements[section])
    if privesc is not None:
        needed['privesc'].update(privesc)
    return {section: needed[section] & set(planned) for section in SECTIONS}


def states(provider, scopes, needed, collections, revisions, *, finished=False, global_types=(), global_scope=None):
    """A section completes only after all of its expected reads have settled.

    Completion describes execution, not success: denied/partial evidence keeps
    its native status. Dynamic scope discovery remains running until sealed.
    """
    explicit = bool(scopes) and all(isinstance(scope, str) and (scope not in ('*', '/') or provider == 'k8s') for scope in scopes)
    out = {}
    for section, kinds in needed.items():
        if not kinds:
            out[section] = {'status': 'not_selected', 'data_revision': 0}
            continue
        expected = set()
        if explicit:
            for kind in kinds:
                for scope in scopes:
                    if provider == 'aws' and kind in global_types:
                        scope = scope.split('/', 1)[0] + '/global'
                    elif kind in global_types and provider in ('k8s', 'azure'):
                        scope = global_scope or scopes[0]
                    expected.add((kind, scope))
        observed = {key for key in collections if key[0] in kinds}
        complete = finished or bool(expected) and expected <= set(collections)
        revision = max((revisions.get(key, 0) for key in observed), default=0)
        out[section] = {'status': 'complete' if complete else 'running', 'data_revision': revision,
                        'completed_collections': len(observed & expected) if expected else len(observed),
                        'expected_collections': len(expected) if expected else None}
    return out
