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
    """Calculate all section watermarks from one pass over settled read keys.

    Completion describes execution, not success: denied/partial evidence keeps
    its native status. Dynamic scope discovery remains running until sealed.
    """
    explicit = bool(scopes) and all(isinstance(scope, str) and (scope not in ('*', '/') or provider == 'k8s') for scope in scopes)
    groups = {section: set(kinds) if kinds else set() for section, kinds in needed.items()}
    kinds = set().union(*groups.values())
    expected_scopes = set(scopes) if explicit else set()
    if explicit and provider == 'aws':
        global_scopes = {scope.split('/', 1)[0] + '/global' for scope in scopes}
    elif explicit and provider in ('k8s', 'azure'):
        global_scopes = {global_scope or scopes[0]}
    else:
        global_scopes = expected_scopes
    scopes_by_kind = {kind: global_scopes if kind in global_types else expected_scopes for kind in kinds}
    # Kinds partition keys, so per-kind counts can be added without materializing
    # a cross product or repeatedly rebuilding all collection-key sets.
    observed = {}
    if kinds:
        for key in collections:
            kind = key[0]
            if kind not in kinds:
                continue
            revision = revisions.get(key, 0)
            stats = observed.get(kind)
            if stats is None:
                stats = observed[kind] = [0, revision, 0]
            stats[0] += 1
            if revision > stats[1]:
                stats[1] = revision
            if isinstance(key, tuple) and len(key) == 2 and key[1] in scopes_by_kind[kind]:
                stats[2] += 1
    out = {}
    for section, kinds in groups.items():
        if not kinds:
            out[section] = {'status': 'not_selected', 'data_revision': 0}
            continue
        expected = completed = count = 0
        revision = None
        for kind in kinds:
            expected += len(scopes_by_kind[kind])
            stats = observed.get(kind)
            if stats is not None:
                count += stats[0]
                completed += stats[2]
                revision = stats[1] if revision is None else max(revision, stats[1])
        complete = finished or bool(expected) and completed == expected
        out[section] = {'status': 'complete' if complete else 'running',
                        'data_revision': revision if revision is not None else 0,
                        'completed_collections': completed if expected else count,
                        'expected_collections': expected if expected else None}
    return out
