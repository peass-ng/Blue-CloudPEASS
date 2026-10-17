"""Admitted Pod declarations with explicit cluster/namespace and policy bindings."""
from __future__ import annotations

from . import result, unknown
from .facts import Unavailable, get, list_of_objects, optional
from decimal import Decimal, DecimalException
from datetime import timedelta
import re
from .compliance_new_sw25_facts import (
    LIMITS_ID, APPARMOR_ID, IMAGES_ID, _text, _strings, _scope, _policy, _rows,
    _arm, _one, _coverage, _aggregate, _literal, _date, _now,
)

_QUANTITY = re.compile(r'([+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))([eE][+-]?[0-9]+|[numkKMGTPE]|[KMGTPE]i)?')


def _quantity(value):
    if not isinstance(value, str) or not (match := _QUANTITY.fullmatch(value)):
        raise Unavailable('Kubernetes resource quantity malformed')
    factors = {'n': Decimal('1e-9'), 'u': Decimal('1e-6'), 'm': Decimal('1e-3'),
               'k': Decimal(1000), 'K': Decimal(1000), 'M': Decimal(1000)**2,
               'G': Decimal(1000)**3, 'T': Decimal(1000)**4,
               'P': Decimal(1000)**5, 'E': Decimal(1000)**6,
               **{p + 'i': Decimal(1024)**n for n, p in enumerate('KMGTPE', 1)}}
    suffix = match[2] or ''
    try:
        factor = Decimal(10) ** int(suffix[1:]) if suffix.startswith(('e', 'E')) and len(suffix) > 1 else factors.get(suffix, Decimal(1))
        value = Decimal(match[1]) * factor
    except (DecimalException, OverflowError, ValueError) as exc:
        raise Unavailable('Kubernetes resource quantity unresolved') from exc
    if not value.is_finite() or value <= 0:
        raise Unavailable('Kubernetes resource quantity must be positive')
    return value


def _pod_inventory(index, cid):
    policy = _policy(index, cid)
    scope = _one(index, 'kubernetes_scope')
    clusters = list_of_objects(get(scope, 'clusters', list))
    identities = {}
    for cluster in clusters:
        rid = _arm(get(cluster, 'id', str), _scope(index))
        if rid in identities or get(cluster, 'kind', str) not in ('AKS', 'Arc'):
            raise Unavailable('cluster identity/applicability unresolved')
        if cid == APPARMOR_ID and get(cluster, 'kind', str) != 'AKS':
            continue
        _coverage(cluster, 'namespaces'); _coverage(cluster, 'pods')
        identities[rid] = set(_strings(get(cluster, 'namespaces', list)))
    pods = _rows(index, 'pod', identity='metadata.uid')
    found = set()
    for pod in pods:
        rid = _arm(get(pod, '_provenance.cluster_id', str), _scope(index))
        namespace, uid = _text(get(pod, 'metadata.namespace', str)), _text(get(pod, 'metadata.uid', str))
        _text(get(pod, 'metadata.name', str))
        if get(pod, '_provenance.source_operation', str) != 'list_pods' or get(pod, '_provenance.representation', str) != 'full':
            raise Unavailable('Pod full admitted API representation unavailable')
        if rid not in identities or namespace not in identities[rid] or (rid, uid) in found:
            raise Unavailable('foreign/duplicate cluster namespace Pod')
        found.add((rid, uid))
    return policy, pods, identities


def _containers(pod, policy):
    spec = get(pod, 'spec', dict)
    include = _strings(get(policy, 'containerKinds', list))
    allowed = {'containers', 'initContainers', 'ephemeralContainers'}
    if not include or not set(include) <= allowed or 'containers' not in include:
        raise Unavailable('container applicability policy unresolved')
    seen, containers = set(), []
    # Full admitted Pod responses permit documented absent optional arrays.
    for kind in ('containers', 'initContainers', 'ephemeralContainers'):
        rows = list_of_objects(optional(spec, kind, [], list))
        if kind == 'containers' and not rows:
            raise Unavailable('Pod regular container list absent')
        for container in rows:
            name = _text(get(container, 'name', str))
            if name in seen:
                raise Unavailable('duplicate Pod container name')
            seen.add(name)
            if kind in include:
                containers.append((kind, name, container))
    return containers


def _runtime(index, pods):
    facts = _rows(index, 'pod_runtime')
    by_uid = {}
    for fact in facts:
        key = (_arm(get(fact, 'clusterId', str), _scope(index)), _text(get(fact, 'podUid', str)))
        if key in by_uid:
            raise Unavailable('duplicate Pod runtime identity')
        by_uid[key] = fact
    expected = {(_arm(get(p, '_provenance.cluster_id', str), _scope(index)), get(p, 'metadata.uid', str)) for p in pods}
    if set(by_uid) - expected:
        raise Unavailable('runtime facts belong to foreign Pods')
    return by_uid


def _limits(index):
    policy, pods, clusters = _pod_inventory(index, LIMITS_ID)
    maximums = {key: _quantity(get(policy, 'max' + key.capitalize(), str)) for key in ('cpu', 'memory')}
    runtime = _runtime(index, pods)
    ranges = _rows(index, 'limit_range', identity='metadata.uid')
    defaults, range_versions = {}, {}
    for row in ranges:
        cluster = _arm(get(row, '_provenance.cluster_id', str), _scope(index))
        namespace = get(row, 'metadata.namespace', str)
        if cluster not in clusters or namespace not in clusters[cluster]:
            raise Unavailable('foreign namespace LimitRange')
        range_versions.setdefault((cluster, namespace), set()).add((get(row, 'metadata.uid', str), get(row, 'metadata.resourceVersion', str)))
        for entry in list_of_objects(get(row, 'spec.limits', list)):
            kind = get(entry, 'type', str)
            if kind not in ('Container', 'Pod', 'PersistentVolumeClaim'):
                raise Unavailable('unsupported LimitRange type')
            if kind == 'Container':
                default = optional(entry, 'default', {}, dict)
                for resource in ('cpu', 'memory'):
                    if resource in default or resource in default.get('_coverage', {}):
                        defaults.setdefault((cluster, namespace, resource), []).append(_quantity(get(default, resource, str)))
    failures, uncertain, count = [], [], 0
    for pod in pods:
        cluster, uid, namespace = get(pod, '_provenance.cluster_id', str).casefold(), get(pod, 'metadata.uid', str), get(pod, 'metadata.namespace', str)
        try:
            fact = runtime.get((cluster, uid))
            if fact is None or get(fact, 'admissionEffectsResolved', bool) is not True:
                raise Unavailable('admission/LimitRange effects unresolved')
            _coverage(fact, 'limitRangeBindings')
            bindings = list_of_objects(get(fact, 'limitRangeBindings', list))
            bound_versions = {(get(binding, 'uid', str), get(binding, 'resourceVersion', str)) for binding in bindings}
            if len(bindings) != len(bound_versions):
                raise Unavailable('duplicate admission-time LimitRange bindings')
            for kind, name, container in _containers(pod, policy):
                try:
                    resources = optional(container, 'resources', {}, dict)
                    declared = optional(resources, 'limits', {}, dict)
                    values = {}
                    for resource in ('cpu', 'memory'):
                        if resource in declared or resource in declared.get('_coverage', {}):
                            values[resource] = _quantity(get(declared, resource, str))
                        else:
                            if bound_versions != range_versions.get((cluster, namespace), set()):
                                raise Unavailable('current LimitRange defaults not bound to this Pod admission')
                            choices = defaults.get((cluster, namespace, resource), [])
                            if len(set(choices)) > 1:
                                raise Unavailable('multiple effective LimitRange defaults conflict')
                            values[resource] = choices[0] if choices else None
                    count += 1
                    if any(values[r] is None or values[r] > maximums[r] for r in values):
                        failures.append({'podUid': uid, 'container': name, 'kind': kind,
                                         'reason': 'Effective CPU/memory limit absent or exceeds policy maximum'})
                except Unavailable as exc:
                    uncertain.append({'podUid': uid, 'container': name, 'kind': kind, 'reason': str(exc)})
        except Unavailable as exc:
            uncertain.append({'podUid': uid, 'reason': str(exc)})
    return _aggregate(failures, uncertain, assessed_container_count=count)


def _profile(profile):
    kind = get(profile, 'type', str)
    if kind not in ('RuntimeDefault', 'Localhost', 'Unconfined'):
        raise Unavailable('unrecognized AppArmor type')
    local = _text(get(profile, 'localhostProfile', str)) if kind == 'Localhost' else None
    if local is not None and '\x00' in local:
        raise Unavailable('Localhost AppArmor profile unresolved')
    return kind, local


def _apparmor_proof(proof, index, operation):
    """Bind an explicitly external read to this capture and snapshot time."""
    if (get(proof, 'sourceOperation', str) != operation
            or get(proof, 'readOnly', bool) is not True):
        raise Unavailable('independent AppArmor observation source unresolved')
    _text(get(proof, 'observer', str))
    _text(get(proof, 'sourceDocumentId', str))
    metadata = get(index, 'context.metadata', dict)
    for field in ('credential_context_id', 'customer_context_id'):
        if _text(get(proof, field, str)) != _text(get(metadata, field, str)):
            raise Unavailable('AppArmor runtime observation capture mismatch')
    age = _now(index) - _date(get(proof, 'observedAt', str))
    if not timedelta(0) <= age <= timedelta(minutes=15):
        raise Unavailable('AppArmor runtime observation stale or future')


def _apparmor_effective(index, pod, fact, containers):
    """External host measurements; native admitted Pod fields never imply these."""
    node = get(fact, 'appArmorNodeEvidence', dict)
    _apparmor_proof(node, index, 'external_node_runtime_read')
    cluster = _arm(get(pod, '_provenance.cluster_id', str), _scope(index))
    uid = _text(get(pod, 'metadata.uid', str))
    node_name = _text(get(pod, 'spec.nodeName', str))
    node_uid = _text(get(node, 'nodeUid', str))
    if (_arm(get(node, 'clusterId', str), _scope(index)) != cluster
            or get(node, 'podUid', str) != uid
            or get(node, 'nodeName', str) != node_name):
        raise Unavailable('AppArmor measured node/Pod identity mismatch')
    os = get(node, 'nodeOs', str)
    if os not in ('linux', 'windows'):
        raise Unavailable('unsupported measured node OS')
    if os != 'linux':
        return node, {}
    if get(node, 'appArmorEnabled', bool) is not True:
        raise Unavailable('Linux node AppArmor support unavailable')
    rows = list_of_objects(get(fact, 'appArmorProfiles', list))
    observed = {}
    for row in rows:
        _apparmor_proof(row, index, 'external_container_kernel_profile_read')
        kind, name = get(row, 'containerKind', str), _text(get(row, 'containerName', str))
        key = (kind, name)
        if (key in observed or kind not in ('containers', 'initContainers', 'ephemeralContainers')
                or _arm(get(row, 'clusterId', str), _scope(index)) != cluster
                or get(row, 'podUid', str) != uid
                or get(row, 'nodeName', str) != node_name
                or get(row, 'nodeUid', str) != node_uid):
            raise Unavailable('ambiguous or foreign applied AppArmor profile')
        observed[key] = row
    expected = {(kind, name) for kind, name, _ in containers}
    if set(observed) != expected:
        raise Unavailable('applied AppArmor profile inventory incomplete or foreign')
    status = get(pod, 'status', dict)
    status_names = {'containers': 'containerStatuses', 'initContainers': 'initContainerStatuses',
                    'ephemeralContainers': 'ephemeralContainerStatuses'}
    for kind, name, _ in containers:
        statuses = list_of_objects(get(status, status_names[kind], list))
        matches = [row for row in statuses if get(row, 'name', str) == name]
        if len(matches) != 1:
            raise Unavailable('applied AppArmor profile container ID mismatch')
        status_id = _text(get(matches[0], 'containerID', str))
        observed_id = _text(get(observed[(kind, name)], 'containerId', str))
        if status_id != observed_id:
            raise Unavailable('applied AppArmor profile container ID mismatch')
    return node, observed


def _apparmor_actual(profile, node, evidence):
    """Use measured kernel profile/mode and explicit runtime resolution."""
    actual = get(evidence, 'profileType', str)
    mode = get(evidence, 'enforcementMode', str)
    name = _text(get(evidence, 'appliedProfileName', str))
    if actual not in ('RuntimeDefault', 'Localhost', 'Unconfined') or mode not in ('enforce', 'complain', 'unconfined'):
        raise Unavailable('applied AppArmor profile or mode unrecognized')
    if actual == 'Unconfined' or mode in ('complain', 'unconfined'):
        return False
    if profile[0] != actual:
        return False
    if actual == 'RuntimeDefault':
        # The runtime supplies its actual default name; never guess from a prefix.
        return name == _text(get(node, 'runtimeDefaultProfileName', str))
    return name == get(evidence, 'resolvedLocalhostProfile', str) == profile[1]


def _apparmor(index):
    policy, pods, _ = _pod_inventory(index, APPARMOR_ID)
    allowed = {_profile(p) for p in list_of_objects(get(policy, 'allowedProfiles', list))}
    if not allowed:
        raise Unavailable('AppArmor allowlist absent')
    nonlinux = get(policy, 'nonLinuxApplies', bool)
    runtime = _runtime(index, pods)
    failures, uncertain, count, excluded = [], [], 0, 0
    for pod in pods:
        cluster, uid = get(pod, '_provenance.cluster_id', str).casefold(), get(pod, 'metadata.uid', str)
        try:
            fact = runtime.get((cluster, uid))
            if fact is None:
                raise Unavailable('Pod runtime observation unavailable')
            containers = _containers(pod, policy)
            node, observed = _apparmor_effective(index, pod, fact, containers)
            os = get(node, 'nodeOs', str)
            if os != 'linux':
                if nonlinux:
                    raise Unavailable('non-Linux applicable AppArmor semantics unresolved')
                excluded += 1
                continue
            version = get(node, 'kubernetesVersion', str)
            match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9.-]+)?', version)
            if not match or int(match[1]) != 1:
                raise Unavailable('Kubernetes AppArmor version unsupported')
            minor = int(match[2])
            spec = get(pod, 'spec', dict)
            pod_security = optional(spec, 'securityContext', {}, dict)
            annotations = optional(get(pod, 'metadata', dict), 'annotations', {}, dict)
            for kind, name, container in containers:
                security = optional(container, 'securityContext', {}, dict)
                container_profile = optional(security, 'appArmorProfile', None)
                pod_profile = optional(pod_security, 'appArmorProfile', None)
                annotation_key = 'container.apparmor.security.beta.kubernetes.io/' + name
                annotation = _literal(annotations, annotation_key) if annotation_key in annotations or annotation_key in annotations.get('_coverage', {}) else None
                if minor >= 30:
                    if annotation is not None:
                        raise Unavailable('legacy annotation/structured AppArmor precedence unresolved')
                    profile = _profile(container_profile if container_profile is not None else pod_profile) if container_profile is not None or pod_profile is not None else ('RuntimeDefault', None)
                    if container_profile is None and pod_profile is None and not get(node, 'runtimeDefaultSupported', bool):
                        raise Unavailable('implicit RuntimeDefault not proven supported')
                else:
                    if container_profile is not None or pod_profile is not None or minor < 19:
                        raise Unavailable('legacy AppArmor version/profile semantics unresolved')
                    if annotation == 'runtime/default':
                        profile = ('RuntimeDefault', None)
                    elif annotation == 'unconfined':
                        profile = ('Unconfined', None)
                    elif isinstance(annotation, str) and annotation.startswith('localhost/'):
                        profile = _profile({'type': 'Localhost', 'localhostProfile': annotation[len('localhost/'):]})
                    else:
                        raise Unavailable('legacy AppArmor declaration unresolved')
                count += 1
                actual = observed[(kind, name)]
                if profile not in allowed or not _apparmor_actual(profile, node, actual):
                    failures.append({'podUid': uid, 'container': name, 'kind': kind,
                                     'declaredType': profile[0], 'appliedProfileName': get(actual, 'appliedProfileName', str),
                                     'enforcementMode': get(actual, 'enforcementMode', str)})
        except Unavailable as exc:
            uncertain.append({'podUid': uid, 'reason': str(exc)})
    if pods and excluded == len(pods) and not uncertain:
        return 'NOT_APPLICABLE', {'reason': 'All workloads are non-Linux and explicit policy excludes them'}
    return _aggregate(failures, uncertain, assessed_container_count=count)


def _image(value):
    value = _text(value)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@+-]*', value) or value.count('@') > 1:
        raise Unavailable('image reference malformed')
    reference, _, digest = value.partition('@')
    if digest and not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
        raise Unavailable('unsupported image digest')
    first = reference.split('/')[0]
    registry = first if '.' in first or ':' in first or first == 'localhost' else 'docker.io'
    if '/' not in reference and registry != 'docker.io':
        # nginx:tag is an unqualified docker.io reference, not a host/port.
        registry = 'docker.io'
    if reference.startswith('/') or '//' in reference or '..' in reference.split('/'):
        raise Unavailable('image repository malformed')
    return value, registry.lower(), digest


def _images(index):
    policy, pods, _ = _pod_inventory(index, IMAGES_ID)
    mode = get(policy, 'mode', str)
    if mode not in ('images', 'registries', 'digests'):
        raise Unavailable('image policy mode unresolved')
    approved = set(_strings(get(policy, 'allowed', list)))
    if not approved:
        raise Unavailable('image allowlist absent')
    immutable = get(policy, 'immutableImages', bool)
    approved_bytes = set(_strings(get(policy, 'allowedDigests', list))) if immutable else set()
    if immutable and (not approved_bytes or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', d) for d in approved_bytes)):
        raise Unavailable('immutable image byte allowlist unresolved')
    if mode == 'digests' and any(not re.fullmatch(r'sha256:[a-f0-9]{64}', d) for d in approved):
        raise Unavailable('approved image digest malformed')
    if mode == 'images':
        for image in approved:
            _image(image)
    if mode == 'registries' and any(not re.fullmatch(r'[a-z0-9][a-z0-9.-]*(?::[0-9]+)?', r) for r in approved):
        raise Unavailable('approved registry malformed')
    failures, uncertain, count = [], [], 0
    for pod in pods:
        uid = get(pod, 'metadata.uid', str)
        try:
            status = optional(pod, 'status', {}, dict)
            for kind, name, container in _containers(pod, policy):
                image, registry, digest = _image(get(container, 'image', str))
                disallowed = mode == 'images' and image not in approved or mode == 'registries' and registry not in approved
                if disallowed:
                    failures.append({'podUid': uid, 'container': name, 'image': image})
                    count += 1
                    continue
                if mode == 'digests' or immutable or mode == 'images' and digest:
                    key = {'containers': 'containerStatuses', 'initContainers': 'initContainerStatuses',
                           'ephemeralContainers': 'ephemeralContainerStatuses'}[kind]
                    statuses = list_of_objects(get(status, key, list))
                    names = [get(s, 'name', str) for s in statuses]
                    if len(set(names)) != len(names):
                        raise Unavailable('duplicate runtime container status')
                    matches = [s for s in statuses if get(s, 'name', str) == name]
                    if len(matches) != 1:
                        raise Unavailable('running imageID unresolved')
                    image_id = _text(get(matches[0], 'imageID', str))
                    resolved = re.search(r'(?:@|^|://)(sha256:[a-f0-9]{64})$', image_id)
                    if resolved is None:
                        raise Unavailable('running imageID digest unresolved')
                    if (mode == 'digests' and resolved[1] not in approved
                            or immutable and resolved[1] not in approved_bytes
                            or digest and resolved[1] != digest):
                        failures.append({'podUid': uid, 'container': name, 'reason': 'Resolved running image digest outside policy'})
                count += 1
        except Unavailable as exc:
            uncertain.append({'podUid': uid, 'reason': str(exc)})
    return _aggregate(failures, uncertain, assessed_container_count=count,
                      semantics='Current admitted Pod image declarations and required runtime digests; admission enforcement unassessed')


