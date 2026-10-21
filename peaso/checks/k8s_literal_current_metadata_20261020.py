"""Source-bound current workload literal metadata; signed predecessors stay intact.

Root installs this distinct title/remediation hook after the original install and
admits CURRENT_FIELDS through the existing canonical native-extension path.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import inspect
import json
from . import k8s_literal_secret_review_20261020 as predecessor

CHECK = 'k8s.review.selected_literals.secret_indicators'
PREDICATE_SHA256 = '6a825cbbe6e1b0efe3df29b5e81443eb00ea3cb7636e3b5995227daba0639c8c'
CURRENT_DISPATCH_SHA256 = 'c42632fbf8fcbcb1592ba32b00be44ca8135c6c6d1fec833430eb03cdb4d201b'
DECLARATIONS_SHA256 = '19c6043989b98d3d9efd6af62964c1afaf8a352e4f87a4af203bea1b7a6bc706'
CURRENT_FIELDS = {
    'title': 'Selected workload and ConfigMap literals have no detected secrets',
    'description': 'Inspect literal environment values, command and args in exact selected Kubernetes workload PodSpecs and text data in ConfigMaps using both offline detectors. Controllers are assessed through their current templates; running replicas and referenced content are outside coverage.',
    'finding_type': 'secrets', 'ui_group': 'Secrets', 'requirement_controls': [],
    'supported_kinds': ['Pod', 'ConfigMap', 'Deployment', 'DaemonSet', 'StatefulSet', 'ReplicaSet',
        'Job', 'CronJob', 'ReplicationController', 'PodTemplate'],
    'evaluated': ['Exact selected GVK, cluster, namespace, name, UID and resourceVersion across two authenticated named GETs',
        'PodSpec containers/initContainers/ephemeralContainers literal env.value, command and args',
        'Pod spec; apps and Job spec.template.spec; CronJob spec.jobTemplate.spec.template.spec; PodTemplate template.spec',
        'ConfigMap data string values and bounded text binaryData',
        'Both pinned offline engines, HMAC value deduplication and union redaction'],
    'pass_when': 'Both offline detectors complete on the supported identity-bound selected literals without detecting a supported secret indicator.',
    'fail_when': 'A completed offline detector finds a supported secret indicator in fully bound selected literals. Failure remains decisive with incomplete coverage when the other detector is unavailable.',
    'not_applicable_when': 'Disabled, missing, unsupported or incomplete selected content never establishes a clean result.',
    'remediation': 'Remove exposed credential literals from the selected workload specifications or ConfigMaps and rotate confirmed exposed credentials. Use supported secret references or workload identities.',
    'purpose': 'Named selected current declarations only, including controller templates. No Secret payloads, reference resolution, execution, effective runtime state, credential verification or entire-cluster coverage.',
    'observation_subject': 'selected workload and ConfigMap literals',
}


def fields():
    """Return a fresh exact canonical proposal only after the source guard passes."""
    fn = inspect.unwrap(predecessor.evaluate)
    body = inspect.getsource(fn)
    historical = inspect.getsource(predecessor._evaluate_legacy)
    if historical.count('def _evaluate_legacy(') != 1:
        raise ValueError('Kubernetes literal metadata predecessor changed')
    historical = historical.replace('def _evaluate_legacy(', 'def evaluate(', 1)
    declarations = json.dumps(predecessor.DECLARATIONS, sort_keys=True, separators=(',', ':'))
    if (hashlib.sha256(historical.encode()).hexdigest() != PREDICATE_SHA256
            or hashlib.sha256(body.encode()).hexdigest() != CURRENT_DISPATCH_SHA256
            or hashlib.sha256(declarations.encode()).hexdigest() != DECLARATIONS_SHA256):
        raise ValueError('Kubernetes literal metadata predecessor changed')
    return deepcopy(CURRENT_FIELDS)


def install():
    """Distinct root-owned registry hook: presentation fields only, no CASES edits."""
    from . import CHECKS
    current = fields()
    positions = [i for i, check in enumerate(CHECKS) if check.id == CHECK]
    if len(positions) != 1:
        raise ValueError('Kubernetes literal check is not uniquely registered')
    position, = positions
    check = CHECKS[position]
    if (check.kind != predecessor.KIND or inspect.unwrap(check.evaluate) is not inspect.unwrap(predecessor.evaluate)
            or check.title not in (predecessor.DECLARATIONS[0]['title'], current['title'])
            or check.remediation not in (predecessor.DECLARATIONS[0]['remediation'], current['remediation'])):
        raise ValueError('Kubernetes literal registered predecessor changed')
    CHECKS[position] = replace(check, title=current['title'], remediation=current['remediation'])
