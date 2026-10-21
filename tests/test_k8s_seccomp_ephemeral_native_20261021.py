"""Isolated exact-AST regression while the root's unrelated source epoch blocks imports."""
import ast
from pathlib import Path

import pytest


from peaso.checks.compliance_new_k8s import _runtime_seccomp
from peaso.checks.facts import Unavailable


def pod(ephemeral=None, *, os_name='linux', inherited='RuntimeDefault'):
    spec = {'os': {'name': os_name}, 'securityContext': {'seccompProfile': {'type': inherited}},
            'containers': [{'name': 'main'}]}
    if ephemeral is not None:
        spec['ephemeralContainers'] = ephemeral
    return {'spec': spec}


def test_ephemeral_unconfined_changes_false_pass_to_fail():
    item = pod([{'name': 'debug', 'securityContext': {'seccompProfile': {'type': 'Unconfined'}}}])
    assert _runtime_seccomp(item, 'pod') == ('FAIL', {'non_runtime_default': [
        {'container': 'debug', 'effective_profile': 'Unconfined'}],
        'semantics': 'Pod/container declaration, not runtime enforcement'})


def test_ephemeral_inheritance_and_incomplete_fields():
    evaluate, unavailable = _runtime_seccomp, Unavailable
    assert evaluate(pod([{'name': 'debug'}]), 'pod')[0] == 'PASS'
    assert evaluate(pod([{'name': 'debug'}], inherited='Localhost'), 'pod')[0] == 'FAIL'
    assert evaluate(pod([{'name': 'debug'}], inherited=None), 'pod')[0] == 'UNKNOWN'
    assert evaluate(pod([{'name': 'debug'}], os_name='windows'), 'pod')[0] == 'NOT_APPLICABLE'
    with pytest.raises(unavailable):
        evaluate(pod([{'name': 'debug'}, 'malformed']), 'pod')
