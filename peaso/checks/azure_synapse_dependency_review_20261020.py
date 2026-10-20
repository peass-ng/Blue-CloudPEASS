"""Exact dependency successor; preserve the signed Synapse predicate and fixtures."""
from dataclasses import replace
import hashlib
import inspect

CHECK_ID = 'azure_pci_1_3_1_33'
BEFORE = ('synapse_workspace',)
AFTER = (*BEFORE, 'synapse_sql_private_endpoint_evidence')
PREDICATE_SHA256 = '6cee45b578932bab87fc4876f00b7e1b4067761d6177a679c3711dc1726de12a'


def reviewed_check(check):
    if (check.id != CHECK_ID or check.provider != 'azure' or check.kind != 'synapse_workspace'
            or check.target != 'resource' or check.declared_dependencies not in (BEFORE, AFTER)):
        raise ValueError('Reviewed Synapse dependency predecessor changed')
    try:
        source = inspect.getsource(check.evaluate)
    except (OSError, TypeError) as exc:
        raise ValueError('Reviewed Synapse predicate source unavailable') from exc
    if hashlib.sha256(source.encode()).hexdigest() != PREDICATE_SHA256:
        raise ValueError('Reviewed Synapse predicate source changed')
    return replace(check, declared_dependencies=AFTER)


def install():
    from . import CHECKS
    matches = [position for position, check in enumerate(CHECKS) if check.id == CHECK_ID]
    if len(matches) != 1:
        raise ValueError('Reviewed Synapse dependency target is missing or ambiguous')
    position = matches[0]
    CHECKS[position] = reviewed_check(CHECKS[position])
