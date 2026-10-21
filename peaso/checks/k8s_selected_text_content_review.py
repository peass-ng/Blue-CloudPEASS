"""Conservative consumer for the optional selected text reader proposal."""
from types import FunctionType
from copy import deepcopy
import re
from peaso.checks import k8s_literal_secret_review_20261020 as base
from peaso.collectors import k8s_selected_text_content as source

_GLOBALS = {**vars(base), '__name__': __name__, 'KIND': source.KIND,
            'CHECK': source.CHECK, 'MARKER': source.MARKER,
            'SCHEMA': source.SCHEMA, 'NATIVE_KINDS': source.NATIVE_KINDS}
_original = getattr(base, '_evaluate_legacy', base.evaluate)
_evaluate = FunctionType(_original.__code__, _GLOBALS, '_evaluate',
                         _original.__defaults__, _original.__closure__)


def _bounded_partial_hit(item, index):
    try:
        scope = index['context']['scope']
        own, = [row for row in index['collections'][source.KIND] if row.get('scope') == scope]
        selected = index['context']['metadata'][source.KIND + '_selection'][scope]
        ids = [row.get('id') for row in own['items']]
        if (own.get('status') != 'partial' or own.get('error', {}).get('code') != 'resource_limit'
                or not isinstance(selected, list) or not 1 <= len(selected) <= 8
                or len(set(selected)) != len(selected)
                or any(not isinstance(value, str) or not re.fullmatch(source.KIND + ':[0-9a-f]{64}', value)
                       for value in selected)
                or not 1 <= len(ids) < len(selected) or len(set(ids)) != len(ids)
                or not set(ids) < set(selected) or sum(row == item for row in own['items']) != 1):
            return None
        projected = deepcopy(index)
        projected['context']['metadata'][source.KIND + '_selection'][scope] = ids
        result = _evaluate(item, projected)
        return result if result[0] == 'FAIL' and result[1].get('complete') is False else None
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def evaluate(item, index):
    status, evidence = _evaluate(item, index)
    if status == 'UNKNOWN':
        partial = _bounded_partial_hit(item, index)
        if partial is not None:
            status, evidence = partial
    if status == 'FAIL':
        evidence['observed'] = ('A likely secret was found in a selected Kubernetes text field.\n'
            'Its value is hidden and was not validated.\n'
            'Someone with access to that field could see the value.')
        if evidence.get('complete') is False:
            evidence['observed'] += '\nOther selected objects were not fully read.'
    elif status == 'PASS':
        evidence['observed'] = ('The selected Kubernetes text fields held no secret recognized by either offline detector.\n'
            'Those fields came from the named objects at their recorded versions.\n'
            'Other fields may still hold sensitive values.')
    else:
        evidence = {'observed': ('The selected text or its recorded UID and resourceVersion were unavailable or inconsistent.\n'
            'The value stored in that field is unclear.\n'
            'It could contain a secret.')}
    return status, evidence


def install():
    from peaso.checks import CHECKS, register
    if any(check.id == source.CHECK for check in CHECKS):
        return
    from .provider_content_native_cases_20261021 import native_case
    from .fixtures import CASES
    case = native_case(source.CHECK)
    register(source.CHECK, 'k8s', 'hardening', source.KIND,
             'Selected Kubernetes text fields have no detected secrets', 'high',
             'security_configuration',
             'Remove confirmed credential values from selected text fields and rotate them.',
             dependencies=[source.KIND], allow_incomplete_failure=True)(evaluate)

    CASES[source.CHECK] = case
