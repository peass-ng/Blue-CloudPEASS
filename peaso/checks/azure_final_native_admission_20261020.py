"""Explicit admission boundary for reviewed native Azure successors.

Importing this module has no effect. The coordinator supplies the exact source
and native-fixture receipt together with canonical catalog entries before adding
the single install hook. Historical SW30 code and fixtures remain unchanged.
"""
from copy import deepcopy
from functools import wraps
import hashlib
import importlib
import inspect
import json
from pathlib import Path


def _reviewed_inputs(directory=None):
    directory = Path(directory or Path(__file__).resolve().parent).resolve()
    root = directory.parents[1]
    receipt = json.loads((directory / 'azure_final_native_admission_20261020.json').read_text())
    if receipt.get('schema_version') != 1:
        raise RuntimeError('Unrecognized native Azure admission receipt')
    for source in receipt['sources']:
        path = (root / source['path']).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != source['sha256']:
            raise RuntimeError('Native Azure admission source differs from its review')
    fixture = receipt['fixtures']
    fixture_path = (root / fixture['path']).resolve()
    if not fixture_path.is_relative_to(directory):
        raise RuntimeError('Native Azure admission fixture path is invalid')
    raw = fixture_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != fixture['sha256']:
        raise RuntimeError('Native Azure admission fixtures differ from their review')
    cases = json.loads(raw)
    if set(cases) != set(receipt['new_check_ids']) or any(
        not isinstance(row, dict) or not {
            'pass', 'pass_index', 'fail', 'fail_index', 'unknown', 'unknown_index'
        } <= set(row) for row in cases.values()
    ):
        raise RuntimeError('Native Azure admission fixtures are incomplete')
    return receipt, cases


def _declarations():
    aks = importlib.import_module('.azure_aks_legacy_projection_review_20261020', __package__)
    hsm = importlib.import_module('.azure_hsm_audit_destination_review_20261020', __package__)
    encryption = importlib.import_module('.azure_native_contract_closure_20261020', __package__)
    declarations = [(aks.DECLARATIONS[0], aks.diagnostic_declaration),
                    (hsm.DECLARATIONS[0], hsm.evaluate)]
    for proposal in encryption.PROPOSALS:
        # Encryption is the existing presentation group, not a registry category.
        metadata = {**proposal, 'category': 'hardening', 'finding_type': 'encryption',
                    'ui_group': 'Encryption', 'requirements': []}
        declarations.append((metadata, proposal['evaluate']))
    return aks, declarations


def _display_result(function, check_id):
    @wraps(function)
    def evaluate(item, index):
        status, evidence = function(item, index)
        if status in ('PASS', 'FAIL'):
            evidence = {**evidence, 'native_declaration_id': check_id,
                        'native_declaration_satisfied': status == 'PASS',
                        'effective_access': 'not_tested'}
        return status, evidence
    evaluate._native_final_admission_20261020 = check_id
    return evaluate


def install():
    """Install only the exact source-reviewed declarations and SW30 bridges."""
    from . import CHECKS, register
    from .fixtures import CASES

    receipt, cases = _reviewed_inputs()
    aks, declarations = _declarations()
    declared_ids = [metadata['id'] for metadata, _ in declarations]
    if len(set(declared_ids)) != len(declared_ids) or set(declared_ids) != set(receipt['new_check_ids']):
        raise RuntimeError('Native Azure declarations do not match their admission')
    before = tuple(CHECKS)
    previous_originals = dict(aks._ORIGINALS)
    previous_cases = {ident: deepcopy(CASES[ident]) for ident in cases if ident in CASES}
    try:
        aks.install_successors()
        for metadata, function in declarations:
            ident = metadata['id']
            existing = next((check for check in CHECKS if check.id == ident), None)
            if existing is not None:
                if (inspect.unwrap(existing.evaluate) is not inspect.unwrap(function)
                        or getattr(existing.evaluate, '_native_final_admission_20261020', None) != ident):
                    raise RuntimeError('Native Azure admission overlaps another evaluator')
                continue
            hint = metadata['remediation']
            if isinstance(hint, (tuple, list)):
                hint = ' '.join(hint)
            register(ident, 'azure', metadata['category'], metadata['kind'],
                     metadata['title'], metadata['severity'], 'security_configuration', hint,
                     dependencies=metadata['dependencies'])(_display_result(function, ident))
            CASES[ident] = deepcopy(cases[ident])
    except Exception:
        CHECKS[:] = before
        aks._ORIGINALS.clear()
        aks._ORIGINALS.update(previous_originals)
        for ident in cases:
            if ident in previous_cases:
                CASES[ident] = previous_cases[ident]
            else:
                CASES.pop(ident, None)
        raise
