"""Atomic admission of explicit selected-content reads; no default grants."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path


def reviewed_inputs():
    root=Path(__file__).resolve().parents[2]
    path=Path(__file__).with_name('aws_selected_configuration_secret_review_20261020_admission.json')
    receipt=json.loads(path.read_text())
    for name,digest in receipt['source_hashes'].items():
        source=(root/name).resolve()
        if not source.is_relative_to(root) or hashlib.sha256(source.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('Selected AWS content source changed')
    fixture=receipt['fixture'];source=(root/fixture['path']).resolve()
    if not source.is_relative_to(root) or hashlib.sha256(source.read_bytes()).hexdigest()!=fixture['sha256']:
        raise RuntimeError('Selected AWS content native fixtures changed')
    from .aws_selected_configuration_secret_review_20261020 import CHECK,evaluate
    cases=json.loads(source.read_text())
    if set(cases)!={CHECK} or not {'pass','fail','unknown','pass_index','fail_index','unknown_index'}<=set(cases[CHECK]):
        raise RuntimeError('Selected AWS content native branches missing')
    for branch in ('pass','fail','unknown'):
        if evaluate(cases[CHECK][branch],cases[CHECK][branch+'_index'])[0]!=branch.upper():
            raise RuntimeError('Selected AWS content native branch changed')
    return cases


def install():
    from . import CHECKS,register
    from .fixtures import CASES
    from . import aws_selected_configuration_secret_review_20261020 as reviewed
    cases=reviewed_inputs()
    old=next((c for c in CHECKS if c.id==reviewed.CHECK),None)
    if old is not None:
        if inspect.unwrap(old.evaluate)is not reviewed.evaluate:
            raise RuntimeError('Selected AWS content registration collision')
        return
    before=tuple(CHECKS);prior=deepcopy(CASES.get(reviewed.CHECK))
    try:
        reviewed.install(register)
        CASES[reviewed.CHECK]=deepcopy(cases[reviewed.CHECK])
    except Exception:
        CHECKS[:]=before
        if prior is None:CASES.pop(reviewed.CHECK,None)
        else:CASES[reviewed.CHECK]=prior
        raise
