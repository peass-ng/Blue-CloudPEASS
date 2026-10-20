"""Immutable standalone proposal attestation; importing never installs checks."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path

RECEIPT = Path(__file__).with_suffix('.json')


def validate_proposal():
    receipt = json.loads(RECEIPT.read_text())
    if receipt.get('registration') != 'unregistered_proposal_only':
        raise ValueError('proposal status')
    root = Path(__file__).resolve().parents[2]
    for relative, expected in receipt['files'].items():
        if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected:
            raise ValueError('proposal file changed: ' + relative)
    for qualified, expected in receipt['dependencies'].items():
        module, name = qualified.split(':')
        body = inspect.getsource(inspect.unwrap(getattr(importlib.import_module(module), name)))
        if hashlib.sha256(body.encode()).hexdigest() != expected:
            raise ValueError('proposal dependency changed: ' + qualified)
    return deepcopy(receipt)
