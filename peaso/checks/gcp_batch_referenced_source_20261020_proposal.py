"""Immutable source attestation for an unregistered proposal; never installs it."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path

RECEIPT = Path(__file__).with_suffix('.json')


def validate_proposal():
    data = json.loads(RECEIPT.read_text())
    if data.get('registration') != 'unregistered_proposal_only':
        raise ValueError('proposal status')
    root = Path(__file__).resolve().parents[2]
    for relative, expected in data['files'].items():
        if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected:
            raise ValueError('proposal file changed: ' + relative)
    for qualified, expected in data['dependencies'].items():
        module, name = qualified.split(':')
        fn = getattr(importlib.import_module(module), name)
        if hashlib.sha256(inspect.getsource(inspect.unwrap(fn)).encode()).hexdigest() != expected:
            raise ValueError('proposal dependency changed: ' + qualified)
    return deepcopy(data)
