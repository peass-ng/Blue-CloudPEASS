"""Source-bound unregistered Function proposal receipt; no registration hook."""
import hashlib
import importlib
import inspect
import json
from pathlib import Path


def validate_proposal():
    root = Path(__file__).resolve().parents[2]
    receipt = json.loads(Path(__file__).with_suffix('.json').read_text())
    if (receipt.get('schema') != 'azure-selected-function-source-receipt-v1'
            or receipt.get('registered') is not False):
        raise ValueError('function_proposal_source_mismatch')
    for item in receipt['new_modules']:
        if hashlib.sha256((root / item['path']).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('function_proposal_source_mismatch')
    for item in receipt['callables']:
        value = importlib.import_module(item['module'])
        for part in item['qualname'].split('.'):
            value = getattr(value, part)
        value = inspect.unwrap(value)
        if (hashlib.sha256(inspect.getsource(value).encode()).hexdigest() != item['sha256']
                or str(Path(inspect.getsourcefile(value)).relative_to(root)) != item['path']):
            raise ValueError('function_proposal_source_mismatch')
    cases = receipt['native_cases']
    if hashlib.sha256((root / cases['path']).read_bytes()).hexdigest() != cases['sha256']:
        raise ValueError('function_proposal_source_mismatch')
    description = receipt['descriptions']
    if hashlib.sha256((root / description['path']).read_bytes()).hexdigest() != description['sha256']:
        raise ValueError('function_proposal_source_mismatch')
    return receipt
