"""Research source receipt only; this is not production admission authority."""
import hashlib
import importlib
import inspect
import json
from pathlib import Path


def validate_proposal():
    root = Path(__file__).resolve().parents[2]
    receipt = json.loads(Path(__file__).with_suffix('.json').read_text())
    if (receipt.get('schema') != 'azure-apim-operation-window-source-v1' or receipt.get('registered') is not False
            or receipt.get('research_only') is not True or receipt.get('admission_recommended') is not False):
        raise ValueError('apim_proposal_source_mismatch')
    for row in receipt['modules'] + [receipt['descriptions'], receipt['native_cases']]:
        if hashlib.sha256((root / row['path']).read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('apim_proposal_source_mismatch')
    for row in receipt['callables']:
        value = importlib.import_module(row['module'])
        for part in row['qualname'].split('.'):
            value = getattr(value, part)
        value = inspect.unwrap(value)
        if (hashlib.sha256(inspect.getsource(value).encode()).hexdigest() != row['sha256']
                or str(Path(inspect.getsourcefile(value)).relative_to(root)) != row['path']):
            raise ValueError('apim_proposal_source_mismatch')
    return receipt
