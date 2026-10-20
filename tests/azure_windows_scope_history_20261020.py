"""Replay a signed archived Windows scope witness without changing native checks."""
import ast
import hashlib
import importlib
import inspect
import json
from pathlib import Path

PATH = Path(__file__).parent / 'fixtures/azure-windows-scope-predecessor-20261020.json'
SHA256 = '8b11ae7df764b533456cc70590e54da83e1e09885794211558fefaef19ec7ad8'


def historical_secure_boot(item, index):
    raw = PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA256
    data = json.loads(raw)
    assert data['schema'] == 1 and data['commit'] == 'f1ced4267df3a0e0b17375f3ed9fe98d574f784a'
    assert set(data['functions']) == {'_os_type', 'vm_windows_secure_boot'}
    assert set(data['dependencies']) == {'get', 'enum', 'result'}
    namespace = {}
    for alias, row in data['dependencies'].items():
        fn = getattr(importlib.import_module(row['module']), row['name'])
        assert hashlib.sha256(inspect.getsource(fn).encode()).hexdigest() == row['source_sha256']
        namespace[alias] = fn
    for name in ('_os_type', 'vm_windows_secure_boot'):
        source = data['functions'][name]
        tree = ast.parse(source)
        assert len(tree.body) == 1 and isinstance(tree.body[0], ast.FunctionDef)
        assert tree.body[0].name == name and not tree.body[0].decorator_list
        exec(compile(tree, str(PATH), 'exec'), namespace)
    return namespace['vm_windows_secure_boot'](item, index)
