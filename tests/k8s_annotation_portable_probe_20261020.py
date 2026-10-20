"""Stdlib-only installed-interpreter proof; no full dependency environment claim."""
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sys
import types


def main():
    root = Path(sys.argv[1]).resolve()
    def forbidden(*args, **kwargs):
        raise AssertionError('network/auth forbidden')
    for name in ('connect', 'connect_ex'):
        setattr(socket.socket, name, forbidden)
    for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection'):
        setattr(socket, name, forbidden)
    # Import only the reviewed stdlib-only modules. Empty package shells avoid
    # importing incompatible third-party wheels from another Python's venv.
    # No predicate, code comparison or native proof is replaced by a stub.
    for name in ('peaso', 'peaso.collectors', 'peaso.checks'):
        package = types.ModuleType(name); package.__path__ = [str(root.joinpath(*name.split('.')))]
        sys.modules[name] = package
    def load(name, relative):
        spec = importlib.util.spec_from_file_location(name, root / relative)
        module = importlib.util.module_from_spec(spec); sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    producer = load('peaso.collectors.k8s_annotation_indicators_20261020',
        'peaso/collectors/k8s_annotation_indicators_20261020.py')
    candidate = load('peaso.checks.k8s_annotation_indicators_review_20261020',
        'peaso/checks/k8s_annotation_indicators_review_20261020.py')
    guard = load('peaso.checks.k8s_annotation_native_admission_20261020',
        'peaso/checks/k8s_annotation_native_admission_20261020.py')
    receipt = guard._source_receipt(); units = []
    for relative, expected in receipt['compiled_sources'].items():
        raw = guard._verified_source(relative, (root / relative).read_bytes(), expected)
        compiled = guard._compiled_source(raw, str(root / relative), sys.flags.optimize)
        assert compiled
        units.append({'path': relative, 'verified_unit_sha256': hashlib.sha256(raw).hexdigest(), 'definitions': len(compiled)})
    for entry in receipt['callables']:
        if entry['module'] not in (producer.__name__, candidate.__name__):
            continue
        module = sys.modules[entry['module']]
        assert guard._function(getattr(module, entry['symbol'])) == entry['proof']
    cases = json.loads((root / receipt['fixtures']['path']).read_text())
    rows = []
    for cid in guard.IDS:
        evaluate = candidate.evaluate_for(cid)
        before = guard._function(evaluate)
        assert before['closure'] == {'check_id': {'value': cid}}
        for tag, expected in (('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')):
            status = evaluate(cases[cid][tag], cases[cid][tag + '_index'])[0]
            assert status == expected
            rows.append({'id': cid, 'case': tag, 'status': status})
        saved = evaluate.__code__
        try:
            evaluate.__code__ = saved.replace(co_consts=saved.co_consts + ('UNREVIEWED',))
            try:
                guard._function(evaluate)
            except RuntimeError:
                pass
            else:
                raise AssertionError('loaded factory code replacement accepted')
        finally:
            evaluate.__code__ = saved
        relocated = types.FunctionType(saved.replace(co_filename='/relocated/source.py',
            co_firstlineno=saved.co_firstlineno + 100), evaluate.__globals__,
            evaluate.__name__, evaluate.__defaults__, evaluate.__closure__)
        relocated.__qualname__ = evaluate.__qualname__
        assert guard._function(relocated) == before
    print(json.dumps({'python': sys.version, 'executable': sys.executable,
        'scope': 'stdlib-only actual reviewed producer/consumer/guard modules; full third-party catalog environment not asserted',
        'source_units_compiled_without_execution': units,
        'native_fixture_statuses': rows, 'factory_code_tamper_rejected': 5,
        'relocation_preserved': 5, 'mode': receipt['python_bytecode']}, sort_keys=True))


if __name__ == '__main__':
    main()
