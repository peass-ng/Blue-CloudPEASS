"""Atomic package-only admission for two selected native GCS source controls."""
from copy import deepcopy
import hashlib
import ast
import gzip
import textwrap
import importlib
import inspect
import json
from pathlib import Path
import re
import types

from peaso.collectors import gcp_dataflow_batch_source_runtime_20261020 as runtime
from . import gcp_dataflow_batch_source_runtime_consumer_20261020 as candidate
from . import gcp_dataflow_batch_shared_hook_successor_20261020 as shared

RECEIPT_SHA256 = '8277fadb5c0f67131c47755e10ac06f48454e40730088aba09234b92dd3451a1'
RECEIPT = 'gcp_dataflow_batch_source_runtime_admission_20261020.json'
CASES = 'gcp_dataflow_batch_source_runtime_cases_20261020.json'
_GRANT, _SEAL = runtime._Grant, runtime._SEAL


def _self(raw):
    result, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('Selected job admission self changed')
    return result


def _bindings():
    from peaso import secret_scanning as scanning
    from peaso.collectors import gcp_dataflow_referenced_source_20261020 as df
    from peaso.collectors import gcp_batch_referenced_source_20261020 as bt
    from peaso.collectors import gcp_selected_object_secret_indicators as objects
    from peaso.collectors import gcp_selected_archive_secret_indicators as archives
    from peaso.collectors import gcp_git_transport as git
    from peaso.collectors import gcp_dataproc_referenced_source_secret_indicators as reads
    from . import gcp_dataflow_referenced_source_request_binding_20261020 as df_consumer
    from . import gcp_dataflow_referenced_source_20261020 as df_original
    from . import gcp_batch_source_row_successor_20261020 as bt_consumer
    from . import gcp_batch_referenced_source_20261020 as bt_original
    return ((runtime.dataflow, df), (runtime.batch, bt), (candidate.dataflow, df_consumer),
            (df_consumer.predecessor, df_original), (candidate.batch, bt_consumer), (bt_consumer.predecessor, bt_original),
            (df.objects, objects), (df.archives, archives), (df.git, git), (bt.reads, reads),
            (reads.objects, objects), (reads.git, git), (runtime.scan_content, scanning.scan_content),
            (df.scan_content, scanning.scan_content), (bt.scan_content, scanning.scan_content),
            (df_original.merge_leaks, scanning.merge_leaks), (bt_original.merge_leaks, scanning.merge_leaks),
            (bt_consumer.merge_leaks, scanning.merge_leaks))


def _gcp_delta(root, receipt):
    from peaso.collectors import gcp
    archive = json.loads(gzip.decompress((root / receipt['hook_predecessor']).read_bytes()))
    prior = archive['peaso/collectors/gcp.py']
    if hashlib.sha256(prior['content'].encode()).hexdigest() != prior['sha256']:
        raise RuntimeError('Selected job GCP predecessor changed')
    source = (root / 'peaso/collectors/gcp.py').read_text()
    for delta in receipt['gcp_global_additions']:
        if source.count(delta) != 1:
            raise RuntimeError('Selected job GCP global hook changed')
    for name, row in receipt['gcp_function_deltas'].items():
        function = getattr(gcp.GCPCollector, name)
        restored = inspect.getsource(function)
        for addition in row['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('Selected job GCP exact branch changed')
            restored = restored.replace(addition, '', 1)
        if (hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']
                or ast.dump(ast.parse(textwrap.dedent(restored)), include_attributes=False) != row['predecessor_ast']):
            raise RuntimeError('Selected job GCP non-selected-source branch changed')


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Selected job admission receipt changed')
    receipt = json.loads(raw)
    if (receipt['schema_version'] != 1 or tuple(d['id'] for d in receipt['declarations']) != runtime.CHECKS
            or receipt['declarations'] != candidate.DECLARATIONS
            or runtime._Grant is not _GRANT or runtime._SEAL is not _SEAL
            or candidate.runtime is not runtime or candidate.dataflow.predecessor.source is not runtime.dataflow
            or candidate.batch.source is not runtime.batch):
        raise RuntimeError('Selected job admission metadata/binding changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Selected job admission dependency outside package')
        raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = _self(raw)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('Selected job admission reviewed source changed')
    if any(actual is not expected for actual, expected in _bindings()):
        raise RuntimeError('Selected job admission imported binding changed')
    public_profiles = {name: {k: p[k] for k in ('check', 'kind', 'marker')} for name, p in runtime.PROFILES.items()}
    if public_profiles != receipt['profiles'] or any(p['source'] is not (runtime.dataflow if name == 'dataflow' else runtime.batch) for name, p in runtime.PROFILES.items()):
        raise RuntimeError('Selected job admission profile changed')
    _gcp_delta(root, receipt)
    shared.reviewed_inputs(root)
    compiled = {}
    for qualified, row in receipt['runtime_functions'].items():
        owner_name, attribute = qualified.split(':'); owner = importlib.import_module(owner_name)
        function = owner
        for part in attribute.split('.'):
            function = getattr(function, part)
        if qualified in _FUNCTIONS and function is not _FUNCTIONS[qualified]:
            raise RuntimeError('Selected job admission callable replaced')
        shared.original._check_function(function, row, root, compiled)
    path = (root / 'peaso/checks' / CASES).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != receipt['cases_sha256']:
        raise RuntimeError('Selected job native cases changed')
    cases = json.loads(path.read_bytes())
    if set(cases) != set(runtime.CHECKS):
        raise RuntimeError('Selected job native case identities changed')
    declarations = []
    for profile, declaration in zip(runtime.PROFILES, candidate.DECLARATIONS):
        function = getattr(candidate, profile + '_source'); case = cases[declaration['id']]
        for branch in ('pass', 'fail', 'unknown', 'partial', 'missing', 'malformed'):
            status, details = function(deepcopy(case[branch]), deepcopy(case.get(branch + '_index', case['index'])))
            expected = 'FAIL' if branch == 'partial' else branch.upper() if branch in ('pass', 'fail') else 'UNKNOWN'
            if status != expected or branch == 'partial' and details.get('complete') is not False:
                raise RuntimeError('Selected job native branch changed')
        declarations.append((declaration, function))
    return receipt, cases, declarations


def _signature(check):
    return (check.provider, check.category, check.kind, check.title, check.severity, check.control,
            check.remediation, tuple(check.dependencies), check.allow_incomplete_failure)


def install():
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES as store
    receipt, cases, declarations = reviewed_inputs()
    for declaration, function in declarations:
        ident = declaration['id']; found = [check for check in CHECKS if check.id == ident]
        expected = ('gcp', declaration['category'], declaration['kind'], declaration['title'], declaration['severity'],
                    'security_configuration', declaration['remediation'], tuple(declaration['dependencies']), True)
        if (ident in CHECK_ALIASES or ident in CHECK_ALIASES.values() or len(found) > 1
                or found and (inspect.unwrap(found[0].evaluate) is not function or _signature(found[0]) != expected)
                or ident in store and store[ident] != cases[ident]):
            raise RuntimeError('Selected job admission collision')
    before = tuple(CHECKS); previous = {ident: deepcopy(store[ident]) for ident in cases if ident in store}
    try:
        for declaration, function in declarations:
            ident = declaration['id']
            if not any(check.id == ident for check in CHECKS):
                register(ident, 'gcp', declaration['category'], declaration['kind'], declaration['title'], declaration['severity'],
                         'security_configuration', declaration['remediation'], dependencies=declaration['dependencies'], allow_incomplete_failure=True)(function)
            store[ident] = deepcopy(cases[ident])
    except Exception:
        CHECKS[:] = before
        for ident in cases:
            if ident in previous: store[ident] = previous[ident]
            else: store.pop(ident, None)
        raise

_FUNCTIONS = {__name__ + ':' + name: function for name, function in tuple(globals().items())
              if isinstance(function, types.FunctionType) and function.__globals__ is globals()}
