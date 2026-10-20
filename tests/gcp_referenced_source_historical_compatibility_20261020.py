"""Exact predecessor reproductions followed by current consumers on the same data.

Loaded by the new collected regression module, never by production. Only the
literal node IDs below are intercepted. Original functions execute unchanged;
only their pinned terminal AssertionError is an expected historical observation.
No report rewriting, markers, deselection, registry patches or capture synthesis.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import importlib
import inspect
from pathlib import Path
import sys
from types import CodeType, MappingProxyType
from types import FunctionType

import pytest

ROOT = Path(__file__).resolve().parents[1]
INDEPENDENT = 'tests/gcp_referenced_source_independent_review_20261020_test.py'
WORKBENCH = 'tests/gcp_workbench_referenced_source_20261020_test.py'
BATCH_REVIEW = 'tests/gcp_batch_independent_review_20261020_test.py'
BATCH = 'tests/gcp_batch_referenced_source_20261020_test.py'

# These are the existing sealed proposal/review identities, never regenerated.
SOURCES = MappingProxyType({
    INDEPENDENT: '9a36c86b2deabaccc9c9e9fc928e7f30784c50ab0d5fca4121e5f90dd8c2d5cf',
    WORKBENCH: 'c11a9db8abae6d39caa843d282242fa98b637b0a107c16894ff6670c1ca3fb71',
    BATCH_REVIEW: 'f2c92058a5f60a37aec6c1e222fe3b08a04a3c30f8b423641ff5000da905c3e5',
    BATCH: 'cd60ed24c2fa2cd02eea9519a52a9007ba42d4c3347dd1b9b078c4037901d7ef',
    'tests/gcp_dataflow_referenced_source_20261020_test.py': 'd2afae932cc0ffb90ea6f9dd6ef97b8c8c77f523b842c12d7ab36c9df0211ff7',
    'peaso/checks/gcp_workbench_source_runtime_consumer_20261020.py': 'c72dacd26ccba160b22a919d5d4885984f69bf3aebc5c2e08539cf7ddf751ad7',
    'peaso/checks/gcp_dataflow_referenced_source_request_binding_20261020.py': '509741729db3c225f0c32a5707e56a5e9fb42a8c4b77458cad1ebfd0af215f4a',
    'peaso/checks/gcp_workbench_referenced_source_20261020.py': '475399b2a09db35282535891993809d416eb0252a37752e94b0622f61cdd3567',
    'peaso/checks/gcp_dataflow_referenced_source_20261020.py': '25a16777c0973ee99cf761827da6a13089d0d240758626b990aa50a8bc1f00b6',
    'peaso/checks/gcp_batch_referenced_source_20261020.py': '17bfaf26a194892cd7ca1b08c28ee470a480a35226a5922ffaa60834329c0c41',
})


@dataclass(frozen=True)
class Historical:
    path: str
    function: str
    line: int
    semantics: str
    parameters: tuple = ()


_workbench_fn = 'test_workbench_invalid_sibling_cannot_establish_complete_capture'
_batch_fn = 'test_malformed_selected_sibling_cannot_erase_trusted_own_hit'
NODES = MappingProxyType({
    WORKBENCH + '::test_proposal_not_installed': Historical(WORKBENCH, 'test_proposal_not_installed', 399, 'workbench_proposal'),
    INDEPENDENT + '::' + _workbench_fn + '[clean_sibling_invalid]': Historical(INDEPENDENT, _workbench_fn, 64, 'workbench', (('hit', False),)),
    INDEPENDENT + '::' + _workbench_fn + '[trusted_hit_sibling_invalid]': Historical(INDEPENDENT, _workbench_fn, 64, 'workbench', (('hit', True),)),
    INDEPENDENT + '::test_dataflow_closing_request_must_bind_opening_request': Historical(INDEPENDENT, 'test_dataflow_closing_request_must_bind_opening_request', 77, 'dataflow'),
    BATCH_REVIEW + '::' + _batch_fn + '[null_marker-trusted_hit]': Historical(BATCH_REVIEW, _batch_fn, 115, 'batch', (('hit', True), ('shape', 'null_marker'))),
    BATCH + '::test_unregistered_declaration': Historical(BATCH, 'test_unregistered_declaration', 390, 'batch_proposal'),
})


def attest_sources():
    for relative, digest in SOURCES.items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != digest:
            raise AssertionError('Historical/current source changed: ' + relative)


def _code(code):
    """Structural executing-code identity, including source and line mapping."""
    return tuple((name, tuple(_code(c) if isinstance(c, CodeType) else c for c in value)
                  if name == 'co_consts' else value)
                 for name in ('co_code', 'co_consts', 'co_names', 'co_varnames',
                     'co_freevars', 'co_cellvars', 'co_argcount', 'co_posonlyargcount',
                     'co_kwonlyargcount', 'co_flags', 'co_firstlineno', 'co_filename',
                     'co_name', 'co_qualname', 'co_linetable', 'co_exceptiontable')
                 for value in [getattr(code, name)])


def bound_function(module, spec, config=None):
    """Bind the live function to pristine source, allowing pytest's own rewrite."""
    if spec not in NODES.values():
        raise AssertionError('Unreviewed historical source mapping')
    path = ROOT / spec.path
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCES[spec.path]:
        raise AssertionError('Historical source changed: ' + spec.path)
    function = getattr(module, spec.function)
    if (Path(module.__file__).resolve() != path or function.__globals__ is not vars(module)
            or function.__name__ != spec.function or inspect.unwrap(function) is not function):
        raise AssertionError('Historical callable mapping changed')
    expected = []
    for rewritten in (False, True):
        tree = ast.parse(raw, filename=str(path))
        if rewritten:
            from _pytest.assertion.rewrite import rewrite_asserts
            rewrite_asserts(tree, raw, str(path), config)
        compiled = compile(tree, str(path), 'exec', dont_inherit=True, optimize=sys.flags.optimize)
        expected.extend(c for c in compiled.co_consts if isinstance(c, CodeType) and c.co_name == spec.function)
    if not any(_code(function.__code__) == _code(code) for code in expected):
        raise AssertionError('Historical executing code or source mapping changed')
    return function


def historical_frame(function, spec, arguments):
    """Earlier assertions, other exceptions and unexpected success remain red."""
    try:
        function(**arguments)
    except AssertionError as error:
        last = error.__traceback__
        while last.tb_next is not None:
            last = last.tb_next
        if (type(error) is not AssertionError or last.tb_frame.f_code is not function.__code__
                or last.tb_lineno != spec.line or Path(last.tb_frame.f_code.co_filename).resolve() != ROOT / spec.path):
            raise
        return last.tb_frame
    raise AssertionError('Historical predecessor unexpectedly passed: ' + spec.function)


def _module(name):
    return importlib.import_module('peaso.checks.' + name)


def admitted(profile):
    from peaso import engine
    name = ('gcp_workbench_source_runtime_admission_20261020' if profile == 'workbench'
            else 'gcp_dataflow_batch_source_runtime_admission_20261020')
    _, _, declarations = _module(name).reviewed_inputs()
    metadata, function = next((m, f) for m, f in declarations if profile in m['id'])
    check, = [c for c in engine._registry() if c.id == metadata['id']]
    assert inspect.unwrap(check.evaluate) is function
    return check, function


def proposal_boundary(profile):
    """Explicit reimport and validation must preserve every existing registration."""
    from peaso import checks, engine
    from peaso.checks import fixtures
    check, function = admitted(profile)
    before = tuple(engine._registry())
    aliases = deepcopy(checks.CHECK_ALIASES)
    cases = deepcopy(fixtures.CASES)
    name = 'gcp_' + profile + '_referenced_source_20261020_proposal'
    proposal = _module(name)
    proposal = importlib.reload(proposal)
    receipt = proposal.validate_proposal()
    assert receipt['registration'] == 'unregistered_proposal_only'
    assert tuple(engine._registry()) == before and all(a is b for a, b in zip(engine._registry(), before))
    assert checks.CHECK_ALIASES == aliases and fixtures.CASES == cases
    assert admitted(profile) == (check, function)
    if profile == 'batch':
        predecessor = _module('gcp_batch_referenced_source_20261020')
        assert predecessor.DECLARATION['requirements'] == []
        assert predecessor.DECLARATION['dependencies'] == [predecessor.source.KIND]
    return {'current_id': check.id, 'proposal_registration_delta': 0}


@dataclass(frozen=True)
class Current:
    owner: object
    evaluate: object
    functions: tuple


def prepare_current(spec):
    """Attest before native HTTP harnesses install their narrowly scoped fakes."""
    if spec.semantics.endswith('_proposal'):
        return None
    if spec.semantics == 'workbench':
        _, function = admitted('workbench')
        owner = importlib.import_module(function.__module__)
    elif spec.semantics == 'dataflow':
        owner = _module('gcp_dataflow_referenced_source_request_binding_20261020')
        owner.validate_successor()
        function = owner.evaluate
    else:
        admitted('batch')
        owner = _module('gcp_batch_source_row_successor_20261020')
        function = owner.evaluate
    functions = tuple((name, value, _code(value.__code__)) for name, value in vars(owner).items()
                      if isinstance(value, FunctionType) and value.__globals__ is vars(owner))
    return Current(owner, function, functions)


def current_on_same_capture(spec, frame, current):
    local = frame.f_locals
    if spec.semantics.endswith('_proposal'):
        return proposal_boundary(spec.semantics.removesuffix('_proposal'))
    assert isinstance(current, Current)
    for name, function, code in current.functions:
        assert getattr(current.owner, name) is function and _code(function.__code__) == code, 'Current pure consumer changed during capture'
    evaluate = current.evaluate
    if spec.semantics == 'workbench':
        first, second, index, hit = (local[n] for n in ('first', 'second', 'index', 'hit'))
        before = deepcopy(index)
        assert local['status'] == ('FAIL' if hit else 'PASS') and local['details']['complete'] is True
        assert second[frame.f_globals['workbench'].source.MARKER]['parts'][0]['engines'][0]['version'] == '0.0.0'
        assert evaluate(second, index)[0] == 'UNKNOWN'
        status, details = evaluate(first, index)
        assert status == ('FAIL' if hit else 'UNKNOWN') and details['complete'] is False
        assert index == before
    elif spec.semantics == 'dataflow':
        capture = local['capture']; before = deepcopy(capture)
        assert local['status'] == 'PASS' and local['opening']['request'] != local['closing']['request']
        status, details = evaluate(capture['items'][0], capture)
        assert status == 'UNKNOWN' and details['complete'] is False
        assert capture == before
    else:
        evidence, first = local['evidence'], local['first']; before = deepcopy(evidence)
        assert local['rows'][0][0] == 'UNKNOWN' and local['hit'] is True and local['shape'] == 'null_marker'
        assert local['sibling'][frame.f_globals['source'].MARKER] is None
        status, details = evaluate(first, evidence, frame.f_globals['batch'].SCOPE)
        assert status == 'FAIL' and details['complete'] is False
        assert evaluate(local['sibling'], evidence, frame.f_globals['batch'].SCOPE)[0] == 'UNKNOWN'
        assert evidence == before
    if status == 'FAIL':
        leak, = details['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    return {'predecessor_final_assertion_line': spec.line, 'current_status': status, 'complete': details['complete']}


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    spec = NODES.get(pyfuncitem.nodeid)
    if spec is None:
        return None
    attest_sources()
    function = bound_function(pyfuncitem.module, spec, pyfuncitem.config)
    assert pyfuncitem.obj is function
    current = prepare_current(spec)
    arguments = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames}
    for name, value in spec.parameters:
        assert arguments[name] == value and type(arguments[name]) is type(value)
    frame = historical_frame(function, spec, arguments)
    try:
        proof = current_on_same_capture(spec, frame, current)
        pyfuncitem.user_properties.append(('historical_to_current', str(proof)))
    finally:
        del frame
    return True
