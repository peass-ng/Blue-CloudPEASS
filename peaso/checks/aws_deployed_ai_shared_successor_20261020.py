"""Exact deployed-AI integration over the sealed AWS-command admission epoch.

Only the parent package aliases this bridge. Canonical historical modules,
receipts, callable objects, grant identities and native witnesses stay intact.
"""
from copy import deepcopy
import hashlib
import inspect
import importlib
import json
from pathlib import Path
import re
import sys
import types
from . import azure_function_package_shared_successor_20261020 as predecessor
original = predecessor.original
PREDECESSOR_REVIEWED_INPUTS = predecessor.PREDECESSOR_REVIEWED_INPUTS
historical = importlib.import_module(__package__ + '.aws_workload_command_shared_successor_20261020')
_HISTORICAL_FUNCTIONS = dict(historical._FUNCTIONS)
RECEIPT = 'aws_deployed_ai_shared_successor_20261020.json'
RECEIPT_SHA256 = '4ef13e1af7ac9ec64fbed9d2ced5783c8c78d5f64cbf4dd096846731e93d8b4a'


def _self(raw):
    value, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('AWS command successor self binding changed')
    return value


def _reverse(text, row):
    if hashlib.sha256(text.encode()).hexdigest() != row['current_sha256']:
        raise RuntimeError('Deployed AI current source changed')
    for before, after in row.get('exact_replacements', []):
        if text.count(after) != 1:
            raise RuntimeError('Deployed AI exact replacement changed')
        text = text.replace(after, before, 1)
    for addition in row['exact_additions']:
        if text.count(addition) != 1:
            raise RuntimeError('Deployed AI exact addition changed')
        text = text.replace(addition, '', 1)
    return text


def _verify_bridge(root):
    """Attest this executing bridge independently of reviewed_delta dispatch."""
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Deployed AI bridge receipt changed')
    receipt = json.loads(raw)
    helper = 'peaso/checks/aws_deployed_ai_shared_successor_20261020.py'
    if hashlib.sha256(_self((root / helper).read_bytes())).hexdigest() != receipt['sources'][helper]['sha256']:
        raise RuntimeError('Deployed AI bridge self source changed')
    compiled = {}
    for qualified, function in _FUNCTIONS.items():
        name = qualified.split(':')[1]
        if globals().get(name) is not function:
            raise RuntimeError('Deployed AI bridge executing callable replaced: ' + name)
        original._check_function(function, receipt['functions'][qualified], root, compiled)


def reviewed_delta(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    _verify_bridge(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('AWS command successor receipt changed')
    receipt = json.loads(raw)
    if receipt['accepted_receipt_sha256'] != historical.RECEIPT_SHA256:
        raise RuntimeError('Deployed AI historical receipt binding changed')
    # This unchanged predecessor verifies WB/DF/CodeBuild historical source,
    # receipts, helpers, the isolated K8s router and prepared native contracts.
    predecessor.predecessor.reviewed_delta(root)
    for name, row in receipt['sources'].items():
        data = (root / name).read_bytes()
        if row['normalization'] == 'self':
            data = _self(data)
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('AWS command successor source changed: ' + name)
    sealed = json.loads((root / 'peaso/checks' / historical.RECEIPT).read_bytes())
    # First reconstruct the *entire* accepted AWS-command epoch. Then the
    # unchanged epoch's exact reversals below reconstruct its own predecessor.
    for name, row in receipt['integration_file_deltas'].items():
        restored = _reverse((root / name).read_text(), row)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Deployed AI whole-file historical reconstruction changed: ' + name)
        if name in sealed['file_deltas'] and row['predecessor_sha256'] != sealed['file_deltas'][name]['current_sha256']:
            raise RuntimeError('Deployed AI historical file binding changed: ' + name)
        if name in sealed['file_deltas']:
            previous = _reverse(restored, sealed['file_deltas'][name])
            if hashlib.sha256(previous.encode()).hexdigest() != sealed['file_deltas'][name]['predecessor_sha256']:
                raise RuntimeError('Deployed AI sealed historical reversal changed: ' + name)
    compiled = {}
    for qualified, row in receipt['integration_functions'].items():
        owner, name = qualified.split(':')
        function = getattr(importlib.import_module(owner), name)
        if function is not _INTEGRATION_FUNCTIONS[qualified]:
            raise RuntimeError('Deployed AI shared callable replaced: ' + qualified)
        if qualified == 'peaso.collectors.aws_facts_swc:_event_rule':
            facts = importlib.import_module(owner)
            if (function.__closure__ is not _EVENT_RULE_CLOSURE
                    or len(function.__closure__) != 1
                    or function.__closure__[0].cell_contents is not _EVENT_RULE_INNER
                    or facts.ENRICHERS.get('eventbridge_rule') is not function
                    or facts.ENRICHERS.get('event_rule') is not function):
                raise RuntimeError('Deployed AI event-rule wrapper/closure binding changed')
            original._check_function(function, row['wrapper'], root, compiled)
            function = _EVENT_RULE_INNER
        try:
            restored = _reverse(inspect.getsource(inspect.unwrap(function)), row)
        except RuntimeError as exc:
            raise RuntimeError('Deployed AI shared source changed: ' + qualified) from exc
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Deployed AI shared callable historical reconstruction changed: ' + qualified)
        original._check_function(function, row['current'], root, compiled)
    for name, row in receipt['file_deltas'].items():
        restored = (root / name).read_text()
        for before, after in row.get('exact_replacements', []):
            if restored.count(after) != 1:
                raise RuntimeError('AWS command exact entrypoint changed')
            restored = restored.replace(after, before, 1)
        for addition in row['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('AWS command exact source addition changed')
            restored = restored.replace(addition, '', 1)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('AWS command changed outside admitted source additions')
        # Re-run the previous epoch's exact whole-file reconstruction, on the
        # just-proven previous bytes, without mutating files or guard globals.
        historical_receipt = json.loads((root / 'peaso/checks' / predecessor.RECEIPT).read_bytes())
        if name in historical_receipt['file_deltas']:
            prior = historical_receipt['file_deltas'][name]
            for before, after in prior.get('exact_replacements', []):
                if restored.count(after) != 1:
                    raise RuntimeError('AWS command historical entrypoint changed')
                restored = restored.replace(after, before, 1)
            for addition in prior['exact_additions']:
                if restored.count(addition) != 1:
                    raise RuntimeError('AWS command historical file delta changed')
                restored = restored.replace(addition, '', 1)
            if hashlib.sha256(restored.encode()).hexdigest() != prior['predecessor_sha256']:
                raise RuntimeError('AWS command historical whole-file source changed')
    compiled = {}
    for qualified, row in receipt['functions'].items():
        module_name, name = qualified.split(':')
        module = importlib.import_module(module_name)
        function = module
        for part in name.split('.'):
            function = getattr(function, part)
        if qualified == 'peaso.checks.gcp_workbench_head3_admission_20261020:reviewed_inputs':
            historical_function = module._ORIGINALS[qualified]
            successor = importlib.import_module('peaso.checks.gcp_cloudrun_job_image_workbench_source_successor_20261020')
            if function not in (historical_function, successor.reviewed_inputs):
                raise RuntimeError('Workbench shared admission alias changed')
            function = historical_function
        if qualified == 'peaso.gcp_function_secret_page_source_20261020:reviewed_inputs':
            successor = importlib.import_module('peaso.gcp_cloudrun_job_image_function_source_successor_20261020')
            historical_function = successor._HISTORICAL_PAGE_REVIEWED_INPUTS
            if function not in (historical_function, successor.reviewed_inputs):
                raise RuntimeError('Functions shared runtime admission alias changed')
            function = historical_function
        if qualified in _HISTORICAL_FUNCTIONS and function is not _HISTORICAL_FUNCTIONS[qualified]:
            raise RuntimeError('Deployed AI canonical historical callable replaced: ' + qualified)
        if qualified in _FUNCTIONS and function is not _FUNCTIONS[qualified]:
            raise RuntimeError('AWS command successor callable replaced')
        try:
            original._check_function(function, row, root, compiled)
        except RuntimeError as exc:
            raise RuntimeError('AWS command executing callable changed: ' + qualified) from exc
    historical_receipt = json.loads((root / 'peaso/checks' / predecessor.RECEIPT).read_bytes())
    # Existing consumers require the unchanged Azure collection binding.
    receipt['azure_collect'] = historical_receipt['azure_collect']
    return receipt


def check_shared(fn, historical, name, root, compiled, receipt):
    current = receipt['shared_functions'][name]
    restored = inspect.getsource(inspect.unwrap(fn))
    layers = [current]
    for module in (predecessor, predecessor.predecessor,
                   predecessor.predecessor.predecessor,
                   predecessor.predecessor.predecessor.predecessor):
        layers.append(json.loads((root / 'peaso/checks' / module.RECEIPT).read_bytes())['shared_functions'][name])
    for row in layers:
        if hashlib.sha256(restored.encode()).hexdigest() != row['current_sha256']:
            raise RuntimeError('AWS command shared executing source changed')
        for addition in row['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('AWS command inherited source addition changed')
            restored = restored.replace(addition, '', 1)
        if hashlib.sha256(restored.encode()).hexdigest() != row.get('predecessor_sha256', row.get('predecessor', {}).get('sha256')):
            raise RuntimeError('AWS command inherited source epoch changed')
    if hashlib.sha256(restored.encode()).hexdigest() != historical['sha256']:
        raise RuntimeError('AWS command original callable source changed')
    original._check_function(fn, dict(historical, sha256=current['current_sha256']), root, compiled)


def prepared_inputs(root, compiled, successor):
    return predecessor.prepared_inputs(root, compiled, successor)


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    _verify_bridge(root)
    successor = reviewed_delta(root)
    raw = (root / 'peaso/checks' / original.RECEIPT).read_bytes()
    if original.prepared._hash(raw) != original.RECEIPT_SHA256:
        raise RuntimeError('metadata runtime receipt changed')
    receipt = json.loads(raw, object_pairs_hook=original.proof._pairs)
    compiled = {}
    runtime = original.runtime
    if (receipt['check'] != original.CHECK or runtime.CHECK != original.CHECK
            or runtime.KIND != original.prepared.producer.KIND or runtime.OPTION != original.prepared.producer.OPTION
            or runtime.GRANT != '_k8s_selected_metadata_grant'
            or json.dumps(receipt['declaration'], sort_keys=True) != json.dumps(original.candidate.DECLARATION, sort_keys=True)
            or runtime._Grant is not original._GRANT_CLASS or runtime._TOKEN is not original._TOKEN
            or runtime.source is not original.prepared.producer or original.candidate is not original.prepared.candidate
            or original.k8s.TYPES.count(runtime.KIND) != 1 or runtime.KIND in original.k8s.ENDPOINTS
            or runtime.KIND not in original.engine.BULK_STREAM_TYPES['k8s'] or runtime.OPTION not in original.validation.OPTIONS):
        raise RuntimeError('metadata runtime metadata/binding changed')
    for name, expected in receipt['sources'].items():
        path = (root / name).resolve()
        raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = original._self(raw)
        if not path.is_relative_to(root) or original.prepared._hash(raw) != expected:
            raise RuntimeError('metadata runtime source changed')
    for row in receipt['fixtures']:
        path = (root / row['path']).resolve()
        if not path.is_relative_to(root / 'peaso/checks') or original.prepared._hash(path.read_bytes()) != row['sha256']:
            raise RuntimeError('metadata packaged runtime fixture changed')
    prepared_inputs(root, compiled, successor)
    current = original._runtime()
    alias = original.__name__ + ':reviewed_inputs'
    if original.reviewed_inputs is reviewed_inputs:
        if alias in current:
            raise RuntimeError('metadata runtime successor alias changed')
        current[alias] = PREDECESSOR_REVIEWED_INPUTS
    elif original.reviewed_inputs not in (PREDECESSOR_REVIEWED_INPUTS, historical.reviewed_inputs, predecessor.reviewed_inputs, predecessor.predecessor.reviewed_inputs, predecessor.predecessor.predecessor.reviewed_inputs, predecessor.predecessor.predecessor.predecessor.reviewed_inputs):
        raise RuntimeError('metadata runtime successor alias replaced')
    if set(current) != set(original._ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('metadata runtime callable set changed')
    for name, fn in current.items():
        if fn is not original._ORIGINALS[name]:
            raise RuntimeError('metadata runtime callable replacement')
        if name in successor['shared_functions']:
            check_shared(fn, receipt['functions'][name], name, root, compiled, successor)
        else:
            original._check_function(fn, receipt['functions'][name], root, compiled)
    cases = json.loads((root / 'peaso/checks' / original.CASES).read_bytes(), object_pairs_hook=original.proof._pairs)
    if set(cases) != {original.CHECK}:
        raise RuntimeError('metadata runtime CASES changed')
    for branch in ('pass', 'fail', 'unknown'):
        if original.candidate.evaluate(deepcopy(cases[original.CHECK][branch]), deepcopy(cases[original.CHECK][branch + '_index']))[0] != branch.upper():
            raise RuntimeError('metadata runtime native witness changed')
    return receipt, cases, deepcopy(original.candidate.DECLARATION), original.candidate.evaluate


def install():
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES as store
    receipt, cases, declaration, function = reviewed_inputs()
    # The immutable authorize/collect functions import this original module path.
    # Route only its reviewed-input entrypoint; the historical object is retained
    # and attested separately, while this actual successor source is self-pinned.
    original.reviewed_inputs = reviewed_inputs
    ident = original.CHECK
    if ident in CHECK_ALIASES or ident in CHECK_ALIASES.values():
        raise RuntimeError('metadata runtime alias collision')
    found = [check for check in CHECKS if check.id == ident]
    if found:
        if len(found) != 1 or not original._INSTALLED:
            raise RuntimeError('metadata runtime collision')
        original._verify(found[0], receipt)
        if json.dumps(store.get(ident), sort_keys=True) != json.dumps(cases[ident], sort_keys=True):
            raise RuntimeError('metadata runtime CASES replacement')
        return
    if ident in store:
        raise RuntimeError('metadata runtime CASES collision')
    before = tuple(CHECKS)
    try:
        register(ident, 'k8s', declaration['category'], original.runtime.KIND, declaration['title'], declaration['severity'],
                 'security_configuration', declaration['remediation'], dependencies=[original.runtime.KIND], allow_incomplete_failure=True)(function)
        check = CHECKS[-1]
        setattr(check.evaluate, original.MARK, ident)
        original._verify(check, receipt)
        store[ident] = deepcopy(cases[ident])
        original._INSTALLED = (check.evaluate, original.proof._bindings(check.evaluate)['checked'])
    except Exception:
        CHECKS[:] = before
        store.pop(ident, None)
        raise


def install_dataflow(admission):
    """Only reviewed shared admission alias changes; its 119 functions stay exact."""
    receipt = reviewed_delta()
    if admission.shared not in (historical, predecessor.predecessor.predecessor, predecessor.predecessor, predecessor, __import__(__name__, fromlist=[''])):
        raise RuntimeError('CodeBuild Dataflow shared alias replaced')
    old = admission.shared
    admission.shared = __import__(__name__, fromlist=[''])
    try:
        admission.install()
    except Exception:
        admission.shared = old
        raise


def install_bundle():
    """Preflight before registry/alias mutation, then roll back this whole wave."""
    _verify_bridge(Path(__file__).resolve().parents[2])
    from . import CHECKS
    from .fixtures import CASES
    from . import gcp_workbench_source_runtime_admission_20261020 as workbench
    from . import gcp_dataflow_batch_source_runtime_admission_20261020 as dataflow
    from . import aws_workload_command_codebuild_successor_20261020 as codebuild_successor
    codebuild = codebuild_successor.original
    from . import azure_function_package_integration_admission_20261020 as package
    from . import azure_function_package_tde_successor_20261020 as tde
    from . import gcp_function_secret_page_admission_20261020 as function_pairs
    # This validation has no registry or shared-alias writes.
    from . import aws_workload_command_runtime_admission_20261020 as commands
    commands.reviewed_inputs()
    package.reviewed_inputs()
    codebuild_successor.reviewed_inputs()
    tde.reviewed_inputs()
    function_pairs.reviewed_inputs()
    ids = {commands.runtime.CHECK, original.CHECK, *workbench.CHECK_IDS, *dataflow.runtime.CHECKS, codebuild.runtime.CHECK, package.runtime.CHECK, *tde.IDS, function_pairs.original.CHECK_ID}
    before = tuple(CHECKS)
    old_cases = {ident: CASES[ident] for ident in ids if ident in CASES}
    old_reviewed, old_installed, old_shared = original.reviewed_inputs, original._INSTALLED, dataflow.shared
    old_package, old_tde = package._INSTALLED, dict(tde.original._INSTALLED)
    old_codebuild_reviewed = codebuild.reviewed_inputs
    old_command_reviewed = commands.runtime.source.reviewed_sources
    try:
        tde.install()
        install()
        workbench.install()
        install_dataflow(dataflow)
        codebuild_successor.install()
        package.install()
        function_pairs.install()
        commands.install()
    except Exception:
        CHECKS[:] = before
        for ident in ids:
            if ident in old_cases:
                CASES[ident] = old_cases[ident]
            else:
                CASES.pop(ident, None)
        original.reviewed_inputs, original._INSTALLED, dataflow.shared = old_reviewed, old_installed, old_shared
        package._INSTALLED = old_package
        codebuild.reviewed_inputs = old_codebuild_reviewed
        commands.runtime.source.reviewed_sources = old_command_reviewed
        tde.original._INSTALLED.clear()
        tde.original._INSTALLED.update(old_tde)
        raise


def check_aws(function, expected):
    from . import aws_s3_selected_source_admission_20261020 as s3
    receipt = reviewed_delta()
    row = receipt['shared_functions']['aws.collect']
    restored = inspect.getsource(function)
    for layer in (row, json.loads(Path(predecessor.predecessor.__file__).with_suffix('.json').read_bytes())['shared_functions']['aws.collect']):
        if hashlib.sha256(restored.encode()).hexdigest() != layer['current_sha256']:
            raise RuntimeError('AWS command collector source epoch changed')
        for addition in layer['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('AWS command collector addition changed')
            restored = restored.replace(addition, '', 1)
    if hashlib.sha256(restored.encode()).hexdigest() != expected['sha256']:
        raise RuntimeError('AWS command original S3 collector changed')
    if s3.proof(function) != dict(expected, sha256=row['current_sha256']):
        raise RuntimeError('AWS command native collector code changed')


def s3_reviewed_inputs():
    from . import aws_s3_selected_source_admission_20261020 as original
    root = Path(__file__).resolve().parents[2]
    _verify_bridge(root)
    receipt = json.loads((root / 'peaso/checks' / original.RECEIPT).read_bytes())
    reviewed_delta(root)
    for name, digest in receipt['source_hashes'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Selected S3 unchanged source changed')
    for expected in receipt['callables']:
        function = importlib.import_module(expected['module'])
        for name in expected['qualname'].split('.'):
            function = getattr(function, name)
        if expected['module'] == 'peaso.collectors.aws' and expected['qualname'] == 'collect':
            check_aws(function, expected)
        elif original.proof(function) != expected:
            raise RuntimeError('Selected S3 unchanged callable changed')
    from peaso.collectors import aws_s3_selected_source_secret_indicators as producer
    if original.schema(producer) != receipt['producer_schema']:
        raise RuntimeError('Selected S3 producer schema changed')
    for binding in receipt['bindings']:
        left = importlib.import_module(binding['module'])
        right = importlib.import_module(binding['origin_module'])
        if getattr(left, binding['name']) is not getattr(right, binding['origin_name']):
            raise RuntimeError('Selected S3 unchanged imported binding changed')
    fixture = receipt['fixture']
    path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != fixture['sha256']:
        raise RuntimeError('Selected S3 packaged native fixture changed')
    cases = json.loads(path.read_bytes())
    from .aws_s3_selected_source_secret_review_20261020 import CHECK, evaluate
    if set(cases) != {CHECK}:
        raise RuntimeError('Selected S3 native identities changed')
    for branch in ('pass', 'fail', 'unknown'):
        if evaluate(cases[CHECK][branch], cases[CHECK][branch + '_index'])[0] != branch.upper():
            raise RuntimeError('Selected S3 native branch changed')
    return cases


def install_s3():
    from . import CHECKS,register
    from .fixtures import CASES
    from . import aws_s3_selected_source_secret_review_20261020 as reviewed
    cases=s3_reviewed_inputs();declaration,=reviewed.DECLARATIONS
    old=[c for c in CHECKS if c.id==reviewed.CHECK]
    if old:
        if len(old)!=1 or inspect.unwrap(old[0].evaluate) is not reviewed.evaluate or old[0].kind!=declaration['kind']:
            raise RuntimeError('Selected S3 registration collision')
        if CASES.get(reviewed.CHECK)!=cases[reviewed.CHECK]:raise RuntimeError('Selected S3 registered fixture changed')
        return
    before=tuple(CHECKS);had_case=reviewed.CHECK in CASES;previous=deepcopy(CASES.get(reviewed.CHECK))
    try:
        register(reviewed.CHECK,'aws',declaration['category'],declaration['kind'],declaration['title'],'high',
            'security_configuration',declaration['remediation'],dependencies=declaration['dependencies'],
            allow_incomplete_failure=True)(reviewed.evaluate)
        CASES[reviewed.CHECK]=deepcopy(cases[reviewed.CHECK])
    except Exception:
        CHECKS[:]=before
        if had_case:CASES[reviewed.CHECK]=previous
        else:CASES.pop(reviewed.CHECK,None)
        raise


_FUNCTIONS = {__name__ + ':' + name: fn for name, fn in tuple(globals().items()) if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}

# Capture executing objects before any bridge installer can publish aliases.
_INTEGRATION_FUNCTIONS = {
    'peaso.collectors.aws:collect': importlib.import_module('peaso.collectors.aws').collect,
    'peaso.collectors.aws:_safe': importlib.import_module('peaso.collectors.aws')._safe,
    'peaso.engine:collect_snapshot': importlib.import_module('peaso.engine').collect_snapshot,
    'peaso.collectors.aws_facts_swc:_event_rule': importlib.import_module('peaso.collectors.aws_facts_swc')._event_rule,
}
_EVENT_RULE_CLOSURE = _INTEGRATION_FUNCTIONS['peaso.collectors.aws_facts_swc:_event_rule'].__closure__
_EVENT_RULE_INNER = _EVENT_RULE_CLOSURE[0].cell_contents
