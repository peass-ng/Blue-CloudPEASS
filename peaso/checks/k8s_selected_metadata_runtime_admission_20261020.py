"""Atomic packaged production admission for one selected metadata secret check."""
from copy import deepcopy
import gzip
import inspect
import json
from pathlib import Path
import re
import sys
import types

from . import k8s_selected_metadata_secret_admission_20261020 as prepared
from . import k8s_selected_metadata_secret_review_20261020 as candidate
from peaso.collectors import k8s_selected_metadata_runtime_20261020 as runtime
from peaso.collectors import k8s
from peaso import engine
from peaso.server import validation

proof=prepared.proof
RECEIPT='k8s_selected_metadata_runtime_admission_20261020.json'
RECEIPT_SHA256='6965847531ced2c7263b8072290d8625b5ff2f64bf3be85fd984f01348ca25cc'
ASSETS='k8s_selected_metadata_runtime_predecessor_assets_20261020.json.gz'
CASES='k8s_selected_metadata_runtime_cases_20261020.json'
CHECK=runtime.CHECK
MARK='_k8s_selected_metadata_runtime_admission_20261020'


def _self(raw):
    value,count=re.subn(rb"(?m)^RECEIPT_SHA256='[0-9a-f]{64}'$",b"RECEIPT_SHA256='"+b'0'*64+b"'",raw)
    if count!=1:raise RuntimeError('metadata runtime receipt binding changed')
    return value


def _runtime():
    result={}
    for module in(runtime,sys.modules[__name__]):
        for name,fn in vars(module).items():
            if isinstance(fn,types.FunctionType)and fn.__globals__ is vars(module):result[module.__name__+':'+name]=fn
    for name,fn in vars(runtime._Grant).items():
        if isinstance(fn,types.FunctionType):result[runtime.__name__+':_Grant.'+name]=fn
    result.update({'k8s.collect':k8s.collect,'engine._request':engine._request,
                   'engine.collect_snapshot':engine.collect_snapshot,'validation.validate_connector':validation.validate_connector})
    return result


def _check_function(fn,row,root,compiled):
    native=inspect.unwrap(fn);path=(root/row['path']).resolve()
    if not path.is_relative_to(root):raise RuntimeError('metadata runtime source escaped package')
    if row['path']not in compiled:compiled[row['path']]=proof._compiled_source(path.read_bytes(),str(path),sys.flags.optimize)
    matches=[(record,code)for record,code in compiled[row['path']]if record['qualname']==row['qualname']]
    if (len(matches)!=1 or matches[0][0]['source_sha256']!=row['sha256']
            or prepared._hash(inspect.getsource(native).encode())!=row['sha256']
            or json.dumps(proof._code(native.__code__),sort_keys=True)!=json.dumps(proof._code(matches[0][1]),sort_keys=True)
            or native.__globals__ is not vars(sys.modules[native.__module__])
            or json.dumps(native.__defaults__,sort_keys=True)!=json.dumps(row['defaults'],sort_keys=True)
            or json.dumps(native.__kwdefaults__,sort_keys=True)!=json.dumps(row['kwdefaults'],sort_keys=True)):
        raise RuntimeError('metadata runtime executing callable changed')


def _prepared_inputs(root,compiled):
    """Verify immutable predecessor fixtures from packaged bytes, never tests/docs."""
    raw=(root/'peaso/checks'/prepared.RECEIPT).read_bytes()
    if prepared._hash(raw)!=prepared.RECEIPT_SHA256:raise RuntimeError('metadata predecessor receipt changed')
    receipt=json.loads(raw,object_pairs_hook=proof._pairs)
    if json.dumps(receipt['schema'],sort_keys=True)!=json.dumps(prepared._schema(),sort_keys=True):
        raise RuntimeError('metadata predecessor schema changed')
    for relative,expected in receipt['sources'].items():
        path=(root/relative).resolve();raw=path.read_bytes()
        if relative==receipt['helper_path']:raw=prepared._self(raw)
        if not path.is_relative_to(root)or prepared._hash(raw)!=expected:raise RuntimeError('metadata predecessor source changed')
    assets=json.loads(gzip.decompress((root/'peaso/checks'/ASSETS).read_bytes()),object_pairs_hook=proof._pairs)
    required=[row for row in receipt['fixtures']if row['path'].startswith('peaso/checks/')or row['path'].endswith('/k8s_selected_metadata_secret_native_20261020.json.gz')]
    if set(assets)!={row['path']for row in required}:raise RuntimeError('metadata packaged predecessor assets changed')
    for row in required:
        entry=assets[row['path']]
        if entry['sha256']!=row['sha256']or prepared._hash(bytes.fromhex(entry['hex']))!=row['sha256']:
            raise RuntimeError('metadata packaged predecessor fixture changed')
    current=prepared._runtime()
    if set(current)!=set(prepared._ORIGINALS)or set(current)!=set(receipt['functions']):raise RuntimeError('metadata predecessor callable set changed')
    for name,fn in current.items():
        if fn is not prepared._ORIGINALS[name]or inspect.unwrap(fn)is not prepared._INNERS[name]:
            raise RuntimeError('metadata predecessor callable replacement')
        _check_function(fn,receipt['functions'][name],root,compiled)
        if isinstance(fn,types.FunctionType)and(fn.__code__ is not prepared._CODES[name]or fn.__closure__!=prepared._CLOSURES[name]):
            raise RuntimeError('metadata predecessor wrapper replacement')
    prepared._clone_bindings()


def _metadata(check):
    return {name:getattr(check,name)for name in('id','provider','category','kind','title','severity','control','remediation','target','allow_incomplete_failure')}|{
        'declared_dependencies':list(check.declared_dependencies),'empty_applicability_dependencies':list(check.empty_applicability_dependencies)}


def reviewed_inputs(root=None):
    root=Path(root or Path(__file__).resolve().parents[2]).resolve()
    try:
        raw=(root/'peaso/checks'/RECEIPT).read_bytes()
        if prepared._hash(raw)!=RECEIPT_SHA256:raise RuntimeError('metadata runtime receipt changed')
        receipt=json.loads(raw,object_pairs_hook=proof._pairs);compiled={}
        if (receipt['check']!=CHECK or runtime.CHECK!=CHECK or runtime.KIND!=prepared.producer.KIND
                or runtime.OPTION!=prepared.producer.OPTION or runtime.GRANT!='_k8s_selected_metadata_grant' or json.dumps(receipt['declaration'],sort_keys=True)!=json.dumps(candidate.DECLARATION,sort_keys=True)
                or runtime._Grant is not _GRANT_CLASS or runtime._TOKEN is not _TOKEN
                or runtime.source is not prepared.producer or candidate is not prepared.candidate
                or k8s.TYPES.count(runtime.KIND)!=1 or runtime.KIND in k8s.ENDPOINTS
                or runtime.KIND not in engine.BULK_STREAM_TYPES['k8s']or runtime.OPTION not in validation.OPTIONS):
            raise RuntimeError('metadata runtime metadata/binding changed')
        for relative,expected in receipt['sources'].items():
            path=(root/relative).resolve();raw=path.read_bytes()
            if relative==receipt['helper_path']:raw=_self(raw)
            if not path.is_relative_to(root)or prepared._hash(raw)!=expected:raise RuntimeError('metadata runtime source changed')
        for row in receipt['fixtures']:
            path=(root/row['path']).resolve()
            if not path.is_relative_to(root/'peaso/checks')or prepared._hash(path.read_bytes())!=row['sha256']:
                raise RuntimeError('metadata packaged runtime fixture changed')
        _prepared_inputs(root,compiled)
        current=_runtime()
        if set(current)!=set(_ORIGINALS)or set(current)!=set(receipt['functions']):raise RuntimeError('metadata runtime callable set changed')
        for name,fn in current.items():
            if fn is not _ORIGINALS[name]:raise RuntimeError('metadata runtime callable replacement')
            _check_function(fn,receipt['functions'][name],root,compiled)
        cases=json.loads((root/'peaso/checks'/CASES).read_bytes(),object_pairs_hook=proof._pairs)
        if set(cases)!={CHECK}:raise RuntimeError('metadata runtime CASES changed')
        for branch in('pass','fail','unknown'):
            if candidate.evaluate(deepcopy(cases[CHECK][branch]),deepcopy(cases[CHECK][branch+'_index']))[0]!=branch.upper():
                raise RuntimeError('metadata runtime native witness changed')
        return receipt,cases,deepcopy(candidate.DECLARATION),candidate.evaluate
    except RuntimeError:raise
    except(OSError,KeyError,TypeError,ValueError,AttributeError,IndexError):
        raise RuntimeError('malformed metadata runtime admission')from None


def _verify(check,receipt):
    if json.dumps(_metadata(check),sort_keys=True)!=json.dumps(receipt['metadata'],sort_keys=True):raise RuntimeError('metadata runtime registration changed')
    safe=check.evaluate;bindings=proof._bindings(safe)
    if (getattr(safe,MARK,None)!=CHECK or safe.__wrapped__ is not candidate.evaluate
            or set(bindings)!={'checked','id','kind','provider','target'}
            or any(bindings[key]!=getattr(check,key)for key in('id','kind','provider','target'))):
        raise RuntimeError('metadata runtime safe wrapper changed')
    checked=bindings['checked']
    if proof._bindings(checked)!={'function':candidate.evaluate}:raise RuntimeError('metadata runtime checked wrapper changed')
    proof._trusted_definition(safe);proof._trusted_definition(checked)
    if _INSTALLED and(safe,checked)!=_INSTALLED:raise RuntimeError('metadata runtime wrapper replacement')


def install():
    global _INSTALLED
    from . import CHECKS,CHECK_ALIASES,register
    from .fixtures import CASES as store
    receipt,cases,declaration,function=reviewed_inputs()
    if CHECK in CHECK_ALIASES or CHECK in CHECK_ALIASES.values():raise RuntimeError('metadata runtime alias collision')
    found=[check for check in CHECKS if check.id==CHECK]
    if found:
        if len(found)!=1 or not _INSTALLED:raise RuntimeError('metadata runtime collision')
        _verify(found[0],receipt)
        if json.dumps(store.get(CHECK),sort_keys=True)!=json.dumps(cases[CHECK],sort_keys=True):raise RuntimeError('metadata runtime CASES replacement')
        return
    if CHECK in store:raise RuntimeError('metadata runtime CASES collision')
    before=tuple(CHECKS)
    try:
        register(CHECK,'k8s',declaration['category'],runtime.KIND,declaration['title'],declaration['severity'],
                 'security_configuration',declaration['remediation'],dependencies=[runtime.KIND],allow_incomplete_failure=True)(function)
        check=CHECKS[-1];setattr(check.evaluate,MARK,CHECK);_verify(check,receipt)
        store[CHECK]=deepcopy(cases[CHECK]);_INSTALLED=(check.evaluate,proof._bindings(check.evaluate)['checked'])
    except Exception:
        CHECKS[:]=before;store.pop(CHECK,None);raise


_ORIGINALS=_runtime()
_GRANT_CLASS=runtime._Grant
_TOKEN=runtime._TOKEN
_INSTALLED=()
