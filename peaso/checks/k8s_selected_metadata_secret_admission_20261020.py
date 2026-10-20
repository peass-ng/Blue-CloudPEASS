"""Prepared source/native-case inputs only; importing this module installs nothing."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
import types

from . import k8s_annotation_native_admission_20261020 as proof
from . import k8s_selected_metadata_secret_review_20261020 as candidate
from peaso.collectors import k8s_selected_metadata_secret_indicators_20261020 as producer
from peaso.collectors import k8s, azure
from peaso import secret_scanning as scanning

RECEIPT='k8s_selected_metadata_secret_admission_20261020.json'
RECEIPT_SHA256='17c8e31b1d2d4125417cf32d9d7fa9b4c45154ac7fa84e7a4adfcde194eca19d'
CASES='k8s_selected_metadata_secret_cases_20261020.json'


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _self(raw):
    value,count=re.subn(rb"(?m)^RECEIPT_SHA256='[0-9a-f]{64}'$",b"RECEIPT_SHA256='"+b'0'*64+b"'",raw)
    if count!=1:raise RuntimeError('metadata receipt binding changed')
    return value


def _runtime():
    result={}
    for module in(producer,candidate,sys.modules[__name__]):
        for name,fn in vars(module).items():
            if isinstance(fn,types.FunctionType)and fn.__globals__ is vars(module):result[module.__name__+':'+name]=fn
    for name in producer._REUSED:
        result['literal:'+name]=getattr(producer.predecessor,name)
    result['literal:redact_output']=producer.predecessor.redact_output
    result['literal:consumer']=candidate.predecessor.evaluate
    for name in('scan_content','merge_leaks','redact_matches','_fingerprint','_scan_kingfisher','_scan_trufflehog','_kingfisher','_trufflehog','_run','_label'):
        result['detector:'+name]=getattr(scanning,name)
    for name in('private_native_logs','_wire_debug_enabled'):
        result['privacy:'+name]=getattr(sys.modules['peaso.collectors.k8s_selected_log_sample_secret_indicators'],name)
    for name,fn in{'pool_init':k8s._BoundedPool.__init__,'pool_request':k8s._BoundedPool.request,
                  'reader_init':azure._Reader.__init__,'reader_call':azure._Reader.call,
                  'reader_cancelled':azure._Reader.check_cancelled,'k8s_reader_call':k8s.K8sReader.call,
                  'proof_code':proof._code,'proof_compile':proof._compiled_source,'proof_bindings':proof._bindings}.items():
        result['shared:'+name]=fn
    return result


def _schema():
    return json.loads(json.dumps({'declaration':candidate.DECLARATION,'kinds':producer.NATIVE_KINDS,
        'producer':{name:getattr(producer,name)for name in('KIND','CHECK','OPTION','MARKER','SCHEMA','MAX_CONTENT','MAX_VALUE','MAX_LITERALS')},
        'inherited_limits':{name:producer._GLOBALS[name]for name in('MAX_WIRE','MAX_TOTAL','MAX_SECONDS','MAX_LEAKS','MAX_LOCATIONS')},
        'patterns':{name:{'pattern':getattr(producer,name).pattern,'flags':getattr(producer,name).flags}for name in('_NAME','_DNS')},
        'engines':{'kingfisher':scanning.KINGFISHER_VERSION,'trufflehog':scanning.TRUFFLEHOG_VERSION}}))


def _clone_bindings():
    privacy=sys.modules['peaso.collectors.k8s_selected_log_sample_secret_indicators']
    if (producer.predecessor is not sys.modules['peaso.collectors.k8s_literal_secret_indicators']
            or candidate.predecessor is not sys.modules['peaso.checks.k8s_literal_secret_review_20261020']
            or candidate.source is not producer or producer.private_native_logs is not privacy.private_native_logs
            or producer._wire_debug_enabled is not privacy._wire_debug_enabled
            or k8s._BoundedPool is not _POOL_CLASS or k8s.K8sReader is not _READER_CLASS):
        raise RuntimeError('metadata imported runtime binding changed')
    if producer._GLOBALS.get('_extract')is not producer._extract or producer._GLOBALS.get('_read')is not producer._read:
        raise RuntimeError('metadata private reader replacement')
    for name in producer._REUSED:
        fn=producer._NATIVE_READ if name=='_read'else producer._GLOBALS[name]
        original=getattr(producer.predecessor,name)
        if (not isinstance(fn,types.FunctionType)or fn is not _CLONES[name]
                or fn.__globals__ is not producer._GLOBALS or fn.__closure__!=original.__closure__
                or fn.__code__ is not original.__code__ or fn.__defaults__!=original.__defaults__
                or fn.__kwdefaults__!=original.__kwdefaults__):
            raise RuntimeError('metadata cloned reader changed')
        if name in('enabled','selected_targets','identity','_path')and getattr(producer,name)is not fn:
            raise RuntimeError('metadata exported clone changed')
    for name in('KIND','CHECK','OPTION','MARKER','SCHEMA','NATIVE_KINDS'):
        if producer._GLOBALS[name]!=getattr(producer,name):raise RuntimeError('metadata private namespace changed')
    for name in('Incomplete','MAX_WIRE','MAX_TOTAL','MAX_SECONDS','MAX_CONTENT','MAX_VALUE','MAX_LITERALS','MAX_LEAKS','MAX_LOCATIONS',
                'scan_content','merge_leaks','redact_matches','_fingerprint','_NAMESPACE','_NAME','json','time','urlsplit','deepcopy'):
        if producer._GLOBALS[name]is not getattr(producer.predecessor,name):
            raise RuntimeError('metadata inherited runtime binding changed')
    for name in('KIND','MARKER','SCHEMA','NATIVE_KINDS'):
        if candidate._GLOBALS[name]!=getattr(producer,name):raise RuntimeError('metadata consumer namespace changed')
    fn=candidate._evaluate;original=candidate.predecessor.evaluate
    if (fn is not _CONSUMER_CLONE or fn.__globals__ is not candidate._GLOBALS or fn.__code__ is not original.__code__
            or fn.__closure__!=original.__closure__ or fn.__defaults__!=original.__defaults__):
        raise RuntimeError('metadata consumer clone changed')
    for name in('merge_leaks','deepcopy','json','re','MAX_CONTENT','MAX_WIRE','MAX_LITERALS','MAX_LEAKS','MAX_LOCATIONS','KINGFISHER_VERSION','TRUFFLEHOG_VERSION'):
        if candidate._GLOBALS[name]is not getattr(candidate.predecessor,name):
            raise RuntimeError('metadata consumer inherited binding changed')
    if producer.Incomplete is not producer.predecessor.Incomplete or producer.redact_output.__globals__['predecessor']is not producer.predecessor:
        raise RuntimeError('metadata predecessor binding changed')


def reviewed_inputs(root=None):
    """Return fresh (receipt, native CASES, declaration, evaluator), never register."""
    root=Path(root or Path(__file__).resolve().parents[2]).resolve()
    try:
        raw=(root/'peaso/checks'/RECEIPT).read_bytes()
        if _hash(raw)!=RECEIPT_SHA256:raise RuntimeError('metadata admission receipt changed')
        receipt=json.loads(raw,object_pairs_hook=proof._pairs)
        if json.dumps(receipt['schema'],sort_keys=True)!=json.dumps(_schema(),sort_keys=True)or receipt['registered']is not False:raise RuntimeError('metadata schema changed')
        for relative,expected in receipt['sources'].items():
            path=(root/relative).resolve();raw=path.read_bytes()
            if relative==receipt['helper_path']:raw=_self(raw)
            if not path.is_relative_to(root)or _hash(raw)!=expected:raise RuntimeError('metadata source changed')
        for row in receipt['fixtures']:
            path=(root/row['path']).resolve()
            if not path.is_relative_to(root)or _hash(path.read_bytes())!=row['sha256']:raise RuntimeError('metadata fixture changed')
        current=_runtime()
        if set(current)!=set(_ORIGINALS)or set(current)!=set(receipt['functions']):raise RuntimeError('metadata callable set changed')
        compiled={}
        for name,fn in current.items():
            row=receipt['functions'][name];native=inspect.unwrap(fn);path=(root/row['path']).resolve()
            if not path.is_relative_to(root):raise RuntimeError('metadata callable path changed')
            if row['path']not in compiled:compiled[row['path']]=proof._compiled_source(path.read_bytes(),str(path),sys.flags.optimize)
            matches=[(record,code)for record,code in compiled[row['path']]if record['qualname']==row['qualname']]
            codes=[code for record,code in matches]
            if len(matches)!=1 or matches[0][0]['source_sha256']!=row['sha256']:
                raise RuntimeError('metadata exact disk source changed')
            if (fn is not _ORIGINALS[name]or native is not _INNERS[name]
                    or _hash(inspect.getsource(native).encode())!=row['sha256']or len(codes)!=1
                    or json.dumps(proof._code(native.__code__),sort_keys=True)!=json.dumps(proof._code(codes[0]),sort_keys=True)
                    or native.__globals__ is not vars(sys.modules[native.__module__])
                    or json.dumps(native.__defaults__,sort_keys=True)!=json.dumps(row['defaults'],sort_keys=True)
                    or json.dumps(native.__kwdefaults__,sort_keys=True)!=json.dumps(row['kwdefaults'],sort_keys=True)):
                raise RuntimeError('metadata executing callable changed')
            if isinstance(fn,types.FunctionType)and(fn.__code__ is not _CODES[name]or fn.__closure__!=_CLOSURES[name]):
                raise RuntimeError('metadata wrapper changed')
        _clone_bindings()
        cases=json.loads((root/'peaso/checks'/CASES).read_bytes(),object_pairs_hook=proof._pairs)
        if set(cases)!={producer.CHECK}:raise RuntimeError('metadata CASES changed')
        case=cases[producer.CHECK]
        for branch in('pass','fail','unknown'):
            if candidate.evaluate(deepcopy(case[branch]),deepcopy(case[branch+'_index']))[0]!=branch.upper():
                raise RuntimeError('metadata native witness changed')
        for branch in('missing','malformed'):
            if candidate.evaluate(deepcopy(case[branch]),deepcopy(case['index']))[0]!='UNKNOWN':
                raise RuntimeError('metadata unavailable witness changed')
        return receipt,cases,deepcopy(candidate.DECLARATION),candidate.evaluate
    except RuntimeError:raise
    except(OSError,ValueError,TypeError,KeyError,AttributeError,IndexError):
        raise RuntimeError('malformed metadata admission inputs')from None


_ORIGINALS=_runtime()
_INNERS={name:inspect.unwrap(fn)for name,fn in _ORIGINALS.items()}
_CODES={name:fn.__code__ for name,fn in _ORIGINALS.items()if isinstance(fn,types.FunctionType)}
_CLOSURES={name:fn.__closure__ for name,fn in _ORIGINALS.items()if isinstance(fn,types.FunctionType)}
_CLONES={name:producer._NATIVE_READ if name=='_read'else producer._GLOBALS[name]for name in producer._REUSED}
_CONSUMER_CLONE=candidate._evaluate

_POOL_CLASS=k8s._BoundedPool
_READER_CLASS=k8s.K8sReader
