"""Atomic, source-bound admission of one optional selected S3 source check."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import types

RECEIPT = 'aws_s3_selected_source_runtime_admission_20261020.json'


def _constant(value):
    if isinstance(value, types.CodeType):return _code(value)
    if isinstance(value, (tuple, list)):return [_constant(v) for v in value]
    if isinstance(value, frozenset):return sorted((_constant(v) for v in value), key=repr)
    if isinstance(value, bytes):return {'bytes': value.hex()}
    if value is None or type(value) in (str, int, float, bool):return value
    if value is Ellipsis:return {'ellipsis': True}
    raise RuntimeError('Unreviewed S3 callable constant')


def _code(code):
    return {'bytecode':code.co_code.hex(),'constants':[_constant(v) for v in code.co_consts],
        'names':code.co_names,'variables':code.co_varnames,'free':code.co_freevars,'cells':code.co_cellvars,
        'args':(code.co_argcount,code.co_posonlyargcount,code.co_kwonlyargcount),
        'flags':code.co_flags,'exceptions':getattr(code,'co_exceptiontable',b'').hex()}


def proof(function):
    fn=inspect.unwrap(function);root=Path(__file__).resolve().parents[2]
    path=Path(inspect.getsourcefile(fn)).resolve()
    if not path.is_relative_to(root):raise RuntimeError('S3 callable source outside package')
    module=importlib.import_module(fn.__module__);actual=module
    expected=compile(path.read_bytes(),str(path),'exec')
    for name in fn.__qualname__.split('.'):
        if name=='<locals>':raise RuntimeError('Unreviewed S3 callable closure')
        actual=getattr(actual,name)
        matches=[v for v in expected.co_consts if isinstance(v,types.CodeType) and v.co_name==name]
        if len(matches)!=1:raise RuntimeError('S3 callable definition ambiguous')
        expected=matches[0]
    if inspect.unwrap(actual) is not fn or _code(fn.__code__)!=_code(expected):
        raise RuntimeError('S3 callable memory changed')
    lines,line=inspect.getsourcelines(fn);body=''.join(lines)
    return {'module':fn.__module__,'qualname':fn.__qualname__,'path':str(path.relative_to(root)),
        'sha256':hashlib.sha256(body.encode()).hexdigest()}



def schema(module):
    def stable(value):
        if isinstance(value,(set,frozenset)):return sorted((stable(v) for v in value),key=repr)
        if isinstance(value,tuple):return [stable(v)for v in value]
        if hasattr(value,'pattern')and hasattr(value,'flags'):return {'pattern':value.pattern,'flags':value.flags}
        if value is None or type(value)in(str,int,float,bool):return value
        raise RuntimeError('Unreviewed S3 schema value')
    return {name:stable(value)for name,value in vars(module).items()if name.isupper()}

def reviewed_inputs():
    root=Path(__file__).resolve().parents[2]
    receipt=json.loads(Path(__file__).with_name(RECEIPT).read_text())
    for name,digest in receipt['source_hashes'].items():
        path=(root/name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('Selected S3 source changed')
    for expected in receipt['callables']:
        fn=importlib.import_module(expected['module'])
        for name in expected['qualname'].split('.'):fn=getattr(fn,name)
        if proof(fn)!=expected:raise RuntimeError('Selected S3 callable changed')
    from peaso.collectors import aws_s3_selected_source_secret_indicators as producer
    if schema(producer)!=receipt['producer_schema']:
        raise RuntimeError('Selected S3 producer schema changed')
    for binding in receipt['bindings']:
        target=importlib.import_module(binding['module']);origin=importlib.import_module(binding['origin_module'])
        if getattr(target,binding['name']) is not getattr(origin,binding['origin_name']):
            raise RuntimeError('Selected S3 callable binding changed')
    fixture=receipt['fixture'];path=(root/fixture['path']).resolve()
    if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=fixture['sha256']:
        raise RuntimeError('Selected S3 native fixtures changed')
    from .aws_s3_selected_source_secret_review_20261020 import evaluate,CHECK
    cases=json.loads(path.read_text())
    if set(cases)!={CHECK} or not {'pass','fail','unknown','pass_index','fail_index','unknown_index'}<=set(cases[CHECK]):
        raise RuntimeError('Selected S3 native branches missing')
    for branch in ('pass','fail','unknown'):
        if evaluate(cases[CHECK][branch],cases[CHECK][branch+'_index'])[0]!=branch.upper():
            raise RuntimeError('Selected S3 native branch changed')
    return cases


def install():
    from . import CHECKS,register
    from .fixtures import CASES
    from . import aws_s3_selected_source_secret_review_20261020 as reviewed
    cases=reviewed_inputs();declaration,=reviewed.DECLARATIONS
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
