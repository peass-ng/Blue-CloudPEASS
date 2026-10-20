"""Atomic native-source admission of eight kubelet ConfigMap declarations."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import types

from . import k8s_annotation_native_admission_20261020 as proof
from . import k8s_kubelet_configmap_review_20261020 as candidate
from peaso.collectors import k8s_kubelet_configmap_indicators_20261020 as producer

RECEIPT = 'k8s_kubelet_configmap_admission_log_successor_20261020.json'
MARK = '_kubelet_configmap_admission_20261020'
IDS = candidate.IDS


def _hash(raw):
    return hashlib.sha256(raw if isinstance(raw,bytes) else raw.encode()).hexdigest()


def _metadata(check):
    return {key:getattr(check,key) for key in ('id','provider','category','kind','title','severity','control','remediation','target','allow_incomplete_failure')} | {
        'declared_dependencies':list(check.declared_dependencies),
        'empty_applicability_dependencies':list(check.empty_applicability_dependencies)}


def _schema():
    return {'producer':{key:getattr(producer,key) for key in ('KIND','MARKER','SCHEMA','PREFIX','MAX_YAML_BYTES','MAX_TOKENS',
        'MAX_DEPTH','MAX_PAGE_BYTES','MAX_TOTAL_BYTES','MAX_PAGES','MAX_TARGETS','MAX_SECONDS','FIELDS')},
        'ciphers':sorted(producer.CIPHERS),'other_ciphers':sorted(producer.KNOWN_OTHER_CIPHERS),
        'ids':list(candidate.IDS),'specs':candidate.SPECS,'limit':candidate.LIMIT,'declarations':candidate.DECLARATIONS}


def _execution(function, records):
    """Reuse current-interpreter code proof; never execute compiled source."""
    module=sys.modules.get(function.__module__) if isinstance(function,types.FunctionType) else None
    if module is None or function.__globals__ is not vars(module):
        raise RuntimeError('Kubelet declaration executing callable changed')
    matches=[code for record,code in records if record['qualname']==function.__qualname__]
    if len(matches)!=1 or json.dumps(proof._code(function.__code__),sort_keys=True,allow_nan=False)!=json.dumps(proof._code(matches[0]),sort_keys=True,allow_nan=False):
        raise RuntimeError('Kubelet declaration executing code changed')


def reviewed_inputs():
    root=Path(__file__).resolve().parents[2]
    try:
        receipt=json.loads(Path(__file__).with_name(RECEIPT).read_text(),object_pairs_hook=proof._pairs)
        if (set(receipt)!={'schema_version','ids','sources','fixture','schema','metadata'} or receipt['schema_version']!=1
                or receipt['ids']!=list(IDS) or set(receipt['metadata'])!=set(IDS)):
            raise RuntimeError('Unrecognized kubelet declaration admission')
        expected_paths={str(Path(m.__file__).resolve().relative_to(root)) for m in (producer,candidate,sys.modules[__name__])}
        if set(receipt['sources'])!=expected_paths:
            raise RuntimeError('Kubelet declaration source set changed')
        compiled={}
        for relative,expected in receipt['sources'].items():
            path=(root/relative).resolve();raw=path.read_bytes()
            if not path.is_relative_to(root) or _hash(raw)!=expected:
                raise RuntimeError('Kubelet declaration source changed')
            compiled[relative]=proof._compiled_source(raw,str(path),sys.flags.optimize)
        for module in (producer,candidate):
            records=compiled[str(Path(module.__file__).resolve().relative_to(root))]
            for name,function in vars(module).items():
                if isinstance(function,types.FunctionType) and function.__module__==module.__name__:
                    _execution(function,records)
            if module is producer:
                _execution(producer._DistinctLoader.construct_mapping,records)
        if json.loads(json.dumps(_schema()))!=receipt['schema']:
            raise RuntimeError('Kubelet declaration schema changed')
        # Shared source proof already verifies narrow register/collect/_native
        # ancestors and their executing functions, without pinning shared files.
        proof._reviewed_inputs()
        fixture=receipt['fixture'];path=(root/fixture['path']).resolve()
        if set(fixture)!={'path','sha256'} or not path.is_relative_to(Path(__file__).parent) or _hash(path.read_bytes())!=fixture['sha256']:
            raise RuntimeError('Kubelet declaration native fixtures changed')
        cases=json.loads(path.read_text(),object_pairs_hook=proof._pairs)
        if set(cases)!=set(IDS) or any(set(v)!={'pass','pass_index','fail','fail_index','unknown','unknown_index','missing','malformed','index'} for v in cases.values()):
            raise RuntimeError('Kubelet declaration native fixtures incomplete')
        for cid in IDS:
            for branch in ('pass','fail','unknown'):
                if candidate.evaluate(cid,deepcopy(cases[cid][branch]),deepcopy(cases[cid][branch+'_index']))[0]!=branch.upper():
                    raise RuntimeError('Kubelet declaration native witness changed')
        return receipt,cases,compiled
    except RuntimeError:
        raise
    except (KeyError,TypeError,ValueError,AttributeError,OSError,IndexError):
        raise RuntimeError('Malformed kubelet declaration admission') from None


def _verify(check,receipt,compiled):
    if _metadata(check)!=receipt['metadata'][check.id] or getattr(check.evaluate,MARK,None)!=check.id:
        raise RuntimeError('Kubelet declaration registration metadata changed')
    safe=check.evaluate;bindings=proof._bindings(safe)
    if getattr(safe,'evaluate_empty_inventory',None) is not candidate.evaluate_empty:
        raise RuntimeError('Kubelet declaration empty callback changed')
    if (set(bindings)!={'checked','id','kind','provider','target'} or
            any(bindings[k]!=getattr(check,k) for k in ('id','kind','provider','target'))):
        raise RuntimeError('Kubelet declaration safe wrapper binding changed')
    checked=bindings['checked'];inner=proof._bindings(checked)
    if set(inner)!={'function'} or safe.__wrapped__ is not inner['function']:
        raise RuntimeError('Kubelet declaration checked wrapper binding changed')
    proof._trusted_definition(safe);proof._trusted_definition(checked)
    leaf=inner['function'];records=compiled[str(Path(candidate.__file__).resolve().relative_to(Path(__file__).resolve().parents[2]))]
    _execution(leaf,records)
    if (leaf.__globals__ is not vars(candidate) or proof._bindings(leaf)!={'check_id':check.id}
            or leaf.__defaults__ is not None or leaf.__kwdefaults__ is not None
            or getattr(leaf,'evaluate_empty_inventory',None) is not candidate.evaluate_empty):
        raise RuntimeError('Kubelet declaration factory closure changed')


def install():
    from . import CHECKS,register
    from .fixtures import CASES
    receipt,cases,compiled=reviewed_inputs()
    from peaso.collectors import k8s
    if k8s.TYPES.count(producer.KIND)!=1 or producer.KIND in k8s.ENDPOINTS:
        raise RuntimeError('Kubelet declaration dedicated producer kind unavailable')
    found={cid:[c for c in CHECKS if c.id==cid] for cid in IDS}
    if any(len(rows)>1 for rows in found.values()) or any(found.values()) and not all(found.values()):
        raise RuntimeError('Kubelet declaration registration collision')
    if all(found.values()):
        for cid,rows in found.items():
            _verify(rows[0],receipt,compiled)
            if CASES.get(cid)!=cases[cid]:raise RuntimeError('Kubelet declaration CASES changed')
        return
    if any(cid in CASES for cid in IDS):raise RuntimeError('Kubelet declaration CASES collision')
    before=tuple(CHECKS);prior={cid:deepcopy(CASES[cid]) for cid in IDS if cid in CASES}
    try:
        for spec in candidate.DECLARATIONS:
            cid=spec['id']
            register(cid,'k8s','hardening',producer.KIND,spec['title'],spec['severity'],spec['control'],
                spec['remediation'],dependencies=[producer.KIND])(candidate.evaluate_for(cid))
            check=CHECKS[-1];setattr(check.evaluate,MARK,cid)
            _verify(check,receipt,compiled)
            for branch in ('pass','fail','unknown'):
                if check.evaluate(deepcopy(cases[cid][branch]),deepcopy(cases[cid][branch+'_index']))[0]!=branch.upper():
                    raise RuntimeError('Kubelet declaration registered witness changed')
            CASES[cid]=deepcopy(cases[cid])
    except Exception:
        CHECKS[:]=before
        for cid in IDS:
            if cid in prior:CASES[cid]=prior[cid]
            else:CASES.pop(cid,None)
        raise
