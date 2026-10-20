"""Atomic source-bound admission of final native Azure edge criteria.

Historical signed source and CASES remain unchanged; the visible-URL criterion
has its own ID and does not inherit hidden-repository completeness requirements.
"""
from copy import deepcopy
from dataclasses import replace
from functools import wraps
import hashlib
import inspect
import json
from pathlib import Path


def _inputs():
    root=Path(__file__).resolve().parents[2]
    receipt=json.loads(Path(__file__).with_suffix('.json').read_text())
    if receipt.get('schema_version')!=1:
        raise RuntimeError('Unrecognized Azure edge admission')
    for row in receipt['sources']:
        p=(root/row['path']).resolve()
        if not p.is_relative_to(root) or hashlib.sha256(p.read_bytes()).hexdigest()!=row['sha256']:
            raise RuntimeError('Reviewed Azure edge source changed')
    p=(root/receipt['fixtures']['path']).resolve()
    if not p.is_relative_to(Path(__file__).parent) or hashlib.sha256(p.read_bytes()).hexdigest()!=receipt['fixtures']['sha256']:
        raise RuntimeError('Reviewed Azure edge fixture changed')
    cases=json.loads(p.read_text())
    if set(cases)!={receipt['new_check_id']} or any(not {'pass','fail','unknown','pass_index','fail_index','unknown_index'}<=set(row)for row in cases.values()):
        raise RuntimeError('Azure edge native witnesses are incomplete')
    return receipt,cases


def _display(function,cid):
    @wraps(function)
    def evaluate(item,index):
        status,evidence=function(item,index)
        if status in ('PASS','FAIL'):
            evidence={**evidence,'native_review_id':cid,'native_review_satisfied':status=='PASS','runtime_protection':'not_tested'}
        return status,evidence
    evaluate._azure_edge_admission_20261020=cid
    return evaluate


def install():
    from . import CHECKS,register
    from .fixtures import CASES
    from . import azure_public_edge_config_review_20261020 as edge
    from . import azure_gateway_logging_review_20261020 as logs
    from . import azure_devops_visible_urls_review_20261020 as devops
    receipt,cases=_inputs()
    specifications={edge.CHECK:(edge.evaluate,None),logs.CHECK:(logs.evaluate,logs.DEPENDENCIES)}
    # Verify all predecessors before changing any registry entry.
    for cid,(fn,deps)in specifications.items():
        existing=next(c for c in CHECKS if c.id==cid)
        if getattr(existing.evaluate,'_azure_edge_admission_20261020',None)==cid:
            if inspect.unwrap(existing.evaluate)is not fn:
                raise RuntimeError('Azure edge successor identity changed')
        elif hashlib.sha256(inspect.getsource(inspect.unwrap(existing.evaluate)).encode()).hexdigest()!=receipt['predecessor_evaluators'][cid]:
            raise RuntimeError('Azure edge predecessor evaluator changed')
    registered=next((c for c in CHECKS if c.id==devops.CHECK),None)
    if registered is not None and (inspect.unwrap(registered.evaluate)is not devops.evaluate or getattr(registered.evaluate,'_azure_edge_admission_20261020',None)!=devops.CHECK):
        raise RuntimeError('Azure visible-URL admission overlaps another evaluator')
    before=tuple(CHECKS);previous=deepcopy(CASES.get(devops.CHECK))
    try:
        for cid,(function,dependencies)in specifications.items():
            old=next(c for c in CHECKS if c.id==cid)
            if getattr(old.evaluate,'_azure_edge_admission_20261020',None)==cid:continue
            position=CHECKS.index(old);CHECKS.remove(old)
            register(cid,old.provider,old.category if old.category in ('hardening','exposure','least_privilege','iam_graph','network') else 'hardening','application_gateway'if cid==logs.CHECK else old.kind,
                     'Application Gateway declares HTTP access-log export'if cid==logs.CHECK else old.title,
                     old.severity,old.control,old.remediation,target=old.target,
                     dependencies=dependencies or old.dependencies,
                     allow_incomplete_failure=old.allow_incomplete_failure,
                     empty_applicability_dependencies=logs.EMPTY_APPLICABILITY_DEPENDENCIES if cid==logs.CHECK else old.empty_applicability_dependencies)(_display(function,cid))
            CHECKS.insert(position,replace(CHECKS.pop(),category=old.category))
        if registered is None:
            d=devops.DECLARATION
            register(devops.CHECK,'azure','exposure',d['kind'],d['title'],d['severity'],'security_configuration',d['remediation'],target='scope',dependencies=d['dependencies'])(_display(devops.evaluate,devops.CHECK))
            CASES[devops.CHECK]=deepcopy(cases[devops.CHECK])
    except Exception:
        CHECKS[:]=before
        if previous is None:CASES.pop(devops.CHECK,None)
        else:CASES[devops.CHECK]=previous
        raise
