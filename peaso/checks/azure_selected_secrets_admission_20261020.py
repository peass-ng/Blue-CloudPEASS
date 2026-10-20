"""Atomic admission of three exact native selected-content proposals."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path

RECEIPT_SHA256='407816905ba6de0885241a275040d3227aee90d7fa3039ea830788ef8ee75009'
MODULES=('azure_selected_configuration_secret_review_20261020','azure_selected_storage_secret_review_20261020','azure_devops_selected_content_secret_review_20261020')


def reviewed_inputs(root=None):
    root=Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw=(root/'peaso/checks/azure_selected_secrets_admission_20261020.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=RECEIPT_SHA256:raise RuntimeError('Selected Azure admission receipt changed')
    receipt=json.loads(raw)
    if receipt.get('schema_version')!=1 or tuple(row['module'] for row in receipt['checks'])!=MODULES:raise RuntimeError('Selected Azure admission declarations changed')
    for name,digest in receipt['sources'].items():
        path=(root/name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise RuntimeError('Selected Azure reviewed source changed')
    fixture=receipt['fixture'];path=(root/fixture['path']).resolve()
    if not path.is_relative_to(root/'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest()!=fixture['sha256']:raise RuntimeError('Selected Azure native fixture changed')
    cases=json.loads(path.read_text());declarations=[]
    if set(cases)!={row['declaration']['id'] for row in receipt['checks']}:raise RuntimeError('Selected Azure native fixture identities changed')
    for row in receipt['checks']:
        module=importlib.import_module('.'+row['module'],__package__);function=module.evaluate;metadata=module.DECLARATIONS[0]
        if (function is not inspect.unwrap(function) or metadata!=row['declaration']
                or hashlib.sha256(inspect.getsource(function).encode()).hexdigest()!=row['predicate_sha256']):raise RuntimeError('Selected Azure evaluator changed')
        case=cases[metadata['id']]
        if not {'pass','pass_index','fail','fail_index','unknown','unknown_index','missing','malformed','index'}<=set(case):raise RuntimeError('Selected Azure native branches missing')
        for branch in ('pass','fail','unknown'):
            if function(case[branch],case[branch+'_index'])[0]!=branch.upper():raise RuntimeError('Selected Azure native branch changed')
        for branch in ('missing','malformed'):
            if function(case[branch],case['index'])[0]!='UNKNOWN':raise RuntimeError('Selected Azure malformed native branch changed')
        declarations.append((metadata,function))
    return receipt,cases,declarations


def _signature(check):
    return (check.provider,check.category,check.kind,check.title,check.severity,check.control,check.remediation,tuple(check.dependencies),check.allow_incomplete_failure)


def install():
    from . import CHECKS,register
    from .fixtures import CASES
    receipt,cases,declarations=reviewed_inputs()
    for metadata,function in declarations:
        ident=metadata['id'];matches=[c for c in CHECKS if c.id==ident]
        expected=('azure',metadata['category'],metadata['kind'],metadata['title'],'high','security_configuration',metadata['remediation'],tuple(metadata['dependencies']),True)
        if len(matches)>1 or matches and (inspect.unwrap(matches[0].evaluate) is not function or _signature(matches[0])!=expected):raise RuntimeError('Selected Azure registration collision')
        if ident in CASES and CASES[ident]!=cases[ident]:raise RuntimeError('Selected Azure native fixture collision')
    before=tuple(CHECKS);previous={ident:deepcopy(CASES[ident]) for ident in cases if ident in CASES}
    try:
        for metadata,function in declarations:
            ident=metadata['id']
            if not any(c.id==ident for c in CHECKS):
                register(ident,'azure',metadata['category'],metadata['kind'],metadata['title'],'high','security_configuration',metadata['remediation'],
                         dependencies=metadata['dependencies'],allow_incomplete_failure=True)(function)
            CASES[ident]=deepcopy(cases[ident])
    except Exception:
        CHECKS[:]=before
        for ident in cases:
            if ident in previous:CASES[ident]=previous[ident]
            else:CASES.pop(ident,None)
        raise
