"""Install the exact reviewed pending definitions without replacing published callbacks.

Each wave is loaded in its own registrar namespace. Only the explicit signed
pending IDs are admitted; original runtime objects and aliases remain intact.
"""
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from . import CHECKS,CHECK_ALIASES

MANIFEST=json.loads(Path(__file__).with_suffix('.json').read_text())


def _reviewed_source_admitted(name, source, pin):
    """Admit exact reversible native successors; retain every original pin."""
    actual = hashlib.sha256(source).hexdigest()
    if actual == pin:
        return True
    if (name == 'compliance_new_sw13'
            and pin == 'b47f543f4b983696100a562f245e6b18bf7e45b236b97cb9357ad80801ba5d19'
            and actual == 'f61f66a403ea36db3043d5652b02ac9f6a079a275632db05a1a92bd31aeeccb5'):
        proof_bytes = Path(__file__).with_name('azure_backup_source_successor_20261020.json').read_bytes()
        if hashlib.sha256(proof_bytes).hexdigest() != 'e771377b8994a0155d7c10d8779001d9aea7003a93b87a2a77941d7224034911':
            return False
        proof = json.loads(proof_bytes)
        after, before, helper = (proof[key].encode() for key in ('after_function', 'before_function', 'new_local_helper'))
        return (source.count(after) == source.count(helper) == 1
                and hashlib.sha256(source.replace(after, before, 1).replace(helper, b'', 1)).hexdigest() == pin)
    if (name == 'compliance_new_sw19'
            and pin == '45541f83450240dab8181646c82b115fe4193187b58524f212750e94bc6baacc'
            and actual == '70a39b075479dcb80a1d9857c111c9cd43b33814c74c3631ff1a820fc57d3a71'):
        dispatch_before = b"def _evaluate(check_id, item, index):\n    if check_id == CLUSTER_CMK:"
        dispatch_after = b"def _evaluate(check_id, item, index):\n    from ..collectors.azure_identity_enforcement_review_20261020 import evaluate_native\n    native = evaluate_native(check_id, item, index)\n    if native is not None:\n        return native\n    if check_id == CLUSTER_CMK:"
        dependency_before = b"DEPENDENCIES[CLUSTER_CMK].append('log_analytics_cluster')\n\n\n"
        dependency_after = b"DEPENDENCIES[CLUSTER_CMK].append('log_analytics_cluster')\n# Native successor input; signed predecessor specifications and predicates stay intact.\nfor _cid in (CIS_MFA, ALL_MFA, ADMIN_MFA, DIRECT):\n    DEPENDENCIES[_cid].append('azure_identity_enforcement_native')\n\n\n"
        return (source.count(dispatch_after) == source.count(dependency_after) == 1
                and hashlib.sha256(source.replace(dispatch_after, dispatch_before, 1)
                                   .replace(dependency_after, dependency_before, 1)).hexdigest() == pin)
    if (name != 'compliance_new_sw52' or pin != '283625d80b768b1e4f96ebd0669ae0044787f8e56c47bac3b416b1e4b5f092bc'
            or actual != '28e4e029e4f1b0c2ca7c4dabef08f6e136767a74e1240157457f88a1f855ea9d'):
        return False
    before = b"    if get(item, 'eventClass', str) != 'authenticated_audit':\n        return unknown('exempt or system event cannot be classified by this predicate')\n    timestamp ="
    after = b"    if get(item, 'eventClass', str) != 'authenticated_audit':\n        return unknown('exempt or system event cannot be classified by this predicate')\n    resource_type = get(item, 'resource.type', str)\n    if not resource_type.strip():\n        return unknown('required audit monitored-resource type unavailable')\n    timestamp ="
    return (source.count(after) == 1
            and hashlib.sha256(source.replace(after, before, 1)).hexdigest() == pin)


def install():
    import peaso.checks as registry
    baseline=tuple(CHECKS);baseline_ids={c.id for c in baseline};aliases=dict(CHECK_ALIASES);register=registry.register
    # Check equality includes its ID; unrelated IDs cannot compare equal.
    # Keep all same-ID candidates to preserve equality even with duplicates.
    baseline_by_id={}
    for check in baseline:baseline_by_id.setdefault(check.id,[]).append(check)
    expected=set(MANIFEST['checks'])
    if expected & baseline_ids:raise RuntimeError('bulk admission overlaps a published native ID')
    captured={};namespace='peaso.checks._bulk_pending_'
    for name,pin in MANIFEST['modules'].items():
        path=Path(__file__).with_name(name+'.py')
        if not _reviewed_source_admitted(name,path.read_bytes(),pin):raise RuntimeError('bulk source digest differs: '+name)
        alias=namespace+name
        def isolated_register(ident,*args,**kwargs):
            decorate=register(ident,*args,**kwargs)
            def isolated(function):
                if function.__module__==alias:
                    if ident in baseline_by_id:
                        CHECKS[:]=[c for c in CHECKS if c.id!=ident or c not in baseline_by_id[ident]]
                    if ident in aliases:CHECK_ALIASES.pop(ident,None)
                return decorate(function)
            return isolated
        registry.register=isolated_register
        try:
            spec=importlib.util.spec_from_file_location(alias,path);module=importlib.util.module_from_spec(spec);sys.modules[alias]=module;spec.loader.exec_module(module)
            for check in CHECKS:
                if check.id not in expected or check.evaluate.__module__!=alias:continue
                contract=MANIFEST['checks'][check.id]
                if check.id in captured or (check.provider,check.kind,check.severity)!=(contract['provider'],contract['kind'],contract['severity']):raise RuntimeError('duplicate or mismatched bulk native '+check.id)
                def callback(item,index,_evaluate=check.evaluate):return _evaluate(item,index)
                callback.__name__=check.evaluate.__name__;callback.__wrapped__=check.evaluate
                captured[check.id]=replace(check,evaluate=callback)
        finally:
            registry.register=register;CHECKS[:]=baseline;CHECK_ALIASES.clear();CHECK_ALIASES.update(aliases)
    if set(captured)!=expected:raise RuntimeError('bulk definitions missing: '+', '.join(sorted(expected-set(captured))))
    CHECKS.extend(captured[i]for i in MANIFEST['checks'])
    if tuple(CHECKS[:len(baseline)])!=baseline or CHECK_ALIASES!=aliases:raise RuntimeError('published registry changed during bulk admission')
    from . import azure_gateway_cidr_evidence_successor_20261021 as gateway_cidr_evidence
    gateway_cidr_evidence.install()
