"""Unregistered metadata-only interpretation of the reviewed detector contract."""
from types import FunctionType
from copy import deepcopy
import re
from . import k8s_literal_secret_review_20261020 as predecessor
from peaso.collectors import k8s_selected_metadata_secret_indicators_20261020 as source

CHECK=source.CHECK
_GLOBALS={**vars(predecessor),'__name__':__name__,'CHECK':CHECK,'KIND':source.KIND,'MARKER':source.MARKER,
          'SCHEMA':source.SCHEMA,'NATIVE_KINDS':source.NATIVE_KINDS}
_original=predecessor._evaluate_legacy
_evaluate=FunctionType(_original.__code__,_GLOBALS,'_evaluate',_original.__defaults__,_original.__closure__)
DECLARATION={'id':CHECK,'provider':'k8s','category':'exposure','kind':source.KIND,'severity':'high',
    'finding_type':'secrets','ui_group':'Secrets','dependencies':[source.KIND],'requirements':[],
    'allow_incomplete_failure':True,'title':'Selected object labels and annotations have no detected secrets',
    'remediation':'Remove credential literals from object metadata and rotate confirmed exposed credentials. Use an appropriate secret reference instead.',
    'scope':'Top-level labels and annotations of exact selected supported objects only; no template metadata, references, files, Secrets, logs, images or execution.'}


def _bounded_partial_hit(item,index):
    """Validate an observed hit without asserting absence on uncollected targets."""
    try:
        scope=index['context']['scope']
        own,=[row for row in index['collections'][source.KIND]if row.get('scope')==scope]
        selected=index['context']['metadata'][source.KIND+'_selection'][scope]
        ids=[row.get('id')for row in own['items']]
        if (own.get('status')!='partial'or own.get('error',{}).get('code')!='resource_limit'
                or not isinstance(selected,list)or not 1<=len(selected)<=8 or len(set(selected))!=len(selected)
                or any(not isinstance(value,str)or not re.fullmatch(source.KIND+':[0-9a-f]{64}',value)for value in selected)
                or not 1<=len(ids)<len(selected)or len(set(ids))!=len(ids)or not set(ids)<set(selected)
                or sum(row==item for row in own['items'])!=1):
            return None
        # Only the delegate's membership view is narrowed. Native source receipts,
        # actual selection evidence, scope, rows and partial status stay intact.
        projected=deepcopy(index)
        projected['context']['metadata'][source.KIND+'_selection'][scope]=ids
        outcome=_evaluate(item,projected)
        return outcome if outcome[0]=='FAIL'and outcome[1].get('complete')is False else None
    except (KeyError,TypeError,ValueError,AttributeError):
        return None


def evaluate(item,index):
    status,evidence=_evaluate(item,index)
    if status=='UNKNOWN':
        outcome=_bounded_partial_hit(item,index)
        if outcome is not None:status,evidence=outcome
    if status in('PASS','FAIL'):
        evidence['coverage']='selected_object_metadata_only'if evidence['complete']else'incomplete_selected_object_metadata'
        evidence['observed']=('A likely secret was detected in the selected object labels or annotations. Its value is hidden and was not validated.'if status=='FAIL'else'Both offline detectors completed without detecting a supported secret in the selected object labels and annotations.')
        if not evidence['complete']:evidence['observed']+=' Inspection is incomplete.'
    else:
        evidence={'observed':'Selected object metadata was unavailable, changed or incompletely inspected. A clean result cannot be established.'}
    return status,evidence
