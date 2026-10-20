"""Validate production scan provenance, then reuse immutable Function predicates.

Only the two validated additive provenance keys are removed in copied inputs.
No native fields, statuses or legacy predicate requirements are synthesized.
"""
from copy import deepcopy
import re
from . import azure_function_settings_review_20261020 as predecessor
from peaso.collectors import azure_function_settings_declarations_20261020 as source


def _bound(item,index):
    context=index['context'];meta=context['metadata'];scope=context['scope']
    capture=meta['credential_context_id'];customer=meta['customer_context_id'];tenant=meta['tenant_id']
    if (context['provider']!='azure' or not isinstance(scope,str)or not source._SCOPE.fullmatch(scope)
            or meta['context_binding']!='scan_local' or meta['tenant_verified']is not True
            or not isinstance(capture,str)or not re.fullmatch('[0-9a-f]{32}',capture)
            or customer!='scan-local:'+capture or not isinstance(tenant,str)or not source.GUID.fullmatch(tenant)
            or meta[source.KIND+'_capture']!=capture or meta[source.KIND+'_tenant'].casefold()!=tenant.casefold()):
        raise ValueError('parent_unbound')
    own,=[c for c in index['collections'][source.KIND]if c.get('scope')==scope]
    if (set(own['_provenance'])!={'credential_context_id','customer_context_id'}
            or own['_provenance']['credential_context_id']!=capture or own['_provenance']['customer_context_id']!=customer
            or not isinstance(own['items'],list)or not 1<=len(own['items'])<=source.MAX_TARGETS
            or sum(row==item for row in own['items'])!=1):raise ValueError('collection_unbound')
    expected={'scope','capture','tenant_id','source_requests','credential_context_id','customer_context_id'}
    for row in own['items']:
        proof=row['_provenance']
        if (set(proof)!=expected or proof['credential_context_id']!=capture or proof['customer_context_id']!=customer
                or proof['scope']!=scope or proof['capture']!=capture or proof['tenant_id'].casefold()!=tenant.casefold()
                or row[source.MARKER]['capture']!=capture or row[source.MARKER]['scope']!=scope):raise ValueError('item_unbound')
    projected=deepcopy(own)
    for row in projected['items']:
        row['_provenance'].pop('credential_context_id');row['_provenance'].pop('customer_context_id')
    selected=next(row for row,original in zip(projected['items'],own['items'])if original==item)
    # Only the consumed collection/context view is copied; every other native
    # payload field is passed unchanged to the original exact-shape guards.
    projected_index={'context':deepcopy(context),'collections':{source.KIND:[projected]}}
    return selected,projected_index


def _evaluate(item,index,check):
    try:
        projected,view=_bound(item,index)
        return predecessor._evaluate(projected,view,check)
    except(KeyError,TypeError,ValueError,AttributeError,IndexError,StopIteration):
        return 'UNKNOWN',{'observed':'The selected Function declaration lacks coherent native scan provenance.',
            'coverage':'incomplete_selected_function_configuration'}


def telemetry(item,index):return _evaluate(item,index,source.TELEMETRY)


def runtime(item,index):return _evaluate(item,index,source.RUNTIME)


PROPOSALS=[{**row,'evaluate':telemetry if row['id']==source.TELEMETRY else runtime}for row in predecessor.PROPOSALS]
