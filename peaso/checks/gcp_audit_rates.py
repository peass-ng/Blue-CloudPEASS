"""Native AuditLog RPC names and exact five-minute principal rate observations."""
from collections import defaultdict
from bisect import bisect_left
from pathlib import Path
import json
from . import register,result,unknown
from .facts import Unavailable,get,memoized
from .gcp_audit_native import read_scope

METHODS={
 'gcp_logging_detect_t1518':{'google.cloud.osconfig.v1.OsConfigZonalService.GetInventory','google.cloud.osconfig.v1alpha.OsConfigZonalService.GetInventory'},
 'gcp_logging_detect_t1614':{'v1.compute.regions.list','v1.compute.zones.list'},
}
SERVICES={'gcp_logging_detect_t1518':'osconfig.googleapis.com','gcp_logging_detect_t1614':'compute.googleapis.com'}
SPECS=json.loads(Path(__file__).with_suffix('.json').read_text())


def evaluate(ident,item,index):
    context,coverage,policy,events,_,identities=memoized(index,'gcp-audit-v1',lambda:read_scope(index))
    if get(item,'scope',str)!=context['scope']:raise Unavailable('foreign rate evaluation scope')
    if 'data_access'not in coverage['classes']:raise Unavailable('Data Access class not selected for rate detection')
    rate=policy.get('approved_list_rate')
    if type(rate)is not int or not 0<=rate<=100000:raise Unavailable('approved list rate missing or malformed')
    # Pagination and the selected window do not attest that Data Access logging
    # is enabled. Absence of observed matching events can never PASS this check.
    grouped=defaultdict(list)
    unreadable=False
    for row,event,reason in identities.values():
        payload=row.get('protoPayload',{})
        if payload.get('methodName')not in METHODS[ident]:continue
        if reason is not None or payload.get('serviceName')!=SERVICES[ident]:unreadable=True;continue
        ts,_,principal,code,_=event
        if code==0:grouped[principal].append(ts)
    if not grouped:return unknown('No successful matching rate observations; logging enablement and event absence remain unproved')
    maximum={}
    for principal,timestamps in grouped.items():
        times=sorted(t.timestamp()for t in timestamps)
        maximum[principal]=max(i-bisect_left(times,ts-300,0,i+1)+1 for i,ts in enumerate(times))
    hits={principal:count for principal,count in maximum.items()if count>rate}
    if hits:return result(True,observed_principal_rates=hits,approved_list_rate=rate,window_seconds=300,
                          semantics='Observed successful matching RPCs in this selected log window; no audit enablement or future traffic claim')
    if unreadable:return unknown('Matching event has redacted principal/status or incorrect service')
    selected=coverage.get('detector_methods')
    if not isinstance(selected,list) or not METHODS[ident]<=set(selected):return unknown('Complete native RPC selector coverage missing')
    return result(False,observed_principal_rates=maximum,approved_list_rate=rate,window_seconds=300,
                  semantics='Observed matching RPCs only; does not certify logging coverage or event absence')


for ident,spec in SPECS.items():
    def callback(item,index,ident=ident):return evaluate(ident,item,index)
    register(ident,'gcp','hardening','audit_log',spec['title'],spec['severity'],'AU-6',spec['remediation_hint'],target='scope',dependencies=['audit_log'])(callback)
from .fixtures import CASES
CASES.update(json.loads(Path(__file__).with_name('gcp_audit_rates_fixtures.json').read_text()))
