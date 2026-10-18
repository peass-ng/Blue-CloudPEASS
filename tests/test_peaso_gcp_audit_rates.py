import copy
from datetime import datetime,timedelta,timezone
import pytest
from peaso.checks.gcp_audit_rates import METHODS
from peaso.checks import evaluate_check
from peaso.collectors.gcp_audit_native import validate_audit_options
from tests.test_gcp_audit_native import collect,event,status
from peaso.engine import evaluate_snapshot


@pytest.mark.parametrize('ident,method',[(i, m) for i, methods in sorted(METHODS.items()) for m in sorted(methods)])
def test_native_rpc_paged_collector_to_rate_engine(ident,method):
    service='osconfig.googleapis.com'if ident.endswith('1518')else 'compute.googleapis.com'
    a=event(method,service=service,identity='a',logclass='data_access')
    b=event(method,service=service,identity='b',logclass='data_access',ts='2026-10-13T00:02:00Z')
    snap,t=collect([{'entries':[a],'nextPageToken':'next'},{'entries':[b]}],classes=['data_access'],policy={'approved_list_rate':1})
    assert len(t.calls)==2 and method in t.calls[0][2]['filter']
    assert status(snap,ident)=='FAIL'
    # A fixture's approved rate is organizational policy, not native evidence.
    # Retain evaluator regressions while proving automated scans reject it.
    before = copy.deepcopy(snap)
    with pytest.raises(ValueError, match='requires external policy or manual evidence'):
        evaluate_snapshot(snap, checks=[ident])
    assert snap == before
    snap,_=collect([{'entries':[a]}],classes=['data_access'],policy={'approved_list_rate':1})
    assert status(snap,ident)=='PASS'
    for policy in ({},{'approved_list_rate':True}):
        if policy.get('approved_list_rate')is True:
            with pytest.raises(ValueError):collect([{'entries':[a]}],classes=['data_access'],policy=policy)
        else:
            snap,_=collect([{'entries':[a]}],classes=['data_access'],policy=policy);assert status(snap,ident)=='UNKNOWN'


@pytest.mark.parametrize('ident',METHODS)
def test_rate_window_principal_service_and_complete_page_boundaries(ident):
    method=sorted(METHODS[ident])[0];service='osconfig.googleapis.com'if ident.endswith('1518')else 'compute.googleapis.com'
    a=event(method,service=service,identity='a',logclass='data_access')
    b=event(method,service=service,identity='b',logclass='data_access',ts='2026-10-13T00:06:01Z')
    snap,_=collect([{'entries':[a,b]}],classes=['data_access'],policy={'approved_list_rate':1});assert status(snap,ident)=='PASS'
    b['timestamp']='2026-10-13T00:02:00Z';b['protoPayload']['authenticationInfo']['principalEmail']='other@example.com'
    snap,_=collect([{'entries':[a,b]}],classes=['data_access'],policy={'approved_list_rate':1});assert status(snap,ident)=='PASS'
    b['protoPayload']['authenticationInfo']['principalEmail']=a['protoPayload']['authenticationInfo']['principalEmail'];b['protoPayload']['serviceName']='foreign.googleapis.com'
    snap,_=collect([{'entries':[a,b]}],classes=['data_access'],policy={'approved_list_rate':1});assert status(snap,ident)=='UNKNOWN'
    b['protoPayload']['serviceName']=service
    snap,_=collect([{'entries':[a,b],'nextPageToken':'unfinished'}],classes=['data_access'],policy={'approved_list_rate':1},max_pages=1);assert status(snap,ident)=='UNKNOWN'
    snap,_=collect([{}],classes=['data_access'],policy={'approved_list_rate':1});assert status(snap,ident)in ('EMPTY','UNKNOWN')
