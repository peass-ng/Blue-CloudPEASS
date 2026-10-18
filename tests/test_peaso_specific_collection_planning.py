import importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest
from peaso.collectors import supported_types
from peaso.engine import plan_collection as previous
import peaso.engine as m
@pytest.mark.parametrize('provider,check,required',[('aws','aws.ec2.imdsv2',{'instance'}),('gcp','gcp.storage.uniform_access',{'bucket'}),('azure','azure.storage.https_only',{'storage_account'}),('k8s','k8s.pod.no_privileged_containers',{'pod'})])
def test_single_native_predicate_does_not_collect_unrequested_graphs(provider,check,required):
 request={'connector':{'provider':provider},'checks':[check]}
 assert set(m.plan_collection(request))==required
 assert required<=set(previous(request))
@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_unfiltered_default_plan_keeps_the_existing_inventory(provider):
 request={'connector':{'provider':provider}}
 assert m.plan_collection(request)==previous(request)
@pytest.mark.parametrize('explicit,checks,frameworks,expected',[(None,['id'],None,set()),(['network'],['id'],None,{'network'}),(None,None,['CIS'],set()),(None,None,None,{'network','iam_graph'})])
def test_graph_intent_respects_explicit_category_or_selected_predicates(explicit,checks,frameworks,expected):
 result=m._selected_graph_categories(['network','iam_graph','hardening'],[SimpleNamespace(category='hardening')],[],explicit,checks,frameworks)
 assert result==expected
@pytest.mark.parametrize('category',['network','iam_graph'])
def test_graph_predicate_and_analysis_dependencies_remain_requested(category):
 assert m._selected_graph_categories(['network','iam_graph','hardening'],[SimpleNamespace(category=category)],[],None,['id'],None)=={category}
 assert m._selected_graph_categories(['network','iam_graph','hardening'],[],[{'category':category}],None,['id'],None)=={category}
def test_explicit_inventory_override_remains_exact():
 request={'connector':{'provider':'azure','options':{'inventories':['storage_account']}},'checks':['azure.storage.https_only']}
 assert m.plan_collection(request)==['storage_account']
def test_filtered_report_does_not_build_unrequested_graphs(monkeypatch):
 from peaso.snapshot import make_snapshot
 import peaso.analysis
 def forbidden(*args,**kwargs):raise AssertionError('unrequested graph construction')
 monkeypatch.setattr(peaso.analysis,'build_graphs',forbidden)
 s=make_snapshot('azure',['scope'],[{'type':'storage_account','scope':'scope','status':'collected','items':[{'id':'storage','properties':{'supportsHttpsTrafficOnly':True}}]}])
 result=m.evaluate_snapshot(s,checks=['azure.storage.https_only'])
 assert len(result['findings'])==1 and result['findings'][0]['status']=='PASS'
 assert all(not g['nodes'] for g in result['graphs'].values())


@pytest.mark.parametrize('check', [
    'aws.nist.ec2_instance_effective_public_reachability',
    'aws_fedramp_ec2_effective_public_exposure',
])
def test_direct_public_ingress_plan_includes_independent_native_route_evidence(check):
    planned = set(m.plan_collection({'connector': {'provider': 'aws'}, 'checks': [check]}))
    assert {'instance', 'network_interface', 'vpc', 'subnet', 'security_group',
            'network_acl', 'route_table', 'internet_gateway',
            'vpc_block_public_access_options', 'ec2_effective_ingress'} <= planned
    assert not {'iam_user', 'iam_role', 'cloudtrail'} & planned


@pytest.mark.parametrize('inventories, expected', [
    (['instance'], {'instance'}),
    (['ec2_effective_ingress'], {'instance', 'network_interface', 'vpc', 'subnet',
      'security_group', 'network_acl', 'route_table', 'internet_gateway',
      'vpc_block_public_access_options', 'ec2_effective_ingress'}),
])
def test_direct_public_ingress_explicit_inventory_selection_controls_native_reads(inventories, expected):
    request = {'connector': {'provider': 'aws', 'options': {'inventories': inventories}},
               'checks': ['aws.nist.ec2_instance_effective_public_reachability']}
    assert set(m.plan_collection(request)) == expected
