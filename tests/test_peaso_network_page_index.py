"""Repeated network pages reuse preparation without crossing artifact or tenant boundaries."""
import copy
import pytest
from peaso.analysis.projection import GraphPageIndex
from tests.test_peaso_report_api_paging_perf import api, route


def test_network_page_cache_reuses_only_exact_tenant_revision_and_size(api, monkeypatch):
    client, artifacts, _, manifest = api
    graph = {'nodes': [{'id':f'n-{i:04d}', 'label':f'Node {i}', 'type':'instance'} for i in range(360)],
             'edges': [{'id':f'e-{i:04d}', 'source':f'n-{i:04d}', 'target':'n-0000', 'type':'route'} for i in range(1,360)]}
    manifest['graphs']={'network':'graph-a'}
    artifacts.items['graph-a']=copy.deepcopy(graph)
    observed=[]
    original=GraphPageIndex.__init__
    def prepare(self, graph, page_size=120):
        observed.append(page_size)
        original(self, graph, page_size)
    monkeypatch.setattr(GraphPageIndex,'__init__',prepare)
    headers={'Authorization':'Bearer alice'}
    first=client.get(route('graphs/network/page'),params={'page_size':120},headers=headers)
    second=client.get(route('graphs/network/page'),params={'page_size':120,'page':1},headers=headers)
    assert first.status_code==second.status_code==200
    assert first.json()['total_nodes']==second.json()['total_nodes']==360
    first_ids={n['id']for n in first.json()['nodes']if not n.get('stub')}
    second_ids={n['id']for n in second.json()['nodes']if not n.get('stub')}
    assert len(first_ids)==len(second_ids)==120 and not first_ids & second_ids
    assert client.get(route('graphs/network/page'),headers={'Authorization':'Bearer bob'}).status_code==404
    assert observed==[120] and artifacts.reads['graph-a']==1
    assert client.get(route('graphs/network/page'),params={'page_size':40},headers=headers).status_code==200
    changed=copy.deepcopy(graph);changed['nodes'][0]['label']='Revised node'
    artifacts.items['graph-b']=changed;manifest['graphs']['network']='graph-b'
    updated=client.get(route('graphs/network/page'),params={'page_size':120},headers=headers)
    assert updated.status_code==200
    assert next(n for n in updated.json()['nodes']if n['id']=='n-0000')['label']=='Revised node'
    assert observed==[120,40,120] and artifacts.reads['graph-b']==1
    assert artifacts.items['graph-a']==graph


@pytest.mark.parametrize('value',[True,-1,1.5,'1'])
def test_index_rejects_invalid_page_before_reading_edges(value):
    index=GraphPageIndex({'nodes':[],'edges':[]})
    with pytest.raises(ValueError):index.page(value)


def test_page_indexes_do_not_retain_graphs_after_shared_cache_eviction(api, monkeypatch):
    import gc
    import weakref
    client, artifacts, _, manifest = api
    references = []
    original = GraphPageIndex.__init__
    def prepare(self, graph, page_size=120, **kwargs):
        original(self, graph, page_size, **kwargs)
        references.append(weakref.ref(self))
    monkeypatch.setattr(GraphPageIndex, '__init__', prepare)
    for revision in range(5):
        reference = f'network-revision-{revision}'
        manifest['graphs'] = {'network': reference}
        artifacts.items[reference] = {'nodes': [{'id': f'n-{revision}', 'type': 'instance'}], 'edges': []}
        response = client.get(route('graphs/network/page'), headers={'Authorization': 'Bearer alice'})
        assert response.status_code == 200
    gc.collect()
    assert len(references) == 5 and references[0]() is None
    assert all(reference() is not None for reference in references[1:])


def test_pages_do_not_build_unused_projection_and_expand_reuses_it(api, monkeypatch):
    import peaso.analysis as analysis
    client, artifacts, _, manifest = api
    graph = {'nodes': [{'id': f'n-{i}', 'type': 'instance'} for i in range(240)], 'edges': []}
    manifest['graphs'] = {'network': 'network-lazy'}
    artifacts.items['network-lazy'] = graph
    calls = []
    original = analysis.project_graph
    def project(value, limit):
        calls.append(limit)
        return original(value, limit)
    monkeypatch.setattr(analysis, 'project_graph', project)
    headers = {'Authorization': 'Bearer alice'}
    for page in (0, 1):
        response = client.get(route('graphs/network/page'), params={'page': page}, headers=headers)
        assert response.status_code == 200
    assert calls == []
    for _ in range(2):
        response = client.get(route('graphs/network/expand'), params={'node': 'n-0'}, headers=headers)
        assert response.status_code == 200
        assert any(node['id'] == 'n-0' for node in response.json()['nodes'])
    assert calls == [500] and artifacts.reads['network-lazy'] == 1
