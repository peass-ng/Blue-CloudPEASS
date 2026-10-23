"""Principal detail conserves archived finding selection and public field bounds."""
from copy import deepcopy
from urllib.parse import quote
import pytest
from tests.test_peaso_report_api_paging_perf import api, SCAN

SUFFIX=' [Full value available in finding detail]'


def prepare(api, *, inline=False, principal='principal-primary'):
    client,artifacts,rows,manifest=api
    graph={'nodes':[{'id':principal,'label':'Fixture principal','kind':'entity','type':'aws_iam_role'},
        {'id':'principal-other','label':'Other principal','kind':'entity','type':'aws_iam_role'}],'edges':[]}
    manifest['summary']['provider']='aws'
    manifest['check_meta']['a']['category']='privesc'
    for row in rows:row['resource_id']='principal-other'
    if inline:
        manifest.update(bundle_version=0,findings=rows,graphs={'privesc':graph})
    else:
        manifest['graphs']={'privesc':'principal-graph'}
        artifacts.items['principal-graph']=graph
    return client,artifacts,rows,manifest


def detail(client,principal='principal-primary',**kwargs):
    return client.get(f'/api/scans/{SCAN}/privesc/principals/'+quote(principal,safe=''),
        headers={'Authorization':'Bearer alice'},**kwargs)


@pytest.mark.parametrize('inline',[False,True],ids=['chunked','inline'])
def test_principal_findings_keep_default_and_explicit_categories_frameworks_and_order(api,inline):
    client,artifacts,rows,manifest=prepare(api,inline=inline)
    for index in (1,3,4,6):rows[index]['resource_id']='principal-primary'
    rows[4]['category']='privesc'
    rows[3]['category']='hardening'
    response=detail(client)
    assert response.status_code==200,response.text
    data=response.json()
    assert [row['id']for row in data['findings']]==[rows[1]['id'],rows[4]['id']]
    assert data['findings_total']==2
    assert all(row['resource_id']=='principal-primary'and row['category']=='privesc'for row in data['findings'])
    assert data['findings'][0]['frameworks']==['NIST 800-53']
    assert data['findings'][1]['frameworks']==['CIS AWS']
    assert detail(client,'does-not-exist').status_code==404
    assert client.get(f'/api/scans/{SCAN}/privesc/principals/principal-primary',headers={'Authorization':'Bearer bob'}).status_code==404


@pytest.mark.parametrize('inline',[False,True],ids=['chunked','inline'])
def test_missing_resource_id_uses_archived_default_before_principal_selection(api,inline):
    client,_,rows,manifest=prepare(api,inline=inline)
    rows[1].pop('resource_id')
    manifest['check_meta']['a']['resource_id']='principal-primary'
    response=detail(client)
    assert response.status_code==200,response.text
    assert [row['id']for row in response.json()['findings']]==[rows[1]['id']]


@pytest.mark.parametrize('inline',[False,True],ids=['chunked','inline'])
def test_long_archived_resource_id_keeps_existing_summary_truncation_selection(api,inline):
    raw='R'*1001;principal='R'*1000+SUFFIX
    client,_,rows,_=prepare(api,inline=inline,principal=principal)
    rows[1]['resource_id']=raw
    response=detail(client,principal)
    assert response.status_code==200,response.text
    assert [row['id']for row in response.json()['findings']]==[rows[1]['id']]
    assert response.json()['findings'][0]['resource_id']==principal


def test_total_counts_all_matching_findings_before_existing_five_hundred_cap(api):
    client,artifacts,rows,_=prepare(api)
    base=rows[1]
    artifacts.items['index']['items']=[dict(base,id=f'own-{i:04d}',resource_id='principal-primary')for i in range(600)]
    artifacts.items['index']['items'] += [dict(base,id=f'other-{i:04d}',resource_id='principal-other')for i in range(700)]
    response=detail(client)
    assert response.status_code==200,response.text
    value=response.json()
    assert value['findings_total']==600 and len(value['findings'])==500
    assert [row['id']for row in value['findings']]==[f'own-{i:04d}'for i in range(500)]


def test_changed_report_reference_reloads_findings_and_archived_metadata(api,monkeypatch):
    client,artifacts,rows,manifest=prepare(api)
    rows[1]['resource_id']='principal-primary'
    assert detail(client).json()['findings_total']==1
    changed=deepcopy(manifest)
    changed['finding_chunks']=[{'index_reference':'index-next'}]
    changed['check_meta']['a']['category']='hardening'
    artifacts.items['manifest-next']=changed
    artifacts.items['index-next']={'items':[dict(rows[1],id='next-finding')]}
    store=client.app.state.store;original=store.job
    monkeypatch.setattr(store,'job',lambda tenant,ident:dict(original(tenant,ident),report='manifest-next'))
    response=detail(client)
    assert response.status_code==200,response.text
    assert response.json()['findings_total']==0 and response.json()['findings']==[]
