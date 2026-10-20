"""Reference inventory rejects malformed/polluted inputs without network access."""
import json
import pytest
from scripts.audit_provider_source_inventory import Inventory,blob,sha,selected

@pytest.mark.parametrize('provider,native',[('azure','azure'),('k8s','kubernetes')])
def test_provider_metadata_boundary(provider,native):
    path='prowler/providers/'+native+'/services/iam/review/review.metadata.json'
    assert selected('prowler-cloud/prowler',path,provider)
    assert not selected('prowler-cloud/prowler',path.replace(native,'aws'),provider)
    assert not selected('prowler-cloud/prowler',path.replace('.metadata.json','.py'),provider)
    assert selected('prowler-cloud/prowler','prowler/compliance/'+native+'/framework.json',provider)

def test_control_inventory_parses_blocks_and_keeps_exact_git_identity(tmp_path):
    repo='turbot/steampipe-mod-azure-perimeter'
    data=b'control "public" {\n title = "Public service"\n query = query.review\n}\nquery "review" { sql = "select 1" }'
    path=tmp_path/'steampipe-mod-azure-perimeter'/'controls.pp'
    path.parent.mkdir();path.write_bytes(data)
    source={'repository':repo,'revision':'a'*40,'files':[{'path':'controls.pp','sha256':sha(data),'git_blob_sha1':blob(data)}]}
    audit=Inventory('azure',tmp_path)
    rows=audit.rows([source])
    assert [r['check_id']for r in rows]==['azure-perimeter.control.public']
    assert rows[0]['title']=='Public service'
    assert rows[0]['source_sha256']==sha(data)
    with pytest.raises(ValueError,match='Duplicate'):audit.rows([source,source])


def test_framework_only_reference_is_preserved_without_inventing_a_definition(tmp_path):
    documents = {
        'prowler/providers/azure/services/example/defined/defined.metadata.json':
            {'CheckID': 'defined', 'CheckTitle': 'Defined control'},
        'prowler/compliance/azure/current_framework.json':
            {'Requirements': [{'Id': '2.3', 'Checks': ['defined', 'missing']}]},
    }
    files = []
    for name, document in documents.items():
        data = json.dumps(document).encode()
        path = tmp_path / 'prowler' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        files.append({'path': name, 'sha256': sha(data), 'git_blob_sha1': blob(data)})
    source = {'repository': 'prowler-cloud/prowler', 'revision': 'b' * 40, 'files': files}
    rows = {r['check_id']: r for r in Inventory('azure', tmp_path).rows([source])}
    assert set(rows) == {'prowler.azure.defined', 'prowler.azure.missing'}
    assert rows['prowler.azure.defined']['framework_references'][0]['control_id'] == '2.3'
    missing = rows['prowler.azure.missing']
    assert missing['catalog_entry_type'] == 'missing_definition'
    assert 'path' not in missing and 'source_sha256' not in missing
    assert missing['framework_references'][0]['framework_id'] == 'current_framework'

@pytest.mark.parametrize('fault',['traversal','tamper','revision','roster'])
def test_invalid_cached_sources_are_rejected(tmp_path,fault):
    repositories=['prowler-cloud/prowler','turbot/steampipe-mod-kubernetes-compliance']
    sources=[{'repository':repo,'revision':'a'*40,'files':[]}for repo in repositories]
    repo=sources[1]
    data=b'control "review" { title = "Review" }'
    file={'path':'controls.pp','sha256':sha(data),'git_blob_sha1':blob(data)}
    path=tmp_path/'steampipe-mod-kubernetes-compliance'/'controls.pp';path.parent.mkdir();path.write_bytes(data)
    repo['files']=[file]
    if fault=='traversal':file['path']='../controls.pp'
    elif fault=='tamper':path.write_bytes(data+b' changed')
    elif fault=='revision':repo['revision']='HEAD'
    elif fault=='roster':sources.pop(0)
    (tmp_path/'sources.json').write_text(json.dumps(sources))
    with pytest.raises(ValueError):Inventory('k8s',tmp_path).verify()
