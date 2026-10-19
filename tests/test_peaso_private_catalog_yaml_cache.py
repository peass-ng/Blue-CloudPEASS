"""Fresh source reads, schema authority and isolation of the bounded parse cache."""
from copy import deepcopy
import os
from pathlib import Path
import pytest
import yaml
from peaso.privesc import schema


@pytest.fixture(autouse=True)
def empty_cache():
    schema._clear_parsed_yaml_cache()
    yield
    schema._clear_parsed_yaml_cache()


@pytest.fixture(scope='module')
def entry():
    return deepcopy(next(e for e in schema.load_catalog(strict=True)['entries'] if e['provider']=='aws'))


def write_entry(root,entry,name='a.yaml',suffix=''):
    folder=root/'aws';folder.mkdir(exist_ok=True)
    value=deepcopy(entry);value.pop('_file',None);value['id']+=suffix
    path=folder/name;path.write_text(yaml.safe_dump([value],sort_keys=False,width=100000))
    return path


def count_constructors(monkeypatch):
    original=schema.yaml.load;calls=[]
    def counted(text,Loader):
        calls.append(Loader)
        return original(text,Loader=Loader)
    monkeypatch.setattr(schema.yaml,'load',counted)
    return calls


def test_entire_catalog_keeps_every_strict_and_non_strict_result(monkeypatch):
    original=schema._catalog_document
    monkeypatch.setattr(schema,'_catalog_document',lambda text:(yaml.load(text,Loader=schema.SAFE_YAML_LOADER),None))
    expected_non_strict=schema.load_catalog()
    expected_strict=schema.load_catalog(strict=True)
    monkeypatch.setattr(schema,'_catalog_document',original)
    calls=count_constructors(monkeypatch)
    first=schema.load_catalog()
    count=len(calls)
    second=schema.load_catalog(strict=True)
    assert first==expected_non_strict and second==expected_strict
    assert count==len({p.read_text() for p in schema.catalog_files()}) and len(calls)==count
    info=schema._parsed_yaml_cache_info()
    assert info['documents']==len({p.read_text() for p in schema.catalog_files()})
    assert info['source_bytes']<=4*1024*1024 and info['graph_bytes']<=16*1024*1024


def test_nested_mutation_never_changes_private_document(tmp_path,entry,monkeypatch):
    write_entry(tmp_path,entry)
    calls=count_constructors(monkeypatch)
    expected=schema.load_catalog(tmp_path,strict=True)
    first=schema.load_catalog(tmp_path,strict=True)
    first['entries'][0]['requires']['all_of'][0]['action']='caller:Mutation'
    first['entries'][0]['references'].append('https://invalid.example/caller-mutation')
    first['entries'].clear()
    assert schema.load_catalog(tmp_path,strict=True)==expected
    assert len(calls)==1


def test_same_length_same_mtime_edit_is_read_and_revalidated(tmp_path,entry,monkeypatch):
    path=write_entry(tmp_path,entry)
    calls=count_constructors(monkeypatch)
    first=schema.load_catalog(tmp_path,strict=True)
    original=path.read_text();before=path.stat()
    # A valid title change keeps source length and mtime unchanged.
    changed=original.replace(entry['title'],entry['title'].swapcase())
    assert len(changed)==len(original) and changed!=original
    path.write_text(changed);os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
    second=schema.load_catalog(tmp_path,strict=True)
    assert second['entries'][0]['title']!=first['entries'][0]['title']
    assert len(calls)==2
    # A subsequent schema-invalid edit must still fail strict validation.
    path.write_text('- id: invalid\n  provider: aws\n')
    with pytest.raises(schema.CatalogError):schema.load_catalog(tmp_path,strict=True)
    assert schema.load_catalog(tmp_path)['errors']


def test_symlink_target_changes_are_read_normally(tmp_path,entry):
    real=write_entry(tmp_path,entry)
    payload=tmp_path/'source.txt';real.rename(payload);real.symlink_to(payload)
    first=schema.load_catalog(tmp_path,strict=True)
    payload.write_text(payload.read_text().replace(entry['title'],entry['title'].swapcase()))
    assert schema.load_catalog(tmp_path,strict=True)['entries'][0]['title']!=first['entries'][0]['title']


@pytest.mark.parametrize('payload',['[unclosed','!!python/object/apply:builtins.eval ["1+1"]','- id: invalid\n  provider: aws\n'])
def test_invalid_documents_and_python_tags_are_not_cached(tmp_path,monkeypatch,payload):
    folder=tmp_path/'aws';folder.mkdir();(folder/'bad.yaml').write_text(payload)
    calls=count_constructors(monkeypatch)
    for _ in range(2):
        with pytest.raises(schema.CatalogError):schema.load_catalog(tmp_path,strict=True)
        assert schema._parsed_yaml_cache_info()['documents']==0
    assert len(calls)==2


def test_selected_parser_is_part_of_content_key(tmp_path,entry,monkeypatch):
    if not hasattr(yaml,'CSafeLoader'):pytest.skip('Safe fallback is the only installed parser')
    write_entry(tmp_path,entry)
    calls=count_constructors(monkeypatch)
    monkeypatch.setattr(schema,'SAFE_YAML_LOADER',yaml.SafeLoader)
    first=schema.load_catalog(tmp_path,strict=True)
    monkeypatch.setattr(schema,'SAFE_YAML_LOADER',yaml.CSafeLoader)
    assert schema.load_catalog(tmp_path,strict=True)==first
    assert calls==[yaml.SafeLoader,yaml.CSafeLoader]


@pytest.mark.parametrize('limit',[('_PARSED_YAML_MAX_SOURCE_BYTES',1),('_PARSED_YAML_MAX_GRAPH_BYTES',1)])
def test_oversize_documents_are_returned_but_not_retained(tmp_path,entry,monkeypatch,limit):
    write_entry(tmp_path,entry);monkeypatch.setattr(schema,*limit)
    calls=count_constructors(monkeypatch)
    first=schema.load_catalog(tmp_path,strict=True)
    assert schema.load_catalog(tmp_path,strict=True)==first
    assert len(calls)==2 and schema._parsed_yaml_cache_info()=={'documents':0,'source_bytes':0,'graph_bytes':0}


def test_lru_document_bound_evicts_without_changing_results(tmp_path,entry,monkeypatch):
    monkeypatch.setattr(schema,'_PARSED_YAML_MAX_DOCUMENTS',2)
    for number in range(3):write_entry(tmp_path,entry,f'{number}.yaml',f'-cache-{number}')
    expected=schema.load_catalog(tmp_path,strict=True)
    assert schema._parsed_yaml_cache_info()['documents']==2
    assert schema.load_catalog(tmp_path,strict=True)==expected
    assert schema._parsed_yaml_cache_info()['documents']==2
