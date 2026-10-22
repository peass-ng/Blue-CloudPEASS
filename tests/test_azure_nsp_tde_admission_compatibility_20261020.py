"""Current source consumers preserve exact immutable predecessor assertions."""
import ast
import gzip
import hashlib
import inspect
import json
from pathlib import Path

import pytest
from peaso.checks import azure_metadata_only_tde_admission_successor_20261020 as admission
from peaso.checks import azure_function_package_shared_successor_20261020 as shared
from peaso.checks import azure_nsp_query_cmk_production_tde_successor_20261020 as tde_predecessor
from peaso.checks import azure_nsp_query_cmk_production_admission_20261020 as historical
from tests.test_azure_nsp_query_cmk_production_20261020 import offline

ROOT=Path(__file__).resolve().parents[1]
PREDECESSOR='tests/fixtures/azure_nsp_tde_admission_test_predecessor_20261020.json.gz'
PREDECESSOR_SHA256='55ba09a9613e75b450a0720eb3c7e7d7c95f37bd58cfb70be9c597d7b634ae69'


def test_current_consumers_preserve_historical_assertions_and_parameter_roster():
    raw=(ROOT/PREDECESSOR).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==PREDECESSOR_SHA256
    original=json.loads(gzip.decompress(raw))
    assert hashlib.sha256(original['text'].encode()).hexdigest()==original['sha256']=='95a479631123bf2acad50d8f718eee342e8f161f2b0dcb69ce14059dd4648440'
    before=ast.parse(original['text']);after=ast.parse((ROOT/original['path']).read_text())
    def tests(tree):return {n.name:n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')}
    old,new=tests(before),tests(after)
    assert old.keys()==new.keys()
    for name,node in old.items():
        current=new[name]
        assert ast.dump(node.args)==ast.dump(current.args)
        assert [ast.dump(d)for d in node.decorator_list]==[ast.dump(d)for d in current.decorator_list]
        assert [ast.dump(n)for n in ast.walk(node)if isinstance(n,ast.Assert)]==[ast.dump(n)for n in ast.walk(current)if isinstance(n,ast.Assert)]
        def raised(function):
            return [ast.dump(i.context_expr)for n in ast.walk(function)if isinstance(n,ast.With)for i in n.items
                    if isinstance(i.context_expr,ast.Call) and isinstance(i.context_expr.func,ast.Attribute) and i.context_expr.func.attr=='raises']
        assert raised(node)==raised(current)


def test_current_successor_does_not_repin_the_historical_production_contract():
    receipt,_,_=admission.reviewed_inputs()
    # Package collection is a separately reviewed successor of the TDE-only
    # epoch; the immutable TDE helper must still reject those extra statements.
    assert receipt==json.loads((ROOT/'peaso/checks'/tde_predecessor.RECEIPT).read_bytes())
    assert admission.RECEIPT_SHA256==tde_predecessor.RECEIPT_SHA256
    binding=shared.reviewed_delta()['azure_collect']
    current=shared.predecessor_azure_collect(inspect.getsource(admission.azure.collect), ROOT)
    assert hashlib.sha256(current.encode()).hexdigest()==binding['current_sha256']
    assert len(binding['exact_additions'])==6
    for addition in binding['exact_additions']:
        assert current.count(addition)==1
        current=current.replace(addition,'',1)
    assert hashlib.sha256(current.encode()).hexdigest()==binding['predecessor_sha256']==receipt['functions']['peaso.collectors.azure:collect']['source_sha256']
    tree=ast.parse(current)
    tde,=[n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='tde']
    source=''.join(current.splitlines(keepends=True)[tde.lineno-1:tde.end_lineno])
    assert hashlib.sha256(source.encode()).hexdigest()==receipt['after_tde_sha256']
    with pytest.raises(RuntimeError,match='Azure collect changed outside reviewed TDE body'):
        tde_predecessor.reviewed_inputs()
    for relative,digest in receipt['predecessor_files'].items():
        assert hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()==digest
    retained=json.loads(gzip.decompress((ROOT/receipt['predecessor_pack']['path']).read_bytes()))['files']
    old_receipt=json.loads(retained['peaso/checks/azure_nsp_query_cmk_production_admission_20261020.json']['text'])
    original=retained['peaso/collectors/azure.py']['text']
    node=next(n for n in ast.parse(original).body if isinstance(n,ast.FunctionDef) and n.name=='collect')
    source=''.join(original.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
    assert hashlib.sha256(source.encode()).hexdigest()==old_receipt['functions']['peaso.collectors.azure:collect']['source_sha256']==receipt['before_collect_sha256']
    assert historical.RECEIPT_SHA256==receipt['predecessor_files']['peaso/checks/'+historical.RECEIPT]
    # Historical admission must reject today's reviewed TDE successor source;
    # it is not an active helper with silently refreshed original hashes.
    with pytest.raises(RuntimeError,match='production disk callable source changed'):
        historical.reviewed_inputs()
