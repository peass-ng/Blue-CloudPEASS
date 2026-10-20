"""Historical unregistered proposal retained; production owns all226 cases once."""
import ast
import gzip
import hashlib
from pathlib import Path


def test_original_proposal_bytes_and_complete_native_roster_conserved():
    root=Path(__file__).resolve().parents[1]
    raw=gzip.decompress((root/'tests/fixtures/aws_s3_selected_source_pre_integration_20261020.py.gz').read_bytes())
    assert hashlib.sha256(raw).hexdigest()=='961c9391015b9403c301cad256f5438563c216ab01b02990e1f613090dc26a9e'
    original=ast.parse(raw)
    current=ast.parse((root/'tests/test_aws_s3_selected_source_integration_20261020.py').read_bytes())
    def tests(tree):return {n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')}
    before,after=tests(original),tests(current)
    assert set(before)==set(after)
    for name,old in before.items():
        assert [ast.dump(d,include_attributes=False)for d in old.decorator_list]==[ast.dump(d,include_attributes=False)for d in after[name].decorator_list]
    # Native wire/stream and public-engine assertions remain in the successor;
    # draft Requests/client/registry monkeypatch bridges are removed.
    text=ast.get_source_segment((root/'tests/test_aws_s3_selected_source_integration_20261020.py').read_text(),after['test_native_each_format_three_branches'])
    assert "'PASS'"in text and "'FAIL'"in text and "'UNKNOWN'"in text
    successor=(root/'tests/test_aws_s3_selected_source_integration_20261020.py').read_text()
    assert 'snapshot=engine.collect_snapshot(request)'in successor
    for bridge in ("monkeypatch.setattr(aws.Requests,'call'", "monkeypatch.setattr(aws.Requests,'client'", "monkeypatch.setattr(engine,'_registry'"):
        assert bridge not in successor
