"""Bundled remediation decoding retains every command and independent container."""
import json
import pytest
from peaso import remediation
from peaso.checks.catalog import _shared_metadata_strings

PATHS=[remediation.RULEPACK,remediation.CURATED,remediation.AWS_REVIEWED,
       remediation.AWS_FAMILIES_REVIEWED,remediation.AZURE_REVIEWED,
       *(path for path,_ in remediation.COMPLIANCE_REVIEWED)]


@pytest.mark.parametrize('path',PATHS,ids=lambda p:p.name)
def test_every_remediation_source_preserves_exact_json_and_row_independence(path):
    raw=path.read_text()
    ordinary=json.loads(raw)
    shared=json.loads(raw,object_hook=_shared_metadata_strings)
    assert shared==ordinary
    assert json.dumps(shared)==json.dumps(ordinary)
    # Separate decode calls must never share any mutable command, reference or
    # binding container even though immutable package labels are interned.
    second=json.loads(raw,object_hook=_shared_metadata_strings)
    def assert_independent(left,right):
        if isinstance(left,dict):
            assert left is not right
            for key,value in left.items():assert_independent(value,right[key])
        elif isinstance(left,list):
            assert left is not right
            for a,b in zip(left,right):assert_independent(a,b)
    assert_independent(shared,second)


def test_nested_decoded_commands_remain_independent_within_and_between_documents():
    raw='{"a":{"cli":[{"code":"same-command","args":["same-argument"]}]},"b":{"cli":[{"code":"same-command","args":["same-argument"]}]}}'
    first=json.loads(raw,object_hook=_shared_metadata_strings)
    second=json.loads(raw,object_hook=_shared_metadata_strings)
    assert first['a']['cli'][0]['code'] is first['b']['cli'][0]['code'] is second['a']['cli'][0]['code']
    first['a']['cli'][0]['args'].append('caller-change')
    first['a']['cli'][0]['code']='changed'
    assert first['b']==second['b']==second['a']
