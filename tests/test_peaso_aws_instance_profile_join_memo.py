"""Repeated pure profile joins preserve normal-index evidence and failures."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks import aws_gap_ec2 as ec2
from peaso.checks.facts import MemoIndex, Unavailable
from peaso.checks.fixtures import CASES

OWNED=[c for c in CHECKS if c.id.startswith('aws.gap.ec2.instance_no_iam_')]

@pytest.mark.parametrize('check',OWNED,ids=lambda c:c.id)
def test_native_fixture_verdicts_and_evidence_match_uncached_indexes(check):
    fixture=CASES[check.id]
    for name,item in fixture.items():
        if name.endswith(('_index','_expect')) or name=='index' or not isinstance(item,dict):continue
        index=fixture.get(name+'_index',fixture.get('index',{}))
        expected=check.evaluate(deepcopy(item),deepcopy(index))
        memo=MemoIndex(deepcopy(index));before=deepcopy(dict(memo))
        assert check.evaluate(deepcopy(item),memo)==expected
        assert check.evaluate(deepcopy(item),memo)==expected
        assert dict(memo)==before


def test_repeated_profile_join_reads_roles_only_once_per_arn(monkeypatch):
    from peaso.checks.claude_aws_a_common import idx
    index=MemoIndex(idx(iam_role=[ec2.APP],iam_policy=[]))
    calls=[];original=ec2.items
    def counted(index,kind):
        calls.append(kind);return original(index,kind)
    monkeypatch.setattr(ec2,'items',counted)
    assert ec2.instance_roles(ec2.INST,index)==[ec2.APP]
    assert ec2.instance_roles(ec2.INST,index)==[ec2.APP]
    assert calls==['iam_role']


def test_absence_and_malformed_errors_replay_exactly_without_cross_index_leaks():
    from peaso.checks.claude_aws_a_common import idx
    for roles in ([],[{'RoleName':'bad','InstanceProfileList':[{}]}]):
        index=idx(iam_role=roles,iam_policy=[]);memo=MemoIndex(deepcopy(index))
        with pytest.raises(Unavailable) as expected:ec2.instance_roles(ec2.INST,index)
        for _ in range(2):
            with pytest.raises(Unavailable) as actual:ec2.instance_roles(ec2.INST,memo)
            assert (type(actual.value),actual.value.args)==(type(expected.value),expected.value.args)
    good=MemoIndex(idx(iam_role=[ec2.APP],iam_policy=[]))
    assert ec2.instance_roles(ec2.INST,good)==[ec2.APP]
