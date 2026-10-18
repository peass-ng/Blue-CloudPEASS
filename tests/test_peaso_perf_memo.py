"""The per-scope MemoIndex memo must never change a check result.

The engine evaluates every check of a scope against one MemoIndex; shared helpers derive joins from it once
(complete_items, security-group/ENI maps). Plain dict indexes (tests, ad-hoc callers) take the original
sequential code path. These tests pin that both paths return the same values and raise the same errors,
including duplicates, unhashable ids and incomplete inventories.
"""
import pytest

from peaso.checks import claude_aws_a_common as common
from peaso.checks.facts import MemoIndex, Unavailable, complete_items, memoized


def _index(kind_rows, status="collected"):
    index = {"collections": {kind: [{"type": kind, "scope": "s", "status": status}] for kind in kind_rows}}
    for kind, rows in kind_rows.items():
        index[kind] = [{"type": kind, "scope": "s", "data": row} for row in rows]
    return index


ENIS = [
    {"NetworkInterfaceId": "eni-1", "VpcId": "vpc-1", "SubnetId": "sub-1", "Groups": [{"GroupId": "sg-1"}, {"GroupId": "sg-1"}]},
    {"NetworkInterfaceId": "eni-2", "VpcId": "vpc-2", "SubnetId": "sub-2", "Groups": [{"GroupId": "sg-2"}, {"GroupId": "sg-1"}]},
    {"NetworkInterfaceId": "eni-3", "VpcId": ["unhashable"], "SubnetId": None, "Groups": [{"GroupId": ["x"]}, {}]},
]
SGS = [{"GroupId": "sg-1", "VpcId": "vpc-1", "n": 1}, {"GroupId": "sg-2", "VpcId": "vpc-2"}, {"GroupId": "sg-1", "VpcId": "vpc-1", "n": 2}]


def both(rows, status="collected"):
    plain = _index(rows, status)
    return plain, MemoIndex(plain)


def outcome(fn, *args):
    try:
        return ("ok", fn(*args))
    except Unavailable as exc:
        return ("err", type(exc), exc.args)


def test_memoized_only_on_memo_index_and_replays_unavailable():
    calls = []

    def compute():
        calls.append(1)
        raise Unavailable("dependency not collected: x")

    for _ in range(2):
        with pytest.raises(Unavailable, match="dependency not collected: x"):
            memoized({}, ("k",), compute)
    assert len(calls) == 2
    memo = MemoIndex()
    for _ in range(3):
        with pytest.raises(Unavailable, match="dependency not collected: x"):
            memoized(memo, ("k",), compute)
    assert len(calls) == 3
    assert memoized(memo, ("v",), lambda: [1]) is memoized(memo, ("v",), lambda: [2])


@pytest.mark.parametrize("status", ["collected", "empty", "partial", "denied"])
def test_complete_items_same_result_and_fresh_list(status):
    plain, memo = both({"network_interface": ENIS}, status)
    assert outcome(complete_items, plain, "network_interface") == outcome(complete_items, memo, "network_interface")
    assert outcome(complete_items, plain, "missing") == outcome(complete_items, memo, "missing")
    if status in ("collected", "empty"):
        first = complete_items(memo, "network_interface")
        first.append("mutated by a caller")
        assert complete_items(memo, "network_interface") == complete_items(plain, "network_interface")


@pytest.mark.parametrize("status", ["collected", "partial"])
@pytest.mark.parametrize("value", ["sg-1", "sg-2", "sg-9", None, ("t",)])
def test_sg_enis_matches_sequential_scan(status, value):
    plain, memo = both({"network_interface": ENIS}, status)
    assert outcome(common.sg_enis, plain, value) == outcome(common.sg_enis, memo, value)
    # Unhashable lookups take the sequential path on a MemoIndex too.
    assert outcome(common.sg_enis, memo, ["x"]) == outcome(common.sg_enis, plain, ["x"])


@pytest.mark.parametrize("value", ["vpc-1", "vpc-2", "vpc-9", None, ["unhashable"]])
def test_vpc_and_subnet_in_use_match(value):
    plain, memo = both({"network_interface": ENIS})
    assert outcome(common.vpc_in_use, plain, value) == outcome(common.vpc_in_use, memo, value)
    assert outcome(common.subnet_in_use, plain, value) == outcome(common.subnet_in_use, memo, value)


@pytest.mark.parametrize("ids", [["sg-1"], ["sg-2", "sg-1"], ("sg-1",), {"sg-2"}, [], ["sg-1", "sg-9"], ["sg-1", "sg-1"]])
def test_security_groups_match(ids):
    plain, memo = both({"security_group": SGS})
    assert outcome(common.security_groups, plain, ids) == outcome(common.security_groups, memo, ids)


def test_security_groups_unhashable_row_falls_back():
    rows = SGS + [{"GroupId": ["odd"]}]
    plain, memo = both({"security_group": rows})
    for ids in (["sg-1"], ["sg-9"]):
        assert outcome(common.security_groups, plain, ids) == outcome(common.security_groups, memo, ids)
