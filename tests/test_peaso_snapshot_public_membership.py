"""API-shaped restore grants must not hide public snapshots among account IDs."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.checks import CHECKS


CHECKS_BY_ID = {check.id: check for check in CHECKS}
CASES = (
    ("aws.c2b.docdb.snapshot_restore_not_all_exact", "docdb", "DBClusterSnapshotAttributesResult", "DBClusterSnapshotAttributes"),
    ("aws.cb.neptune.snapshot_restore_not_all_exact", "neptune", "DBClusterSnapshotAttributesResult", "DBClusterSnapshotAttributes"),
    ("aws.cb.rds.cluster_snapshot_restore_not_all_exact", "aurora-postgresql", "DBClusterSnapshotAttributesResult", "DBClusterSnapshotAttributes"),
    ("aws.cb.rds.instance_snapshot_restore_not_all_exact", "postgres", "DBSnapshotAttributesResult", "DBSnapshotAttributes"),
)


def snapshot(engine, result_key, rows_key, rows):
    return {"Engine": engine, "Attributes": {result_key: {rows_key: rows}}}


def restore(values):
    return {"AttributeName": "restore", "AttributeValues": values}


@pytest.mark.parametrize("check_id,engine,result_key,rows_key", CASES)
def test_public_membership_and_unrelated_attributes(check_id, engine, result_key, rows_key):
    check = CHECKS_BY_ID[check_id]

    def evaluate(rows):
        item = snapshot(engine, result_key, rows_key, rows)
        before = deepcopy(item)
        result = check.evaluate(item, {})
        assert item == before
        return result[0]

    assert evaluate([restore(["all"])]) == "FAIL"
    assert evaluate([restore(["222222222222", "all"])]) == "FAIL"
    assert evaluate([restore(["222222222222"])]) == "PASS"
    assert evaluate([restore([])]) == "PASS"
    assert evaluate([{"AttributeName": "other", "AttributeValues": ["all"]}, restore(["222222222222"])]) == "PASS"


@pytest.mark.parametrize("check_id,engine,result_key,rows_key", CASES)
def test_missing_malformed_and_denied_restore_evidence_is_unknown(check_id, engine, result_key, rows_key):
    check = CHECKS_BY_ID[check_id]
    payloads = [
        {"Engine": engine},
        snapshot(engine, result_key, rows_key, []),
        snapshot(engine, result_key, rows_key, [{"AttributeName": "other", "AttributeValues": []}]),
        snapshot(engine, result_key, rows_key, [{"AttributeName": "restore"}]),
        snapshot(engine, result_key, rows_key, [restore(None)]),
        snapshot(engine, result_key, rows_key, [restore(["all", 222222222222])]),
        snapshot(engine, result_key, rows_key, [restore(["all"]), {"AttributeName": "other", "AttributeValues": None}]),
        {**snapshot(engine, result_key, rows_key, [restore(["all"])]), "collection_status": "denied"},
    ]
    for item in payloads:
        assert check.evaluate(item, {})[0] == "UNKNOWN", (check_id, item)


@pytest.mark.parametrize("check_id,engine,result_key,rows_key", CASES[:2])
def test_docdb_and_neptune_remain_engine_scoped(check_id, engine, result_key, rows_key):
    item = snapshot("postgres", result_key, rows_key, [restore(["all"])])
    assert CHECKS_BY_ID[check_id].evaluate(item, {})[0] == "NOT_APPLICABLE"
