import copy
import pytest
from peaso.checks.batch import evaluate_many, scalar_sql, summarize_many
from peaso.checks.facts import FIELD_SPECS
from peaso.checks.fixtures import nest


@pytest.mark.parametrize("check_id", sorted(FIELD_SPECS))
def test_duckdb_scalar_parity(check_id):
    pytest.importorskip("duckdb")
    spec = FIELD_SPECS[check_id]
    good = spec["good"][0] if isinstance(spec["good"], tuple) else spec["good"]
    passing = nest(spec["path"], good)
    failing = nest(spec["path"], spec["bad"])
    denied = {**passing, "collection_status": "denied"}
    partial = {**passing, "_coverage": {spec["path"].split(".")[0]: {"status": "partial"}}}
    malformed_coverage = {**passing, "_coverage": []}
    malformed_detail_coverage = {**passing, "_coverage": {spec["path"].split(".")[0]: []}}
    items = [passing, failing, {}, None, [], denied, partial, malformed_coverage, malformed_detail_coverage, nest(spec["path"], "unexpected"), nest(spec["path"], {"malformed": True})]
    before = copy.deepcopy(items)
    python = evaluate_many([check_id], items)[check_id]
    sql = evaluate_many([check_id], items, "duckdb")[check_id]
    assert [status for status, _ in python] == [status for status, _ in sql]
    assert items == before
    assert "FROM facts" in scalar_sql(check_id)


def test_batch_rejects_unsupported_semantic_rule():
    with pytest.raises(ValueError, match="strict scalar"):
        evaluate_many(["aws.iam.no_full_admin"], [], "duckdb")


def test_duckdb_summary_preserves_unknown_and_failure_counts():
    pytest.importorskip("duckdb")
    rows = [{"Encrypted": True}, {"Encrypted": False}, {}, {"Encrypted": True, "collection_status": "denied"}]
    assert summarize_many(["aws.ebs.encryption"], rows) == {"aws.ebs.encryption": {"PASS": 1, "FAIL": 1, "UNKNOWN": 2}}
