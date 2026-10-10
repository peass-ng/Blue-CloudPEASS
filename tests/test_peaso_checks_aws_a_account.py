"""Owner-review questions remain separate from automated security predicates."""
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS, aws_a_account

@pytest.mark.parametrize("cid", aws_a_account.MANUAL_SOURCE_IDS)
def test_manual_owner_review_retains_exact_question_and_provenance(cid):
    root = Path(__file__).resolve().parents[1]
    reviews = json.loads((root / "peaso/rulepacks/reviewed_aws_a_account.json").read_text())
    rows = {r["check_id"]: r for r in json.loads((root / "peaso/rulepacks/upstream_manifest.json").read_text())["checks"]}
    review, source = reviews[cid], rows[cid]
    assert review["disposition"] == "rejected"
    assert review["review_classification"] == "manual_attestation"
    assert review["native_checks"] == []
    assert review["manual_requirement"]["question"] == source["title"]
    assert review["reviewed_source"]["revision"] == source["revision"]
    assert review["reviewed_source"]["evaluator_sha256"] == source["upstream_evaluator"]["sha256"]
    assert not any(c.id.startswith("aws.a.account.") for c in CHECKS)
