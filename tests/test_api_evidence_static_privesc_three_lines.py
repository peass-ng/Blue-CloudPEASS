"""The server's frozen presenter returns reviewed privilege evidence."""

from peaso import privesc
from peaso.server.evidence_static import evidence_summary
from tests.test_peaso_privesc_finding_explanations_review import projected


def test_all_active_aws_and_gcp_privilege_paths_have_three_lines():
    seen = {"aws": 0, "gcp": 0}
    for entry in privesc.catalog()["entries"]:
        provider = entry["provider"]
        if provider not in seen:
            continue
        seen[provider] += 1
        for confidence in ("derived", "conditional", "unknown"):
            finding = projected(entry, confidence)
            text = evidence_summary(finding)
            assert text is not None, (entry["id"], confidence)
            assert len(text.splitlines()) == 3, (entry["id"], confidence, text)
            assert finding["evidence"]["confidence"] == confidence
    assert seen == {"aws": 220, "gcp": 223}
