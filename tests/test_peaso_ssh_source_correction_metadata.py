"""Public source-erratum and report metadata for the one corrected SSH check."""
from __future__ import annotations

import copy
import hashlib
import json
from urllib.parse import urlsplit

from peaso.checks import CHECKS
from peaso.checks.azure_vm_ssh_source_correction import (
    CHECK_ID, CORRECTED_SPEC, CORRECTED_SPEC_SHA256, DESCRIPTION, EVALUATOR_VERSION,
    PREDICATE, PREDICATE_SHA256, PRIOR_FROZEN_SPEC_SHA256, REMEDIATION, TITLE,
)
from peaso.checks.catalog import description_for, proposal_provenance_for
from peaso.collectors import azure
from peaso.engine import evaluate_snapshot, hydrate_frameworks
from peaso.remediation import details_for, report_templates

SCOPE = "/subscriptions/sub"
VM = SCOPE + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


def test_exact_successor_hashes_and_historical_provenance():
    canonical = json.dumps(CORRECTED_SPEC, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert hashlib.sha256(canonical.encode()).hexdigest() == CORRECTED_SPEC_SHA256
    assert hashlib.sha256(PREDICATE.encode()).hexdigest() == PREDICATE_SHA256
    assert PRIOR_FROZEN_SPEC_SHA256 == "f3577db5974d92481250f1d8a59f82e389a143febc41e4b0784c40ea343f5886"
    assert CORRECTED_SPEC_SHA256 == "e64e5ce92cd6765844f89a8e02d607d9b573a8c3fb90bad70ccb5b8081e68337"
    assert PREDICATE_SHA256 == "f0015cbf926c4b1f5a9bb2e88d23e724ea747234eca535b5dc0b64fdac46714b"
    source = proposal_provenance_for(CHECK_ID)
    assert source["signed_spec_sha256"] == PRIOR_FROZEN_SPEC_SHA256
    assert source["signed_spec_status"] == "historical_superseded_for_this_check"
    assert source["source_correction"]["current_canonical_spec_sha256"] == CORRECTED_SPEC_SHA256
    assert source["source_correction"]["current_predicate_sha256"] == PREDICATE_SHA256
    assert source["source_correction"]["prior_frozen_signed_spec_sha256"] == PRIOR_FROZEN_SPEC_SHA256
    assert len(source["source_correction"]["requirement_ids"]) == 5
    source["source_correction"]["requirement_ids"].clear()
    assert len(proposal_provenance_for(CHECK_ID)["source_correction"]["requirement_ids"]) == 5


def test_public_and_remediation_surfaces_agree_without_other_id_override():
    check = next(row for row in CHECKS if row.id == CHECK_ID)
    public = check.public()
    assert public["title"] == TITLE
    assert check.remediation == REMEDIATION  # Frozen evaluator/source hint is retained.
    from tests.reviewed_guidance_presentation import assert_description_preserves_contract
    assert_description_preserves_contract(CHECK_ID)
    assert "running Linux" in public["description"] and "publicKeys" in public["description"]
    assert public["evaluator_version"] == EVALUATOR_VERSION
    current=details_for(CHECK_ID, provider="azure")
    assert public["remediation"] == current["summary"]
    assert "bootstrap public keys" in current["summary"]
    assert "preserve a working administrative access" in current["summary"]
    assert public["remediation_details"]["summary"] == current["summary"]
    assert public["source_correction"] == public["proposal_provenance"]["source_correction"]
    assert details_for(CHECK_ID, provider="azure")["summary"] == current["summary"]
    assert report_templates([CHECK_ID], "azure")[CHECK_ID]["summary"] == current["summary"]
    assert "Use SSH keys" not in json.dumps(public)
    reviewed = description_for(CHECK_ID)
    reviewed["evaluated"].clear()
    assert description_for(CHECK_ID)["evaluated"]
    unrelated = "aws.iam.no_full_admin"
    assert description_for(unrelated).get("source_correction") is None
    assert proposal_provenance_for(unrelated) is None
    assert report_templates([unrelated], "aws")[unrelated]["summary"] != REMEDIATION


class _Transport:
    tenant = "tenant-a"

    def __init__(self):
        self.row = {"id": VM, "type": "Microsoft.Compute/virtualMachines", "properties": {
            "storageProfile": {"osDisk": {"osType": "Linux"}},
            "osProfile": {"linuxConfiguration": {"ssh": {"publicKeys": [
                {"path": "/home/test/.ssh/authorized_keys", "keyData": "inert-public-key"}]}}},
            "instanceView": {"statuses": [{"code": "PowerState/running"}]}}}

    def request(self, url, *, body=None, audience=azure.ARM):
        path = urlsplit(url).path
        if path == SCOPE + "/providers/Microsoft.Compute/virtualMachines":
            return {"value": [{"id": VM}]}
        if path == VM and "$expand=instanceView" in urlsplit(url).query:
            return copy.deepcopy(self.row)
        if path == VM + "/instanceView":
            return copy.deepcopy(self.row["properties"]["instanceView"])
        return {"value": []}

    def close(self):
        pass


def test_real_report_remediation_and_title_use_corrected_source():
    snapshot = azure.collect({"scopes": ["sub"]}, ["vm"], transport=_Transport())
    report = evaluate_snapshot(snapshot, checks=[CHECK_ID], categories=["network"])
    finding = next(row for row in hydrate_frameworks(report)["findings"] if row["check_id"] == CHECK_ID and row["status"] == "FAIL")
    assert finding["status"] == "FAIL"
    assert finding["title"] == TITLE
    current=details_for(CHECK_ID, provider="azure")
    assert finding["remediation"] == current["summary"]
    assert "preserve a working administrative access" in current["summary"]
    assert report["remediation_templates"][CHECK_ID]["summary"] == current["summary"]
    assert report["check_meta"][CHECK_ID]["description"] == description_for(CHECK_ID)["description"]
    for field in ("evaluated", "pass_when", "fail_when", "not_applicable_when"):
        assert report["check_meta"][CHECK_ID].get(field) == DESCRIPTION.get(field)
