"""Public SW23 SAS ingress with inert external evidence metadata."""
import copy
import json
from pathlib import Path

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot


SAS = "azure.cis.shared_access_signature_tokens_expire_within_hour"
FIXTURE = Path(__file__).parent / "fixtures" / "bulk_pending_behavior.json"


def _finding(check_id, mutate):
    index = copy.deepcopy(json.loads(FIXTURE.read_text())[check_id]["pass_index"])
    context = index["context"]
    envelopes = [copy.deepcopy(batch) for batches in index["collections"].values() for batch in batches]
    account = next(batch for batch in envelopes if batch["type"] == "storage_account")["items"][0]
    evidence = next(batch for batch in envelopes if batch["type"] in
                    {"storage_sas_issuance", "siem_archive_evidence"})["items"][0]["payload"]
    mutate(account, evidence)
    snapshot = make_snapshot("azure", [context["scope"]], envelopes,
                             metadata=context.get("metadata", {}), created_at=context["created_at"])
    collected = collect_snapshot({"connector": {"provider": "azure", "scopes": [context["scope"]],
                                  "auth": {}, "options": {"snapshot": snapshot}}, "checks": [check_id]})
    findings = [finding for finding in evaluate_snapshot(collected, checks=[check_id],
                 include_not_applicable=True)["findings"] if finding["check_id"] == check_id]
    assert len(findings) == 1
    return findings[0]


def test_overlong_sas_cannot_bypass_malformed_account_policy():
    def mutate(account, evidence):
        account["properties"]["sasPolicy"]["sasExpirationPeriod"] = "malformed"
        evidence["tokens"]["items"][0]["effective_start"] = "2026-10-12T10:00:00+00:00"
    assert _finding(SAS, mutate)["status"] == "UNKNOWN"


def test_overlong_sas_cannot_bypass_incomplete_issuer_inventory():
    def mutate(account, evidence):
        evidence["issuer_inventory_complete"] = False
        evidence["tokens"]["items"][0]["effective_start"] = "2026-10-12T10:00:00+00:00"
    assert _finding(SAS, mutate)["status"] == "UNKNOWN"


def test_overlong_sas_cannot_bypass_foreign_issuance_authority():
    def mutate(account, evidence):
        token = evidence["tokens"]["items"][0]
        token["effective_start"] = "2026-10-12T10:00:00+00:00"
        foreign = copy.deepcopy(token)
        foreign["issuance_id"] = "issuer-foreign"
        foreign["account_id"] = account["id"] + "-other"
        evidence["tokens"]["items"].append(foreign)
    assert _finding(SAS, mutate)["status"] == "UNKNOWN"


def test_overlong_sas_requires_resolved_service_exceptions():
    def mutate(account,evidence):
        evidence['service_exceptions_resolved']=False
        evidence['tokens']['items'][0]['effective_start']='2026-10-12T10:00:00+00:00'
    assert _finding(SAS,mutate)['status']=='UNKNOWN'


def test_overlong_sas_requires_resolved_stored_policies():
    def mutate(account,evidence):
        evidence['stored_policies_resolved']=False
        evidence['tokens']['items'][0]['effective_start']='2026-10-12T10:00:00+00:00'
    assert _finding(SAS,mutate)['status']=='UNKNOWN'
