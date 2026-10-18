"""Public SW23 SAS and SIEM ingress with inert external evidence metadata."""
import copy
import hashlib
import json
from pathlib import Path

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot


SAS = "azure.cis.shared_access_signature_tokens_expire_within_hour"
SIEM = "azure_c5_ops_13_03b"
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


def _second_hash_record(account, evidence):
    container = evidence["containers"]["items"][0]
    second = copy.deepcopy(container["hash_records"]["items"][0])
    second.update(event_id="event-2", source_event_id="event-2", destination_event_id="event-2")
    container["hash_records"]["items"].append(second)
    for side in ("source", "destination"):
        container[side + "_event_ids"].append("event-2")
        container[side + "_count"] = 2
        digest = hashlib.sha256(json.dumps(sorted(container[side + "_event_ids"]),
                                separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        container["observation"][side + "_event_ids_sha256"] = digest
        container["observation"][side + "_count"] = 2
    return container, second


def test_verified_siem_hash_mismatch_survives_other_foreign_record():
    def mutate(account, evidence):
        container, second = _second_hash_record(account, evidence)
        container["hash_records"]["items"][0]["copy_sha256"] = "0" * 64
        second["window_start"] = "2026-10-11T11:00:00+00:00"
    assert _finding(SIEM, mutate)["status"] == "FAIL"


def test_foreign_siem_record_cannot_prove_archive_integrity():
    def mutate(account, evidence):
        _, second = _second_hash_record(account, evidence)
        second["container_id"] = account["id"] + "/blobServices/default/containers/elsewhere"
    assert _finding(SIEM, mutate)["status"] == "UNKNOWN"


def test_equivalent_siem_window_instants_join():
    def mutate(account, evidence):
        container = evidence["containers"]["items"][0]
        container["observation"]["window_start"] = "2026-10-12T13:00:00+02:00"
        container["observation"]["window_end"] = "2026-10-12T14:00:00+02:00"
        record = container["hash_records"]["items"][0]
        record["window_start"] = "2026-10-12T13:00:00+02:00"
        record["window_end"] = "2026-10-12T14:00:00+02:00"
    assert _finding(SIEM, mutate)["status"] == "PASS"


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
