"""Authority boundaries for normalized imported backup-alert evidence."""
from peaso.checks import evaluate_check
from tests.test_peaso_azure_database_alert_delivery_binding import observed, proof_of
from tests.test_peaso_azure_wave_backup_native_alert import CID, SERVICE


def verdict(index):
    return evaluate_check(CID, {}, index)


def test_unattributed_failed_test_is_unresolved():
    index = observed()
    proof = proof_of(index)
    proof.pop("_provenance")
    proof["signals"]["disabled"]["testStatus"] = "failed"
    assert verdict(index)[0] == "UNKNOWN"


def test_foreign_capture_cannot_prove_signal_absent():
    index = observed()
    proof = proof_of(index)
    proof["_provenance"]["customer_context_id"] = "other-customer"
    proof["signals"]["disabled"]["observable"] = False
    assert verdict(index)[0] == "UNKNOWN"


def test_authorized_failure_survives_unavailable_peer_service():
    index = observed()
    proof = proof_of(index)
    proof["signals"]["disabled"]["testStatus"] = "failed"
    other = SERVICE.rsplit("/", 1)[0] + "/peer"
    index["collections"]["database_backup_service"][0]["items"].append({"id": other})
    index["database_backup_service"].append({"type": "database_backup_service", "scope": index["context"]["scope"], "data": {"id": other}})
    status, evidence = verdict(index)
    assert status == "FAIL", evidence
    assert other.casefold() in evidence["unresolved_services"]


def test_unapproved_capture_cannot_prove_failed_test():
    index = observed()
    proof = proof_of(index)
    proof["_provenance"]["authorizationDocumentId"] = "unapproved-read"
    proof["signals"]["disabled"]["testStatus"] = "failed"
    assert verdict(index)[0] == "UNKNOWN"
