"""Semantic states for the signed Cloud Build trigger logging predicate."""
from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_gcp_cloudbuild  # noqa: F401: registration
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


CHECK_ID = "gcp_pci_cloudbuild_trigger_3302edf7cb18"


def trigger(logging="NONE", *, state="present", disabled=False, **extra):
    inline = {"logging_field_state": state}
    if state == "present":
        inline["logging"] = logging
    return {"id": "t1", "resourceName": "projects/p-one/locations/global/triggers/t1",
            "disabled": disabled, "inlineBuild": inline,
            "_provenance": {"representation": "full"}, **extra}


def evaluate(item):
    return evaluate_check(CHECK_ID, item, {})


def test_inline_logging_pass_fail_and_disabled_not_applicable():
    assert evaluate(trigger("NONE"))[0] == "FAIL"
    for enum in ("LEGACY", "GCS_ONLY", "CLOUD_LOGGING_ONLY"):
        assert evaluate(trigger(enum))[0] == "PASS"
    assert evaluate(trigger(state="omitted"))[0] == "PASS"
    assert evaluate(trigger(disabled=True))[0] == "NOT_APPLICABLE"


def test_file_backed_and_uncertain_trigger_facts_stay_unknown():
    file_backed = trigger(filename="cloudbuild.yaml")
    assert evaluate(file_backed)[0] == "UNKNOWN"
    assert evaluate(trigger(state="malformed"))[0] == "UNKNOWN"
    assert evaluate(trigger("FUTURE_MODE"))[0] == "UNKNOWN"
    assert evaluate(trigger(disabled=None))[0] == "UNKNOWN"
    missing_disabled = trigger()
    del missing_disabled["disabled"]
    assert evaluate(missing_disabled)[0] == "FAIL"
    masked = trigger()
    del masked["_provenance"]
    assert evaluate(masked)[0] == "UNKNOWN"
    denied = trigger(collection_status="denied")
    assert evaluate(denied)[0] == "UNKNOWN"
    covered = trigger(_coverage={"disabled": {"status": "denied"}})
    assert evaluate(covered)[0] == "UNKNOWN"


def test_production_engine_scopes_cloudbuild_trigger():
    item = trigger("NONE")
    snapshot = make_snapshot("gcp", ["projects/p-one"], [
        {"type": "cloudbuild_trigger", "scope": "projects/p-one", "service": "cloudbuild",
         "status": "collected", "items": [item]},
    ], created_at="2026-10-12T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CHECK_ID])
    findings = [finding for finding in report["findings"] if finding["check_id"] == CHECK_ID]
    assert len(findings) == 1 and findings[0]["status"] == "FAIL"
    check = next(check for check in CHECKS if check.id == CHECK_ID)
    assert (check.provider, check.kind, check.category, check.severity, check.target) == (
        "gcp", "cloudbuild_trigger", "hardening", "medium", "resource")
