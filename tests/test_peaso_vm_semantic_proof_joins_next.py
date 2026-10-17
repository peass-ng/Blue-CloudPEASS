"""Fresh observation read order is not deployment or activation order."""
from tests.compliance_draft_isolation import staged_registry

with staged_registry(("compliance_new_sw17",)):
    from test_peaso_compliance_new_sw17 import case, native, normalized_fact, run


def test_fresh_alert_before_later_policy_observation_can_pass():
    suffix = "adaptive_application_controls_enabled"
    machine, index = case(suffix)
    attestation = native(index, "application_allowlist_attestation")
    attestation["policy_observation"]["_provenance"]["observed_at"] = "2026-10-12T09:50:00Z"
    attestation["alert_observation"]["_provenance"]["observed_at"] = "2026-10-12T09:10:00Z"
    assert run(suffix, machine, index)[0] == "PASS"


def test_fresh_monitoring_before_later_exception_and_report_can_pass():
    suffix = "rdp_service_disabled"
    machine, index = case(suffix)
    report = native(index, "guest_configuration_report")
    report["properties"]["details"]["resources"][0]["properties"]["state"] = "Enabled"
    normalized_fact(index, "vm_rdp_exception", approved=True, officer="officer-1",
        valid_from="2026-10-12T09:30:00Z", valid_until="2026-10-12T11:00:00Z")
    normalized_fact(index, "vm_remote_access_monitoring", routingEnabled=True, monitoredAlerts=True,
        eventCategories=["rdp-sign-in", "rdp-session"])["_provenance"]["observed_at"] = "2026-10-12T09:05:00Z"
    assert run(suffix, machine, index)[0] == "PASS"
