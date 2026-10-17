"""Directed SW17 post-installation evidence ingress cases."""
from tests.compliance_draft_isolation import staged_registry

with staged_registry(("compliance_new_sw17",)):
    from test_peaso_compliance_new_sw17 import case, normalized_fact, run, VM, NOW


SUFFIX = "system_updates_installed"


def pci_case():
    machine, index = case(SUFFIX)
    policy = index["context"]["metadata"]["compliance_policy"]["checks"][
        "azure.gap.compute_vm_system_updates_installed"]
    policy["requirePciCompliance"] = True
    return machine, index


def test_zero_available_patches_alone_does_not_certify_pci():
    machine, index = pci_case()
    assert run(SUFFIX, machine, index)[0] == "UNKNOWN"


def test_foreign_capture_pci_compliance_cannot_certify_vm():
    machine, index = pci_case()
    metadata = index["context"]["metadata"]
    for field in ("credential_context_id", "customer_context_id"):
        metadata[field] = "current-capture"
        machine.setdefault("_provenance", {})[field] = "current-capture"
    record = normalized_fact(index, "vm_patch_installation_compliance",
                             operationId="operation-1", installedAt="2026-10-12T09:30:00Z",
                             status="COMPLIANT")
    record["_provenance"].update(credential_context_id="current-capture",
                                  customer_context_id="current-capture")
    assert run(SUFFIX, machine, index)[0] == "PASS"
    for field in ("credential_context_id", "customer_context_id"):
        record["_provenance"][field] = "foreign-capture"
        assert run(SUFFIX, machine, index)[0] == "UNKNOWN"
        record["_provenance"][field] = "current-capture"
    record["status"] = "NON_COMPLIANT"
    assert run(SUFFIX, machine, index)[0] == "FAIL"


def test_pci_compliance_record_is_exact_vm_bound():
    machine, index = pci_case()
    record = normalized_fact(index, "vm_patch_installation_compliance",
                             operationId="operation-1", installedAt="2026-10-12T09:30:00Z",
                             status="COMPLIANT")
    assert run(SUFFIX, machine, index)[0] == "PASS"
    record["vm_id"] = VM + "-other"
    assert run(SUFFIX, machine, index)[0] == "UNKNOWN"
