"""Versioned source erratum for the literal Azure PCI launch-key criterion.

The verified historical proposal and compiled packs are intentionally immutable.
This successor describes stored VM launch configuration, not guest SSH behavior.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy

CHECK_ID = "azure_vm_8_2_1_1_712e1ad"
VERSION = "peaso-source-correction-v1"
EVALUATOR_VERSION = "2.0.0"
PRIOR_FROZEN_SPEC_SHA256 = "f3577db5974d92481250f1d8a59f82e389a143febc41e4b0784c40ea343f5886"
SOURCE_URL = "https://raw.githubusercontent.com/prowler-cloud/prowler/61d2cc55c4539a6b48a3cf9f3729d8f2af300882/prowler/compliance/azure/pci_4.0_azure.json"
SOURCE_SHA256 = "e36914af07128f9e7dcda093e3bb89ca97245829c1d55caf0fba33f8dcdd60e0"
SOURCE_SELECTION_SHA256 = "fd0019e589e996f53e12f92daf5b82dda5532d7b00080f1e5c1baf27bd31f6ad"
PCI_REQUIREMENTS = ("8.2.1.1", "8.2.2.2", "8.2.4.1", "8.2.5.1", "8.3.11.1")
SOURCE_SENTENCE = (
    "Checks if running Azure Virtual Machines (VMs) are launched using Azure SSH public keys. "
    "The rule is NON_COMPLIANT if a running VM instance is launched with a public SSH key."
)
TITLE = "Running Linux VM launch configuration has no SSH public key"
DESCRIPTION_TEXT = (
    "Checks the literal Azure PCI source criterion: a running Linux VM is noncompliant "
    "when its recorded launch configuration contains an SSH public key. This checks "
    "the stored launch configuration only; it does not measure guest SSH or password authentication."
)
DATA_SOURCE = (
    "Complete paged Microsoft.Compute/virtualMachines GET and instanceView: "
    "properties.storageProfile.osDisk.osType, "
    "properties.osProfile.linuxConfiguration.ssh.publicKeys[] and PowerState status."
)
PREDICATE = (
    "For each running Linux VM with complete launch-configuration evidence, FAIL if "
    "properties.osProfile.linuxConfiguration.ssh.publicKeys is a nonempty array; "
    "PASS if that array is explicitly present and empty. UNKNOWN if OS type, running "
    "state, launch-key array, or inventory completeness is unresolved or malformed. "
    "Windows and nonrunning VMs are NOT_APPLICABLE. This is a literal launch-key "
    "presence criterion, not a claim about effective guest authentication."
)
REMEDIATION = (
    "Review the VM's recorded launch SSH public keys against the approved access policy. "
    "If this literal source criterion applies, use an approved deployment configuration "
    "without a launch SSH public key; assess guest authentication separately."
)
CORRECTED_SPEC = {
    "id": CHECK_ID,
    "provider": "azure",
    "resource_kind": "vm",
    "data_source": DATA_SOURCE,
    "predicate": PREDICATE,
    "severity": "high",
    "category": "network",
    "title": TITLE,
    "description": DESCRIPTION_TEXT,
    "remediation_hint": REMEDIATION,
}

def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

CORRECTED_SPEC_SHA256 = _digest(json.dumps(CORRECTED_SPEC, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
PREDICATE_SHA256 = _digest(PREDICATE)
SOURCE_CORRECTION = {
    "version": VERSION,
    "status": "source_erratum_successor",
    "prior_frozen_signed_spec_sha256": PRIOR_FROZEN_SPEC_SHA256,
    "prior_frozen_status": "historical_superseded_for_this_check",
    "current_canonical_spec_sha256": CORRECTED_SPEC_SHA256,
    "current_predicate_sha256": PREDICATE_SHA256,
    "source_url": SOURCE_URL,
    "source_sha256": SOURCE_SHA256,
    "source_selection_sha256": SOURCE_SELECTION_SHA256,
    "framework_id": "pci_4.0_azure",
    "requirement_ids": list(PCI_REQUIREMENTS),
    "criterion_scope": "recorded VM launch SSH public-key presence; no runtime authentication claim",
}
DESCRIPTION = {
    "title": TITLE,
    "description": DESCRIPTION_TEXT,
    "evaluated": [DATA_SOURCE, "Complete scoped vm inventory and explicit ssh.publicKeys array"],
    "pass_when": "Running Linux VM with complete evidence has an explicitly present empty launch ssh.publicKeys array.",
    "fail_when": "Running Linux VM with complete evidence has a nonempty launch ssh.publicKeys array.",
    "not_applicable_when": "VM is Windows or is conclusively stopped or deallocated.",
    "remediation": REMEDIATION,
    "evaluator_version": EVALUATOR_VERSION,
    "source_correction": SOURCE_CORRECTION,
}

def description():
    """Return independent public metadata for this one successor check."""
    return deepcopy(DESCRIPTION)

def correction_provenance():
    """Keep current source/canonical hashes separate from historical signature."""
    return deepcopy(SOURCE_CORRECTION)
