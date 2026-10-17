"""Directed SW17 registrar test kept outside the ordinary full-suite registry."""

import importlib

from peaso.snapshot import make_snapshot
from tests.compliance_draft_isolation import staged_registry
from tests.test_peaso_azure_assessment_list_read_capture import SCOPE, VM, assessment, collect


CID = 'azure.gap.compute_vm_container_security_configurations_vulnerabilities_remediated'


def test_actual_list_capture_reaches_registered_sw17_with_explicit_external_authority():
    snapshot, envelope, _ = collect({'value': [assessment(status='Unhealthy')]})
    policy = {'status': 'collected', 'scope': SCOPE,
              'checks': {CID: {'assessmentKeys': ['stable-key'], 'maxReportAgeSeconds': 3600}}}
    external = {'id': VM + '/providers/Microsoft.ComplianceEvidence/vm_compliance_applicability/evidence',
                'vm_id': VM, 'check_id': CID, 'applicable': True, 'basis': 'explicit external Docker-host roster',
                '_provenance': {'read_only': True, 'source_operation': 'ExternalDockerHostRoster_Read',
                                'observed_at': snapshot['created_at']}}
    facts = {'type': 'vm_compliance_applicability', 'scope': SCOPE, 'service': 'ExternalEvidence',
             'status': 'collected', 'items': [external]}
    rebound = make_snapshot('azure', [SCOPE], snapshot['collections'] + [facts],
                            metadata={**snapshot['metadata'], 'compliance_policy': policy},
                            created_at=snapshot['created_at'])
    with staged_registry(['compliance_new_sw17']):
        importlib.import_module('peaso.checks.compliance_new_sw17')
        from peaso.engine import evaluate_snapshot
        findings = evaluate_snapshot(rebound, checks=[CID])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'FAIL'
    assert envelope['items'][0]['_provenance']['source_operation'] == 'Assessments_List'
