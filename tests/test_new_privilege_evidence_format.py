"""New privilege paths must emit readable evidence from validated findings."""

import pytest

from peaso.privesc import catalog
from peaso.privesc.aws_observed_evidence_v3 import evidence_summary as aws_summary
from peaso.privesc.gcp_observed_impact import evidence_summary as gcp_summary


@pytest.mark.parametrize('provider,check_id,subject', [
    ('aws', 'aws-cloudformation-updatestack-attached-role', 'stack'),
    ('aws', 'aws-cloudformation-changeset-attached-role', 'change set'),
    ('aws', 'aws-eks-associateaccesspolicy-existing-entry', 'EKS access entry'),
    ('gcp', 'gcp-agentidentity-retrieve-credentials', 'Google OAuth token'),
    ('gcp', 'gcp-agentidentity-update-token-url', 'token URL'),
    ('gcp', 'gcp-cloudbuild-builds-create-cross-project-actas', 'Cloud Build'),
    ('gcp', 'gcp-run-jobs-create-run-cross-project-actas', 'Cloud Run'),
    ('gcp', 'gcp-run-services-create-cross-project-actas', 'Cloud Run'),
    ('gcp', 'gcp-storage-managedfolders-setiampolicy-composer', 'Composer DAG'),
    ('gcp', 'gcp-storage-managedfolders-setiampolicy-dataproc-init', 'Dataproc'),
    ('gcp', 'gcp-workflows-create-cross-project-actas', 'Workflows'),
])
@pytest.mark.parametrize('status,confidence', [
    ('FAIL', 'derived'), ('MANUAL', 'conditional'), ('UNKNOWN', 'unknown'),
])
def test_new_privilege_path_uses_three_source_specific_lines(provider, check_id, subject,
                                                            status, confidence):
    entry = next(item for item in catalog()['entries'] if item['id'] == check_id)
    unknown = status == 'UNKNOWN'
    evidence = {
        'technique': {'id': check_id, 'source': entry['source']},
        'source': {'id': 'alice', 'label': 'alice'},
        'targets': [{'id': 'reviewed-target', 'label': 'reviewed-target',
                     'underlying_count': 0 if unknown else 1}],
        'target_count': 0 if unknown else 1,
        'confidence': confidence,
        'conditions': [],
        'blockers_not_evaluated': [],
        'granting_statements': [] if unknown else [{'effect': 'Allow'}],
    }
    finding = {'provider': provider, 'check_id': check_id, 'status': status,
               'evidence': evidence}
    summary = (aws_summary if provider == 'aws' else gcp_summary)(finding)
    assert summary is not None
    lines = summary.splitlines()
    assert len(lines) == 3
    assert all(line.endswith('.') for line in lines)
    assert subject in summary
    assert '{"' not in summary
