from copy import deepcopy
from scripts.audit_aws_requirement_associations import reconcile_edge


def test_exact_accepted_topic_decision_does_not_claim_requirement_automation():
    key=('pci_4.0_aws','7.2.1.3')
    source='codebuild_project_no_secrets_in_variables'
    row={'decision':'MAPPING_FIX','native_checks':['aws.b.codebuild.nonprivileged'],'removed_checks':[]}
    before=reconcile_edge(source,['aws.review.codebuild_project.configuration_secret_indicators'],key,{key:row},{})
    review=before['directed_review']
    accepted={(source,*key):dict(review,decision=review['recommendation'],admission_status='accepted_by_root',intake='source_topic_only_no_runtime_compliance_link')}
    result=reconcile_edge(source,['aws.review.codebuild_project.configuration_secret_indicators'],key,{key:row},{},accepted)
    assert result['disposition']=='accepted_no_requirement_membership_change'
    assert not result['counts_as_requirement_automation']
    assert row['native_checks']==['aws.b.codebuild.nonprivileged']
    wrong=deepcopy(accepted);wrong[(source,*key)]['reason']='Different semantic claim'
    assert reconcile_edge(source,['new'],key,{key:row},{},wrong)['disposition'].startswith('unresolved')
