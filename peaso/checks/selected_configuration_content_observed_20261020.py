"""Brief typed observations for reviewed selected-content readers."""
from peaso.secret_scanning import merge_leaks,KINGFISHER_VERSION,TRUFFLEHOG_VERSION

RULES={
 'aws.review.codebuild.selected_inline_buildspec_secret_indicators':('aws','selected_returned_inline_buildspec_only','the selected inline CodeBuild buildspec'),
 'gcp.review.dataflow.selected_package_referenced_source_secret_indicators':('gcp','selected_current_referenced_package_only','the selected Dataflow package source'),
 'gcp.review.batch.selected_mounted_script_source_secret_indicators':('gcp','selected_captured_mounted_script_source_only','the selected Batch mounted script source'),
 'gcp.review.workbench.selected_referenced_source_secret_indicators_20261020':('gcp','selected_captured_referenced_source_only','the selected Workbench referenced source'),
 'k8s.review.selected_metadata.secret_indicators':('k8s','selected_object_metadata_only','the selected object labels and annotations'),
 'gcp.review.dataproc.selected_job_referenced_source_secret_indicators':('gcp','selected_captured_referenced_source_only','the selected Dataproc referenced source'),
 'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators':('gcp','selected_captured_referenced_source_only','the selected Dataproc referenced source'),
 'azure.review.machine_learning.selected_code_file_secret_indicators':('azure','selected_captured_ml_asset_text_only','the selected associated code file'),
 'azure.review.machine_learning.selected_environment_conda_secret_indicators':('azure','selected_captured_ml_asset_text_only','the selected inline Conda text'),
 'azure.review.databricks.selected_notebook_source_secret_indicators':('azure','selected_workspace_content_export_only','the selected Databricks workspace content'),
 'k8s.review.selected_container_logs.secret_indicators':('k8s','selected_current_container_sample_only','selected current-container log samples and resource names'),
 'azure.review.machine_learning.selected_command_job_secret_indicators':('azure','selected_job_literal_declarations_only','selected Machine Learning job literals'),
 'aws.review.s3.selected_source_secret_indicators':('aws','selected_s3_source_text_only','the selected S3 source text'),
 'azure.review.log_analytics.selected_message_sample_secret_indicators':('azure','selected_message_sample_only','the selected Log Analytics message sample'),
 'azure.review.application_insights.selected_trace_sample_secret_indicators':('azure','selected_message_sample_only','the selected Application Insights trace sample'),
 'azure.review.app_configuration.selected_value_secret_indicators':('azure', 'selected_public_literals_only', 'the selected App Configuration value'),
 'azure.review.data_factory.selected_declaration_secret_indicators':('azure', 'selected_public_literals_only', 'selected Data Factory declarations'),
 'azure.review.synapse.selected_pipeline_secret_indicators':('azure', 'selected_public_literals_only', 'the selected Synapse pipeline'),
 'aws.review.configuration.selected_content_secret_indicators':('aws','selected_returned_literals_only','selected AWS configuration literals'),
 'azure.review.configuration.selected_content_secret_indicators':('azure','selected_arm_literals_only','selected Azure configuration literals'),
 'azure.review.storage.selected_source_secret_indicators':('azure','selected_captured_stored_source_only','the selected Azure stored source'),
 'azure.review.devops.selected_content_secret_indicators':('azure','selected_devops_literals_only','selected Azure DevOps literals'),
}


def observation(finding):
    try:
        from .aws_workload_command_observed_20261020 import observation as commands
        command = commands(finding)
        if command:return command
        from .public_source_secret_observed_20261020 import observation as public_source
        grouped = public_source(finding)
        if grouped:return grouped
        from .azure_configured_package_observed_20261020 import observation as package
        configured = package(finding)
        if configured:return configured
        from .gcp_consolidated_secret_observed_20261020 import observation as consolidated
        public=consolidated(finding)
        if public:return public
        rule=RULES.get(finding.get('check_id'))
        if rule is None or finding.get('provider')!=rule[0] or finding.get('status')not in ('PASS','FAIL'):
            return None
        e=finding['evidence']
        merged_partial=e.get('complete')is False and e.get('coverage')=='incomplete'
        merged_hit='complete'not in e and 'coverage'not in e
        if (finding['check_id']=='aws.review.codebuild.selected_inline_buildspec_secret_indicators'
                and finding['status']=='FAIL' and (merged_partial or merged_hit)
                and e.get('credential_validation')=='not_attempted'):
            import re
            leaks=e.get('secret_leaks')
            if (finding.get('linked_check_ids')!=[finding['check_id']] or not isinstance(leaks,list)or len(leaks)!=1
                    or merge_leaks(leaks)!=leaks or finding.get('secret_fingerprint')!=leaks[0]['fingerprint']):return None
            if any(not re.fullmatch(r'codebuild_selected_inline_buildspec:[0-9a-f]{64}',loc.get('resource_id',''))
                   or loc['path']!=loc['resource_id']+'.source.buildspec'
                   or not re.fullmatch(r'[0-9]{12}/[a-z0-9-]+',loc.get('scope',''))
                   for loc in leaks[0]['locations']):return None
            return ('A likely secret was detected in the selected inline CodeBuild buildspec. Its value is hidden and was not validated'
                    + ('; inspection is incomplete.'if merged_partial else '.'))
        if (finding['check_id']=='k8s.review.selected_metadata.secret_indicators' and finding['status']=='FAIL'
                and (merged_partial or merged_hit)
                and e.get('credential_validation')=='not_attempted'):
            leaks=e.get('secret_leaks')
            if (finding.get('linked_check_ids')!=[finding['check_id']] or not isinstance(leaks,list)or len(leaks)!=1
                    or merge_leaks(leaks)!=leaks or finding.get('secret_fingerprint')!=leaks[0]['fingerprint']):return None
            import re
            if any(not re.fullmatch(r'k8s_selected_metadata:[0-9a-f]{64}',loc.get('resource_id',''))
                   or loc['path']!=loc['resource_id']+'.literals'for loc in leaks[0]['locations']):return None
            return ('A likely secret was detected in the selected object labels or annotations. Its value is hidden and was not validated'
                    + ('; inspection is incomplete.'if merged_partial else '.'))
        partial=(finding['check_id']=='k8s.review.selected_metadata.secret_indicators'
                 and finding['status']=='FAIL' and e.get('complete')is False
                 and e.get('coverage')=='incomplete_selected_object_metadata')
        if (not partial and (e.get('complete')is not True or e.get('coverage')!=rule[1])) or e.get('credential_validation')!='not_attempted':
            return None
        parts=[{'complete':True,'engines':e.get('engines')}]if rule[0]=='aws' and rule[1] in ('selected_returned_literals_only','selected_returned_inline_buildspec_only') else e.get('parts')
        if not isinstance(parts,list)or not parts or len(parts)>256:return None
        versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        if partial and len(parts)!=1:return None
        completed=set()
        for part in parts:
            engines=part.get('engines')
            if (not isinstance(engines,list)or len(engines)!=2
                or {r.get('engine')for r in engines}!=set(versions)
                or any(r.get('status')not in (('complete','unavailable')if partial else ('complete',))or r.get('version')!=versions.get(r.get('engine'))for r in engines)):
                return None
            completed={r['engine']for r in engines if r['status']=='complete'}
            if (not completed or (partial and (type(part.get('complete'))is not bool or part['complete']!=(len(completed)==2)))
                    or not partial and part.get('complete')is not True):return None
        leaks=e.get('secret_leaks')
        if not isinstance(leaks,list)or merge_leaks(leaks)!=leaks or (finding['status']=='FAIL')!=bool(leaks):return None
        if partial:
            if any(d['engine']not in completed for leak in leaks for d in leak['detectors']):return None
            return f'A likely secret was detected in {rule[2]}. Its value is hidden and was not validated; inspection is incomplete.'
        return (f'A likely secret was detected in {rule[2]}. Its value is hidden and was not validated.'if leaks else
                f'Both offline detectors found no supported secret in {rule[2]}.')
    except (KeyError,TypeError,ValueError,AttributeError):
        return None
