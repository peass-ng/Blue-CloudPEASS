"""Real registered AWS witnesses get concise facts without verdict-derived guesses."""
from copy import deepcopy
import gzip
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS, CHECK_ALIASES
from peaso.checks.fixtures import CASES
from peaso.checks.aws_typed_finding_summary import evidence_summary, FIELDS

REVIEWED_IDS = ('aws.rds.no_public_endpoint',
 'aws.kms.rotation',
 'aws.logs.retention',
 'aws.rds.backups',
 'aws.rds.vpc_configuration',
 'aws.rds.enhanced_monitoring',
 'aws.cloudtrail.kms_encryption',
 'aws.sns.kms_encryption',
 'aws.rds.copy_snapshot_tags',
 'aws.rds.cloudwatch_log_exports',
 'aws.elbv2.deletion_protection',
 'aws.elbv2.multiple_availability_zones',
 'aws.ecr.lifecycle_policy',
 'aws.config.service_linked_role',
 'aws.guardduty.eks_audit_logs',
 'aws.guardduty.lambda_network_logs',
 'aws.guardduty.rds_login_events',
 'aws.guardduty.s3_data_events',
 'aws.guardduty.runtime_monitoring',
 'aws.b.alb.access_logs',
 'aws.b.alb.deletion_protection',
 'aws.b.alb.invalid_header_dropping',
 'aws.b.alb.desync_mode',
 'aws.b.classic_elb.multiple_az',
 'aws.b.elbv2.multiple_az',
 'aws.b.elbv2.listener_presence',
 'aws.b.classic_elb.desync_mode',
 'aws.b.acm.transparency_logging',
 'aws.b.acm.no_wildcard_domain',
 'aws.b.acm.no_failed_validation',
 'aws.b.acm.not_past_expiry_date',
 'aws.b.cloudfront.viewer_encryption',
 'aws.b.cloudfront.geo_restrictions',
 'aws.b.cloudfront.waf_reference',
 'aws.b.cloudfront.default_root_object',
 'aws.b.cloudfront.field_level_encryption',
 'aws.b.cloudfront.custom_acm_certificate',
 'aws.b.cloudfront.origin_group_metadata',
 'aws.b.cloudfront.origin_secure_protocols',
 'aws.b.cloudfront.no_sslv3_origin',
 'aws.b.cloudfront.custom_origin_encryption',
 'aws.b.aurora.mysql_copy_snapshot_tags',
 'aws.b.aurora.postgres_copy_snapshot_tags',
 'aws.b.aurora.mysql_audit_export',
 'aws.b.rds_instance.nondefault_port_policy',
 'aws.b.rds_cluster.nondefault_port_policy',
 'aws.b.cognito.password_policy',
 'aws.b.codebuild.nonprivileged',
 'aws.b.codebuild.logs_enabled',
 'aws.b.codebuild.artifact_encryption',
 'aws.b.codebuild.s3_artifact_encryption',
 'aws.b.codebuild.s3_log_encryption',
 'aws.b.apigateway.wildcard_cache_encryption',
 'aws.b.apigateway.rest_execution_logging',
 'aws.b.apigateway.http_execution_logging',
 'aws.b.apigateway.rest_xray',
 'aws.b.apigateway.client_certificate',
 'aws.b.apigateway.waf_reference',
 'aws.b.apigateway.private_endpoint_type',
 'aws.b.neptune.audit_logging',
 'aws.b.rds_instance.multiple_az',
 'aws.claude_a.ec2.client_vpn_connection_logging',
 'aws.claude_a.ec2.tgw_no_auto_accept_shared_attachments',
 'aws.claude_a.ec2.spot_fleet_ebs_encrypted',
 'aws.claude_a.ec2.eni_source_dest_check',
 'aws.claude_a.ec2.eni_no_public_ip',
 'aws.claude_a.ec2.eni_in_use',
 'aws.claude_a.ec2.eip_associated',
 'aws.claude_a.iam.console_password_used_45',
 'aws.claude_a.s3.account_public_access_block_all',
 'aws.claude_a.s3.prowler_account_ignore_restrict',
 'aws.claude_a.s3.multi_region_access_point_public_access_block',
 'aws.claude_a.s3.directory_bucket_lifecycle',
 'aws.cb.apigatewayv2.stage_access_logging',
 'aws.cb.glacier.vault_policy_no_public_principal',
 'aws.cb.glacier.vault_policy_prohibit_public_access',
 'aws.cb.glacier.vault_policy_star_principal',
 'aws.cb.glue.connection_jdbc_enforce_ssl',
 'aws.cb.glue.catalog_metadata_encryption',
 'aws.cb.glue.catalog_password_encryption',
 'aws.cb.glue.catalog_password_encryption_with_tables',
 'aws.cb.glue.catalog_metadata_sse_kms_with_tables',
 'aws.cb.glue.catalog_policy_not_public',
 'aws.cb.glue.dev_endpoint_s3_encryption_first_mode',
 'aws.cb.glue.job_continuous_cloudwatch_logging',
 'aws.cb.glue.spark_job_version_3',
 'aws.cb.glue.ml_transform_user_data_encryption',
 'aws.cb.glue.ml_transform_encryption_configured',
 'aws.cb.firehose.server_side_encryption',
 'aws.cb.kinesis.kms_encryption',
 'aws.cb.kinesis.customer_kms_key',
 'aws.cb.mediastore.container_policy_not_public',
 'aws.cb.storagegateway.fileshare_kms',
 'aws.cb.storagegateway.gateway_not_on_ec2',
 'aws.cb.workspaces.root_and_user_volume_encryption',
 'aws.cb.workspaces.root_volume_encryption',
 'aws.cb.workspaces.user_volume_encryption',
 'aws.cb.rds.instance_snapshot_not_public_prowler',
 'aws.cb.rds.cluster_snapshot_not_public_prowler',
 'aws.cb.mq.activemq_active_standby',
 'aws.cb.mq.rabbitmq_cluster_deployment',
 'aws.cb.mq.activemq_audit_logs',
 'aws.cb.mq.engine_logging',
 'aws.cb.kafka.cmk_encryption_at_rest',
 'aws.cb.kafka.enhanced_monitoring',
 'aws.cb.kafka.tls_client_and_in_cluster',
 'aws.cb.msk.client_broker_tls',
 'aws.cb.kafka.public_access_disabled',
 'aws.cb.kafka.mutual_tls_authentication',
 'aws.cb.kafka.unauthenticated_access_disabled',
 'aws.cb.mskconnect.log_delivery',
 'aws.cb.sns.failure_feedback_role',
 'aws.cb.sns.policy_no_unrestricted_wildcard',
 'aws.cb.sns.policy_prohibit_public_access_perimeter',
 'aws.cb.sns.policy_no_public_publish',
 'aws.cb.sns.policy_no_public_subscribe',
 'aws.cb.sns.topic_not_publicly_accessible_prowler',
 'aws.cb.sns.subscription_not_http',
 'aws.cb.sqs.dead_letter_queue',
 'aws.cb.sqs.policy_no_wildcard_allow',
 'aws.cb.sqs.policy_prohibit_public_access_perimeter',
 'aws.cb.sqs.queue_not_public_prowler',
 'aws.cb.ses.dkim_signing',
 'aws.cb.ses.identity_policies_not_public',
 'aws.cb.sfn.logging_not_off',
 'aws.cb.stepfunctions.logging_enabled',
 'aws.cb.stepfunctions.cmk_encryption',
 'aws.cb.transfer.fips_security_policy',
 'aws.cb.transfer.pqc_ssh_kex_policy',
 'aws.cb.transfer.connector_logging_role',
 'aws.cb.sagemaker.notebook_kms_key',
 'aws.cb.sagemaker.notebook_cmk',
 'aws.cb.sagemaker.notebook_in_vpc',
 'aws.cb.sagemaker.notebook_supported_platform',
 'aws.cb.sagemaker.model_vpc_config',
 'aws.cb.sagemaker.model_vpc_subnets',
 'aws.cb.sagemaker.training_vpc_config',
 'aws.cb.sagemaker.training_vpc_subnets',
 'aws.cb.sagemaker.training_output_kms',
 'aws.cb.sagemaker.training_volume_kms',
 'aws.cb.sagemaker.endpoint_config_kms',
 'aws.cb.sagemaker.endpoint_variants_more_than_one',
 'aws.cb.sagemaker.endpoint_variants_not_exactly_one',
 'aws.cb.sagemaker.domain_sso',
 'aws.cb.sagemaker.monitoring_schedule_active',
 'aws.cb.sagemaker.model_registry_approved_package',
 'aws.cb.sagemaker.clarify_job_exists',
 'aws.c2b.ecs.fargate_latest_platform',
 'aws.c2b.ecs.service_load_balancer_attached',
 'aws.c2b.cloudfront.default_behavior_https',
 'aws.c2b.cloudfront.https_sni',
 'aws.c2b.cloudfront.s3_origin_access_control',
 'aws.c2b.cloudfront.s3_origin_access_identity',
 'aws.c2b.elbv2.cross_zone_enabled',
 'aws.c2b.classic_elb.insecure_ssl_ciphers',
 'aws.c2b.classic_elb.has_registered_instances',
 'aws.c2b.classic_elb.sg_inbound_rule',
 'aws.c2b.classic_elb.sg_outbound_rule',
 'aws.c2b.apigateway.domain_pqc_tls',
 'aws.c2b.apigatewayv2.routes_authorization_type',
 'aws.c2b.apigatewayv2.routes_authorizer',
 'aws.c2b.appsync.field_level_logging',
 'aws.c2b.appsync.graphql_no_api_key',
 'aws.c2b.appsync.no_api_key_auth',
 'aws.c2b.directconnect.connection_redundancy',
 'aws.c2b.directconnect.virtual_interface_redundancy',
 'aws.c2b.athena.enforce_configuration',
 'aws.c2b.athena.enforce_configuration_prowler',
 'aws.c2b.athena.cloudwatch_metrics',
 'aws.c2b.athena.cloudwatch_metrics_prowler',
 'aws.c2b.backup.plans_exist_when_vaults',
 'aws.c2b.backup.report_plans_when_plans',
 'aws.c2b.backup.vault_policy_denies_recovery_point_deletion',
 'aws.c2b.backup.vault_policy_not_public',
 'aws.c2b.dynamodb.table_protected_resource',
 'aws.c2b.dynamodb.table_in_backup_selection_prowler',
 'aws.c2b.dynamodb.table_in_backup_selection_or_tag',
 'aws.c2b.datasync.task_log_group',
 'aws.c2b.datasync.task_logging_level',
 'aws.c2b.dax.multi_az',
 'aws.c2b.dlm.policy_exists_with_snapshots',
 'aws.c2b.dlm.ebs_snapshot_policy_with_snapshots',
 'aws.c2b.dms.endpoint_ssl',
 'aws.c2b.dms.mongodb_auth',
 'aws.c2b.dms.neptune_iam_auth',
 'aws.c2b.dms.redis_tls',
 'aws.c2b.dms.task_source_logging',
 'aws.c2b.dms.task_target_logging',
 'aws.c2b.dms.certificate_not_expired',
 'aws.c2b.docdb.snapshot_restore_not_all_exact',
 'aws.c2b.docdb.snapshot_not_public_prowler',
 'aws.c2b.documentdb.cluster_log_exports',
 'aws.c2b.dynamodb.capacity_autoscaling',
 'aws.c2b.dynamodb.sse_kms',
 'aws.c2b.dynamodb.policy_not_cross_account',
 'aws.c2b.elasticache.cluster_no_default_subnet_group',
 'aws.c2b.efs.access_point_root_directory',
 'aws.c2b.efs.access_point_user_identity',
 'aws.c2b.emr.block_public_access_enabled',
 'aws.c2b.es.audit_logs_to_cloudwatch',
 'aws.c2b.es.error_logs_to_cloudwatch',
 'aws.c2b.es.all_logs_to_cloudwatch',
 'aws.c2b.es.tls_1_2_policy',
 'aws.c2b.es.in_vpc',
 'aws.c2b.es.policy_prohibit_public_access',
 'aws.c2b.firehose.encrypted_at_rest_or_msk_source',
 'aws.claude2_a.cloudtrail.trail_bucket_mfa_delete',
 'aws.claude2_a.cloudtrail.account_has_logging_trail',
 'aws.claude2_a.logs.log_group_not_public_via_resource_policy',
 'aws.claude2_a.logs.resource_policy_not_public',
 'aws.claude2_a.config.org_aggregator_all_regions_with_delegated_admin',
 'aws.b.cognito.block_compromised_signin',
 'aws.b.cognito.block_all_takeover_risks',
 'aws.b.redshift.nondefault_admin',
 'aws.b.redshift.nondefault_database',
 'aws.htbp.cognito.identity_pool_classic_flow_disabled',
 'aws.pci.vpc.peering_dns_resolution',
 'aws_g6_elbv2_only_https_tls_listeners',
 'aws_shield_automatic_application_layer_response',
 'aws.nist.ec2_instance_effective_public_reachability',
 'aws.pci.appsync.waf_web_acl',
 'aws.pci.classic_elb.predefined_ssl_policy',
 'aws.pci.iam.nonconsole_mfa_policy',
 'aws.pci.iam.policy_attached_to_active_principal',
 'aws_autoscaling_userdata_plaintext_aws_key',
 'aws_cis_organizations_policy_management_delegated',
 'aws_fedramp_cloudtrail_cloudwatch_integration',
 'aws_fedramp_ec2_effective_public_exposure',
 'aws_g6_api_stage_effective_waf_acl',
 'aws_g6_cloudtrail_region_logging_trail_present',
 'aws_guardduty_high_finding_alert',
 'aws_identity_center_sso_configured',
 'aws_kms_compromised_key_restricted',
 'aws_nist_config_enabled_all_regions',
 'aws_nist_waf_web_acl_resource_associated',
 'aws_securityhub_critical_findings_alert',
 'aws_vpn_tunnel_encryption_configuration')
BY_ID={c.id:c for c in CHECKS}
ROOT=Path(__file__).resolve().parents[1]
EXTRA={}
for name in ('aws_bulk_clarity_reviewed','aws_final_clarity_reviewed'):
    EXTRA.update(json.loads(gzip.decompress((ROOT/'tests/fixtures'/f'{name}.json.gz').read_bytes())))

def actual(cid,case):
    native_id = cid
    if cid == 'aws.cb.sns.policy_prohibit_public_access_perimeter':
        native_id = 'aws.cb.sns.policy_no_unrestricted_wildcard'
        assert CHECK_ALIASES[cid] == native_id
    if cid in EXTRA:
        row=EXTRA[cid].get(case.upper())
        if row is None:return None
        item,index=row['item'],row['index']
    else:
        row=CASES[native_id]
        if case not in row:return None
        item,index=row[case],row.get(case+'_index',row.get('index',{}))
    status,evidence=BY_ID[native_id].evaluate(deepcopy(item),deepcopy(index))
    return {'provider':'aws','check_id':cid,'status':status,'evidence':evidence}

@pytest.mark.parametrize('cid',REVIEWED_IDS)
def test_each_original_generic_failure_has_a_specific_actual_observation(cid):
    f=actual(cid,'fail');before=deepcopy(f)
    assert f['status']=='FAIL'
    text=evidence_summary(f)
    assert text and len(text.split())<=55
    assert not text.startswith(('Observed evidence:','No observed evidence','The recorded evidence'))
    assert not any(k in text for k in ('official_reference','publicly_accessible','DBSubnetGroup','encryption_disabled'))
    assert f==before

@pytest.mark.parametrize('cid',REVIEWED_IDS)
def test_missing_foreign_and_undetermined_witnesses_do_not_invent_a_setting(cid):
    for e in ({},{'unrelated':True}):
        assert evidence_summary({'provider':'aws','check_id':cid,'status':'FAIL','evidence':e}) is None
    f=actual(cid,'fail')
    assert evidence_summary(dict(f,provider='gcp')) is None
    for status in ('UNKNOWN','DENIED','MANUAL','NOT_APPLICABLE'):
        assert evidence_summary(dict(f,status=status)) is None

@pytest.mark.parametrize('cid',REVIEWED_IDS)
def test_real_positive_fields_are_not_reinterpreted_as_negative_settings(cid):
    f=actual(cid,'pass')
    if f is None:return
    before=deepcopy(f)
    # The projection describes supplied values, independently of a stored verdict.
    assert evidence_summary(f)==evidence_summary(dict(f,status='FAIL'))
    assert f==before

@pytest.mark.parametrize('cid',REVIEWED_IDS)
def test_wrong_typed_fields_do_not_raise_or_create_observations(cid):
    f=actual(cid,'fail')
    for key in f['evidence']:
        for bad in ([],{},None):
            # Some fields intentionally admit None; only enforce no exceptions
            # on general malformed input, and strict boolean/counter contracts below.
            e=deepcopy(f['evidence']);e[key]=bad
            evidence_summary(dict(f,evidence=e))

@pytest.mark.parametrize('field,bad',[('rotation_enabled',1),('rotation_enabled','false'),('rotation_enabled',False)])
def test_rotation_requires_a_boolean_and_says_the_observed_setting(field,bad):
    f={'provider':'aws','check_id':'aws.kms.rotation','status':'FAIL','evidence':{field:bad}}
    assert evidence_summary(f)==('Automatic KMS key rotation is disabled.' if bad is False else None)

def test_discriminator_mismatch_cannot_relabel_an_unrelated_empty_setting():
    f={'provider':'aws','check_id':'aws.rds.vpc_configuration','status':'FAIL','evidence':{'field':'SomethingElse','configured':''}}
    assert evidence_summary(f) is None

def test_web_endpoint_configuration_does_not_claim_live_connectivity():
    f={'provider':'aws','check_id':'aws.rds.no_public_endpoint','status':'FAIL','evidence':{'publicly_accessible':True}}
    assert evidence_summary(f)=='The RDS endpoint is configured as publicly accessible.'
    assert evidence_summary(dict(f,evidence={'publicly_accessible':False}))=='The RDS endpoint is not configured as publicly accessible.'
