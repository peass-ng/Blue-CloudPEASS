"""Concise observed facts for source-reviewed AWS bulk callbacks."""
from ipaddress import ip_address
from .aws_bulk_clarity_reviewed import ROWS


def evidence_summary(finding):
    if not isinstance(finding,dict) or finding.get('provider')!='aws' or finding.get('status')!='FAIL':return None
    cid=finding.get('check_id');row=ROWS.get(cid);evidence=finding.get('evidence')
    if row is None or not isinstance(evidence,dict):return None
    if cid in {'aws.nist.ec2_instance_effective_public_reachability','aws_fedramp_ec2_effective_public_exposure'}:
        witness=evidence.get('configured_path_witness')
        if isinstance(witness,dict) and witness.get('model')=='aws-public-config-witness-v1':
            protocol=witness.get('protocol');port=witness.get('destination_port');address=witness.get('public_address')
            try:public=ip_address(address) if isinstance(address,str) else None
            except ValueError:public=None
            if public is not None and public.is_global and protocol in {'tcp','udp','6','17',6,17} and type(port) is int and 0<port<=65535:
                transport='tcp' if protocol in {'tcp','6',6} else 'udp'
                return f'The configuration permits Internet {transport}/{port} ingress to {public}; a listening service is unverified.'
    def strings(value):return isinstance(value,list) and all(isinstance(v,str) and v for v in value)
    if cid=='aws_kms_key_expiry':
        if evidence.get('imported_material_expired') is True:return 'The imported KMS key material has expired.'
        if evidence.get('retired') is True and evidence.get('key_state') in {'Enabled','PendingImport','Unavailable','Creating','Updating'}:return 'The KMS key is marked retired and is not disabled.'
    if cid=='aws_nist_rds_db_cluster_aurora_backtracking_enabled':
        value=evidence.get('backtrack_window')
        if value==0 and type(value) is int:return 'Aurora BacktrackWindow is zero, so backtracking is disabled.'
    if cid=='aws_api_customer_log_delivery':
        if evidence.get('access_log_destination_configured') is False:return 'The REST stage has no configured access-log destination.'
    if cid in {'aws.pci.sns.delivery_status_logging','aws_nist_sns_topic_notification_delivery_status_enabled'}:
        values=evidence.get('missing_feedback_protocols',evidence.get('protocols_without_complete_feedback'))
        known={'SQS','LAMBDA','APPLICATION','HTTP','HTTPS','FIREHOSE'}
        if isinstance(values,list) and values and all(isinstance(v,str) and v.upper() in known for v in values):
            return 'SNS delivery feedback is incomplete for '+', '.join(v.upper() for v in values)+'.'
    if cid=='aws_nist_elb_application_gateway_network_lb_multiple_az_configured':
        zones=evidence.get('healthy_target_zones')
        if strings(zones) and len(zones)<2:
            return f'Healthy instance/IP targets are observed in {len(zones)} declared load-balancer zones; this profile requires two.'
    if cid=='aws_securityhub_no_critical_findings':
        ids=evidence.get('unresolved_finding_ids')
        if strings(ids) and ids:
            return f'{len(ids)} active critical Security Hub '+('finding remains' if len(ids)==1 else 'findings remain')+' unresolved and unsuppressed.'
    if cid=='aws_ssm_application_inventory_fresh':
        missing=evidence.get('unmanaged_instance_ids');stale=evidence.get('stale_inventory_instance_ids')
        if strings(missing) and strings(stale) and (missing or stale):
            return f'Running instances without SSM application inventory: {len(missing)}; outside the 24-hour window: {len(stale)}.'
    counts={
        'aws.nist.waf_classic_regional_acl_logging':('regional_acl_ids_without_logging','regional WAF Classic ACLs have no logging destination'),
        'aws_nist_waf_web_acl_logging_enabled':('acl_ids_without_logging','ACLs across global Classic, regional Classic and WAFv2 lack logging destinations'),
        'aws_backup_recent_restore_test':('missing_recent_restore_tests','selected restore-testing plan/resource-type pairs lack a completed test within 365 days'),
        'aws_wafv2_rate_rule_alarm':('rules_without_alarm','top-level WAF rate rules lack enabled metrics or matching alarms'),
        'aws_nist_apigateway_stage_cache_encryption_at_rest_enabled':('unencrypted_methods','deployed REST methods enable caching without encryption'),
        'aws_nist_apigateway_stage_logging_enabled':('disabled_deployed_rest_methods','deployed REST methods have execution logging disabled'),
    }
    if cid in counts:
        key,text=counts[cid];values=evidence.get(key)
        valid = strings(values)
        if cid=='aws_backup_recent_restore_test':
            valid=isinstance(values,list) and all(isinstance(v,dict) and isinstance(v.get('ResourceType'),str) and bool(v['ResourceType']) and isinstance(v.get('RestoreTestingPlanArn'),str) and v['RestoreTestingPlanArn'].startswith('arn:') for v in values)
        if valid and values:
            if len(values)==1:
                text=text.replace('ACLs have','ACL has').replace('ACLs across','ACL across').replace('lack logging','lacks logging').replace('pairs lack','pair lacks').replace('rules lack','rule lacks').replace('methods enable','method enables').replace('methods have','method has')
            return f'{len(values)} {text}.'
    explicit_lists = {
      'aws.nist.cloudtrail_cloudwatch_destination_kms':('trails_without_enabled_customer_keys','trails lack the required enabled customer-key declarations'),
      'aws.pci.client_vpn.no_authorize_all_groups':('unauthorized_destinations','Client VPN destinations have authorize-all-groups rules'),
      'aws.pci.shield.protection_all_internet_resources':('unprotected_resource_arns','assessed resources lack Shield Advanced protection'),
      'aws_cis_aws_resource_policy_unrestricted_principal':('unrestricted_statements','resource-policy statements match the unrestricted-principal model'),
      'aws_cloudtrail_bucket_lifecycle_retention_365':('early_retention_buckets','trail destination buckets have lifecycle deletion earlier than this profile permits'),
      'aws_cloudtrail_s3_siem_delivery':('undelivered_trails','trails lack the required recent S3 delivery evidence; SIEM receipt is not assessed'),
      'aws_elbv2_stickiness_duration_30_minutes':('excessive_stickiness_sources','declared stickiness sources exceed the required duration'),
      'aws_fedramp_iam_all_policies_no_admin_star':('matching_policy_sources','customer policies match the literal broad-administrator action pattern'),
      'aws_fedramp_iam_all_policies_no_service_wildcard':('matching_policy_sources','customer policies match the literal service-wildcard action pattern'),
      'aws_inspector_critical_image_findings_alert':('missing_resource_types','required Inspector resource types lack matched notification rules'),
      'aws_nist_cloudtrail_trail_integrated_with_logs':('trails_without_integration','trails lack the required declared log integration or permissions'),
      'aws_route53resolver_blocked_query_alert':('vpcs_without_blocked_query_alarm','protected VPCs lack the required blocked-query alarm configuration'),
      'aws_securityhub_findings_alerted':('missing_values','required Security Hub severities lack matched notification rules'),
      'aws_securityhub_medium_findings_alert':('missing_values','required Security Hub severities lack matched notification rules'),
      'aws_shield_ddos_detected_alarm':('protection_resources_without_alarm','protected resources lack the required DDoSDetected alarm configuration'),
      'aws_wafv2_request_validation_rules':('unprotected_albs','public ALBs lack the required configured WAF protection'),
    }
    if cid in explicit_lists:
        key,text=explicit_lists[cid];values=evidence.get(key)
        if strings(values) and values:return str(len(values))+' '+text+'.'
    if cid=='aws_cis_lightsail_bucket_private' and evidence.get('public_get_object') is True:return 'The bucket declares public GetObject access.'
    if cid=='aws_log_archive_immutable' and evidence.get('has_default_retention') is False:return 'The archive bucket has no default Object Lock retention declaration.'
    return None
