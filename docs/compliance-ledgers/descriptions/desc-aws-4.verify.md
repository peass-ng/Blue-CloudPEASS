
## Independent evaluator verification

Coverage: 308 input IDs, 308 unique description keys, 308 resolved live evaluators. Corrected 233 entries. Each ID below has exactly one decision.

| Check ID | Live evaluator | Decision |
| --- | --- | --- |
| `aws.claude_a.iam.role_trust_not_public` | `peaso/checks/claude_aws_a_iam.py:520` (`fe63bc812039`) | Verified unchanged |
| `aws.claude_a.iam.role_used_within_60_days` | `peaso/checks/claude_aws_a_iam.py:506` (`61644d7f59a2`) | Verified unchanged |
| `aws.claude_a.iam.root_console_has_mfa` | `peaso/checks/claude_aws_a_iam.py:541` (`38c3c52054fa`) | Verified unchanged |
| `aws.claude_a.iam.root_credentials_management` | `peaso/checks/claude_aws_a_iam.py:920` (`2f2cd78c1bc1`) | Verified unchanged |
| `aws.claude_a.iam.saml_provider_present` | `peaso/checks/claude_aws_a_iam.py:907` (`7e9f73b35664`) | Verified unchanged |
| `aws.claude_a.iam.securityaudit_role_exists` | `peaso/checks/claude_aws_a_iam.py:880` (`dfcc12d4ca03`) | Verified unchanged |
| `aws.claude_a.iam.server_certificate_not_expired_now` | `peaso/checks/claude_aws_a_iam.py:724` (`ac3d18dbdc67`) | Verified unchanged |
| `aws.claude_a.iam.support_role_exists` | `peaso/checks/claude_aws_a_iam.py:880` (`dfcc12d4ca03`) | Verified unchanged |
| `aws.claude_a.iam.user_bedrock_access_not_stale` | `peaso/checks/claude_aws_a_iam.py:850` (`9e88e6372298`) | Verified unchanged |
| `aws.claude_a.iam.user_in_group` | `peaso/checks/claude_aws_a_iam.py:416` (`339b67247857`) | Verified unchanged |
| `aws.claude_a.iam.user_inline_kms_decrypt_restricted` | `peaso/checks/claude_aws_a_iam.py:358` (`e531def1c4c3`) | Verified unchanged |
| `aws.claude_a.iam.user_inline_no_admin` | `peaso/checks/claude_aws_a_iam.py:372` (`3a18f33e0350`) | Verified unchanged |
| `aws.claude_a.iam.user_inline_no_assume_role_text` | `peaso/checks/claude_aws_a_iam.py:406` (`1bb68e8a2acd`) | Verified unchanged |
| `aws.claude_a.iam.user_inline_no_blocked_kms_actions` | `peaso/checks/claude_aws_a_iam.py:348` (`4b80740897fd`) | Verified unchanged |
| `aws.claude_a.iam.user_long_lived_keys_only_iam_sts` | `peaso/checks/claude_aws_a_iam.py:835` (`f82d51b04799`) | Verified unchanged |
| `aws.claude_a.iam.user_no_cloudshell_full_access` | `peaso/checks/claude_aws_a_iam.py:389` (`b490366870cf`) | Verified unchanged |
| `aws.claude_a.iam.user_no_inline_policies` | `peaso/checks/claude_aws_a_iam.py:379` (`6e1759eb9bfe`) | Verified unchanged |
| `aws.claude_a.iam.user_one_active_key` | `peaso/checks/claude_aws_a_iam.py:429` (`1fa564aa4ac1`) | Verified unchanged |
| `aws.claude_a.iam.user_sagemaker_access_not_stale` | `peaso/checks/claude_aws_a_iam.py:850` (`9e88e6372298`) | Verified unchanged |
| `aws.claude_a.kms.customer_key_enabled_or_pending_deletion` | `peaso/checks/claude_aws_a_security.py:345` (`a8fb21d18225`) | Verified unchanged |
| `aws.claude_a.kms.customer_key_not_pending_deletion` | `peaso/checks/claude_aws_a_security.py:357` (`27e064ae230b`) | Verified unchanged |
| `aws.claude_a.kms.key_policy_not_public` | `peaso/checks/claude_aws_a_security.py:330` (`488ee4402cb2`) | Verified unchanged |
| `aws.claude_a.kms.prowler_cmk_rotation` | `peaso/checks/claude_aws_a_security.py:394` (`e8e4dafc7d25`) | Verified unchanged |
| `aws.claude_a.kms.prowler_cmk_single_region` | `peaso/checks/claude_aws_a_security.py:383` (`3a3a06cce5e5`) | Verified unchanged |
| `aws.claude_a.kms.prowler_cmk_used` | `peaso/checks/claude_aws_a_security.py:369` (`eecf2b6db386`) | Verified unchanged |
| `aws.claude_a.kms.prowler_key_not_public` | `peaso/checks/claude_aws_a_security.py:408` (`912313b4a9e8`) | Verified unchanged |
| `aws.claude_a.networkfirewall.deletion_protection` | `peaso/checks/claude_aws_a_network.py:951` (`54cef2f5485d`) | Verified unchanged |
| `aws.claude_a.networkfirewall.firewall_fragment_default` | `peaso/checks/claude_aws_a_network.py:1034` (`0b92fc9ef7bb`) | Verified unchanged |
| `aws.claude_a.networkfirewall.firewall_full_packets_default` | `peaso/checks/claude_aws_a_network.py:1034` (`0b92fc9ef7bb`) | Verified unchanged |
| `aws.claude_a.networkfirewall.firewall_policy_has_rule_groups` | `peaso/checks/claude_aws_a_network.py:1058` (`c9f8bd6874f9`) | Verified unchanged |
| `aws.claude_a.networkfirewall.in_use_vpc_has_firewall` | `peaso/checks/claude_aws_a_network.py:994` (`5fc2942809b7`) | Verified unchanged |
| `aws.claude_a.networkfirewall.in_vpc` | `peaso/checks/claude_aws_a_network.py:967` (`7333ca21d17e`) | Verified unchanged |
| `aws.claude_a.networkfirewall.logging` | `peaso/checks/claude_aws_a_network.py:975` (`26b82a0a09e1`) | Verified unchanged |
| `aws.claude_a.networkfirewall.multi_az` | `peaso/checks/claude_aws_a_network.py:986` (`62e0ca93311e`) | Verified unchanged |
| `aws.claude_a.networkfirewall.policy_fragment_default` | `peaso/checks/claude_aws_a_network.py:1014` (`cca555987151`) | Verified unchanged |
| `aws.claude_a.networkfirewall.policy_full_packets_default` | `peaso/checks/claude_aws_a_network.py:1014` (`cca555987151`) | Verified unchanged |
| `aws.claude_a.networkfirewall.policy_has_rule_groups` | `peaso/checks/claude_aws_a_network.py:1050` (`267b2fd96a30`) | Verified unchanged |
| `aws.claude_a.networkfirewall.stateless_rule_group_not_empty` | `peaso/checks/claude_aws_a_network.py:1068` (`484d1d19c7bd`) | Verified unchanged |
| `aws.claude_a.networkfirewall.subnet_change_protection` | `peaso/checks/claude_aws_a_network.py:959` (`3dddfe8272e4`) | Verified unchanged |
| `aws.claude_a.organizations.ai_services_opt_out` | `peaso/checks/claude_aws_a_security.py:512` (`e087c3eaf5df`) | Verified unchanged |
| `aws.claude_a.organizations.no_untrusted_delegated_administrators` | `peaso/checks/claude_aws_a_security.py:473` (`a5aba74df440`) | Verified unchanged |
| `aws.claude_a.organizations.scp_restricts_regions` | `peaso/checks/claude_aws_a_security.py:512` (`e087c3eaf5df`) | Verified unchanged |
| `aws.claude_a.organizations.tag_policy_attached` | `peaso/checks/claude_aws_a_security.py:512` (`e087c3eaf5df`) | Verified unchanged |
| `aws.claude_a.s3.access_point_public_access_block` | `peaso/checks/claude_aws_a_s3.py:696` (`88d3a6da77fd`) | Verified unchanged |
| `aws.claude_a.s3.account_public_access_block_all` | `peaso/checks/claude_aws_a_s3.py:167` (`39e551177010`) | Verified unchanged |
| `aws.claude_a.s3.acls_prohibit_user_access` | `peaso/checks/claude_aws_a_s3.py:331` (`f85b491d486e`) | Verified unchanged |
| `aws.claude_a.s3.bucket_public_access_block_all` | `peaso/checks/claude_aws_a_s3.py:179` (`b282da92bab0`) | Verified unchanged |
| `aws.claude_a.s3.default_encryption_kms_key` | `peaso/checks/claude_aws_a_s3.py:220` (`a7458cb16270`) | Verified unchanged |
| `aws.claude_a.s3.directory_bucket_lifecycle` | `peaso/checks/claude_aws_a_s3.py:724` (`8dc31a38aaa1`) | Verified unchanged |
| `aws.claude_a.s3.event_notifications` | `peaso/checks/claude_aws_a_s3.py:317` (`dfe0d25df5e2`) | Verified unchanged |
| `aws.claude_a.s3.lifecycle_rule_enabled` | `peaso/checks/claude_aws_a_s3.py:283` (`3d15b4a988a3`) | Verified unchanged |
| `aws.claude_a.s3.multi_region_access_point_public_access_block` | `peaso/checks/claude_aws_a_s3.py:710` (`f6be92e0d5b7`) | Verified unchanged |
| `aws.claude_a.s3.no_authenticated_users_acl` | `peaso/checks/claude_aws_a_s3.py:355` (`c55cd5b3af96`) | Verified unchanged |
| `aws.claude_a.s3.object_level_logging` | `peaso/checks/claude_aws_a_s3.py:604` (`93b2ffffa8e8`) | Verified unchanged |
| `aws.claude_a.s3.object_lock_configured` | `peaso/checks/claude_aws_a_s3.py:305` (`96caf5b77a25`) | Verified unchanged |
| `aws.claude_a.s3.perimeter_policy_not_public` | `peaso/checks/claude_aws_a_s3.py:521` (`7bf25fb4bbd5`) | Verified unchanged |
| `aws.claude_a.s3.policy_no_cross_account_permission_changes` | `peaso/checks/claude_aws_a_s3.py:458` (`adb8e76dacfe`) | Verified unchanged |
| `aws.claude_a.s3.policy_restrict_public_access` | `peaso/checks/claude_aws_a_s3.py:507` (`3ff93f1e6c4b`) | Verified unchanged |
| `aws.claude_a.s3.protected_by_macie` | `peaso/checks/claude_aws_a_s3.py:649` (`dbdb2d4b2b5c`) | Verified unchanged |
| `aws.claude_a.s3.prowler_account_ignore_restrict` | `peaso/checks/claude_aws_a_s3.py:189` (`b81c0d772ed5`) | Verified unchanged |
| `aws.claude_a.s3.prowler_acl_disabled` | `peaso/checks/claude_aws_a_s3.py:364` (`ba3c5deeabdb`) | Verified unchanged |
| `aws.claude_a.s3.prowler_bucket_level_public_access_block` | `peaso/checks/claude_aws_a_s3.py:205` (`2f6bc40604d3`) | Verified unchanged |
| `aws.claude_a.s3.prowler_cross_account_policy` | `peaso/checks/claude_aws_a_s3.py:533` (`9686ec985825`) | Verified unchanged |
| `aws.claude_a.s3.prowler_cross_region_replication` | `peaso/checks/claude_aws_a_s3.py:256` (`cc1f59d7f180`) | Verified unchanged |
| `aws.claude_a.s3.prowler_kms_encryption` | `peaso/checks/claude_aws_a_s3.py:231` (`431de4565b88`) | Verified unchanged |
| `aws.claude_a.s3.prowler_policy_public_write` | `peaso/checks/claude_aws_a_s3.py:547` (`0ba09cad81be`) | Verified unchanged |
| `aws.claude_a.s3.prowler_public_access` | `peaso/checks/claude_aws_a_s3.py:409` (`5aaa453ca4a2`) | Verified unchanged |
| `aws.claude_a.s3.prowler_public_list_acl` | `peaso/checks/claude_aws_a_s3.py:409` (`5aaa453ca4a2`) | Verified unchanged |
| `aws.claude_a.s3.prowler_public_write_acl` | `peaso/checks/claude_aws_a_s3.py:409` (`5aaa453ca4a2`) | Verified unchanged |
| `aws.claude_a.s3.replication_rule_enabled` | `peaso/checks/claude_aws_a_s3.py:244` (`2287962aeca8`) | Verified unchanged |
| `aws.claude_a.s3.restrict_public_read` | `peaso/checks/claude_aws_a_s3.py:434` (`5caa6df99d34`) | Verified unchanged |
| `aws.claude_a.s3.static_website_disabled` | `peaso/checks/claude_aws_a_s3.py:567` (`8379b293f545`) | Verified unchanged |
| `aws.claude_a.s3.versioning_and_lifecycle` | `peaso/checks/claude_aws_a_s3.py:293` (`f043d06145b7`) | Verified unchanged |
| `aws.claude_a.securityhub.enabled_with_standard_or_integration` | `peaso/checks/claude_aws_a_security.py:581` (`bfa989caa5b7`) | Verified unchanged |
| `aws.claude_a.securityhub.prowler_delegated_admin_region` | `peaso/checks/claude_aws_a_security.py:606` (`7c5196b5c593`) | Verified unchanged |
| `aws.claude_a.vpc.block_public_access_igw` | `peaso/checks/claude_aws_a_network.py:674` (`909e5427bda9`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.default_sg_in_use_no_rules` | `peaso/checks/claude_aws_a_network.py:185` (`4e8e0be425f9`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.default_sg_no_rules` | `peaso/checks/claude_aws_a_network.py:201` (`593157c16e6e`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.endpoint_policy_trust_boundary` | `peaso/checks/claude_aws_a_network.py:779` (`be5f10cd99dc`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.endpoint_service_acceptance_required` | `peaso/checks/claude_aws_a_network.py:807` (`b6df4c2782a8`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.endpoint_service_principals_trusted` | `peaso/checks/claude_aws_a_network.py:819` (`938e7339b8e8`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.flow_logs_active` | `peaso/checks/claude_aws_a_network.py:476` (`aad7636ea791`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.gateway_endpoint_policy_not_open` | `peaso/checks/claude_aws_a_network.py:742` (`e1dc5b8de0eb`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.igw_attached` | `peaso/checks/claude_aws_a_network.py:652` (`e4f90a49d20b`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.in_use_subnet_no_auto_public_ip` | `peaso/checks/claude_aws_a_network.py:601` (`ac8fed9e20d6`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.in_use_vpc_ec2_endpoint` | `peaso/checks/claude_aws_a_network.py:712` (`9c54a7b4b6e7`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.in_use_vpc_has_flow_log` | `peaso/checks/claude_aws_a_network.py:491` (`616a3393706f`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.in_use_vpc_public_and_private_subnets` | `peaso/checks/claude_aws_a_network.py:576` (`602ba0bae63b`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.in_use_vpc_subnets_multi_az` | `peaso/checks/claude_aws_a_network.py:525` (`9b23541dfa10`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.interface_endpoint_ecr_api` | `peaso/checks/claude_aws_a_network.py:696` (`1d9eb4b31e26`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.interface_endpoint_ecr_dkr` | `peaso/checks/claude_aws_a_network.py:696` (`1d9eb4b31e26`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.interface_endpoint_multi_az` | `peaso/checks/claude_aws_a_network.py:725` (`488d07f7bdae`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.interface_endpoint_ssm` | `peaso/checks/claude_aws_a_network.py:696` (`1d9eb4b31e26`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.interface_endpoint_ssm_contacts` | `peaso/checks/claude_aws_a_network.py:696` (`1d9eb4b31e26`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.interface_endpoint_ssm_incidents` | `peaso/checks/claude_aws_a_network.py:696` (`1d9eb4b31e26`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.launch_wizard_sg_not_attached` | `peaso/checks/claude_aws_a_network.py:375` (`838a74ce74fe`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.nacl_associated` | `peaso/checks/claude_aws_a_network.py:442` (`f891ae97187c`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.nacl_no_world_all_ports` | `peaso/checks/claude_aws_a_network.py:413` (`d04e0ba2806a`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.nacl_no_world_remote_admin` | `peaso/checks/claude_aws_a_network.py:450` (`663153cbb635`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.nacl_no_world_tcp_22` | `peaso/checks/claude_aws_a_network.py:413` (`d04e0ba2806a`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.nacl_no_world_tcp_3389` | `peaso/checks/claude_aws_a_network.py:413` (`d04e0ba2806a`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.nondefault_nacl_associated` | `peaso/checks/claude_aws_a_network.py:432` (`7c16d8925f8a`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.nondefault_vpcs_in_multiple_regions` | `peaso/checks/claude_aws_a_network.py:635` (`710b819c9f1b`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.peering_route_tables_least_privilege` | `peaso/checks/claude_aws_a_network.py:886` (`ec1b120f9177`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.peering_routes_least_privilege` | `peaso/checks/claude_aws_a_network.py:866` (`d3b57b44b7d7`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.peering_same_account_active` | `peaso/checks/claude_aws_a_network.py:844` (`56617ef17f31`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.public_and_private_subnets` | `peaso/checks/claude_aws_a_network.py:565` (`1b218707f07e`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.route_table_no_default_igw_route` | `peaso/checks/claude_aws_a_network.py:661` (`89914366b3a3`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_attached_to_eni` | `peaso/checks/claude_aws_a_network.py:346` (`dc27d7b44d0e`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_attached_to_eni_or_instance` | `peaso/checks/claude_aws_a_network.py:358` (`83960af420b4`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_in_use_anywhere` | `peaso/checks/claude_aws_a_network.py:228` (`997ba6a892c3`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_name_not_launch_wizard` | `peaso/checks/claude_aws_a_network.py:214` (`3c5f056ceea5`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_public_ip_any_port` | `peaso/checks/claude_aws_a_network.py:93` (`4d681f86e6b0`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_wide_public_ipv4` | `peaso/checks/claude_aws_a_network.py:160` (`5fe74fc6d417`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_all_traffic` | `peaso/checks/claude_aws_a_network.py:53` (`ae16ead266ec`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis` | `peaso/checks/claude_aws_a_network.py:70` (`f38ced0649f2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_cassandra` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_elasticsearch_kibana` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_ftp` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_high_risk_tcp_ports` | `peaso/checks/claude_aws_a_network.py:113` (`59a4fb020c40`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_kafka` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_memcached` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_mongodb` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_mysql` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_oracle` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_postgres` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_rdp` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_redis` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_sqlserver` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_ssh` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_no_world_telnet` | `peaso/checks/claude_aws_a_network.py:141` (`c22c95141be2`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_rule_count_within_50` | `peaso/checks/claude_aws_a_network.py:255` (`13c50a199434`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_any_cifs` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_any_kafka` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_any_kibana` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_any_redis` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_any_remote_admin` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_cassandra` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_common20` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_common6` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_memcached` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_mongodb` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_no_tcp_udp` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_only_80_443` | `peaso/checks/claude_aws_a_network.py:332` (`4b6e5f4f802a`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_oracle` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_rdp` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.sg_world_v4_ssh` | `peaso/checks/claude_aws_a_network.py:283` (`41ce907b5797`) | IPv4 TCP/6 port 22 or all-protocol -1; complete scoped evidence; no reachability claim |
| `aws.claude_a.vpc.sg_world_v6_remote_admin` | `peaso/checks/claude_aws_a_network.py:282` (`fec2eb8f6d92`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.subnet_no_auto_public_ip` | `peaso/checks/claude_aws_a_network.py:591` (`a5f35fd4548a`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.subnets_in_multiple_azs` | `peaso/checks/claude_aws_a_network.py:515` (`faa3d6b83b49`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.vpc_endpoint_ec2` | `peaso/checks/claude_aws_a_network.py:696` (`1d9eb4b31e26`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.vpc_has_subnets` | `peaso/checks/claude_aws_a_network.py:504` (`769fe9e0b1f7`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.vpcs_in_multiple_regions` | `peaso/checks/claude_aws_a_network.py:625` (`503a7532e592`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.vpn_both_tunnels_up` | `peaso/checks/claude_aws_a_network.py:913` (`cf0a239c8487`) | Corrected pass_when, fail_when |
| `aws.claude_a.vpc.vpn_tunnel_logging` | `peaso/checks/claude_aws_a_network.py:927` (`5833e38ecce6`) | Corrected pass_when, fail_when |
| `aws.cloudtrail.kms_encryption` | `peaso/checks/aws_extended.py:65` (`90a368662453`) | Corrected pass_when, fail_when |
| `aws.cloudtrail.log_validation` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.cloudtrail.logging` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.cloudtrail.management_events` | `peaso/checks/aws.py:79` (`21259ec1ceee`) | Corrected pass_when, fail_when |
| `aws.cloudtrail.multi_region` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.config.service_linked_role` | `peaso/checks/aws_extended.py:249` (`001cbdddb3c2`) | Corrected pass_when, fail_when |
| `aws.ebs.encryption` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.ec2.imdsv2` | `peaso/checks/__init__.py:313` (`2687b0b6c383`) | Corrected pass_when, fail_when |
| `aws.ec2.restrict_internet_ingress` | `peaso/checks/__init__.py:293` (`8db05cbc77ad`) | Corrected pass_when, fail_when |
| `aws.ecr.immutable_tags` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.ecr.lifecycle_policy` | `peaso/checks/aws_extended.py:215` (`6b4b7fd78a75`) | Corrected pass_when, fail_when |
| `aws.ecr.scan_on_push` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.eks.control_plane_logging` | `peaso/checks/aws.py:90` (`30cb7876d2ca`) | Corrected pass_when, fail_when |
| `aws.eks.private_endpoint` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.eks.secrets_encryption` | `peaso/checks/aws_extended.py:269` (`9926a4a72a59`) | Corrected pass_when, fail_when |
| `aws.elbv2.access_logging` | `peaso/checks/aws_extended.py:138` (`a879fff4501c`) | Corrected pass_when, fail_when |
| `aws.elbv2.deletion_protection` | `peaso/checks/aws_extended.py:138` (`a879fff4501c`) | Corrected pass_when, fail_when |
| `aws.elbv2.desync_mitigation` | `peaso/checks/aws_extended.py:164` (`727dae5ed881`) | Corrected pass_when, fail_when |
| `aws.elbv2.drop_invalid_headers` | `peaso/checks/aws_extended.py:138` (`a879fff4501c`) | Corrected pass_when, fail_when |
| `aws.elbv2.multiple_availability_zones` | `peaso/checks/aws_extended.py:184` (`b16cca7cbc0b`) | Corrected pass_when, fail_when |
| `aws.gap.accessanalyzer.no_active_findings` | `peaso/checks/aws_gap_core.py:538` (`9ab2f5680012`) | Corrected pass_when, fail_when |
| `aws.gap.account.distinct_primary_billing_operations_security_contacts` | `peaso/checks/aws_gap_account.py:36` (`b5981cafdb55`) | Corrected pass_when, fail_when |
| `aws.gap.classic_elb.ssl_listeners_use_acm` | `peaso/checks/aws_gap_core.py:592` (`64e54b2c9914`) | Corrected pass_when, fail_when |
| `aws.gap.cloudtrail.bedrock_api_logging` | `peaso/checks/aws_gap_core.py:387` (`29356dbc3025`) | Corrected pass_when, fail_when |
| `aws.gap.cloudtrail.multi_region_read_write_management` | `peaso/checks/aws_gap_core.py:237` (`6eca227107da`) | Corrected pass_when, fail_when |
| `aws.gap.cloudtrail.region_logging_management_events` | `peaso/checks/aws_gap_core.py:253` (`089a38d3b863`) | Corrected pass_when, fail_when |
| `aws.gap.cloudtrail.s3_all_buckets_read_data_events` | `peaso/checks/aws_gap_core.py:321` (`300646d9b7bb`) | Corrected evaluated, pass_when, fail_when |
| `aws.gap.cloudtrail.s3_all_buckets_write_data_events` | `peaso/checks/aws_gap_core.py:321` (`300646d9b7bb`) | Corrected evaluated, pass_when, fail_when |
| `aws.gap.cloudtrail.trail_security_best_practices` | `peaso/checks/aws_gap_core.py:268` (`524a2c038715`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.cloudtrail_configuration_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.cmk_disable_or_scheduled_deletion` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.config_configuration_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.console_authentication_failures` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.console_sign_in_without_mfa` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.iam_policy_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.network_acl_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.network_gateway_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.organizations_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.root_account_usage` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.route_table_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.s3_bucket_policy_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.security_group_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.unauthorized_api_calls` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.cis_alarm.vpc_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.cloudtrail_configuration_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.cmk_disable_or_scheduled_deletion` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.config_configuration_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.console_authentication_failures` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.console_sign_in_without_mfa` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.iam_policy_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.network_acl_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.network_gateway_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.organizations_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.root_account_usage` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.route_table_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.s3_bucket_policy_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.security_group_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.unauthorized_api_calls` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.cloudwatch.metric_alarm.vpc_changes` | `peaso/checks/aws_gap_metrics.py:537` (`4492eaf1eee7`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_passrole_and_lambda_invoke_function_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_attached_with_credentials_exposure_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_alter_critical_s3_permissions_configuration` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_cloud_log_tampering_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_data_destruction_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_database_management_write_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_defense_evasion_impact_of_aws_security_services_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_destruction_kms_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_destruction_rds_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_elastic_ip_hijacking_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_management_level_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_new_group_creation_with_attached_policy_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_new_role_creation_with_attached_policy_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_new_user_creation_with_attached_policy_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_org_write_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_privilege_escalation_risk_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_security_group_write_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_write_access_to_resource_based_policies` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_role_with_write_permission_on_critical_s3_configuration` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.ec2.instance_no_iam_with_write_level_access` | `peaso/checks/aws_gap_ec2.py:228` (`eca9632cd941`) | Corrected pass_when, fail_when |
| `aws.gap.iam.active_keys_used_within_45_days` | `peaso/checks/aws_gap_core.py:617` (`cb8cb9d97118`) | Corrected pass_when, fail_when |
| `aws.gap.iam.root_not_used_1_day` | `peaso/checks/aws_gap_core.py:487` (`7f60924f3b51`) | Corrected pass_when, fail_when |
| `aws.gap.iam.root_not_used_90_days` | `peaso/checks/aws_gap_core.py:487` (`7f60924f3b51`) | Corrected pass_when, fail_when |
| `aws.gap.s3.bucket_policy_denies_insecure_transport` | `peaso/checks/aws_gap_core.py:447` (`81c6c55db8d7`) | Corrected pass_when, fail_when |
| `aws.gap.s3.no_public_write_acl_or_policy` | `peaso/checks/aws_gap_core.py:464` (`20888dcfbee2`) | Corrected pass_when, fail_when |
| `aws.gap.s3.object_read_events_logged` | `peaso/checks/aws_gap_core.py:359` (`2b84b618bd2f`) | Corrected pass_when, fail_when |
| `aws.gap.s3.object_read_write_events_logged` | `peaso/checks/aws_gap_core.py:359` (`2b84b618bd2f`) | Corrected pass_when, fail_when |
| `aws.gap.s3.object_write_events_logged` | `peaso/checks/aws_gap_core.py:359` (`2b84b618bd2f`) | Corrected pass_when, fail_when |
| `aws.gap.securityhub.region_hub_enabled` | `peaso/checks/aws_gap_core.py:524` (`15559abff2ad`) | Corrected pass_when, fail_when |
| `aws.gap.vpc.sg_world_any_common_ports` | `peaso/checks/aws_gap_core.py:561` (`e6ff25168886`) | Corrected pass_when, fail_when |
| `aws.guardduty.eks_audit_logs` | `peaso/checks/aws_extended.py:297` (`ca96d19e36ef`) | Corrected pass_when, fail_when |
| `aws.guardduty.lambda_network_logs` | `peaso/checks/aws_extended.py:297` (`ca96d19e36ef`) | Corrected pass_when, fail_when |
| `aws.guardduty.rds_login_events` | `peaso/checks/aws_extended.py:297` (`ca96d19e36ef`) | Corrected pass_when, fail_when |
| `aws.guardduty.runtime_monitoring` | `peaso/checks/aws_extended.py:297` (`ca96d19e36ef`) | Corrected pass_when, fail_when |
| `aws.guardduty.s3_data_events` | `peaso/checks/aws_extended.py:297` (`ca96d19e36ef`) | Corrected pass_when, fail_when |
| `aws.htbp.appsync.no_api_key_additional_auth` | `peaso/checks/hacktricks_bp_aws.py:246` (`001bcdae7bee`) | Corrected pass_when, fail_when |
| `aws.htbp.cognito.client_no_writable_authorization_attributes` | `peaso/checks/hacktricks_bp_aws.py:48` (`47cd501c8d29`) | Corrected pass_when, fail_when |
| `aws.htbp.cognito.identity_pool_classic_flow_disabled` | `peaso/checks/hacktricks_bp_aws.py:21` (`b0ae6f0e53da`) | Corrected pass_when, fail_when |
| `aws.htbp.ecr.creation_template_policy_trust_boundary` | `peaso/checks/hacktricks_bp_aws_ext.py:319` (`b001332a87e5`) | Corrected pass_when, fail_when |
| `aws.htbp.ecr.registry_policy_trust_boundary` | `peaso/checks/hacktricks_bp_aws_ext.py:255` (`c1f6c9e20148`) | Corrected pass_when, fail_when |
| `aws.htbp.ecr.replication_destinations_trust_boundary` | `peaso/checks/hacktricks_bp_aws_ext.py:287` (`84c357f65771`) | Corrected pass_when, fail_when |
| `aws.htbp.ecs.exec_session_logging_not_disabled` | `peaso/checks/hacktricks_bp_aws.py:119` (`b1493d87b5fd`) | Corrected pass_when, fail_when |
| `aws.htbp.ecs.no_sensitive_host_mounts` | `peaso/checks/hacktricks_bp_aws.py:156` (`36e328d5f795`) | Corrected pass_when, fail_when |
| `aws.htbp.eks.access_entries_authentication` | `peaso/checks/hacktricks_bp_aws.py:90` (`91e3e4c8b5f3`) | Corrected pass_when, fail_when |
| `aws.htbp.eks.access_entry_principal_trust_boundary` | `peaso/checks/hacktricks_bp_aws_ext.py:358` (`97bd6f987ff2`) | Corrected pass_when, fail_when |
| `aws.htbp.glue.dev_endpoint_not_public` | `peaso/checks/hacktricks_bp_aws.py:221` (`20f1774b1fe4`) | Corrected pass_when, fail_when |
| `aws.htbp.kms.grant_grantee_trust_boundary` | `peaso/checks/hacktricks_bp_aws_ext.py:390` (`02f6c6e64481`) | Corrected pass_when, fail_when |
| `aws.htbp.lambda.env_var_names_not_credentials` | `peaso/checks/hacktricks_bp_aws_ext.py:219` (`364bd8c98a86`) | Corrected pass_when, fail_when |
| `aws.htbp.lambda.layer_version_trust_boundary` | `peaso/checks/hacktricks_bp_aws_ext.py:146` (`8eddcc56b6b1`) | Corrected pass_when, fail_when |
| `aws.htbp.lambda.runtime_updates_not_pinned_manual` | `peaso/checks/hacktricks_bp_aws_ext.py:181` (`a169235d29b0`) | Corrected pass_when, fail_when |
| `aws.htbp.opensearch.connection_peer_trust_boundary` | `peaso/checks/hacktricks_bp_aws_ext.py:426` (`c194ac129fa4`) | Corrected pass_when, fail_when |
| `aws.htbp.sagemaker.notebook_imdsv2_required` | `peaso/checks/hacktricks_bp_aws.py:200` (`9d64224ec4f0`) | Corrected pass_when, fail_when |
| `aws.iam.access_key_count` | `peaso/checks/aws.py:105` (`8abf1b49e429`) | Corrected pass_when, fail_when |
| `aws.iam.console_mfa` | `peaso/checks/__init__.py:228` (`1002f346cd19`) | Corrected pass_when, fail_when |
| `aws.iam.no_full_admin` | `peaso/checks/__init__.py:190` (`e83c908dcb07`) | Corrected pass_when |
| `aws.iam.no_root_keys` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.iam.password_lowercase` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.iam.password_max_age` | `peaso/checks/aws_extended.py:47` (`d9d55717e580`) | Corrected pass_when, fail_when |
| `aws.iam.password_minimum_length` | `peaso/checks/aws_extended.py:47` (`d9d55717e580`) | Corrected pass_when, fail_when |
| `aws.iam.password_numbers` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.iam.password_reuse_prevention` | `peaso/checks/aws_extended.py:47` (`d9d55717e580`) | Corrected pass_when, fail_when |
| `aws.iam.password_symbols` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.iam.password_uppercase` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.iam.restrict_public_trust` | `peaso/checks/__init__.py:209` (`018e189cbc65`) | Corrected pass_when |
| `aws.iam.root_mfa` | `peaso/checks/aws.py:138` (`ef93ae935f5d`) | Corrected pass_when, fail_when |
| `aws.kms.no_pending_key_deletion` | `peaso/checks/aws_extended.py:226` (`b3fea3a13a49`) | Corrected pass_when, fail_when |
| `aws.kms.rotation` | `peaso/checks/aws.py:67` (`0f0149d25f11`) | Corrected pass_when, fail_when |
| `aws.lambda.dead_letter_queue` | `peaso/checks/aws_extended.py:98` (`0bb364c7e839`) | Corrected pass_when, fail_when |
| `aws.lambda.function_url_authentication` | `peaso/checks/aws_extended.py:108` (`16972bd8202c`) | Corrected pass_when, fail_when |
| `aws.lambda.vpc_configuration` | `peaso/checks/aws_extended.py:65` (`90a368662453`) | Corrected pass_when, fail_when |
| `aws.logs.retention` | `peaso/checks/aws.py:115` (`2c56910e5bf1`) | Corrected pass_when, fail_when |
| `aws.rds.auto_minor_upgrade` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.rds.backups` | `peaso/checks/aws.py:127` (`9ab9d56de101`) | Corrected pass_when, fail_when |
| `aws.rds.cloudwatch_log_exports` | `peaso/checks/aws_extended.py:89` (`f58831d22ab2`) | Corrected pass_when, fail_when |
| `aws.rds.cluster_copy_snapshot_tags` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.rds.cluster_deletion_protection` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.rds.cluster_encryption` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.rds.cluster_iam_authentication` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.rds.cluster_multi_az` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.rds.copy_snapshot_tags` | `peaso/checks/aws_extended.py:78` (`25146cc055e2`) | Corrected pass_when, fail_when |
| `aws.rds.deletion_protection` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.rds.encryption` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.rds.enhanced_monitoring` | `peaso/checks/aws_extended.py:65` (`90a368662453`) | Corrected pass_when, fail_when |
| `aws.rds.no_public_endpoint` | `peaso/checks/aws.py:26` (`ea6ad3532fce`) | Corrected pass_when, fail_when |
| `aws.rds.snapshot_encryption` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.rds.vpc_configuration` | `peaso/checks/aws_extended.py:65` (`90a368662453`) | Corrected pass_when, fail_when |
| `aws.s3.access_logging` | `peaso/checks/aws.py:43` (`9567ffa6f25f`) | Corrected pass_when, fail_when |
| `aws.s3.default_encryption` | `peaso/checks/__init__.py:279` (`345579e76ebf`) | Corrected pass_when |
| `aws.s3.no_public_acl` | `peaso/checks/aws.py:53` (`ea3bc8ed5678`) | Corrected pass_when |
| `aws.s3.public_access_block` | `peaso/checks/__init__.py:248` (`e71a4fec9e9a`) | Corrected pass_when, fail_when |
| `aws.s3.versioning` | `peaso/checks/aws.py:33` (`13fd3f01a079`) | Corrected pass_when, fail_when |
| `aws.secretsmanager.rotation` | `peaso/checks/facts.py:46` (`41601f6110d3`) | Corrected pass_when, fail_when |
| `aws.sns.kms_encryption` | `peaso/checks/aws_extended.py:65` (`90a368662453`) | Corrected pass_when, fail_when |
| `aws.sqs.encryption` | `peaso/checks/aws_extended.py:194` (`8ed30f3a0a97`) | Corrected pass_when, fail_when |

Notes: The IAM server certificate check uses `timedelta.days >= 0`, which fails at and after expiry. S3 public ACL grants return MANUAL, and absent S3 default encryption returns UNKNOWN; their current descriptions reflect those branches. The CloudTrail all-bucket data-event evaluated fields were narrowed to the fields used by that evaluator family.
