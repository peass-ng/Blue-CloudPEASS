# AWS network semantic source review

Reviewed 78 currently active AWS IDs across six kinds: network_acl=6, network_interface=3, route_table=2, security_group=48, subnet=2, vpc=17.

Every row resolves the registered callback, per-ID closure/dispatch, source hashes, actual field-access witnesses and admitted meaning. Raw EC2 Describe responses retain native members through the actual deepcopy projection; SDK-valid Stubber chains test all six kinds separately from synthetic predicate fixtures. This is a bounded source review, not a proof of all branches or a live network/listener assessment.

The Prowler SG helper accepted names but missed native protocol 6 and accepted invalid TCP/UDP ranges. The authorized correction normalizes native names/numbers and rejects malformed bounds/CIDRs while preserving ICMP and all-protocol semantics. Root owns central metadata hashes.

Authorized corrections reject malformed NACL action/protocol/range/CIDR facts in both ordered and individual-entry checks, normalize numeric protocols in the literal protocol-filter SG variant, validate the native ENI Status enum, and honor route field types/coverage. These preserve intentional SQL scope, rule order and address families. Root owns central metadata materialization. Optional SDK range-array omissions remain conservative UNKNOWN in helpers requiring both arrays; there is no demonstrated live incidence.

Pinned local criteria intentionally differ: literal 80/443 allows UDP; IPv4 route check excludes DestinationIpv6CidrBlock; SQL public/private classification includes NAT while Prowler uses IGW; presence-only flow logs/endpoints/firewalls do not prove ACTIVE state, interface type, routing, or inspection unless that predicate explicitly checks them. These scoped meanings are recorded, not silently broadened.

Cached pinned VPC/EC2/NetworkFirewall/perimeter SQL blobs were checked against Git trees and declaration/port/direction/join semantics inspected by family; per-row query hashes are retained where resolved. Prowler network helper Python bodies were unavailable locally; no upstream execution parity is claimed. Cross-kind dependency producer semantics are explicitly outside this six-kind projection proof. Prior 10,565-pass evidence is preserved; only the focused gate is run.

Reproduce: `.venv/bin/python -m tests.test_aws_network_semantic_review --write-report` then `.venv/bin/python -m pytest -q tests/test_aws_network_semantic_review.py --junitxml=/tmp/peasso-aws-review-20261019/native/network-semantic-review.xml`.

The recorded combined gate also includes `tests/test_aws_ec2_public_reachability_review.py`, `tests/test_peaso_checks_claude_aws_a.py` and `tests/test_peaso_aws_core_ingress_imds_authority.py`. Exact execution receipt summary: `{"errors": 0, "failures": 0, "sha256": "1e653a05f9b88215d0b3eec93a8df84361ec15ea40d0179f93d96d3fb69cadf4", "skipped": 0, "status": "executed", "tests": 1138}`.

| Active check | Kind | Predicate source | Family |
|---|---|---|---|
| `aws.c2b.bedrock.vpc_endpoints` | vpc | `peaso/checks/claude2_aws_b_identity.py:832` | br_vpc_endpoints |
| `aws.claude_a.ec2.eni_in_use` | network_interface | `peaso/checks/claude_aws_a_ec2.py:1178` | eni_unused |
| `aws.claude_a.ec2.eni_no_public_ip` | network_interface | `peaso/checks/claude_aws_a_ec2.py:1169` | eni_public |
| `aws.claude_a.ec2.eni_source_dest_check` | network_interface | `peaso/checks/claude_aws_a_ec2.py:1156` | eni_sdc |
| `aws.claude_a.networkfirewall.in_use_vpc_has_firewall` | vpc | `peaso/checks/claude_aws_a_network.py:1193` | nfw_all_vpc |
| `aws.claude_a.vpc.default_sg_in_use_no_rules` | security_group | `peaso/checks/claude_aws_a_network.py:197` | default_sg_prowler |
| `aws.claude_a.vpc.default_sg_no_rules` | security_group | `peaso/checks/claude_aws_a_network.py:213` | default_sg |
| `aws.claude_a.vpc.flow_logs_active` | vpc | `peaso/checks/claude_aws_a_network.py:495` | vpc_flow_logs |
| `aws.claude_a.vpc.in_use_subnet_no_auto_public_ip` | subnet | `peaso/checks/claude_aws_a_network.py:622` | subnet_auto_public_prowler |
| `aws.claude_a.vpc.in_use_vpc_ec2_endpoint` | vpc | `peaso/checks/claude_aws_a_network.py:745` | vpc_ec2_endpoint_prowler |
| `aws.claude_a.vpc.in_use_vpc_has_flow_log` | vpc | `peaso/checks/claude_aws_a_network.py:510` | vpc_flow_logs_prowler |
| `aws.claude_a.vpc.in_use_vpc_public_and_private_subnets` | vpc | `peaso/checks/claude_aws_a_network.py:597` | vpc_public_private_prowler |
| `aws.claude_a.vpc.in_use_vpc_subnets_multi_az` | vpc | `peaso/checks/claude_aws_a_network.py:546` | vpc_multi_az_prowler |
| `aws.claude_a.vpc.interface_endpoint_ecr_api` | vpc | `peaso/checks/claude_aws_a_network.py:728` | _endpoint_check |
| `aws.claude_a.vpc.interface_endpoint_ecr_dkr` | vpc | `peaso/checks/claude_aws_a_network.py:728` | _endpoint_check |
| `aws.claude_a.vpc.interface_endpoint_ssm` | vpc | `peaso/checks/claude_aws_a_network.py:728` | _endpoint_check |
| `aws.claude_a.vpc.interface_endpoint_ssm_contacts` | vpc | `peaso/checks/claude_aws_a_network.py:728` | _endpoint_check |
| `aws.claude_a.vpc.interface_endpoint_ssm_incidents` | vpc | `peaso/checks/claude_aws_a_network.py:728` | _endpoint_check |
| `aws.claude_a.vpc.launch_wizard_sg_not_attached` | security_group | `peaso/checks/claude_aws_a_network.py:393` | sg_launch_wizard_attached |
| `aws.claude_a.vpc.nacl_associated` | network_acl | `peaso/checks/claude_aws_a_network.py:459` | nacl_unused |
| `aws.claude_a.vpc.nacl_no_world_all_ports` | network_acl | `peaso/checks/claude_aws_a_network.py:431` | _nacl_prowler |
| `aws.claude_a.vpc.nacl_no_world_remote_admin` | network_acl | `peaso/checks/claude_aws_a_network.py:467` | nacl_remote_admin |
| `aws.claude_a.vpc.nacl_no_world_tcp_22` | network_acl | `peaso/checks/claude_aws_a_network.py:431` | _nacl_prowler |
| `aws.claude_a.vpc.nacl_no_world_tcp_3389` | network_acl | `peaso/checks/claude_aws_a_network.py:431` | _nacl_prowler |
| `aws.claude_a.vpc.nondefault_nacl_associated` | network_acl | `peaso/checks/claude_aws_a_network.py:449` | nacl_unused_prowler |
| `aws.claude_a.vpc.public_and_private_subnets` | vpc | `peaso/checks/claude_aws_a_network.py:586` | vpc_public_private |
| `aws.claude_a.vpc.route_table_no_default_igw_route` | route_table | `peaso/checks/claude_aws_a_network.py:682` | rtb_igw |
| `aws.claude_a.vpc.sg_attached_to_eni` | security_group | `peaso/checks/claude_aws_a_network.py:363` | sg_associated_eni |
| `aws.claude_a.vpc.sg_attached_to_eni_or_instance` | security_group | `peaso/checks/claude_aws_a_network.py:376` | sg_unused_compliance |
| `aws.claude_a.vpc.sg_in_use_anywhere` | security_group | `peaso/unused_network_aws.py:201` | _security_group |
| `aws.claude_a.vpc.sg_name_not_launch_wizard` | security_group | `peaso/checks/claude_aws_a_network.py:226` | sg_launch_wizard_name |
| `aws.claude_a.vpc.sg_no_public_ip_any_port` | security_group | `peaso/checks/claude_aws_a_network.py:95` | sg_any_port_from_ip |
| `aws.claude_a.vpc.sg_no_wide_public_ipv4` | security_group | `peaso/checks/claude_aws_a_network.py:172` | sg_wide_open |
| `aws.claude_a.vpc.sg_no_world_all_traffic` | security_group | `peaso/checks/claude_aws_a_network.py:55` | sg_all_ports |
| `aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis` | security_group | `peaso/checks/claude_aws_a_network.py:72` | sg_any_port |
| `aws.claude_a.vpc.sg_no_world_cassandra` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_elasticsearch_kibana` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_ftp` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_high_risk_tcp_ports` | security_group | `peaso/checks/claude_aws_a_network.py:115` | sg_high_risk |
| `aws.claude_a.vpc.sg_no_world_kafka` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_memcached` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_mongodb` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_mysql` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_oracle` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_postgres` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_rdp` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_redis` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_sqlserver` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_ssh` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_no_world_telnet` | security_group | `peaso/checks/claude_aws_a_network.py:143` | _sg_port_check |
| `aws.claude_a.vpc.sg_rule_count_within_50` | security_group | `peaso/checks/claude_aws_a_network.py:267` | sg_many_rules |
| `aws.claude_a.vpc.sg_world_any_cifs` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_any_kafka` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_any_kibana` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_any_redis` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_any_remote_admin` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v4_cassandra` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v4_common20` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v4_common6` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v4_memcached` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v4_mongodb` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v4_no_tcp_udp` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v4_only_80_443` | security_group | `peaso/checks/claude_aws_a_network.py:348` | sg_authorized_ports |
| `aws.claude_a.vpc.sg_world_v4_oracle` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v4_rdp` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v4_ssh` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.sg_world_v6_remote_admin` | security_group | `peaso/checks/claude_aws_a_network.py:296` | _turbot_check |
| `aws.claude_a.vpc.subnet_no_auto_public_ip` | subnet | `peaso/checks/claude_aws_a_network.py:612` | subnet_auto_public |
| `aws.claude_a.vpc.subnets_in_multiple_azs` | vpc | `peaso/checks/claude_aws_a_network.py:536` | vpc_multi_az |
| `aws.claude_a.vpc.vpc_endpoint_ec2` | vpc | `peaso/checks/claude_aws_a_network.py:728` | _endpoint_check |
| `aws.claude_a.vpc.vpc_has_subnets` | vpc | `peaso/checks/claude_aws_a_network.py:524` | vpc_not_in_use |
| `aws.ec2.restrict_internet_ingress` | security_group | `peaso/checks/__init__.py:465` | aws_ingress |
| `aws.gap.vpc.sg_world_any_common_ports` | security_group | `peaso/checks/aws_gap_core.py:585` | sg_common_ports |
| `aws.network.route_table_associated` | route_table | `peaso/unused_network_aws.py:112` | route_table |
| `aws_security_group_common_ports_ipv6_all` | security_group | `peaso/checks/batch_remaining_aws.py:173` | _security_group |
| `aws_security_group_ssh_ipv6_all` | security_group | `peaso/checks/batch_remaining_aws.py:173` | _security_group |
| `aws_security_group_tcp_udp_ipv6_all` | security_group | `peaso/checks/batch_remaining_aws.py:173` | _security_group |
| `aws_vpc_uses_amazonprovided_dns` | vpc | `peaso/checks/post_dfaf_aws.py:124` | dhcp |
