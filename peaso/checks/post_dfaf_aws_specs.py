"""Literal signed proposal rows; offline, no runtime .cache dependency."""
SPECS = {'aws.nist.rds_cluster_member_enhanced_monitoring': {'aliases': [],
                                                     'category': 'hardening',
                                                     'data_source': 'rds:DescribeDBClusters '
                                                                    'DBClusterIdentifier, '
                                                                    'DBClusterMembers[].DBInstanceIdentifier; '
                                                                    'rds:DescribeDBInstances '
                                                                    'DBInstanceIdentifier, '
                                                                    'MonitoringInterval, MonitoringRoleArn, '
                                                                    'Engine',
                                                     'description': 'Detects failure of rds cluster member '
                                                                    'instances enable enhanced monitoring.',
                                                     'id': 'aws.nist.rds_cluster_member_enhanced_monitoring',
                                                     'needs_new_collection': True,
                                                     'predicate': 'For every in-scope cluster, FAIL if any '
                                                                  'member DB instance has '
                                                                  'MonitoringInterval=0 or no '
                                                                  'MonitoringRoleArn; PASS iff every member '
                                                                  'has MonitoringInterval>0 and a '
                                                                  'MonitoringRoleArn; UNKNOWN if '
                                                                  'cluster/member inventory or monitoring '
                                                                  'fields are incomplete.',
                                                     'provider': 'aws',
                                                     'remediation_hint': 'Enable Enhanced Monitoring and a '
                                                                         'monitoring role on every cluster '
                                                                         'member instance.',
                                                     'requirements': [{'framework_id': 'aws-compliance.benchmark.ffiec',
                                                                       'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled'},
                                                                      {'framework_id': 'aws-compliance.benchmark.nist_800_171_rev_2',
                                                                       'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled'},
                                                                      {'framework_id': 'aws-compliance.benchmark.nist_800_172',
                                                                       'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled'}],
                                                     'resource_kind': 'rds_db_cluster',
                                                     'severity': 'medium',
                                                     'title': 'RDS cluster member instances enable Enhanced '
                                                              'Monitoring'},
 'aws.pci.vpc.peering_dns_resolution': {'aliases': [],
                                        'category': 'hardening',
                                        'data_source': 'new read-only API call '
                                                       'ec2:DescribeVpcPeeringConnections; '
                                                       'requester/accepter '
                                                       'PeeringOptions.AllowDnsResolutionFromRemoteVpc',
                                        'description': 'Detects a VPC peering connection whose requester or '
                                                       'accepter peering option disables remote DNS '
                                                       'resolution; this can create an unapproved network or '
                                                       'resource access path.',
                                        'id': 'aws.pci.vpc.peering_dns_resolution',
                                        'needs_new_collection': True,
                                        'predicate': 'For each active VPC peering connection, both '
                                                     'PeeringOptions.AllowDnsResolutionFromRemoteVpc values '
                                                     'are true',
                                        'provider': 'aws',
                                        'remediation_hint': 'Enable AllowDnsResolutionFromRemoteVpc on both '
                                                            'requester and accepter peering options with '
                                                            'modify-vpc-peering-connection-options.',
                                        'requirements': [{'framework_id': 'pci_4.0_aws',
                                                          'requirement_id': '1.2.8.40'},
                                                         {'framework_id': 'pci_4.0_aws',
                                                          'requirement_id': '1.3.1.44'},
                                                         {'framework_id': 'pci_4.0_aws',
                                                          'requirement_id': '1.3.2.44'},
                                                         {'framework_id': 'pci_4.0_aws',
                                                          'requirement_id': '1.4.1.9'},
                                                         {'framework_id': 'pci_4.0_aws',
                                                          'requirement_id': '1.4.2.42'},
                                                         {'framework_id': 'pci_4.0_aws',
                                                          'requirement_id': '1.4.4.9'}],
                                        'resource_kind': 'vpc_peering_connection',
                                        'severity': 'medium',
                                        'title': 'VPC peering resolves remote private DNS'},
 'aws_fedramp_rds_cluster_members_enhanced_monitoring': {'aliases': [],
                                                         'category': 'compliance',
                                                         'data_source': 'RDS DescribeDBClusters '
                                                                        'DBClusterMembers[].DBInstanceIdentifier '
                                                                        'joined to DescribeDBInstances '
                                                                        'MonitoringInterval, '
                                                                        'MonitoringRoleArn',
                                                         'description': 'Tests Enhanced Monitoring settings '
                                                                        'of cluster member instances rather '
                                                                        'than log exports.',
                                                         'id': 'aws_fedramp_rds_cluster_members_enhanced_monitoring',
                                                         'needs_new_collection': True,
                                                         'predicate': 'FAIL if any member instance of an '
                                                                      'in-scope RDS cluster has '
                                                                      'MonitoringInterval <= 0 or no '
                                                                      'MonitoringRoleArn; PASS if every '
                                                                      'member has an interval > 0 and role; '
                                                                      'UNKNOWN if a cluster member cannot be '
                                                                      'resolved.',
                                                         'provider': 'aws',
                                                         'remediation_hint': 'Configure the named AWS '
                                                                             'resource to satisfy the '
                                                                             'predicate and verify all '
                                                                             'in-scope resources.',
                                                         'requirements': [{'framework_id': 'aws-compliance.benchmark.fedramp_low_rev_4',
                                                                           'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled'},
                                                                          {'framework_id': 'aws-compliance.benchmark.fedramp_moderate_rev_4',
                                                                           'requirement_id': 'aws-compliance.control.rds_db_instance_and_cluster_enhanced_monitoring_enabled'}],
                                                         'resource_kind': 'rds_db_cluster',
                                                         'severity': 'medium',
                                                         'title': 'RDS cluster members enable Enhanced '
                                                                  'Monitoring'},
 'aws_g6_api_stage_valid_client_certificate': {'aliases': [],
                                               'category': 'hardening',
                                               'data_source': 'apigateway:GetStages '
                                                              'stageName,clientCertificateId; '
                                                              'apigateway:GetClientCertificate '
                                                              'clientCertificateId,expirationDate; scan '
                                                              'capture time',
                                               'description': 'Read-only assessment of rEST API stages '
                                                              'reference valid client certificates.',
                                               'id': 'aws_g6_api_stage_valid_client_certificate',
                                               'needs_new_collection': True,
                                               'predicate': 'For every in-scope REST stage, FAIL iff '
                                                            'clientCertificateId is empty, '
                                                            'GetClientCertificate cannot resolve it, or '
                                                            'expirationDate is at or before capture time; '
                                                            'PASS iff the referenced client certificate '
                                                            'exists and is unexpired; UNKNOWN on denied or '
                                                            'incomplete detail reads.',
                                               'provider': 'aws',
                                               'remediation_hint': 'Associate each REST API stage with a '
                                                                   'valid, unexpired API Gateway client '
                                                                   'certificate.',
                                               'requirements': [{'framework_id': 'aws-compliance.benchmark.nydfs_23',
                                                                 'requirement_id': 'aws-compliance.control.apigateway_rest_api_stage_use_ssl_certificate'}],
                                               'resource_kind': 'rest_api_stage',
                                               'severity': 'medium',
                                               'title': 'REST API stages reference valid client '
                                                        'certificates'},
 'aws_g6_elbv2_only_https_tls_listeners': {'aliases': [],
                                           'category': 'hardening',
                                           'data_source': 'elasticloadbalancingv2:DescribeLoadBalancers Type '
                                                          'and DescribeListeners Protocol,Certificates for '
                                                          'every application and network load balancer',
                                           'description': 'Read-only assessment of aLB and NLB listeners use '
                                                          'only HTTPS or TLS.',
                                           'id': 'aws_g6_elbv2_only_https_tls_listeners',
                                           'needs_new_collection': True,
                                           'predicate': 'For each ALB/NLB listener, FAIL iff Protocol is not '
                                                        'HTTPS or TLS, or no certificate ARN is configured; '
                                                        'PASS iff every listener uses HTTPS/TLS with a '
                                                        'certificate; UNKNOWN on incomplete load-balancer or '
                                                        'listener inventory.',
                                           'provider': 'aws',
                                           'remediation_hint': 'Replace plaintext listeners with HTTPS/TLS '
                                                               'listeners and attach valid certificates.',
                                           'requirements': [{'framework_id': 'aws-compliance.benchmark.nist_csf_v2',
                                                             'requirement_id': 'aws-compliance.control.elb_application_network_lb_use_ssl_certificate'},
                                                            {'framework_id': 'aws-compliance.benchmark.nydfs_23',
                                                             'requirement_id': 'aws-compliance.control.elb_application_network_lb_use_ssl_certificate'}],
                                           'resource_kind': 'load_balancer_v2',
                                           'severity': 'high',
                                           'title': 'ALB and NLB listeners use only HTTPS or TLS'},
 'aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az': {'aliases': [],
                                                                     'category': 'compliance',
                                                                     'data_source': 'autoscaling:DescribeAutoScalingGroups '
                                                                                    'MixedInstancesPolicy '
                                                                                    'and AvailabilityZones',
                                                                     'description': 'Multiple Availability '
                                                                                    'Zones are not tested by '
                                                                                    'the instance-type '
                                                                                    'evaluator.',
                                                                     'id': 'aws_nist_autoscaling_use_multiple_instance_types_in_multiple_az',
                                                                     'needs_new_collection': True,
                                                                     'predicate': 'For every in-scope Auto '
                                                                                  'Scaling group, PASS only '
                                                                                  'if the effective mixed '
                                                                                  'policy has at least two '
                                                                                  'distinct instance types '
                                                                                  'and AvailabilityZones '
                                                                                  'contains at least two '
                                                                                  'distinct zone names; '
                                                                                  'UNKNOWN on incomplete '
                                                                                  'group data.',
                                                                     'provider': 'aws',
                                                                     'remediation_hint': 'Configure the '
                                                                                         'resource to '
                                                                                         'satisfy the stated '
                                                                                         'predicate and '
                                                                                         'review missing '
                                                                                         'inventory or '
                                                                                         'policy inputs.',
                                                                     'requirements': [{'framework_id': 'aws-compliance.benchmark.nist_csf',
                                                                                       'requirement_id': 'aws-compliance.control.autoscaling_use_multiple_instance_types_in_multiple_az'}],
                                                                     'resource_kind': 'autoscaling_group',
                                                                     'severity': 'medium',
                                                                     'title': 'EC2 auto scaling groups '
                                                                              'should use multiple instance '
                                                                              'types in multiple '
                                                                              'availability zones'},
 'aws_nist_efs_access_point_enforce_root_directory': {'aliases': [],
                                                      'category': 'compliance',
                                                      'data_source': 'elasticfilesystem:DescribeAccessPoints '
                                                                     'RootDirectory.Path',
                                                      'description': 'The evaluator treats an empty path as '
                                                                     'enforcing a root directory.',
                                                      'id': 'aws_nist_efs_access_point_enforce_root_directory',
                                                      'needs_new_collection': True,
                                                      'predicate': 'For each access point, PASS only if '
                                                                   'RootDirectory.Path is a nonempty '
                                                                   'absolute path other than /; FAIL for '
                                                                   'missing, empty or /.',
                                                      'provider': 'aws',
                                                      'remediation_hint': 'Configure the resource to satisfy '
                                                                          'the stated predicate and review '
                                                                          'missing inventory or policy '
                                                                          'inputs.',
                                                      'requirements': [{'framework_id': 'aws-compliance.benchmark.nist_csf',
                                                                        'requirement_id': 'aws-compliance.control.efs_access_point_enforce_root_directory'}],
                                                      'resource_kind': 'efs_access_point',
                                                      'severity': 'medium',
                                                      'title': 'EFS access points should enforce a root '
                                                               'directory'},
 'aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days': {'aliases': [],
                                                                           'category': 'compliance',
                                                                           'data_source': 'elasticache:DescribeReplicationGroups '
                                                                                          'SnapshotRetentionLimit '
                                                                                          'and automatic '
                                                                                          'snapshot settings',
                                                                           'description': 'An omitted '
                                                                                          'retention limit '
                                                                                          'is treated as '
                                                                                          'passing by the '
                                                                                          'evaluator.',
                                                                           'id': 'aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days',
                                                                           'needs_new_collection': True,
                                                                           'predicate': 'For each applicable '
                                                                                        'Redis replication '
                                                                                        'group, PASS only if '
                                                                                        'SnapshotRetentionLimit '
                                                                                        'is an integer >=15; '
                                                                                        'FAIL when it is '
                                                                                        'absent, zero or '
                                                                                        'lower; UNKNOWN on '
                                                                                        'incomplete detail.',
                                                                           'provider': 'aws',
                                                                           'remediation_hint': 'Configure '
                                                                                               'the resource '
                                                                                               'to satisfy '
                                                                                               'the stated '
                                                                                               'predicate '
                                                                                               'and review '
                                                                                               'missing '
                                                                                               'inventory or '
                                                                                               'policy '
                                                                                               'inputs.',
                                                                           'requirements': [{'framework_id': 'aws-compliance.benchmark.nist_800_53_rev_4',
                                                                                             'requirement_id': 'aws-compliance.control.elasticache_redis_cluster_automatic_backup_retention_15_days'},
                                                                                            {'framework_id': 'aws-compliance.benchmark.nist_800_53_rev_5',
                                                                                             'requirement_id': 'aws-compliance.control.elasticache_redis_cluster_automatic_backup_retention_15_days'},
                                                                                            {'framework_id': 'aws-compliance.benchmark.nist_csf',
                                                                                             'requirement_id': 'aws-compliance.control.elasticache_redis_cluster_automatic_backup_retention_15_days'}],
                                                                           'resource_kind': 'elasticache_replication_group',
                                                                           'severity': 'medium',
                                                                           'title': 'ElastiCache Redis '
                                                                                    'cluster automatic '
                                                                                    'backup should be '
                                                                                    'enabled with retention '
                                                                                    'period of 15 days or '
                                                                                    'greater'},
 'aws_shield_automatic_application_layer_response': {'aliases': [],
                                                     'category': 'hardening',
                                                     'data_source': 'new read-only API calls '
                                                                    'shield:DescribeProtection; '
                                                                    'ApplicationLayerAutomaticResponse.Status',
                                                     'description': 'Detects a Shield protection whose '
                                                                    'Shield protection has '
                                                                    'ApplicationLayerAutomaticResponse.Status '
                                                                    'other than ENABLED; this can leave the '
                                                                    'workload exposed to preventable '
                                                                    'compromise or service loss.',
                                                     'id': 'aws_shield_automatic_application_layer_response',
                                                     'needs_new_collection': True,
                                                     'predicate': 'PASS iff each applicable Shield '
                                                                  'protection reports '
                                                                  'ApplicationLayerAutomaticResponse.Status=ENABLED',
                                                     'provider': 'aws',
                                                     'remediation_hint': 'Enable '
                                                                         'ApplicationLayerAutomaticResponse '
                                                                         'on each applicable Shield Advanced '
                                                                         'protection.',
                                                     'requirements': [{'framework_id': 'aws_account_security_onboarding_aws',
                                                                       'requirement_id': 'Enable Shield '
                                                                                         'Advanced automatic '
                                                                                         'application layer '
                                                                                         'DDoS mitigation'}],
                                                     'resource_kind': 'shield_protection',
                                                     'severity': 'medium',
                                                     'title': 'Enable Shield Advanced automatic application '
                                                              'layer DDoS mitigation'},
 'aws_shield_protection_health_checks': {'aliases': [],
                                         'category': 'hardening',
                                         'data_source': 'existing shield_protection collector: '
                                                        'shield:ListProtections (HealthCheckIds); new '
                                                        'read-only route53:GetHealthCheck',
                                         'description': 'Detects a Shield protection whose Shield protection '
                                                        'lacks a live associated Route 53 health check; this '
                                                        'can leave the workload exposed to preventable '
                                                        'compromise or service loss.',
                                         'id': 'aws_shield_protection_health_checks',
                                         'needs_new_collection': True,
                                         'predicate': 'PASS iff each scoped shield:ListProtections item has '
                                                      'nonempty HealthCheckIds and every ID resolves through '
                                                      'route53:GetHealthCheck.',
                                         'provider': 'aws',
                                         'remediation_hint': 'Associate existing Route 53 health-check IDs '
                                                             'with each Shield protection and remove stale '
                                                             'IDs.',
                                         'requirements': [{'framework_id': 'aws_account_security_onboarding_aws',
                                                           'requirement_id': 'Configure R53 health checks '
                                                                             'for all protected resources'}],
                                         'resource_kind': 'shield_protection',
                                         'severity': 'medium',
                                         'title': 'Configure R53 health checks for all protected resources'},
 'aws_vpc_uses_amazonprovided_dns': {'aliases': [],
                                     'category': 'hardening',
                                     'data_source': 'ec2:DescribeVpcs Vpcs[].VpcId, DhcpOptionsId; '
                                                    'ec2:DescribeDhcpOptions '
                                                    'DhcpOptions[].DhcpConfigurations[Key=domain-name-servers].Values[].Value',
                                     'description': 'Detects a VPC whose DHCP options contain DNS servers '
                                                    'other than AmazonProvidedDNS; this can create an '
                                                    'unapproved network or resource access path.',
                                     'id': 'aws_vpc_uses_amazonprovided_dns',
                                     'needs_new_collection': True,
                                     'predicate': 'For every VpcId, PASS iff the associated DhcpOptionsId '
                                                  'resolves to domain-name-servers Values containing '
                                                  'AmazonProvidedDNS and no other DNS server value.',
                                     'provider': 'aws',
                                     'remediation_hint': 'Set the VPC DHCP option domain-name-servers to '
                                                         'AmazonProvidedDNS and remove other DNS server '
                                                         'values.',
                                     'requirements': [{'framework_id': 'aws_account_security_onboarding_aws',
                                                       'requirement_id': 'Use strictly AWS VPC DNS '
                                                                         'resolver'}],
                                     'resource_kind': 'vpc',
                                     'severity': 'medium',
                                     'title': 'Use strictly AWS VPC DNS resolver'}}
