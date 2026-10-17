# Azure PCI compliance checklist

- [ ] pci_4.0_azure 1.2.5.1 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7
- [x] pci_4.0_azure 1.2.5.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.2.5.3 - NEW_CHECK - azure_frontdoor_app_minimum_tls_version_12_0512053
- [ ] pci_4.0_azure 1.2.5.4 - NEW_CHECK - azure_frontdoor_1_2_5_4_ccc7b8f
- [ ] pci_4.0_azure 1.2.5.5 - NEW_CHECK - azure_frontdoor_network_http_internet_access_restricted_7004685
- [ ] pci_4.0_azure 1.2.5.6 - NEW_CHECK - azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9
- [x] pci_4.0_azure 1.2.5.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.2.5.8 - NEW_CHECK - azure_application_gateway_1_2_5_8_33a9d21
- [ ] pci_4.0_azure 1.2.5.9 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17
- [ ] pci_4.0_azure 1.2.5.10 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63
- [ ] pci_4.0_azure 1.2.5.11 - NEW_CHECK - azure_hdinsight_cluster_1_2_5_11_babfa1b
- [x] pci_4.0_azure 1.2.5.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.5.13 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.5.14 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.5.15 - MAPPED - azure.storage.https_only
- [x] pci_4.0_azure 1.2.5.16 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.2.5.17 - NEW_CHECK - azure_nsg_world_ingress_approved_ports
- [ ] pci_4.0_azure 1.2.8.1 - NEW_CHECK - azure_api_management_1_2_8_1_ba319cf
- [x] pci_4.0_azure 1.2.8.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.2.8.3 - NEW_CHECK - azure_api_management_1_2_8_3_e8fe737
- [ ] pci_4.0_azure 1.2.8.4 - PARTIAL - azure.claude.frontdoor_waf_policy_linked, azure_frontdoor_1_2_8_4_90159db (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.2.8.5 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [ ] pci_4.0_azure 1.2.8.6 - NEW_CHECK - azure_devops_project_1_2_8_6_fb0e5a8
- [x] pci_4.0_azure 1.2.8.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.8.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.8.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.2.8.10 - NEW_CHECK - azure_vm_1_2_8_10_1bd35d0
- [x] pci_4.0_azure 1.2.8.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.8.12 - MAPPING_FIX - azure.aks.private_cluster
- [x] pci_4.0_azure 1.2.8.13 - MAPPING_FIX - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link
- [x] pci_4.0_azure 1.2.8.14 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.2.8.15 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [x] pci_4.0_azure 1.2.8.16 - MANUAL - none
- [ ] pci_4.0_azure 1.2.8.17 - PARTIAL - azure.gap.nsg_declared_internet_ssh (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.2.8.18 - NEW_CHECK - azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc
- [ ] pci_4.0_azure 1.2.8.19 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.2.8.20 - MAPPED - azure.claude2.prowler_function_vnet_integration
- [ ] pci_4.0_azure 1.2.8.21 - PARTIAL - azure.gap.nsg_declared_internet_ssh, azure.gap.nsg_declared_internet_rdp (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.2.8.22 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.2.8.23 - NEW_CHECK - azure_firewall_policy_1_2_8_23_59ad733
- [ ] pci_4.0_azure 1.2.8.24 - NEW_CHECK - azure_firewall_policy_1_2_8_24_cc7cb8a
- [ ] pci_4.0_azure 1.2.8.25 - NEW_CHECK - azure_route_table_network_http_internet_access_restricted_5cd2484
- [ ] pci_4.0_azure 1.2.8.26 - PARTIAL - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.2.8.27 - NEW_CHECK - azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d
- [ ] pci_4.0_azure 1.2.8.28 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [ ] pci_4.0_azure 1.2.8.29 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [x] pci_4.0_azure 1.2.8.30 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure 1.2.8.31 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.2.8.32 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.2.8.33 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.2.8.34 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.2.8.35 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.2.8.36 - NEW_CHECK - azure_ml_workspace_1_2_8_36_33f50db
- [ ] pci_4.0_azure 1.2.8.37 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [ ] pci_4.0_azure 1.2.8.38 - NEW_CHECK - azure_azure_resource_keyvault_private_endpoints_c3995a6
- [ ] pci_4.0_azure 1.2.8.39 - PARTIAL - azure.claude.nsg_associated_with_subnet, azure_pci_1_2_8_39 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.2.8.40 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.2.8.41 - NEW_CHECK - azure_nsg_world_ingress_approved_ports
- [ ] pci_4.0_azure 1.2.8.42 - NEW_CHECK - azure_firewall_policy_1_2_8_42_cacbd9e
- [x] pci_4.0_azure 1.2.8.43 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.8.44 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.8.45 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.8.46 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.2.8.47 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.1.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.1.2 - NEW_CHECK - azure_api_management_1_2_8_1_ba319cf
- [x] pci_4.0_azure 1.3.1.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.1.4 - NEW_CHECK - azure_api_management_1_2_8_3_e8fe737
- [ ] pci_4.0_azure 1.3.1.5 - PARTIAL - azure.claude.frontdoor_waf_policy_linked, azure_frontdoor_1_2_8_4_90159db (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.1.6 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [ ] pci_4.0_azure 1.3.1.7 - NEW_CHECK - azure_devops_project_1_2_8_6_fb0e5a8
- [x] pci_4.0_azure 1.3.1.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.1.9 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.1.10 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.1.11 - NEW_CHECK - azure_vm_1_2_8_10_1bd35d0
- [x] pci_4.0_azure 1.3.1.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.1.13 - MAPPING_FIX - azure.aks.private_cluster
- [x] pci_4.0_azure 1.3.1.14 - MAPPING_FIX - azure.port.redis_cache_in_virtual_network
- [x] pci_4.0_azure 1.3.1.15 - MAPPING_FIX - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link
- [x] pci_4.0_azure 1.3.1.16 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.1.17 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [x] pci_4.0_azure 1.3.1.18 - MANUAL - none
- [ ] pci_4.0_azure 1.3.1.19 - PARTIAL - azure.gap.nsg_declared_internet_ssh (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.1.20 - MANUAL - none
- [ ] pci_4.0_azure 1.3.1.21 - NEW_CHECK - azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc
- [ ] pci_4.0_azure 1.3.1.22 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.1.23 - MAPPED - azure.claude2.prowler_function_vnet_integration
- [ ] pci_4.0_azure 1.3.1.24 - PARTIAL - azure.gap.nsg_declared_internet_ssh, azure.gap.nsg_declared_internet_rdp (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.1.25 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.1.26 - NEW_CHECK - azure_firewall_policy_1_2_8_23_59ad733
- [ ] pci_4.0_azure 1.3.1.27 - NEW_CHECK - azure_firewall_policy_1_2_8_24_cc7cb8a
- [ ] pci_4.0_azure 1.3.1.28 - NEW_CHECK - azure_route_table_network_http_internet_access_restricted_5cd2484
- [ ] pci_4.0_azure 1.3.1.29 - PARTIAL - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.1.30 - NEW_CHECK - azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d
- [ ] pci_4.0_azure 1.3.1.31 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [ ] pci_4.0_azure 1.3.1.32 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [ ] pci_4.0_azure 1.3.1.33 - PARTIAL - azure.claude.synapse_workspace_private_link, azure_pci_1_3_1_33 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.1.34 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure 1.3.1.35 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.1.36 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.1.37 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.1.38 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.1.39 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.1.40 - NEW_CHECK - azure_ml_workspace_1_2_8_36_33f50db
- [ ] pci_4.0_azure 1.3.1.41 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [ ] pci_4.0_azure 1.3.1.42 - NEW_CHECK - azure_azure_resource_keyvault_private_endpoints_c3995a6
- [ ] pci_4.0_azure 1.3.1.43 - PARTIAL - azure.claude.nsg_associated_with_subnet, azure_pci_1_2_8_39 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.1.44 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.1.45 - NEW_CHECK - azure_nsg_world_ingress_approved_ports
- [ ] pci_4.0_azure 1.3.1.46 - NEW_CHECK - azure_azure_resource_1_3_1_46_b70e2c8
- [ ] pci_4.0_azure 1.3.1.47 - NEW_CHECK - azure_firewall_policy_1_2_8_42_cacbd9e
- [x] pci_4.0_azure 1.3.1.48 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.1.49 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.1.50 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.1.51 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.1.52 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.2.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.2.2 - NEW_CHECK - azure_api_management_1_2_8_1_ba319cf
- [x] pci_4.0_azure 1.3.2.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.2.4 - NEW_CHECK - azure_api_management_1_2_8_3_e8fe737
- [ ] pci_4.0_azure 1.3.2.5 - PARTIAL - azure.claude.frontdoor_waf_policy_linked, azure_frontdoor_1_2_8_4_90159db (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.2.6 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [ ] pci_4.0_azure 1.3.2.7 - NEW_CHECK - azure_devops_project_1_2_8_6_fb0e5a8
- [x] pci_4.0_azure 1.3.2.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.2.9 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.2.10 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.2.11 - NEW_CHECK - azure_vm_1_2_8_10_1bd35d0
- [x] pci_4.0_azure 1.3.2.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.2.13 - MAPPING_FIX - azure.aks.private_cluster
- [x] pci_4.0_azure 1.3.2.14 - MAPPING_FIX - azure.port.redis_cache_in_virtual_network
- [x] pci_4.0_azure 1.3.2.15 - MAPPING_FIX - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link
- [x] pci_4.0_azure 1.3.2.16 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.2.17 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [x] pci_4.0_azure 1.3.2.18 - MANUAL - none
- [ ] pci_4.0_azure 1.3.2.19 - PARTIAL - azure.gap.nsg_declared_internet_ssh (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.2.20 - MANUAL - none
- [ ] pci_4.0_azure 1.3.2.21 - NEW_CHECK - azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc
- [ ] pci_4.0_azure 1.3.2.22 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.2.23 - MAPPED - azure.claude2.prowler_function_vnet_integration
- [ ] pci_4.0_azure 1.3.2.24 - PARTIAL - azure.gap.nsg_declared_internet_ssh, azure.gap.nsg_declared_internet_rdp (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.2.25 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.2.26 - NEW_CHECK - azure_firewall_policy_1_2_8_23_59ad733
- [ ] pci_4.0_azure 1.3.2.27 - NEW_CHECK - azure_firewall_policy_1_2_8_24_cc7cb8a
- [ ] pci_4.0_azure 1.3.2.28 - NEW_CHECK - azure_route_table_network_http_internet_access_restricted_5cd2484
- [ ] pci_4.0_azure 1.3.2.29 - PARTIAL - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.2.30 - NEW_CHECK - azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d
- [ ] pci_4.0_azure 1.3.2.31 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [ ] pci_4.0_azure 1.3.2.32 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [ ] pci_4.0_azure 1.3.2.33 - PARTIAL - azure.claude.synapse_workspace_private_link, azure_pci_1_3_1_33 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.2.34 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure 1.3.2.35 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.2.36 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.2.37 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.3.2.38 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.2.39 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.2.40 - NEW_CHECK - azure_ml_workspace_1_2_8_36_33f50db
- [ ] pci_4.0_azure 1.3.2.41 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [ ] pci_4.0_azure 1.3.2.42 - NEW_CHECK - azure_azure_resource_keyvault_private_endpoints_c3995a6
- [ ] pci_4.0_azure 1.3.2.43 - PARTIAL - azure.claude.nsg_associated_with_subnet, azure_pci_1_2_8_39 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.3.2.44 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.3.2.45 - NEW_CHECK - azure_nsg_world_ingress_approved_ports
- [ ] pci_4.0_azure 1.3.2.46 - NEW_CHECK - azure_azure_resource_1_3_1_46_b70e2c8
- [ ] pci_4.0_azure 1.3.2.47 - NEW_CHECK - azure_firewall_policy_1_2_8_42_cacbd9e
- [x] pci_4.0_azure 1.3.2.48 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.2.49 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.2.50 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.2.51 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.3.2.52 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.1.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.1.2 - NEW_CHECK - azure_api_management_1_2_8_1_ba319cf
- [x] pci_4.0_azure 1.4.1.3 - MAPPING_FIX - azure.port.redis_cache_in_virtual_network
- [x] pci_4.0_azure 1.4.1.4 - MANUAL - none
- [ ] pci_4.0_azure 1.4.1.5 - NEW_CHECK - azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc
- [ ] pci_4.0_azure 1.4.1.6 - NEW_CHECK - azure_route_table_network_http_internet_access_restricted_5cd2484
- [ ] pci_4.0_azure 1.4.1.7 - PARTIAL - azure.claude.synapse_workspace_private_link, azure_pci_1_3_1_33 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.4.1.8 - NEW_CHECK - azure_ml_workspace_1_2_8_36_33f50db
- [x] pci_4.0_azure 1.4.1.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.1.10 - NEW_CHECK - azure_azure_resource_1_3_1_46_b70e2c8
- [x] pci_4.0_azure 1.4.2.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.2.2 - NEW_CHECK - azure_api_management_1_2_8_1_ba319cf
- [x] pci_4.0_azure 1.4.2.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.2.4 - NEW_CHECK - azure_api_management_1_2_8_3_e8fe737
- [ ] pci_4.0_azure 1.4.2.5 - PARTIAL - azure.claude.frontdoor_waf_policy_linked, azure_frontdoor_1_2_8_4_90159db (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.4.2.6 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [ ] pci_4.0_azure 1.4.2.7 - NEW_CHECK - azure_devops_project_1_2_8_6_fb0e5a8
- [x] pci_4.0_azure 1.4.2.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.2.9 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.2.10 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.2.11 - NEW_CHECK - azure_vm_1_2_8_10_1bd35d0
- [x] pci_4.0_azure 1.4.2.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.2.13 - MAPPING_FIX - azure.aks.private_cluster
- [x] pci_4.0_azure 1.4.2.14 - MAPPING_FIX - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link
- [x] pci_4.0_azure 1.4.2.15 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.2.16 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [x] pci_4.0_azure 1.4.2.17 - MANUAL - none
- [ ] pci_4.0_azure 1.4.2.18 - PARTIAL - azure.gap.nsg_declared_internet_ssh (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.4.2.19 - NEW_CHECK - azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc
- [ ] pci_4.0_azure 1.4.2.20 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.4.2.21 - MAPPED - azure.claude2.prowler_function_vnet_integration
- [ ] pci_4.0_azure 1.4.2.22 - PARTIAL - azure.gap.nsg_declared_internet_ssh, azure.gap.nsg_declared_internet_rdp (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.4.2.23 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.2.24 - NEW_CHECK - azure_firewall_policy_1_2_8_23_59ad733
- [ ] pci_4.0_azure 1.4.2.25 - NEW_CHECK - azure_firewall_policy_1_2_8_24_cc7cb8a
- [ ] pci_4.0_azure 1.4.2.26 - NEW_CHECK - azure_route_table_network_http_internet_access_restricted_5cd2484
- [ ] pci_4.0_azure 1.4.2.27 - PARTIAL - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.4.2.28 - NEW_CHECK - azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d
- [ ] pci_4.0_azure 1.4.2.29 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [ ] pci_4.0_azure 1.4.2.30 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [ ] pci_4.0_azure 1.4.2.31 - PARTIAL - azure.claude.synapse_workspace_private_link, azure_pci_1_3_1_33 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.4.2.32 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure 1.4.2.33 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.4.2.34 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.4.2.35 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.4.2.36 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.4.2.37 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.2.38 - NEW_CHECK - azure_ml_workspace_1_2_8_36_33f50db
- [ ] pci_4.0_azure 1.4.2.39 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [ ] pci_4.0_azure 1.4.2.40 - NEW_CHECK - azure_azure_resource_keyvault_private_endpoints_c3995a6
- [ ] pci_4.0_azure 1.4.2.41 - PARTIAL - azure.claude.nsg_associated_with_subnet, azure_pci_1_2_8_39 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.4.2.42 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.2.43 - NEW_CHECK - azure_nsg_world_ingress_approved_ports
- [ ] pci_4.0_azure 1.4.2.44 - NEW_CHECK - azure_azure_resource_1_3_1_46_b70e2c8
- [ ] pci_4.0_azure 1.4.2.45 - NEW_CHECK - azure_firewall_policy_1_2_8_42_cacbd9e
- [x] pci_4.0_azure 1.4.2.46 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.2.47 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.2.48 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.2.49 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.2.50 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.3.1 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.4.3.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.3.3 - NEW_CHECK - azure_firewall_policy_1_2_8_23_59ad733
- [x] pci_4.0_azure 1.4.4.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.4.2 - NEW_CHECK - azure_api_management_1_2_8_1_ba319cf
- [x] pci_4.0_azure 1.4.4.3 - MAPPING_FIX - azure.port.redis_cache_in_virtual_network
- [x] pci_4.0_azure 1.4.4.4 - MANUAL - none
- [ ] pci_4.0_azure 1.4.4.5 - NEW_CHECK - azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc
- [ ] pci_4.0_azure 1.4.4.6 - NEW_CHECK - azure_route_table_network_http_internet_access_restricted_5cd2484
- [ ] pci_4.0_azure 1.4.4.7 - PARTIAL - azure.claude.synapse_workspace_private_link, azure_pci_1_3_1_33 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.4.4.8 - NEW_CHECK - azure_ml_workspace_1_2_8_36_33f50db
- [x] pci_4.0_azure 1.4.4.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.4.4.10 - NEW_CHECK - azure_azure_resource_1_3_1_46_b70e2c8
- [ ] pci_4.0_azure 1.4.5.1 - NEW_CHECK - azure_vm_1_4_5_1_d40be43
- [ ] pci_4.0_azure 1.4.5.2 - NEW_CHECK - azure_aks_cluster_1_4_5_2_3ac7b3c
- [ ] pci_4.0_azure 1.5.1.1 - NEW_CHECK - azure_api_management_1_2_8_1_ba319cf
- [x] pci_4.0_azure 1.5.1.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.5.1.3 - NEW_CHECK - azure_api_management_1_2_8_3_e8fe737
- [ ] pci_4.0_azure 1.5.1.4 - PARTIAL - azure.claude.frontdoor_waf_policy_linked, azure_frontdoor_1_2_8_4_90159db (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.5.1.5 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [ ] pci_4.0_azure 1.5.1.6 - NEW_CHECK - azure_devops_project_1_2_8_6_fb0e5a8
- [x] pci_4.0_azure 1.5.1.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.5.1.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.5.1.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.5.1.10 - NEW_CHECK - azure_vm_1_2_8_10_1bd35d0
- [x] pci_4.0_azure 1.5.1.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.5.1.12 - MAPPING_FIX - azure.aks.private_cluster
- [x] pci_4.0_azure 1.5.1.13 - MAPPING_FIX - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link
- [x] pci_4.0_azure 1.5.1.14 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.5.1.15 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [x] pci_4.0_azure 1.5.1.16 - MANUAL - none
- [ ] pci_4.0_azure 1.5.1.17 - PARTIAL - azure.gap.nsg_declared_internet_ssh (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.5.1.18 - NEW_CHECK - azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc
- [ ] pci_4.0_azure 1.5.1.19 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.5.1.20 - MAPPED - azure.claude2.prowler_function_vnet_integration
- [ ] pci_4.0_azure 1.5.1.21 - PARTIAL - azure.gap.nsg_declared_internet_ssh, azure.gap.nsg_declared_internet_rdp (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.5.1.22 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.5.1.23 - NEW_CHECK - azure_firewall_policy_1_2_8_23_59ad733
- [ ] pci_4.0_azure 1.5.1.24 - NEW_CHECK - azure_firewall_policy_1_2_8_24_cc7cb8a
- [ ] pci_4.0_azure 1.5.1.25 - NEW_CHECK - azure_route_table_network_http_internet_access_restricted_5cd2484
- [ ] pci_4.0_azure 1.5.1.26 - PARTIAL - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.5.1.27 - NEW_CHECK - azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d
- [ ] pci_4.0_azure 1.5.1.28 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [ ] pci_4.0_azure 1.5.1.29 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [x] pci_4.0_azure 1.5.1.30 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure 1.5.1.31 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.5.1.32 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.5.1.33 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.5.1.34 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure 1.5.1.35 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 1.5.1.36 - NEW_CHECK - azure_ml_workspace_1_2_8_36_33f50db
- [ ] pci_4.0_azure 1.5.1.37 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [ ] pci_4.0_azure 1.5.1.38 - NEW_CHECK - azure_azure_resource_keyvault_private_endpoints_c3995a6
- [ ] pci_4.0_azure 1.5.1.39 - PARTIAL - azure.claude.nsg_associated_with_subnet, azure_pci_1_2_8_39 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 1.5.1.40 - NEW_CHECK - azure_nsg_world_ingress_approved_ports
- [ ] pci_4.0_azure 1.5.1.41 - NEW_CHECK - azure_firewall_policy_1_2_8_42_cacbd9e
- [x] pci_4.0_azure 1.5.1.42 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.5.1.43 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.5.1.44 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.5.1.45 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 1.5.1.46 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.1.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.2.1.1.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.2.1.1.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.2.1.1.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.2.1.1.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.1.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.2.1.1.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.2.1.1.8 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure 10.2.1.1.9 - NEW_CHECK - azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa
- [ ] pci_4.0_azure 10.2.1.1.10 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.1.11 - MANUAL - none
- [x] pci_4.0_azure 10.2.1.1.12 - MANUAL - none
- [ ] pci_4.0_azure 10.2.1.1.13 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.2.1.1.14 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.2.1.1.15 - NEW_CHECK - azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679
- [ ] pci_4.0_azure 10.2.1.1.16 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.2.1.1.17 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.2.1.1.18 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.2.1.1.19 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.2.1.1.20 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.1.21 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.1.22 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.1.23 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.2.1.1.24 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.2.1.1.25 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.1.26 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.2.1.1.27 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.2.1.1.28 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.2.1.1.29 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.1.30 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.1.31 - NEW_CHECK - azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3
- [x] pci_4.0_azure 10.2.1.1.32 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.1.33 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.1.34 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.1.35 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.1.1.36 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.1.1.37 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.2.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.2.1.2.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.2.1.2.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.2.1.2.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.2.1.2.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.2.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.2.1.2.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.2.1.2.8 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.2.9 - MANUAL - none
- [x] pci_4.0_azure 10.2.1.2.10 - MANUAL - none
- [ ] pci_4.0_azure 10.2.1.2.11 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.2.1.2.12 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.2.1.2.13 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.2.1.2.14 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.2.1.2.15 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.2.1.2.16 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.2.1.2.17 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.2.18 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.2.19 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.2.20 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.2.1.2.21 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.2.1.2.22 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.2.23 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.2.1.2.24 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.2.1.2.25 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.2.1.2.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.2.27 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.2.28 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.2.29 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.2.30 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.1.2.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.3.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.2.1.3.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.2.1.3.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.2.1.3.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.2.1.3.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.3.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.2.1.3.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.2.1.3.8 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.3.9 - MANUAL - none
- [x] pci_4.0_azure 10.2.1.3.10 - MANUAL - none
- [ ] pci_4.0_azure 10.2.1.3.11 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.2.1.3.12 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.2.1.3.13 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.2.1.3.14 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.2.1.3.15 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.2.1.3.16 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.2.1.3.17 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.3.18 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.3.19 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.3.20 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.2.1.3.21 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.2.1.3.22 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.3.23 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.2.1.3.24 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.2.1.3.25 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.2.1.3.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.3.27 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.3.28 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.3.29 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.3.30 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.1.3.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.4.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.2.1.4.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.2.1.4.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.2.1.4.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.2.1.4.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.4.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.2.1.4.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.2.1.4.8 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.4.9 - MANUAL - none
- [x] pci_4.0_azure 10.2.1.4.10 - MANUAL - none
- [ ] pci_4.0_azure 10.2.1.4.11 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.2.1.4.12 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.2.1.4.13 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.2.1.4.14 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.2.1.4.15 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.2.1.4.16 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.2.1.4.17 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.4.18 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.4.19 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.4.20 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.2.1.4.21 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.2.1.4.22 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.4.23 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.2.1.4.24 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.2.1.4.25 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.2.1.4.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.4.27 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.4.28 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.4.29 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.4.30 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.1.4.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.5.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.2.1.5.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.2.1.5.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.2.1.5.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.2.1.5.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.5.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.2.1.5.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.2.1.5.8 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.5.9 - MANUAL - none
- [x] pci_4.0_azure 10.2.1.5.10 - MANUAL - none
- [ ] pci_4.0_azure 10.2.1.5.11 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.2.1.5.12 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.2.1.5.13 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.2.1.5.14 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.2.1.5.15 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.2.1.5.16 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.2.1.5.17 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.5.18 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.5.19 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.5.20 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.2.1.5.21 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.2.1.5.22 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.5.23 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.2.1.5.24 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.2.1.5.25 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.2.1.5.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.5.27 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.5.28 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.5.29 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.5.30 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.1.5.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.6.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.2.1.6.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.2.1.6.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.2.1.6.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.2.1.6.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.6.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.2.1.6.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.2.1.6.8 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.6.9 - MANUAL - none
- [x] pci_4.0_azure 10.2.1.6.10 - MANUAL - none
- [ ] pci_4.0_azure 10.2.1.6.11 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.2.1.6.12 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.2.1.6.13 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.2.1.6.14 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.2.1.6.15 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.2.1.6.16 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.2.1.6.17 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.6.18 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.6.19 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.6.20 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.2.1.6.21 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.2.1.6.22 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.6.23 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.2.1.6.24 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.2.1.6.25 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.2.1.6.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.6.27 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.6.28 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.6.29 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.6.30 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.1.6.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.7.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.2.1.7.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.2.1.7.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.2.1.7.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.2.1.7.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.7.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.2.1.7.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.2.1.7.8 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.7.9 - MANUAL - none
- [x] pci_4.0_azure 10.2.1.7.10 - MANUAL - none
- [ ] pci_4.0_azure 10.2.1.7.11 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.2.1.7.12 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.2.1.7.13 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.2.1.7.14 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.2.1.7.15 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.2.1.7.16 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.2.1.7.17 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.7.18 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.7.19 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.7.20 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.2.1.7.21 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.2.1.7.22 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.7.23 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.2.1.7.24 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.2.1.7.25 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.2.1.7.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.7.27 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.7.28 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.7.29 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.7.30 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.1.7.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.2.1.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.2.1.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.2.1.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.2.1.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.2.1.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.2.1.8 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.9 - MANUAL - none
- [x] pci_4.0_azure 10.2.1.10 - MANUAL - none
- [ ] pci_4.0_azure 10.2.1.11 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.2.1.12 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.2.1.13 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.2.1.14 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.2.1.15 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.2.1.16 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.2.1.17 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.18 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.19 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.20 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.2.1.21 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.2.1.22 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.23 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.2.1.24 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.2.1.25 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.2.1.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.1.27 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.28 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.1.29 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.1.30 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.1.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.2.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.2.2.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.2.2.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.2.2.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.2.2.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.2.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.2.2.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.2.2.8 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.2.9 - MANUAL - none
- [x] pci_4.0_azure 10.2.2.10 - MANUAL - none
- [ ] pci_4.0_azure 10.2.2.11 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.2.2.12 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.2.2.13 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.2.2.14 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.2.2.15 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.2.2.16 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.2.2.17 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.2.18 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.2.19 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.2.20 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.2.2.21 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.2.2.22 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.2.23 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.2.2.24 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.2.2.25 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.2.2.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.2.2.27 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.2.28 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.2.2.29 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.2.2.30 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.2.2.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.1.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.3.1.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.3.1.3 - NEW_CHECK - azure_api_management_10_3_1_3_8a50dc0
- [ ] pci_4.0_azure 10.3.1.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.3.1.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.1.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.3.1.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.3.1.8 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.3.1.9 - MANUAL - none
- [x] pci_4.0_azure 10.3.1.10 - MANUAL - none
- [ ] pci_4.0_azure 10.3.1.11 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.3.1.12 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.3.1.13 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.3.1.14 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.3.1.15 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.3.1.16 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.3.1.17 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.1.18 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.1.19 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.1.20 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.3.1.21 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.3.1.22 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.1.23 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.3.1.24 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.3.1.25 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.3.1.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.1.27 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.1.28 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.1.29 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.3.1.30 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.1.31 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.2.1 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.2.2 - MANUAL - none
- [ ] pci_4.0_azure 10.3.2.3 - NEW_CHECK - azure_vault_10_3_2_3_922adc4
- [ ] pci_4.0_azure 10.3.2.4 - PARTIAL - azure.claude.activity_log_storage_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.3.2.5 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.2.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.2.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.2.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.2.9 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [x] pci_4.0_azure 10.3.2.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.2.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.2.12 - MANUAL - none
- [ ] pci_4.0_azure 10.3.2.13 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.3.2.14 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.2.15 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [x] pci_4.0_azure 10.3.2.16 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.2.17 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [x] pci_4.0_azure 10.3.2.18 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure 10.3.2.19 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.2.20 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.2.21 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.3.2.22 - MAPPING_FIX - azure.claude.storage_blob_soft_delete_enabled
- [ ] pci_4.0_azure 10.3.2.23 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.3.2.24 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.2.25 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [x] pci_4.0_azure 10.3.2.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.3.1 - NEW_CHECK - azure_recovery_vault_10_3_3_1_1f42f66
- [ ] pci_4.0_azure 10.3.3.2 - PARTIAL - azure.claude.recovery_vault_backup_retention_30_days, azure_recovery_vault_10_3_3_2_5313a3c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.3.3 - NEW_CHECK - azure_recovery_vault_10_3_3_3_45b190e
- [x] pci_4.0_azure 10.3.3.4 - MANUAL - none
- [ ] pci_4.0_azure 10.3.3.5 - NEW_CHECK - azure_vault_10_3_2_3_922adc4
- [ ] pci_4.0_azure 10.3.3.6 - PARTIAL - azure.claude.activity_log_storage_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.3.3.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.3.8 - NEW_CHECK - azure_recovery_vault_10_3_3_8_26e08d7
- [x] pci_4.0_azure 10.3.3.9 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.3.10 - MAPPING_FIX - azure.claude.cosmos_continuous_backup
- [x] pci_4.0_azure 10.3.3.11 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.3.12 - NEW_CHECK - azure_disk_10_3_3_12_174f526
- [ ] pci_4.0_azure 10.3.3.13 - NEW_CHECK - azure_disk_10_3_3_12_174f526
- [ ] pci_4.0_azure 10.3.3.14 - PARTIAL - azure.claude.vm_backup_protected (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.3.15 - NEW_CHECK - azure_storage_file_share_10_3_3_15_f2d7075
- [ ] pci_4.0_azure 10.3.3.16 - NEW_CHECK - azure_storage_file_share_10_3_3_15_f2d7075
- [ ] pci_4.0_azure 10.3.3.17 - NEW_CHECK - azure_redis_cache_10_3_3_17_5912e19
- [ ] pci_4.0_azure 10.3.3.18 - NEW_CHECK - azure_storage_file_share_10_3_3_18_d67ab34
- [ ] pci_4.0_azure 10.3.3.19 - NEW_CHECK - azure_storage_file_share_10_3_3_18_d67ab34
- [x] pci_4.0_azure 10.3.3.20 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.3.3.21 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.3.22 - NEW_CHECK - azure_synapse_workspace_10_3_3_22_15e4d4e
- [ ] pci_4.0_azure 10.3.3.23 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.3.24 - NEW_CHECK - azure_storage_account_10_3_3_24_61d5e36
- [ ] pci_4.0_azure 10.3.4.1 - NEW_CHECK - azure_cdn_profile_10_3_4_1_4e40487
- [ ] pci_4.0_azure 10.3.4.2 - NEW_CHECK - azure_cdn_profile_10_3_4_1_4e40487
- [x] pci_4.0_azure 10.3.4.3 - MANUAL - none
- [ ] pci_4.0_azure 10.3.4.4 - NEW_CHECK - azure_vault_10_3_2_3_922adc4
- [ ] pci_4.0_azure 10.3.4.5 - PARTIAL - azure.claude.activity_log_storage_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.3.4.6 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.3.4.7 - NEW_CHECK - azure_storage_account_10_3_4_7_02943e9
- [ ] pci_4.0_azure 10.3.4.8 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.3.4.9 - PARTIAL - azure.storage.blob_versioning (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.4.1.1.1 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.4.1.1.2 - NEW_CHECK - azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa
- [ ] pci_4.0_azure 10.4.1.1.3 - PARTIAL - azure.claude.subscription_diagnostic_setting_any_categories, azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.4.1.1.4 - NEW_CHECK - azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679
- [ ] pci_4.0_azure 10.4.1.1.5 - NEW_CHECK - azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3
- [x] pci_4.0_azure 10.4.1.1.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.4.1.1.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.4.1.1 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.4.1.2 - NEW_CHECK - azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa
- [ ] pci_4.0_azure 10.4.1.3 - NEW_CHECK - azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679
- [ ] pci_4.0_azure 10.4.1.4 - NEW_CHECK - azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3
- [x] pci_4.0_azure 10.4.1.5 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.4.1.6 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.4.2.1 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.4.2.2 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure 10.4.2.3 - NEW_CHECK - azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa
- [ ] pci_4.0_azure 10.4.2.4 - NEW_CHECK - azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679
- [ ] pci_4.0_azure 10.4.2.5 - NEW_CHECK - azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3
- [x] pci_4.0_azure 10.4.2.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.4.2.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.4.3.1 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure 10.5.1.1 - PARTIAL - azure.claude.recovery_vault_backup_retention_30_days, azure_recovery_vault_10_3_3_2_5313a3c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.5.1.2 - NEW_CHECK - azure_recovery_vault_10_3_3_3_45b190e
- [x] pci_4.0_azure 10.5.1.3 - MANUAL - none
- [ ] pci_4.0_azure 10.5.1.4 - NEW_CHECK - azure_log_analytics_workspace_10_5_1_4_8c74ccb
- [ ] pci_4.0_azure 10.5.1.5 - NEW_CHECK - azure_cosmos_account_10_5_1_5_2029065
- [x] pci_4.0_azure 10.5.1.6 - MAPPING_FIX - azure.claude.cosmos_continuous_backup
- [ ] pci_4.0_azure 10.5.1.7 - NEW_CHECK - azure_vm_vm_ensure_using_managed_disks_11f205b
- [x] pci_4.0_azure 10.5.1.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.5.1.9 - PARTIAL - azure.claude.search_service_logging_enabled (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.5.1.10 - PARTIAL - azure.claude.search_service_logging_enabled (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.5.1.11 - PARTIAL - azure.claude.search_service_logging_enabled (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.5.1.12 - NEW_CHECK - azure.other.storage_lifecycle
- [ ] pci_4.0_azure 10.5.1.13 - NEW_CHECK - azure_storage_account_10_5_1_13_2f5d4f6
- [ ] pci_4.0_azure 10.6.3.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 10.6.3.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 10.6.3.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 10.6.3.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 10.6.3.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.6.3.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 10.6.3.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [ ] pci_4.0_azure 10.6.3.8 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure 10.6.3.9 - NEW_CHECK - azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa
- [ ] pci_4.0_azure 10.6.3.10 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.6.3.11 - MANUAL - none
- [x] pci_4.0_azure 10.6.3.12 - MANUAL - none
- [ ] pci_4.0_azure 10.6.3.13 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 10.6.3.14 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 10.6.3.15 - NEW_CHECK - azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679
- [ ] pci_4.0_azure 10.6.3.16 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 10.6.3.17 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 10.6.3.18 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 10.6.3.19 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 10.6.3.20 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 10.6.3.21 - NEW_CHECK - azure_directory_user_10_6_3_21_d013932
- [ ] pci_4.0_azure 10.6.3.22 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.6.3.23 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.6.3.24 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.6.3.25 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 10.6.3.26 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 10.6.3.27 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 10.6.3.28 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.6.3.29 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 10.6.3.30 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 10.6.3.31 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 10.6.3.32 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.6.3.33 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.6.3.34 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.6.3.35 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [ ] pci_4.0_azure 10.6.3.36 - NEW_CHECK - azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3
- [x] pci_4.0_azure 10.6.3.37 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.6.3.38 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 10.6.3.39 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 10.6.3.40 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.6.3.41 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.6.3.42 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.7.1.1 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [x] pci_4.0_azure 10.7.1.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.7.1.3 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure 10.7.1.4 - NEW_CHECK - azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa
- [ ] pci_4.0_azure 10.7.1.5 - NEW_CHECK - azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679
- [ ] pci_4.0_azure 10.7.1.6 - NEW_CHECK - azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3
- [x] pci_4.0_azure 10.7.1.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.7.1.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.7.2.1 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [x] pci_4.0_azure 10.7.2.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 10.7.2.3 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure 10.7.2.4 - NEW_CHECK - azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa
- [ ] pci_4.0_azure 10.7.2.5 - NEW_CHECK - azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679
- [ ] pci_4.0_azure 10.7.2.6 - NEW_CHECK - azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3
- [x] pci_4.0_azure 10.7.2.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 10.7.2.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 11.3.1.1.1 - MANUAL - none
- [ ] pci_4.0_azure 11.3.1.1.2 - NEW_CHECK - azure.gap.compute_vm_system_updates_installed
- [x] pci_4.0_azure 11.3.1.2.1 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 11.3.1.3.1 - MANUAL - none
- [ ] pci_4.0_azure 11.3.1.3.2 - NEW_CHECK - azure.gap.compute_vm_system_updates_installed
- [x] pci_4.0_azure 11.3.1.3.3 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 11.3.1.1 - MANUAL - none
- [ ] pci_4.0_azure 11.3.1.2 - NEW_CHECK - azure.gap.compute_vm_system_updates_installed
- [x] pci_4.0_azure 11.3.1.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 11.5.1.1.1 - PARTIAL - azure.network.ddos_configured, azure_application_gateway_11_5_1_1_1_f56bdc2 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 11.5.1.1.2 - PARTIAL - azure.port.security_center_defender_for_cloudposture_enabled, azure.defender.standard_tier (manual or proposed evidence pending)
- [ ] pci_4.0_azure 11.5.1.1 - PARTIAL - azure.network.ddos_configured, azure_application_gateway_11_5_1_1_1_f56bdc2 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 11.5.1.2 - PARTIAL - azure.port.security_center_defender_for_cloudposture_enabled, azure.defender.standard_tier (manual or proposed evidence pending)
- [x] pci_4.0_azure 11.5.2.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 11.5.2.2 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure 11.5.2.3 - NEW_CHECK - azure_diagnostic_setting_11_5_2_3_7959930
- [ ] pci_4.0_azure 11.5.2.4 - PARTIAL - azure.claude.subscription_diagnostic_setting_any_categories, azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b (manual or proposed evidence pending)
- [ ] pci_4.0_azure 11.5.2.5 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9
- [x] pci_4.0_azure 11.5.2.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 11.6.1.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 11.6.1.2 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure 11.6.1.3 - NEW_CHECK - azure_diagnostic_setting_11_5_2_3_7959930
- [ ] pci_4.0_azure 11.6.1.4 - PARTIAL - azure.claude.subscription_diagnostic_setting_any_categories, azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b (manual or proposed evidence pending)
- [ ] pci_4.0_azure 11.6.1.5 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9
- [x] pci_4.0_azure 11.6.1.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 12.10.5.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 12.10.5.2 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure 12.10.5.3 - NEW_CHECK - azure_diagnostic_setting_11_5_2_3_7959930
- [ ] pci_4.0_azure 12.10.5.4 - PARTIAL - azure.claude.subscription_diagnostic_setting_any_categories, azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b (manual or proposed evidence pending)
- [ ] pci_4.0_azure 12.10.5.5 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9
- [x] pci_4.0_azure 12.10.5.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 12.4.2.1.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 2.2.5.1 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7
- [x] pci_4.0_azure 2.2.5.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 2.2.5.3 - NEW_CHECK - azure_frontdoor_app_minimum_tls_version_12_0512053
- [ ] pci_4.0_azure 2.2.5.4 - NEW_CHECK - azure_frontdoor_1_2_5_4_ccc7b8f
- [ ] pci_4.0_azure 2.2.5.5 - NEW_CHECK - azure_frontdoor_network_http_internet_access_restricted_7004685
- [ ] pci_4.0_azure 2.2.5.6 - NEW_CHECK - azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9
- [x] pci_4.0_azure 2.2.5.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 2.2.5.8 - NEW_CHECK - azure_application_gateway_1_2_5_8_33a9d21
- [ ] pci_4.0_azure 2.2.5.9 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17
- [ ] pci_4.0_azure 2.2.5.10 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63
- [ ] pci_4.0_azure 2.2.5.11 - NEW_CHECK - azure_hdinsight_cluster_1_2_5_11_babfa1b
- [x] pci_4.0_azure 2.2.5.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 2.2.5.13 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 2.2.5.14 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 2.2.5.15 - MAPPED - azure.storage.https_only
- [x] pci_4.0_azure 2.2.5.16 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 2.2.5.17 - NEW_CHECK - azure_nsg_world_ingress_approved_ports
- [ ] pci_4.0_azure 2.2.7.1 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7
- [x] pci_4.0_azure 2.2.7.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 2.2.7.3 - NEW_CHECK - azure_frontdoor_network_http_internet_access_restricted_7004685
- [ ] pci_4.0_azure 2.2.7.4 - NEW_CHECK - azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9
- [x] pci_4.0_azure 2.2.7.5 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 2.2.7.6 - MANUAL - none
- [x] pci_4.0_azure 2.2.7.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 2.2.7.8 - MAPPING_FIX - azure.port.redis_cache_ssl_enabled
- [x] pci_4.0_azure 2.2.7.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 2.2.7.10 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 2.2.7.11 - NEW_CHECK - azure_application_gateway_1_2_5_8_33a9d21
- [ ] pci_4.0_azure 2.2.7.12 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17
- [ ] pci_4.0_azure 2.2.7.13 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63
- [ ] pci_4.0_azure 2.2.7.14 - NEW_CHECK - azure_hdinsight_cluster_1_2_5_11_babfa1b
- [x] pci_4.0_azure 2.2.7.15 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 2.2.7.16 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 2.2.7.17 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 2.2.7.18 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 2.2.7.19 - MAPPED - azure.storage.https_only
- [ ] pci_4.0_azure 3.2.1.1 - PARTIAL - azure.claude.recovery_vault_backup_retention_30_days, azure_recovery_vault_10_3_3_2_5313a3c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.2.1.2 - NEW_CHECK - azure_recovery_vault_10_3_3_3_45b190e
- [ ] pci_4.0_azure 3.2.1.3 - NEW_CHECK - azure_log_analytics_workspace_10_5_1_4_8c74ccb
- [ ] pci_4.0_azure 3.2.1.4 - NEW_CHECK - azure_cosmos_account_10_5_1_5_2029065
- [x] pci_4.0_azure 3.2.1.5 - MAPPING_FIX - azure.claude.cosmos_continuous_backup
- [ ] pci_4.0_azure 3.2.1.6 - NEW_CHECK - azure_vm_vm_ensure_using_managed_disks_11f205b
- [x] pci_4.0_azure 3.2.1.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.2.1.8 - NEW_CHECK - azure.other.storage_lifecycle
- [ ] pci_4.0_azure 3.2.1.9 - NEW_CHECK - azure_storage_account_10_5_1_13_2f5d4f6
- [ ] pci_4.0_azure 3.3.1.1.1 - PARTIAL - azure.claude.recovery_vault_backup_retention_30_days, azure_recovery_vault_10_3_3_2_5313a3c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.3.1.1.2 - NEW_CHECK - azure_recovery_vault_10_3_3_3_45b190e
- [ ] pci_4.0_azure 3.3.1.1.3 - NEW_CHECK - azure_log_analytics_workspace_10_5_1_4_8c74ccb
- [ ] pci_4.0_azure 3.3.1.1.4 - NEW_CHECK - azure_cosmos_account_10_5_1_5_2029065
- [x] pci_4.0_azure 3.3.1.1.5 - MAPPING_FIX - azure.claude.cosmos_continuous_backup
- [ ] pci_4.0_azure 3.3.1.1.6 - NEW_CHECK - azure_vm_vm_ensure_using_managed_disks_11f205b
- [x] pci_4.0_azure 3.3.1.1.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.3.1.1.8 - NEW_CHECK - azure.other.storage_lifecycle
- [ ] pci_4.0_azure 3.3.1.1.9 - NEW_CHECK - azure_storage_account_10_5_1_13_2f5d4f6
- [ ] pci_4.0_azure 3.3.1.3.1 - PARTIAL - azure.claude.recovery_vault_backup_retention_30_days, azure_recovery_vault_10_3_3_2_5313a3c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.3.1.3.2 - NEW_CHECK - azure_recovery_vault_10_3_3_3_45b190e
- [ ] pci_4.0_azure 3.3.1.3.3 - NEW_CHECK - azure_log_analytics_workspace_10_5_1_4_8c74ccb
- [ ] pci_4.0_azure 3.3.1.3.4 - NEW_CHECK - azure_cosmos_account_10_5_1_5_2029065
- [x] pci_4.0_azure 3.3.1.3.5 - MAPPING_FIX - azure.claude.cosmos_continuous_backup
- [ ] pci_4.0_azure 3.3.1.3.6 - NEW_CHECK - azure_vm_vm_ensure_using_managed_disks_11f205b
- [x] pci_4.0_azure 3.3.1.3.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.3.1.3.8 - NEW_CHECK - azure.other.storage_lifecycle
- [ ] pci_4.0_azure 3.3.1.3.9 - NEW_CHECK - azure_storage_account_10_5_1_13_2f5d4f6
- [ ] pci_4.0_azure 3.3.2.1 - PARTIAL - azure.claude.recovery_vault_backup_retention_30_days, azure_recovery_vault_10_3_3_2_5313a3c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.3.2.2 - NEW_CHECK - azure_recovery_vault_10_3_3_3_45b190e
- [ ] pci_4.0_azure 3.3.2.3 - NEW_CHECK - azure_log_analytics_workspace_10_5_1_4_8c74ccb
- [ ] pci_4.0_azure 3.3.2.4 - NEW_CHECK - azure_cosmos_account_10_5_1_5_2029065
- [x] pci_4.0_azure 3.3.2.5 - MAPPING_FIX - azure.claude.cosmos_continuous_backup
- [ ] pci_4.0_azure 3.3.2.6 - NEW_CHECK - azure_vm_vm_ensure_using_managed_disks_11f205b
- [x] pci_4.0_azure 3.3.2.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.3.2.8 - NEW_CHECK - azure.other.storage_lifecycle
- [ ] pci_4.0_azure 3.3.2.9 - NEW_CHECK - azure_storage_account_10_5_1_13_2f5d4f6
- [ ] pci_4.0_azure 3.3.3.1 - PARTIAL - azure.claude.recovery_vault_backup_retention_30_days, azure_recovery_vault_10_3_3_2_5313a3c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.3.3.2 - NEW_CHECK - azure_recovery_vault_10_3_3_3_45b190e
- [ ] pci_4.0_azure 3.3.3.3 - NEW_CHECK - azure_log_analytics_workspace_10_5_1_4_8c74ccb
- [ ] pci_4.0_azure 3.3.3.4 - NEW_CHECK - azure_cosmos_account_10_5_1_5_2029065
- [x] pci_4.0_azure 3.3.3.5 - MAPPING_FIX - azure.claude.cosmos_continuous_backup
- [ ] pci_4.0_azure 3.3.3.6 - NEW_CHECK - azure_vm_vm_ensure_using_managed_disks_11f205b
- [x] pci_4.0_azure 3.3.3.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.3.3.8 - NEW_CHECK - azure.other.storage_lifecycle
- [ ] pci_4.0_azure 3.3.3.9 - NEW_CHECK - azure_storage_account_10_5_1_13_2f5d4f6
- [ ] pci_4.0_azure 3.5.1.1.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.5.1.1.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.1.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.1.4 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.5.1.1.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.1.6 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.5.1.1.7 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.5.1.1.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.1.9 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.5.1.3.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.5.1.3.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.3.3 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.3.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.3.5 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.5.1.3.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.3.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.3.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.3.9 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [x] pci_4.0_azure 3.5.1.3.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.3.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.3.12 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.3.13 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [x] pci_4.0_azure 3.5.1.3.14 - MANUAL - none
- [ ] pci_4.0_azure 3.5.1.3.15 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.5.1.3.16 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.3.17 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.5.1.3.18 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.5.1.3.19 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.3.20 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [x] pci_4.0_azure 3.5.1.3.21 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.3.22 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [x] pci_4.0_azure 3.5.1.3.23 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure 3.5.1.3.24 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.5.1.3.25 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.5.1.3.26 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.5.1.3.27 - MAPPING_FIX - azure.claude.storage_blob_soft_delete_enabled
- [ ] pci_4.0_azure 3.5.1.3.28 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.5.1.3.29 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.3.30 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [x] pci_4.0_azure 3.5.1.3.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.1 - NEW_CHECK - azure_api_management_3_5_1_1_345bdac
- [ ] pci_4.0_azure 3.5.1.2 - PARTIAL - azure.claude.synapse_workspace_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.5.1.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.4 - NEW_CHECK - azure_vault_10_3_2_3_922adc4
- [ ] pci_4.0_azure 3.5.1.5 - PARTIAL - azure.claude.activity_log_storage_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.5.1.6 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.7 - NEW_CHECK - azure_devops_project_3_5_1_7_dc58423
- [x] pci_4.0_azure 3.5.1.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.9 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.13 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.14 - PARTIAL - azure.claude.container_group_secure_environment_variables, azure_aks_cluster_3_5_1_14_247ebcd (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.5.1.15 - NEW_CHECK - azure_storage_file_share_3_5_1_15_17dc7f4
- [ ] pci_4.0_azure 3.5.1.16 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_fc209e3
- [ ] pci_4.0_azure 3.5.1.17 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_fc209e3
- [x] pci_4.0_azure 3.5.1.18 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.19 - NEW_CHECK - azure_search_service_3_5_1_19_a3c75c0
- [ ] pci_4.0_azure 3.5.1.20 - PARTIAL - azure.claude.disk_attached_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.5.1.21 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.22 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.23 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.24 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.25 - PARTIAL - azure.sql.tde_enabled, azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5 (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.5.1.26 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.27 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.28 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [ ] pci_4.0_azure 3.5.1.29 - PARTIAL - azure.claude.synapse_workspace_cmk, azure_pci_3_5_1_29 (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.5.1.30 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.31 - PARTIAL - azure.claude.storage_account_cmk, azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3 (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.5.1.32 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.33 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.5.1.34 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.5.1.35 - PARTIAL - azure.claude.servicebus_premium_namespace_cmk (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.6.1.2.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.6.1.2.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.6.1.2.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.2.4 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.6.1.2.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.2.6 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.6.1.2.7 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.6.1.2.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.2.9 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.6.1.3.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.6.1.3.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.6.1.3.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.3.4 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.6.1.3.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.3.6 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.6.1.3.7 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.6.1.3.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.3.9 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.6.1.4.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.6.1.4.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.6.1.4.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.4.4 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.6.1.4.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.4.6 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.6.1.4.7 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.6.1.4.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.4.9 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.6.1.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.6.1.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.6.1.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.4 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.6.1.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.6 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.6.1.7 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.6.1.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.6.1.9 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.7.1.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [ ] pci_4.0_azure 3.7.1.2 - NEW_CHECK - azure_vault_3_7_1_2_532ecd2
- [x] pci_4.0_azure 3.7.1.3 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.7.1.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.1.5 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.7.1.6 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.1.7 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.7.1.8 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.7.1.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.1.10 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.7.2.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.7.2.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.7.2.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.2.4 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.7.2.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.2.6 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.7.2.7 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.7.2.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.2.9 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.7.4.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.7.4.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.7.4.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.4.4 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [ ] pci_4.0_azure 3.7.4.5 - PARTIAL - azure.claude.keyvault_key_rotation_policy, azure_pci_3_7_4_5 (manual or proposed evidence pending)
- [x] pci_4.0_azure 3.7.4.6 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.4.7 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.7.4.8 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.7.4.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.4.10 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.7.5.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [ ] pci_4.0_azure 3.7.5.2 - PARTIAL - azure.claude.keyvault_key_rotation_policy, azure_pci_3_7_4_5 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.7.6.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.7.6.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.7.6.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.6.4 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.7.6.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.6.6 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.7.6.7 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.7.6.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.6.9 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 3.7.7.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 3.7.7.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 3.7.7.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.7.4 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 3.7.7.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.7.6 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 3.7.7.7 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 3.7.7.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 3.7.7.9 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [ ] pci_4.0_azure 4.2.1.1.1 - NEW_CHECK - azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3
- [x] pci_4.0_azure 4.2.1.1.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 4.2.1.1.3 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7
- [x] pci_4.0_azure 4.2.1.1.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 4.2.1.1.5 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [x] pci_4.0_azure 4.2.1.1.6 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 4.2.1.1.7 - NEW_CHECK - azure_frontdoor_network_http_internet_access_restricted_7004685
- [ ] pci_4.0_azure 4.2.1.1.8 - NEW_CHECK - azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9
- [x] pci_4.0_azure 4.2.1.1.9 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.1.10 - MANUAL - none
- [x] pci_4.0_azure 4.2.1.1.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.1.12 - MAPPING_FIX - azure.port.redis_cache_ssl_enabled
- [x] pci_4.0_azure 4.2.1.1.13 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.1.14 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 4.2.1.1.15 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 4.2.1.1.16 - NEW_CHECK - azure_application_gateway_1_2_5_8_33a9d21
- [ ] pci_4.0_azure 4.2.1.1.17 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17
- [ ] pci_4.0_azure 4.2.1.1.18 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63
- [ ] pci_4.0_azure 4.2.1.1.19 - NEW_CHECK - azure_hdinsight_cluster_1_2_5_11_babfa1b
- [ ] pci_4.0_azure 4.2.1.1.20 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 4.2.1.1.21 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 4.2.1.1.22 - PARTIAL - azure.port.keyvault_with_non_rbac_key_expiration_set (manual or proposed evidence pending)
- [x] pci_4.0_azure 4.2.1.1.23 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.1.24 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.1.25 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.1.26 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.1.27 - MAPPED - azure.storage.https_only
- [ ] pci_4.0_azure 4.2.1.1 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7
- [x] pci_4.0_azure 4.2.1.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 4.2.1.3 - NEW_CHECK - azure_frontdoor_network_http_internet_access_restricted_7004685
- [ ] pci_4.0_azure 4.2.1.4 - NEW_CHECK - azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9
- [x] pci_4.0_azure 4.2.1.5 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.6 - MANUAL - none
- [x] pci_4.0_azure 4.2.1.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.8 - MAPPING_FIX - azure.port.redis_cache_ssl_enabled
- [x] pci_4.0_azure 4.2.1.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 4.2.1.10 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 4.2.1.11 - NEW_CHECK - azure_application_gateway_1_2_5_8_33a9d21
- [ ] pci_4.0_azure 4.2.1.12 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17
- [ ] pci_4.0_azure 4.2.1.13 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63
- [ ] pci_4.0_azure 4.2.1.14 - NEW_CHECK - azure_hdinsight_cluster_1_2_5_11_babfa1b
- [x] pci_4.0_azure 4.2.1.15 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.16 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.17 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.18 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 4.2.1.19 - MAPPED - azure.storage.https_only
- [ ] pci_4.0_azure 5.3.4.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure 5.3.4.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure 5.3.4.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure 5.3.4.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure 5.3.4.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 5.3.4.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure 5.3.4.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [x] pci_4.0_azure 5.3.4.8 - MANUAL - none
- [ ] pci_4.0_azure 5.3.4.9 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [x] pci_4.0_azure 5.3.4.10 - MANUAL - none
- [ ] pci_4.0_azure 5.3.4.11 - NEW_CHECK - azure_log_analytics_workspace_10_5_1_4_8c74ccb
- [x] pci_4.0_azure 5.3.4.12 - MANUAL - none
- [ ] pci_4.0_azure 5.3.4.13 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure 5.3.4.14 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure 5.3.4.15 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure 5.3.4.16 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure 5.3.4.17 - PARTIAL - azure.claude.search_service_logging_enabled (manual or proposed evidence pending)
- [ ] pci_4.0_azure 5.3.4.18 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure 5.3.4.19 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure 5.3.4.20 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 5.3.4.21 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure 5.3.4.22 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure 5.3.4.23 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure 5.3.4.24 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure 5.3.4.25 - PARTIAL - azure.claude.search_service_logging_enabled (manual or proposed evidence pending)
- [ ] pci_4.0_azure 5.3.4.26 - PARTIAL - azure.claude.search_service_logging_enabled (manual or proposed evidence pending)
- [ ] pci_4.0_azure 5.3.4.27 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 5.3.4.28 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure 5.3.4.29 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure 5.3.4.30 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure 5.3.4.31 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 5.3.4.32 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 5.3.4.33 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure 5.3.4.34 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure 5.3.4.35 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 5.3.4.36 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.3.3.1 - MANUAL - none
- [ ] pci_4.0_azure 6.3.3.2 - NEW_CHECK - azure.gap.compute_vm_system_updates_installed
- [x] pci_4.0_azure 6.3.3.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.3.3.4 - NEW_CHECK - azure_aks_cluster_6_3_3_4_98a0b2c
- [ ] pci_4.0_azure 6.3.3.5 - NEW_CHECK - azure_aks_cluster_6_3_3_4_98a0b2c
- [x] pci_4.0_azure 6.3.3.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.3.3.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.3.3.8 - NEW_CHECK - azure_app_service_app_function_latest_runtime_version_f50215a
- [x] pci_4.0_azure 6.3.3.9 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.3.3.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.3.3.11 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.4.1.1 - PARTIAL - azure.claude2.app_gateway_waf_enabled (manual or proposed evidence pending)
- [x] pci_4.0_azure 6.4.1.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.4.1.3 - NEW_CHECK - azure_api_management_1_2_8_3_e8fe737
- [ ] pci_4.0_azure 6.4.1.4 - PARTIAL - azure.claude.frontdoor_waf_policy_linked, azure_frontdoor_1_2_8_4_90159db (manual or proposed evidence pending)
- [ ] pci_4.0_azure 6.4.1.5 - PARTIAL - azure.claude2.app_gateway_waf_enabled, azure.claude.frontdoor_waf_policy_linked (manual or proposed evidence pending)
- [ ] pci_4.0_azure 6.4.1.6 - NEW_CHECK - azure_firewall_policy_6_4_1_6_2ad9039
- [ ] pci_4.0_azure 6.4.1.7 - NEW_CHECK - azure_firewall_policy_6_4_1_7_a7975fc
- [x] pci_4.0_azure 6.4.1.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.4.1.9 - NEW_CHECK - azure_firewall_policy_1_2_8_42_cacbd9e
- [x] pci_4.0_azure 6.4.1.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.4.1.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.4.1.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.4.1.13 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.4.1.14 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.4.2.1 - PARTIAL - azure.claude2.app_gateway_waf_enabled (manual or proposed evidence pending)
- [x] pci_4.0_azure 6.4.2.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.4.2.3 - NEW_CHECK - azure_api_management_1_2_8_3_e8fe737
- [ ] pci_4.0_azure 6.4.2.4 - PARTIAL - azure.claude.frontdoor_waf_policy_linked, azure_frontdoor_1_2_8_4_90159db (manual or proposed evidence pending)
- [ ] pci_4.0_azure 6.4.2.5 - PARTIAL - azure.claude2.app_gateway_waf_enabled, azure.claude.frontdoor_waf_policy_linked (manual or proposed evidence pending)
- [ ] pci_4.0_azure 6.4.2.6 - NEW_CHECK - azure_firewall_policy_6_4_1_6_2ad9039
- [ ] pci_4.0_azure 6.4.2.7 - NEW_CHECK - azure_firewall_policy_6_4_1_7_a7975fc
- [x] pci_4.0_azure 6.4.2.8 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.4.2.9 - NEW_CHECK - azure_firewall_policy_1_2_8_42_cacbd9e
- [x] pci_4.0_azure 6.4.2.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.4.2.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.4.2.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.4.2.13 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.4.2.14 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 6.5.5.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.5.5.2 - NEW_CHECK - azure_devops_project_6_5_5_2_2908a87
- [x] pci_4.0_azure 6.5.6.1 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 6.5.6.2 - NEW_CHECK - azure_devops_project_6_5_5_2_2908a87
- [ ] pci_4.0_azure 7.2.1.1 - NEW_CHECK - azure_management_group_7_2_1_1_af95df1
- [x] pci_4.0_azure 7.2.1.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.1.3 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.1.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.1.5 - NEW_CHECK - azure_vm_app_function_identity_is_configured_bdb10d4
- [ ] pci_4.0_azure 7.2.1.6 - NEW_CHECK - azure_aks_cluster_7_2_1_6_93c4fab
- [ ] pci_4.0_azure 7.2.1.7 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 7.2.1.8 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_db12524
- [ ] pci_4.0_azure 7.2.1.9 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 7.2.1.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.1.11 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.1.12 - NEW_CHECK - azure_management_group_7_2_1_12_3f8ec01
- [ ] pci_4.0_azure 7.2.1.13 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [ ] pci_4.0_azure 7.2.1.14 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.2.1.15 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd
- [ ] pci_4.0_azure 7.2.1.16 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_675305a
- [x] pci_4.0_azure 7.2.1.17 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.1.18 - NEW_CHECK - azure_directory_user_10_6_3_21_d013932
- [ ] pci_4.0_azure 7.2.1.19 - NEW_CHECK - azure_directory_user_7_2_1_19_28e2aa7
- [ ] pci_4.0_azure 7.2.1.20 - PARTIAL - azure.claude.postgresql_flexible_entra_authentication, azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.2.1.21 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 7.2.1.22 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.2.1.23 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [x] pci_4.0_azure 7.2.1.24 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.1.25 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.1.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.1.27 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [x] pci_4.0_azure 7.2.1.28 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.1.29 - MANUAL - none
- [ ] pci_4.0_azure 7.2.2.1 - NEW_CHECK - azure_management_group_7_2_1_1_af95df1
- [x] pci_4.0_azure 7.2.2.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.2.3 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.2.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.2.5 - NEW_CHECK - azure_vm_app_function_identity_is_configured_bdb10d4
- [ ] pci_4.0_azure 7.2.2.6 - NEW_CHECK - azure_aks_cluster_7_2_1_6_93c4fab
- [ ] pci_4.0_azure 7.2.2.7 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 7.2.2.8 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_db12524
- [ ] pci_4.0_azure 7.2.2.9 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 7.2.2.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.2.11 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.2.12 - NEW_CHECK - azure_management_group_7_2_1_12_3f8ec01
- [ ] pci_4.0_azure 7.2.2.13 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [ ] pci_4.0_azure 7.2.2.14 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.2.2.15 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd
- [ ] pci_4.0_azure 7.2.2.16 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_675305a
- [x] pci_4.0_azure 7.2.2.17 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.2.18 - NEW_CHECK - azure_directory_user_10_6_3_21_d013932
- [ ] pci_4.0_azure 7.2.2.19 - NEW_CHECK - azure_directory_user_7_2_1_19_28e2aa7
- [ ] pci_4.0_azure 7.2.2.20 - PARTIAL - azure.claude.postgresql_flexible_entra_authentication, azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.2.2.21 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 7.2.2.22 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.2.2.23 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [x] pci_4.0_azure 7.2.2.24 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.2.25 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.2.26 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.2.27 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [x] pci_4.0_azure 7.2.2.28 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.2.29 - MANUAL - none
- [x] pci_4.0_azure 7.2.3.1 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.3.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.3.3 - NEW_CHECK - azure_aks_cluster_7_2_1_6_93c4fab
- [ ] pci_4.0_azure 7.2.3.4 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_db12524
- [ ] pci_4.0_azure 7.2.3.5 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 7.2.3.6 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.3.7 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [x] pci_4.0_azure 7.2.3.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.3.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.4.1 - NEW_CHECK - azure_directory_user_7_2_4_1_712ef31
- [ ] pci_4.0_azure 7.2.4.2 - NEW_CHECK - azure_directory_user_7_2_4_2_7a90cfb
- [ ] pci_4.0_azure 7.2.4.3 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_0041351
- [ ] pci_4.0_azure 7.2.5.1.1 - NEW_CHECK - azure_directory_user_7_2_4_1_712ef31
- [ ] pci_4.0_azure 7.2.5.1.2 - NEW_CHECK - azure_directory_user_7_2_4_2_7a90cfb
- [ ] pci_4.0_azure 7.2.5.1.3 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_0041351
- [ ] pci_4.0_azure 7.2.5.1 - NEW_CHECK - azure_management_group_7_2_1_1_af95df1
- [x] pci_4.0_azure 7.2.5.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.5.3 - NEW_CHECK - azure_vm_app_function_identity_is_configured_bdb10d4
- [ ] pci_4.0_azure 7.2.5.4 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 7.2.5.5 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 7.2.5.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.5.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.5.8 - NEW_CHECK - azure_management_group_7_2_1_12_3f8ec01
- [ ] pci_4.0_azure 7.2.5.9 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [ ] pci_4.0_azure 7.2.5.10 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.2.5.11 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd
- [ ] pci_4.0_azure 7.2.5.12 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_675305a
- [ ] pci_4.0_azure 7.2.5.13 - NEW_CHECK - azure_directory_user_7_2_1_19_28e2aa7
- [ ] pci_4.0_azure 7.2.5.14 - PARTIAL - azure.claude.postgresql_flexible_entra_authentication, azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.2.5.15 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 7.2.5.16 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.2.5.17 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [x] pci_4.0_azure 7.2.5.18 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.5.19 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.2.5.20 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.5.21 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [x] pci_4.0_azure 7.2.5.22 - MANUAL - none
- [ ] pci_4.0_azure 7.2.6.1 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 7.2.6.2 - NEW_CHECK - azure_directory_user_10_6_3_21_d013932
- [ ] pci_4.0_azure 7.2.6.3 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [x] pci_4.0_azure 7.2.6.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.2.6.5 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [ ] pci_4.0_azure 7.3.1.1 - NEW_CHECK - azure_management_group_7_2_1_1_af95df1
- [x] pci_4.0_azure 7.3.1.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.3.1.3 - NEW_CHECK - azure_vm_app_function_identity_is_configured_bdb10d4
- [ ] pci_4.0_azure 7.3.1.4 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 7.3.1.5 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 7.3.1.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.3.1.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.3.1.8 - NEW_CHECK - azure_management_group_7_2_1_12_3f8ec01
- [ ] pci_4.0_azure 7.3.1.9 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [ ] pci_4.0_azure 7.3.1.10 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.3.1.11 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd
- [ ] pci_4.0_azure 7.3.1.12 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_675305a
- [ ] pci_4.0_azure 7.3.1.13 - NEW_CHECK - azure_directory_user_7_2_1_19_28e2aa7
- [ ] pci_4.0_azure 7.3.1.14 - PARTIAL - azure.claude.postgresql_flexible_entra_authentication, azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.3.1.15 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 7.3.1.16 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.3.1.17 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [x] pci_4.0_azure 7.3.1.18 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.3.1.19 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.3.1.20 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.3.1.21 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [x] pci_4.0_azure 7.3.1.22 - MANUAL - none
- [ ] pci_4.0_azure 7.3.2.1 - NEW_CHECK - azure_management_group_7_2_1_1_af95df1
- [x] pci_4.0_azure 7.3.2.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.3.2.3 - NEW_CHECK - azure_vm_app_function_identity_is_configured_bdb10d4
- [ ] pci_4.0_azure 7.3.2.4 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 7.3.2.5 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 7.3.2.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.3.2.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.3.2.8 - NEW_CHECK - azure_management_group_7_2_1_12_3f8ec01
- [ ] pci_4.0_azure 7.3.2.9 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [ ] pci_4.0_azure 7.3.2.10 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.3.2.11 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd
- [ ] pci_4.0_azure 7.3.2.12 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_675305a
- [ ] pci_4.0_azure 7.3.2.13 - NEW_CHECK - azure_directory_user_7_2_1_19_28e2aa7
- [ ] pci_4.0_azure 7.3.2.14 - PARTIAL - azure.claude.postgresql_flexible_entra_authentication, azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.3.2.15 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 7.3.2.16 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.3.2.17 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [x] pci_4.0_azure 7.3.2.18 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.3.2.19 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.3.2.20 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.3.2.21 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [x] pci_4.0_azure 7.3.2.22 - MANUAL - none
- [ ] pci_4.0_azure 7.3.3.1 - NEW_CHECK - azure_management_group_7_2_1_1_af95df1
- [x] pci_4.0_azure 7.3.3.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.3.3.3 - NEW_CHECK - azure_vm_app_function_identity_is_configured_bdb10d4
- [ ] pci_4.0_azure 7.3.3.4 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 7.3.3.5 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 7.3.3.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.3.3.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.3.3.8 - NEW_CHECK - azure_management_group_7_2_1_12_3f8ec01
- [ ] pci_4.0_azure 7.3.3.9 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [ ] pci_4.0_azure 7.3.3.10 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.3.3.11 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd
- [ ] pci_4.0_azure 7.3.3.12 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_675305a
- [ ] pci_4.0_azure 7.3.3.13 - NEW_CHECK - azure_directory_user_7_2_1_19_28e2aa7
- [ ] pci_4.0_azure 7.3.3.14 - PARTIAL - azure.claude.postgresql_flexible_entra_authentication, azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.3.3.15 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 7.3.3.16 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 7.3.3.17 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [x] pci_4.0_azure 7.3.3.18 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.3.3.19 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 7.3.3.20 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 7.3.3.21 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [x] pci_4.0_azure 7.3.3.22 - MANUAL - none
- [ ] pci_4.0_azure 8.2.1.1 - NEW_CHECK - azure_vm_8_2_1_1_712e1ad
- [ ] pci_4.0_azure 8.2.1.2 - NEW_CHECK - azure_directory_user_7_2_4_1_712ef31
- [ ] pci_4.0_azure 8.2.1.3 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [x] pci_4.0_azure 8.2.1.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.1.5 - NEW_CHECK - azure_directory_user_10_6_3_21_d013932
- [ ] pci_4.0_azure 8.2.2.1 - NEW_CHECK - azure_devops_project_3_5_1_7_dc58423
- [ ] pci_4.0_azure 8.2.2.2 - NEW_CHECK - azure_vm_8_2_1_1_712e1ad
- [ ] pci_4.0_azure 8.2.2.3 - PARTIAL - azure.claude.container_group_secure_environment_variables, azure_aks_cluster_3_5_1_14_247ebcd (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.2.2.4 - NEW_CHECK - azure_directory_user_7_2_4_1_712ef31
- [ ] pci_4.0_azure 8.2.2.5 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [x] pci_4.0_azure 8.2.2.6 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.2.7 - NEW_CHECK - azure_directory_user_10_6_3_21_d013932
- [x] pci_4.0_azure 8.2.2.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.2.2.9 - MANUAL - none
- [ ] pci_4.0_azure 8.2.2.10 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7
- [ ] pci_4.0_azure 8.2.2.11 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_0041351
- [ ] pci_4.0_azure 8.2.4.1 - NEW_CHECK - azure_vm_8_2_1_1_712e1ad
- [ ] pci_4.0_azure 8.2.4.2 - NEW_CHECK - azure_directory_user_7_2_4_1_712ef31
- [ ] pci_4.0_azure 8.2.4.3 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [x] pci_4.0_azure 8.2.4.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.4.5 - NEW_CHECK - azure_directory_user_10_6_3_21_d013932
- [ ] pci_4.0_azure 8.2.5.1 - NEW_CHECK - azure_vm_8_2_1_1_712e1ad
- [ ] pci_4.0_azure 8.2.5.2 - NEW_CHECK - azure_directory_user_7_2_4_1_712ef31
- [ ] pci_4.0_azure 8.2.5.3 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [x] pci_4.0_azure 8.2.5.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.5.5 - NEW_CHECK - azure_directory_user_10_6_3_21_d013932
- [ ] pci_4.0_azure 8.2.6.1 - NEW_CHECK - azure_directory_user_7_2_4_1_712ef31
- [ ] pci_4.0_azure 8.2.6.2 - NEW_CHECK - azure_directory_user_7_2_4_2_7a90cfb
- [ ] pci_4.0_azure 8.2.6.3 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_0041351
- [ ] pci_4.0_azure 8.2.7.1 - NEW_CHECK - azure_management_group_7_2_1_1_af95df1
- [x] pci_4.0_azure 8.2.7.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.7.3 - NEW_CHECK - azure_vm_app_function_identity_is_configured_bdb10d4
- [ ] pci_4.0_azure 8.2.7.4 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 8.2.7.5 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 8.2.7.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.2.7.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.7.8 - NEW_CHECK - azure_management_group_7_2_1_12_3f8ec01
- [ ] pci_4.0_azure 8.2.7.9 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [ ] pci_4.0_azure 8.2.7.10 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.2.7.11 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd
- [ ] pci_4.0_azure 8.2.7.12 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_675305a
- [ ] pci_4.0_azure 8.2.7.13 - NEW_CHECK - azure_directory_user_7_2_1_19_28e2aa7
- [ ] pci_4.0_azure 8.2.7.14 - PARTIAL - azure.claude.postgresql_flexible_entra_authentication, azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.2.7.15 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 8.2.7.16 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.2.7.17 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.2.7.18 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.2.7.19 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.2.7.20 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.7.21 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [x] pci_4.0_azure 8.2.7.22 - MANUAL - none
- [ ] pci_4.0_azure 8.2.8.1 - NEW_CHECK - azure_management_group_7_2_1_1_af95df1
- [x] pci_4.0_azure 8.2.8.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.2.8.3 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.2.8.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.8.5 - NEW_CHECK - azure_vm_app_function_identity_is_configured_bdb10d4
- [ ] pci_4.0_azure 8.2.8.6 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 8.2.8.7 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 8.2.8.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.2.8.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.8.10 - NEW_CHECK - azure_management_group_7_2_1_12_3f8ec01
- [ ] pci_4.0_azure 8.2.8.11 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [ ] pci_4.0_azure 8.2.8.12 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.2.8.13 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd
- [ ] pci_4.0_azure 8.2.8.14 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_675305a
- [ ] pci_4.0_azure 8.2.8.15 - NEW_CHECK - azure_directory_user_7_2_1_19_28e2aa7
- [ ] pci_4.0_azure 8.2.8.16 - PARTIAL - azure.claude.postgresql_flexible_entra_authentication, azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.2.8.17 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 8.2.8.18 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.2.8.19 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.2.8.20 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.2.8.21 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.2.8.22 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.2.8.23 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [x] pci_4.0_azure 8.2.8.24 - MANUAL - none
- [ ] pci_4.0_azure 8.3.10.1.1 - NEW_CHECK - azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28
- [x] pci_4.0_azure 8.3.10.1.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.10.1.3 - MANUAL - none
- [ ] pci_4.0_azure 8.3.10.1.4 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7
- [ ] pci_4.0_azure 8.3.11.1 - NEW_CHECK - azure_vm_8_2_1_1_712e1ad
- [ ] pci_4.0_azure 8.3.11.2 - NEW_CHECK - azure_directory_user_7_2_4_1_712ef31
- [ ] pci_4.0_azure 8.3.11.3 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [x] pci_4.0_azure 8.3.11.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.11.5 - NEW_CHECK - azure_directory_user_10_6_3_21_d013932
- [ ] pci_4.0_azure 8.3.2.1 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7
- [ ] pci_4.0_azure 8.3.2.2 - NEW_CHECK - azure_api_management_3_5_1_1_345bdac
- [ ] pci_4.0_azure 8.3.2.3 - PARTIAL - azure.claude.synapse_workspace_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.3.2.4 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.2.6 - NEW_CHECK - azure_frontdoor_network_http_internet_access_restricted_7004685
- [ ] pci_4.0_azure 8.3.2.7 - NEW_CHECK - azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9
- [ ] pci_4.0_azure 8.3.2.8 - NEW_CHECK - azure_vault_10_3_2_3_922adc4
- [ ] pci_4.0_azure 8.3.2.9 - PARTIAL - azure.claude.activity_log_storage_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.3.2.10 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.2.11 - NEW_CHECK - azure_devops_project_3_5_1_7_dc58423
- [x] pci_4.0_azure 8.3.2.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.13 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.14 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.15 - MANUAL - none
- [x] pci_4.0_azure 8.3.2.16 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.17 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.18 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.19 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.20 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.2.21 - PARTIAL - azure.claude.container_group_secure_environment_variables, azure_aks_cluster_3_5_1_14_247ebcd (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.3.2.22 - NEW_CHECK - azure_storage_file_share_3_5_1_15_17dc7f4
- [ ] pci_4.0_azure 8.3.2.23 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_fc209e3
- [ ] pci_4.0_azure 8.3.2.24 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_fc209e3
- [x] pci_4.0_azure 8.3.2.25 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.26 - MAPPING_FIX - azure.port.redis_cache_ssl_enabled
- [ ] pci_4.0_azure 8.3.2.27 - NEW_CHECK - azure_search_service_3_5_1_19_a3c75c0
- [x] pci_4.0_azure 8.3.2.28 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.2.29 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [ ] pci_4.0_azure 8.3.2.30 - NEW_CHECK - azure_application_gateway_1_2_5_8_33a9d21
- [ ] pci_4.0_azure 8.3.2.31 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17
- [ ] pci_4.0_azure 8.3.2.32 - NEW_CHECK - azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63
- [ ] pci_4.0_azure 8.3.2.33 - NEW_CHECK - azure_hdinsight_cluster_1_2_5_11_babfa1b
- [ ] pci_4.0_azure 8.3.2.34 - PARTIAL - azure.claude.disk_attached_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.3.2.35 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.36 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.37 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.38 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.39 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.40 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.41 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.2.42 - PARTIAL - azure.sql.tde_enabled, azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5 (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.3.2.43 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.44 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.2.45 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [ ] pci_4.0_azure 8.3.2.46 - PARTIAL - azure.claude.synapse_workspace_cmk, azure_pci_3_5_1_29 (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.3.2.47 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.48 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.49 - MAPPED - azure.storage.https_only
- [ ] pci_4.0_azure 8.3.2.50 - PARTIAL - azure.claude.storage_account_cmk, azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3 (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.3.2.51 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.52 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.2.53 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.2.54 - PARTIAL - azure.claude.servicebus_premium_namespace_cmk (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.3.4.1 - NEW_CHECK - azure_management_group_7_2_1_1_af95df1
- [x] pci_4.0_azure 8.3.4.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.4.3 - NEW_CHECK - azure_vm_app_function_identity_is_configured_bdb10d4
- [ ] pci_4.0_azure 8.3.4.4 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [ ] pci_4.0_azure 8.3.4.5 - NEW_CHECK - azure_vault_keyvault_rbac_enabled_0179c48
- [x] pci_4.0_azure 8.3.4.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.4.7 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.4.8 - NEW_CHECK - azure_management_group_7_2_1_12_3f8ec01
- [ ] pci_4.0_azure 8.3.4.9 - NEW_CHECK - azure_management_group_7_2_1_13_50babe4
- [ ] pci_4.0_azure 8.3.4.10 - PARTIAL - azure.iam.no_full_custom_role, azure_role_assignment_7_2_1_14_6743a56 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.3.4.11 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd
- [ ] pci_4.0_azure 8.3.4.12 - NEW_CHECK - azure_role_assignment_aks_cluster_rbac_enabled_675305a
- [ ] pci_4.0_azure 8.3.4.13 - NEW_CHECK - azure_directory_user_7_2_1_19_28e2aa7
- [ ] pci_4.0_azure 8.3.4.14 - PARTIAL - azure.claude.postgresql_flexible_entra_authentication, azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.3.4.15 - NEW_CHECK - azure_search_service_10_6_3_27_ba08488
- [ ] pci_4.0_azure 8.3.4.16 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.3.4.17 - PARTIAL - azure.claude.sql_server_entra_admin, azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9 (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.3.4.18 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.4.19 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.4.20 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.3.4.21 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f
- [x] pci_4.0_azure 8.3.4.22 - MANUAL - none
- [ ] pci_4.0_azure 8.3.5.1 - NEW_CHECK - azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28
- [x] pci_4.0_azure 8.3.5.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.5.3 - MANUAL - none
- [ ] pci_4.0_azure 8.3.5.4 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7
- [x] pci_4.0_azure 8.3.6.1 - MANUAL - none
- [ ] pci_4.0_azure 8.3.7.1 - NEW_CHECK - azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28
- [x] pci_4.0_azure 8.3.7.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.7.3 - MANUAL - none
- [ ] pci_4.0_azure 8.3.7.4 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7
- [ ] pci_4.0_azure 8.3.9.1 - NEW_CHECK - azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28
- [x] pci_4.0_azure 8.3.9.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.3.9.3 - MANUAL - none
- [ ] pci_4.0_azure 8.3.9.4 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7
- [ ] pci_4.0_azure 8.4.1.1 - PARTIAL - azure.claude.entra_non_privileged_user_mfa, azure.claude.entra_privileged_user_mfa, azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.4.1.2 - PARTIAL - azure.claude.entra_privileged_user_mfa (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.4.1.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.4.1.4 - PARTIAL - azure.claude.entra_privileged_user_mfa, azure_directory_user_entra_privileged_user_has_mfa_6f6d584 (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.4.1.5 - MAPPING_FIX - azure.claude.storage_blob_soft_delete_enabled
- [ ] pci_4.0_azure 8.4.2.1 - PARTIAL - azure.claude.entra_non_privileged_user_mfa, azure.claude.entra_privileged_user_mfa, azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.4.2.2 - PARTIAL - azure.claude.entra_privileged_user_mfa (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.4.2.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.4.2.4 - PARTIAL - azure.claude.entra_privileged_user_mfa, azure_directory_user_entra_privileged_user_has_mfa_6f6d584 (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.4.2.5 - MAPPING_FIX - azure.claude.storage_blob_soft_delete_enabled
- [ ] pci_4.0_azure 8.4.3.1 - PARTIAL - azure.claude.entra_non_privileged_user_mfa, azure.claude.entra_privileged_user_mfa, azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9 (manual or proposed evidence pending)
- [ ] pci_4.0_azure 8.4.3.2 - PARTIAL - azure.claude.entra_privileged_user_mfa (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.4.3.3 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure 8.4.3.4 - PARTIAL - azure.claude.entra_privileged_user_mfa, azure_directory_user_entra_privileged_user_has_mfa_6f6d584 (manual or proposed evidence pending)
- [x] pci_4.0_azure 8.4.3.5 - MAPPING_FIX - azure.claude.storage_blob_soft_delete_enabled
- [ ] pci_4.0_azure 8.6.3.1 - NEW_CHECK - azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28
- [x] pci_4.0_azure 8.6.3.2 - MANUAL - none
- [x] pci_4.0_azure 8.6.3.3 - NOT_APPLICABLE - none
- [x] pci_4.0_azure 8.6.3.4 - MANUAL - none
- [ ] pci_4.0_azure 8.6.3.5 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7
- [x] pci_4.0_azure A1.1.2.1 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.2.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.2.3 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.2.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.2.5 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [x] pci_4.0_azure A1.1.2.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.2.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.2.8 - MANUAL - none
- [ ] pci_4.0_azure A1.1.2.9 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure A1.1.2.10 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.2.11 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [x] pci_4.0_azure A1.1.2.12 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.2.13 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [x] pci_4.0_azure A1.1.2.14 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure A1.1.2.15 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.1.2.16 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.1.2.17 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure A1.1.2.18 - MAPPING_FIX - azure.claude.storage_blob_soft_delete_enabled
- [ ] pci_4.0_azure A1.1.2.19 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure A1.1.2.20 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.2.21 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [x] pci_4.0_azure A1.1.2.22 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.3.1 - NEW_CHECK - azure_api_management_1_2_8_1_ba319cf
- [x] pci_4.0_azure A1.1.3.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.3.3 - NEW_CHECK - azure_api_management_1_2_8_3_e8fe737
- [ ] pci_4.0_azure A1.1.3.4 - PARTIAL - azure.claude.frontdoor_waf_policy_linked, azure_frontdoor_1_2_8_4_90159db (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.1.3.5 - NEW_CHECK - azure_cdn_profile_1_2_8_5_ed953a0
- [ ] pci_4.0_azure A1.1.3.6 - NEW_CHECK - azure_devops_project_1_2_8_6_fb0e5a8
- [x] pci_4.0_azure A1.1.3.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.3.8 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.3.9 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.3.10 - NEW_CHECK - azure_vm_1_2_8_10_1bd35d0
- [x] pci_4.0_azure A1.1.3.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.3.12 - MAPPING_FIX - azure.aks.private_cluster
- [x] pci_4.0_azure A1.1.3.13 - MAPPING_FIX - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link
- [x] pci_4.0_azure A1.1.3.14 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.3.15 - NEW_CHECK - azure_application_gateway_app_client_certificates_on_fcca0b8
- [x] pci_4.0_azure A1.1.3.16 - MANUAL - none
- [ ] pci_4.0_azure A1.1.3.17 - PARTIAL - azure.gap.nsg_declared_internet_ssh (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.1.3.18 - NEW_CHECK - azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc
- [ ] pci_4.0_azure A1.1.3.19 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure A1.1.3.20 - MAPPED - azure.claude2.prowler_function_vnet_integration
- [ ] pci_4.0_azure A1.1.3.21 - PARTIAL - azure.gap.nsg_declared_internet_ssh, azure.gap.nsg_declared_internet_rdp (manual or proposed evidence pending)
- [x] pci_4.0_azure A1.1.3.22 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.3.23 - NEW_CHECK - azure_firewall_policy_1_2_8_23_59ad733
- [ ] pci_4.0_azure A1.1.3.24 - NEW_CHECK - azure_firewall_policy_1_2_8_24_cc7cb8a
- [ ] pci_4.0_azure A1.1.3.25 - NEW_CHECK - azure_route_table_network_http_internet_access_restricted_5cd2484
- [ ] pci_4.0_azure A1.1.3.26 - PARTIAL - azure.port.search_service_public_network_access_disabled, azure.port.search_service_uses_private_link (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.1.3.27 - NEW_CHECK - azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d
- [ ] pci_4.0_azure A1.1.3.28 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [ ] pci_4.0_azure A1.1.3.29 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [x] pci_4.0_azure A1.1.3.30 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure A1.1.3.31 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.1.3.32 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.1.3.33 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.1.3.34 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure A1.1.3.35 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.1.3.36 - NEW_CHECK - azure_ml_workspace_1_2_8_36_33f50db
- [ ] pci_4.0_azure A1.1.3.37 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [ ] pci_4.0_azure A1.1.3.38 - NEW_CHECK - azure_azure_resource_keyvault_private_endpoints_c3995a6
- [ ] pci_4.0_azure A1.1.3.39 - PARTIAL - azure.claude.nsg_associated_with_subnet, azure_pci_1_2_8_39 (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.1.3.40 - NEW_CHECK - azure_nsg_world_ingress_approved_ports
- [ ] pci_4.0_azure A1.1.3.41 - NEW_CHECK - azure_firewall_policy_1_2_8_42_cacbd9e
- [x] pci_4.0_azure A1.1.3.42 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.3.43 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.3.44 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.3.45 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.1.3.46 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.2.1.1 - NEW_CHECK - azure_api_management_app_http_logs_enabled_21c108d
- [ ] pci_4.0_azure A1.2.1.2 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9ef06db
- [ ] pci_4.0_azure A1.2.1.3 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [ ] pci_4.0_azure A1.2.1.4 - NEW_CHECK - azure_api_management_app_http_logs_enabled_9b3b56e
- [x] pci_4.0_azure A1.2.1.5 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.2.1.6 - NEW_CHECK - azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a
- [x] pci_4.0_azure A1.2.1.7 - MAPPING_FIX - azure.claude.storage_blob_diagnostic_logging
- [x] pci_4.0_azure A1.2.1.8 - MANUAL - none
- [ ] pci_4.0_azure A1.2.1.9 - NEW_CHECK - azure_vault_10_3_2_3_922adc4
- [ ] pci_4.0_azure A1.2.1.10 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.2.1.11 - PARTIAL - azure.claude.activity_log_storage_cmk (manual or proposed evidence pending)
- [x] pci_4.0_azure A1.2.1.12 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.2.1.13 - MANUAL - none
- [x] pci_4.0_azure A1.2.1.14 - MANUAL - none
- [ ] pci_4.0_azure A1.2.1.15 - NEW_CHECK - azure_cosmos_account_10_2_1_1_13_5c115b0
- [ ] pci_4.0_azure A1.2.1.16 - NEW_CHECK - azure_vnet_gateway_10_2_1_1_14_4189d89
- [ ] pci_4.0_azure A1.2.1.17 - NEW_CHECK - azure_pci_10_2_1_1_16
- [ ] pci_4.0_azure A1.2.1.18 - NEW_CHECK - azure_aks_cluster_10_2_1_1_17_885658f
- [ ] pci_4.0_azure A1.2.1.19 - NEW_CHECK - azure_diagnostic_setting_app_http_logs_enabled_d32e8e1
- [ ] pci_4.0_azure A1.2.1.20 - NEW_CHECK - azure_application_gateway_app_http_logs_enabled_2de0361
- [ ] pci_4.0_azure A1.2.1.21 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.2.1.22 - PARTIAL - azure.claude.servicebus_namespace_logging_enabled, azure_storage_account_10_2_1_1_20_5914d2c (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.2.1.23 - PARTIAL - azure.claude.subscription_diagnostic_setting_categories (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.2.1.24 - NEW_CHECK - azure_cosmos_account_10_2_1_1_23_e04a63d
- [ ] pci_4.0_azure A1.2.1.25 - NEW_CHECK - azure_firewall_policy_10_2_1_1_24_0781f5f
- [ ] pci_4.0_azure A1.2.1.26 - PARTIAL - azure.claude.mysql_flexible_audit_log_enabled, azure_pci_10_2_1_1_25 (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.2.1.27 - NEW_CHECK - azure_sql_database_sqlserver_auditing_enabled_77d6841
- [ ] pci_4.0_azure A1.2.1.28 - NEW_CHECK - azure_storage_account_sqlserver_auditing_enabled_e4e4b28
- [ ] pci_4.0_azure A1.2.1.29 - NEW_CHECK - azure_synapse_workspace_10_2_1_1_28_47f4840
- [x] pci_4.0_azure A1.2.1.30 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A1.2.1.31 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.2.1.32 - PARTIAL - azure.claude.storage_blob_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.2.1.33 - PARTIAL - azure.claude.logic_app_workflow_diagnostic_logging (manual or proposed evidence pending)
- [ ] pci_4.0_azure A1.2.1.34 - PARTIAL - azure.claude2.vnet_flow_logs_to_log_analytics (manual or proposed evidence pending)
- [x] pci_4.0_azure A1.2.1.35 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.2.1.36 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A1.2.3.1 - MAPPED - azure.claude.defender_contact_has_email
- [ ] pci_4.0_azure A3.2.5.1.1 - NEW_CHECK - azure_purview_account_a3_2_5_1_1_282bac6
- [ ] pci_4.0_azure A3.2.5.1.2 - NEW_CHECK - azure_purview_account_a3_2_5_1_2_6690c25
- [ ] pci_4.0_azure A3.2.5.1.3 - NEW_CHECK - azure_purview_account_a3_2_5_1_1_282bac6
- [ ] pci_4.0_azure A3.2.5.1.4 - NEW_CHECK - azure_purview_account_a3_2_5_1_2_6690c25
- [ ] pci_4.0_azure A3.3.1.1 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [x] pci_4.0_azure A3.3.1.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A3.3.1.3 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure A3.3.1.4 - NEW_CHECK - azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa
- [ ] pci_4.0_azure A3.3.1.5 - NEW_CHECK - azure_diagnostic_setting_11_5_2_3_7959930
- [ ] pci_4.0_azure A3.3.1.6 - PARTIAL - azure.claude.subscription_diagnostic_setting_any_categories, azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b (manual or proposed evidence pending)
- [ ] pci_4.0_azure A3.3.1.7 - NEW_CHECK - azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679
- [ ] pci_4.0_azure A3.3.1.8 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9
- [ ] pci_4.0_azure A3.3.1.9 - NEW_CHECK - azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3
- [x] pci_4.0_azure A3.3.1.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A3.3.1.11 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A3.4.1.1 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A3.4.1.2 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A3.4.1.3 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A3.4.1.4 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A3.4.1.5 - NEW_CHECK - azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb
- [x] pci_4.0_azure A3.4.1.6 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A3.4.1.7 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A3.4.1.8 - MANUAL - none
- [ ] pci_4.0_azure A3.4.1.9 - NEW_CHECK - azure_directory_user_7_2_4_1_712ef31
- [ ] pci_4.0_azure A3.4.1.10 - NEW_CHECK - azure_directory_user_7_2_4_2_7a90cfb
- [ ] pci_4.0_azure A3.4.1.11 - PARTIAL - azure.claude2.prowler_function_not_public, azure_pci_1_2_8_19 (manual or proposed evidence pending)
- [x] pci_4.0_azure A3.4.1.12 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A3.4.1.13 - NEW_CHECK - azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a
- [x] pci_4.0_azure A3.4.1.14 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A3.4.1.15 - NEW_CHECK - azure_synapse_workspace_1_2_8_29_fcdc827
- [x] pci_4.0_azure A3.4.1.16 - MAPPED - azure.storage.no_blob_public_access
- [ ] pci_4.0_azure A3.4.1.17 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure A3.4.1.18 - PARTIAL - azure.storage.no_blob_public_access, azure_storage_account_storage_blob_public_access_level_is_disabled_4211794 (manual or proposed evidence pending)
- [ ] pci_4.0_azure A3.4.1.19 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure A3.4.1.20 - MAPPING_FIX - azure.claude.storage_blob_soft_delete_enabled
- [ ] pci_4.0_azure A3.4.1.21 - PARTIAL - azure.claude.storage_container_no_public_access (manual or proposed evidence pending)
- [x] pci_4.0_azure A3.4.1.22 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A3.4.1.23 - NEW_CHECK - azure_ml_workspace_1_2_8_37_973721f
- [ ] pci_4.0_azure A3.4.1.24 - NEW_CHECK - azure_vault_keyvault_non_rbac_secret_expiration_set_0041351
- [x] pci_4.0_azure A3.4.1.25 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A3.5.1.1 - NEW_CHECK - azure_api_management_appinsights_ensure_is_configured_42aac6a
- [x] pci_4.0_azure A3.5.1.2 - NOT_APPLICABLE - none
- [ ] pci_4.0_azure A3.5.1.3 - NEW_CHECK - azure_pci_10_2_1_1_8
- [ ] pci_4.0_azure A3.5.1.4 - NEW_CHECK - azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa
- [ ] pci_4.0_azure A3.5.1.5 - NEW_CHECK - azure_diagnostic_setting_11_5_2_3_7959930
- [ ] pci_4.0_azure A3.5.1.6 - PARTIAL - azure.claude.subscription_diagnostic_setting_any_categories, azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b (manual or proposed evidence pending)
- [ ] pci_4.0_azure A3.5.1.7 - NEW_CHECK - azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679
- [ ] pci_4.0_azure A3.5.1.8 - NEW_CHECK - azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9
- [ ] pci_4.0_azure A3.5.1.9 - NEW_CHECK - azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3
- [x] pci_4.0_azure A3.5.1.10 - NOT_APPLICABLE - none
- [x] pci_4.0_azure A3.5.1.11 - NOT_APPLICABLE - none
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_remote_access_restricted_all_ports - PARTIAL - azure.claude.vm_nic_nsg_internet_tcp_ingress, azure.gap.compute_vm_remote_access_restricted_all_ports (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.storage_account_default_network_access_rule_denied - PARTIAL - azure.storage.default_deny (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_external_user_with_owner_role - PARTIAL - azure.claude.iam_external_user_no_owner (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_external_user_with_read_permission - PARTIAL - azure.claude.iam_external_user_no_reader (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_external_user_with_write_permission - PARTIAL - azure.claude.iam_external_user_no_write (manual or proposed evidence pending)
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_no_custom_role - MAPPED - azure.claude.iam_no_custom_role
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_user_with_owner_permission_on_subscription_mfa_enabled - NEW_CHECK - azure_role_assignment_iam_user_with_owner_permission_on_subscription_mfa_enabled_8bf88f9
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_user_with_write_permission_on_subscription_mfa_enabled - NEW_CHECK - azure_role_assignment_iam_user_with_write_permission_on_subscription_mfa_enabled_d1806c1
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.sql_server_azure_ad_authentication_enabled - MAPPED - azure.claude.sql_server_entra_admin
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.appservice_api_app_use_https - MAPPED - azure.claude2.api_app_https_only
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.appservice_function_app_only_https_accessible - MAPPED - azure.app.https_only
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.automation_account_variable_encryption_enabled - MAPPED - azure.claude2.automation_variable_encrypted
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.redis_cache_ssl_enabled - MAPPED - azure.port.redis_cache_ssl_enabled
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_temp_disks_cache_and_data_flows_encrypted - PARTIAL - azure.vm.encryption_at_host (manual or proposed evidence pending)
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.servicefabric_cluster_protection_level_as_encrypt_and_sign - MAPPED - azure.claude.servicefabric_cluster_encrypt_and_sign
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.sql_database_transparent_data_encryption_enabled - MAPPED - azure.sql.tde_enabled
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.storage_account_secure_transfer_required_enabled - MAPPED - azure.storage.https_only
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_endpoint_protection_agent_installed - PARTIAL - azure.claude.defender_assessment_endpoint_protection (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_security_configuration_vulnerabilities_remediated - PARTIAL - azure.claude.vm_windows_security_baseline, azure.claude.vm_linux_security_baseline, azure_security_pricing_compute_vm_security_configuration_vulnerabilities_remediated_64c8b1c (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_system_updates_installed - PARTIAL - azure.claude.defender_assessment_system_updates (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_vulnerability_assessment_solution_enabled - PARTIAL - azure.claude.defender_assessment_vulnerability_solution (manual or proposed evidence pending)
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.sql_database_vulnerability_findings_resolved - MAPPED - azure.claude.sql_database_va_findings_resolved
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_subscription_owner_max_3 - PARTIAL - azure.claude.iam_subscription_owner_max_3 (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_subscription_owner_more_than_1 - PARTIAL - azure.claude.iam_subscription_owner_more_than_1 (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_deprecated_account_with_owner_roles - PARTIAL - azure.claude.iam_disabled_user_no_owner (manual or proposed evidence pending)
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.iam_deprecated_account - PARTIAL - azure.claude.iam_disabled_user_no_role_assignment (manual or proposed evidence pending)
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_guest_configuration_installed_windows - MAPPED - azure.claude.vm_guest_configuration_extension_windows
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_guest_configuration_with_no_managed_identity - PARTIAL - azure.claude.vm_guest_configuration_system_identity (manual or proposed evidence pending)
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_guest_configuration_with_user_and_system_assigned_managed_identity - MAPPED - azure.claude.vm_guest_configuration_user_and_system_identity
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_max_password_age_70_days_windows - MAPPED - azure.claude.vm_windows_max_password_age
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_min_password_length_14_windows - MAPPED - azure.claude.vm_windows_min_password_length
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_restrict_previous_24_passwords_resuse_windows - MAPPED - azure.claude.vm_windows_password_history
- [ ] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.audit_diagnostic_setting - PARTIAL - azure.claude.subscription_diagnostic_setting_any_categories (manual or proposed evidence pending)
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.compute_vm_uses_azure_resource_manager - NOT_APPLICABLE - none
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.sql_server_auditing_on - MAPPED - azure.sql.auditing
- [x] azure-compliance.benchmark.pci_dss_v321 azure-compliance.control.storage_account_uses_azure_resource_manager - NOT_APPLICABLE - none

## Proposed checks

### azure.gap.compute_vm_remote_access_restricted_all_ports

- Resource: vm
- Data source: Collected vm, nic, subnet and nsg items: NIC/subnet networkSecurityGroup.id and each associated NSG properties.securityRules/defaultSecurityRules (sourceAddressPrefix(es), destinationPortRange(s), protocol, access, priority).
- Predicate: For each VM-associated NIC and subnet NSG independently, evaluate inbound securityRules and defaultSecurityRules in priority order. FAIL if a complete effective rule path within either associated NSG permits any inbound traffic from Any, Internet, 0.0.0.0/0 or ::/0; a deny in the other NSG does not excuse the permissive associated NSG under the frozen rule. PASS only when every associated NSG is fully resolved and none has such an effective public allow. UNKNOWN for missing associations, unresolved service tags/ASGs, rule priorities, VM/NIC/subnet joins or incomplete inventories. If a VM has no associated NSG, report that as a separate unprotected-path signal and UNKNOWN for this NSG-rule control unless the source explicitly includes absence.

### azure.gap.compute_vm_system_updates_installed

- Resource: vm
- Data source: Paged VM inventory and each VM GET 2023-09-01 with $expand=instanceView: properties.instanceView.patchStatus.availablePatchSummary.status,lastModifiedTime,criticalAndSecurityPatchCount. For PCI references, collect Azure Update Manager patch-installation compliance state and correlate the exact VM and operation.
- Predicate: For the missing-security-updates references, PASS only on a fresh successful assessment with criticalAndSecurityPatchCount=0; FAIL on a fresh successful assessment with count>0. For PCI references, also require an exact VM post-installation COMPLIANT status; NON_COMPLIANT is FAIL. UNKNOWN if freshness threshold, status, count, PCI compliance record, VM join or inventory is missing; a zero available count alone cannot establish post-installation PCI compliance.

### azure.other.storage_lifecycle

- Resource: storage_account
- Data source: Existing azure.py storage_account.items[]; new managementPolicies/default GET 2023-05-01 per account. properties.policy.rules[].enabled boolean, type=Lifecycle, definition.filters.blobTypes/prefixMatch/blobIndexMatch, definition.actions.baseBlob.delete.daysAfterModificationGreaterThan; policy protected prefixes, minimum retention and maximum deletion days.
- Predicate: For every protected blockBlob prefix, PASS only if every applicable enabled delete rule respects minimum retention and at least one rule guarantees deletion by approved maximum. FAIL if an applicable rule can delete earlier or complete policy has no timely deletion. UNKNOWN if overlap, filters, creation/last-access predicates, version/snapshot protection, bounds or policy read cannot be resolved; a broad safe rule cannot mask an earlier overlapping rule.

### azure_aks_cluster_10_2_1_1_17_885658f

- Resource: aks_cluster
- Data source: ARM GET Microsoft.ContainerService/managedClusters; GET {clusterId}/providers/Microsoft.Insights/diagnosticSettingsCategories and /diagnosticSettings: properties.logs[].category/categoryGroup/enabled and destination IDs.
- Predicate: For each AKS cluster, enumerate the complete supported diagnostic log categories. PASS only if every supported log category is enabled in a diagnostic setting (directly or through allLogs) and routed to a valid workspace, Event Hub, or storage destination. FAIL if complete category and setting lists prove any supported log category is not exported. UNKNOWN if category support, settings, destination or enumeration is unresolved. No clusters is NOT_APPLICABLE.

### azure_aks_cluster_1_4_5_2_3ac7b3c

- Resource: container_group_and_aks_pod
- Data source: Paged Kubernetes core/v1 Pods LIST across every AKS namespace: items[].spec.hostPID (optional boolean, default false). Also enumerate policy-scoped ACI container groups; ARM 2023-05-01 has no equivalent hostPID setting, so obtain deployment/runtime evidence or mark ACI UNKNOWN.
- Predicate: FAIL if any observed in-scope AKS pod has spec.hostPID=true or equivalent ACI evidence shows host process sharing. PASS only if every in-scope AKS pod is false/omitted and every in-scope ACI group has equivalent verified non-sharing evidence. UNKNOWN if AKS pod/namespace/cluster paging or credentials are incomplete, or an in-scope ACI group has no equivalent evidence. Complete empty applicable inventory is NOT_APPLICABLE.

### azure_aks_cluster_3_5_1_14_247ebcd

- Resource: container_group_and_aks_pod
- Data source: NEW: paged Kubernetes core/v1 Pods across all namespaces and ARM ACI containerGroups GET 2023-05-01; Kubernetes env is spec.containers/initContainers/ephemeralContainers[].env[]; ACI is properties.containers[].properties.environmentVariables[] and GET can omit secureValue.
- Predicate: For every running Kubernetes container, initContainer and ephemeralContainer and every ACI container, compare environment variable names with policy secretKeys. FAIL when a matching key has a literal env.value (Kubernetes) or environmentVariables[].value (ACI), regardless of whether the literal looks secret. PASS only when complete workload evidence proves each matching key uses an approved secure reference (Kubernetes secretKeyRef or approved external secret provider; ACI secureValue or approved secure reference with independent configuration evidence). UNKNOWN for other unresolved valueFrom forms, masked ACI secureValue without independent secure-reference evidence, missing policy or incomplete paging. No matching keys with complete inventory is PASS.

### azure_aks_cluster_6_3_3_4_98a0b2c

- Resource: aks_cluster
- Data source: ARM managedClusters GET 2024-05-01 properties.kubernetesVersion and properties.supportPlan; ARM managedClusters availableOrchestratorVersions for cluster location; policy oldestVersionSupported and scan time.
- Predicate: Evaluate the two frozen PCI requirements separately for each AKS cluster using a dated regional support feed and policy oldestVersionSupported. For 6.3.3.4, FAIL when kubernetesVersion is equal to or older than oldestVersionSupported; PASS only when newer and current regional support for its support plan is verified. For 6.3.3.5, FAIL when kubernetesVersion is older than oldestVersionSupported; equality can PASS only when the regional feed confirms support. UNKNOWN for either result if policy threshold, complete version, region, support plan or current feed is unavailable.

### azure_aks_cluster_7_2_1_6_93c4fab

- Resource: aks_cluster
- Data source: New paged Kubernetes core/v1 Pods list across all namespaces of every AKS cluster; spec.containers[],initContainers[],ephemeralContainers[].securityContext.privileged boolean (omitted defaults false). Include RBAC/watch completeness and cluster association.
- Predicate: For every current AKS Pod container, including regular, init and ephemeral containers, FAIL if securityContext.privileged=true. PASS only with complete, consistent paged pod inventory showing false or omitted for every container; omitted defaults false. UNKNOWN for RBAC denial, missing namespace/pod pages, stale resourceVersion or incomplete cluster inventory. Empty complete present-pod set is PASS only for present pods; admission/template enforcement is unmeasured.

### azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb

- Resource: aks_pod
- Data source: Kubernetes apps/v1 Deployments, StatefulSets, DaemonSets; batch/v1 Jobs, CronJobs; core/v1 Pods: spec/template.spec.containers[], initContainers[] and Pod-only ephemeralContainers[] securityContext.readOnlyRootFilesystem.
- Predicate: For every current Pod and controller template (Deployment, StatefulSet, DaemonSet, Job, CronJob), FAIL when any regular/init/ephemeral container has readOnlyRootFilesystem absent or false; PASS if every applicable container explicitly has true; UNKNOWN if any API list page, namespace, template expansion or policy exception is unresolved. This checks root filesystem, not Kubernetes RBAC.

### azure_aks_cluster_aks_cluster_rbac_enabled_db12524

- Resource: aks_cluster
- Data source: Existing aks_cluster inventory; add paged Kubernetes /api/v1/pods list across all namespaces using resourceVersion/continue. Kubernetes Pod v1 schema: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.32/#pod-v1-core. Kubernetes core/v1 list_namespaced_pod (all namespaces): items[].spec.containers[].securityContext.runAsUser,pod.securityContext.runAsUser.
- Predicate: For each in-scope Linux AKS pod, inspect initContainers, containers and ephemeralContainers. Effective runAsUser is container override then pod securityContext; PASS only if every applicable container has an explicit effective nonzero integer UID. FAIL on explicit UID 0 or missing effective UID in a complete pod record. UNKNOWN on incomplete pod/namespace pages, unresolved node OS/applicability or invalid security context. Windows containers require separate user-name semantics and remain UNKNOWN until assessed; no applicable Linux pods is NOT_APPLICABLE. Aggregate FAIL before UNKNOWN.

### azure_aks_cluster_aks_cluster_rbac_enabled_fc209e3

- Resource: aks_cluster
- Data source: Collector peaso/collectors/azure.py: aks_cluster GET 2024-05-01: properties.securityProfile.azureKeyVaultKms.enabled Boolean and keyId string; resolve keyVaultNetworkAccess enum if relevant to usability. Complete cluster inventory required. New Key Vault data-plane GET {keyId}?api-version=7.4 and effective key permission evaluation for the AKS identity are required to prove the configured key is usable; missing key or access evidence is UNKNOWN.
- Predicate: For each applicable AKS cluster, PASS only if properties.securityProfile.azureKeyVaultKms.enabled=true, keyId resolves to an enabled existing Key Vault key and the cluster identity has effective key permissions and network access. FAIL for explicitly disabled KMS, absent keyId on a complete applicable resource or authoritative unusable key/access evidence. UNKNOWN for incomplete cluster/key inventories, key state, identity, access or network reachability. An enabled KMS flag alone is insufficient.

### azure_api_management_10_3_1_3_8a50dc0

- Resource: api_management
- Data source: Paged APIM APIs LIST and per-API diagnostics LIST 2024-05-01; service loggers LIST. Join diagnostic.properties.loggerId (full ARM ID) to logger.id, require logger.properties.loggerType=applicationInsights; inspect diagnostic.properties.sampling.percentage and alwaysLog.
- Predicate: For every APIM REST API, PASS only if its fully paged API diagnostic list contains an Application Insights diagnostic referencing an existing usable logger and producing traces (sampling.percentage>0 or alwaysLog=allErrors). FAIL if complete API, diagnostic and logger reads prove none qualifies; UNKNOWN if credentials, revision coverage, sampling/alwaysLog or any child page is unresolved. No APIs is NOT_APPLICABLE.

### azure_api_management_1_2_8_1_ba319cf

- Resource: api_management
- Data source: Paged ARM Microsoft.ApiManagement/service/apis LIST 2024-05-01: value[].properties.protocols enum http/https/ws/wss; frozen expected endpoint type parameter per API. Protocols cover these four transport types only.
- Predicate: For each in-scope APIM API, compare properties.protocols with the frozen expected endpoint type when it is one of http, https, ws or wss. PASS only if every API has the expected protocol and no protocol forbidden by the supplied rule parameter. FAIL for a fully observed mismatch. UNKNOWN for an endpoint type not represented by this enum, missing rule parameter, absent protocols field, unrecognized value or incomplete pages. Complete empty API inventory is NOT_APPLICABLE.

### azure_api_management_1_2_8_3_e8fe737

- Resource: api_management
- Data source: Paged APIM service GET, APIs LIST, service hostnameConfigurations and publicNetworkAccess/virtualNetworkType; DNS resolution for every APIM default and custom gateway hostname; paged Application Gateway listeners/rules/backends/WAF policy and AFD endpoints/routes/origins/securityPolicies with WAF GET. The API list alone does not establish the gateway path.
- Predicate: For every in-scope APIM API and every publicly usable default or custom gateway hostname/path, PASS only if complete DNS, origin and route evidence proves all reachable paths traverse an effective enabled Prevention-mode WAF and direct APIM gateway ingress is blocked. FAIL for a demonstrated reachable direct or unprotected path. UNKNOWN on API/hostname enumeration, DNS, alternate gateway endpoints, route matching, origin restriction or WAF state. Complete empty API scope is NOT_APPLICABLE.

### azure_api_management_3_5_1_1_345bdac

- Resource: api_management
- Data source: Paged APIM APIs and operations LIST; operation, API, product and global policy GET 2024-05-01 with XML properties.value, plus APIM caches LIST/GET and referenced Azure Cache for Redis TLS configuration. Resolve XML base inheritance, policy conditions and cache-lookup/cache-store IDs; policy supplies requiredOperationIds and approvedEncryptedCacheIds.
- Predicate: For every required APIM operation, PASS only when its effective inbound and outbound policy paths both perform approved cache lookup/store, the referenced external cache is approved, and its endpoint/TLS settings prove encryption in transit and approved at-rest protection. FAIL on a fully resolved path lacking a required caching step or using a known unencrypted/unapproved cache. UNKNOWN on unresolved base inheritance, choose branches, missing cache identity, redacted connection string, encryption evidence or incomplete operation/policy pages. No required operations is UNKNOWN until scope policy is supplied.

### azure_api_management_app_http_logs_enabled_21c108d

- Resource: api_management
- Data source: Paged APIM service, API and API-revision inventory; service and per-API diagnostics LIST plus logger LIST (2024-05-01); diagnostic properties.loggerId, frontend, backend, sampling and alwaysLog; logger destination and dated sink-ingestion evidence.
- Predicate: For every APIM API and deployed revision, resolve its effective API diagnostic or inherited service diagnostic. PASS only if it references an existing usable logger, configured frontend/backend HTTP capture and sampling meet approved coverage, and dated sink evidence confirms receipt. FAIL if complete API, diagnostic, override and logger evidence proves no HTTP access logging. UNKNOWN if API inventory, inheritance, destination, ingestion, sampling policy or any page is unresolved. Do not require a nonexistent diagnostic or logger enabled flag.

### azure_api_management_app_http_logs_enabled_9b3b56e

- Resource: api_management
- Data source: Paged APIM service and API inventory; service diagnostics LIST and API diagnostics LIST 2024-05-01; service loggers LIST. Inspect diagnostic.properties.loggerId, verbosity enum error/information/verbose, sampling, alwaysLog and frontend.request/response, and resolve logger destination.
- Predicate: For every APIM service, PASS only when an applicable service or API diagnostic covers every required API, references a valid logger, has effective HTTP diagnostic logging, and has verbosity error or verbose as specified by the frozen rule. FAIL if complete child inventories prove absent coverage, an invalid logger, disabled effective logging, or a different verbosity. UNKNOWN for missing API, logger, diagnostic, paging or effective routing evidence. Do not require nonzero request/response body bytes when HTTP metadata is logged.

### azure_api_management_app_http_logs_enabled_9ef06db

- Resource: api_management
- Data source: Paged APIM APIs, operations and API/service diagnostics LIST 2024-05-01; join diagnostic.properties.loggerId to service logger.id and inspect loggerType, properties.verbosity enum error/information/verbose, sampling.percentage, alwaysLog, and scope override. There is no diagnostic.enabled or logger.enabled property in this schema.
- Predicate: For every APIM API operation, resolve the effective API or service diagnostic. PASS only if an applicable diagnostic references a present usable logger, has verbosity=error or information as the frozen rule requires, and samples ordinary requests at a positive percentage; alwaysLog=allErrors alone is insufficient when sampling is zero. FAIL if complete inheritance and logger reads prove an operation has no qualifying diagnostic. UNKNOWN if operation coverage, logger destination, credentials, scope override, optional sampling configuration or any page is unresolved. Complete empty operation inventory is NOT_APPLICABLE.

### azure_api_management_appinsights_ensure_is_configured_42aac6a

- Resource: api_management
- Data source: Collector peaso/collectors/azure.py: api_management parent is collected but logger/diagnostic children are not. New paged ARM GET {serviceId}/loggers?api-version=2024-05-01 and {serviceId}/diagnostics?api-version=2024-05-01; logger properties.loggerType enum applicationInsights, properties.resourceId string; diagnostic properties.loggerId string, sampling.percentage number, alwaysLog enum if needed; follow nextLink. Enumerate APIs and API-level diagnostics as well as service diagnostics; resolve documented inheritance/override and GET each referenced Application Insights component. Enumerate APIs and API-level diagnostics as well as service diagnostics; resolve documented inheritance/override and GET each referenced Application Insights component.
- Predicate: For each APIM service and every active API, PASS only if its effective diagnostic (API override or inherited service diagnostic) references an exact applicationInsights logger ID whose resourceId resolves to an existing Application Insights component, and fixed sampling is explicitly positive or its documented effective default is positive. FAIL if complete logger, service/API diagnostic and API inventories prove any active API lacks that effective tracing path. UNKNOWN if child/API pages, logger resource, effective override/inheritance, sampling default or API coverage is unresolved. No active APIs is NOT_APPLICABLE only after complete enumeration.

### azure_app_service_app_function_latest_runtime_version_f50215a

- Resource: app_service
- Data source: Function App site and config GET; app settings FUNCTIONS_WORKER_RUNTIME and FUNCTIONS_EXTENSION_VERSION; function/site runtime metadata and workload configuration for role, timeout and memory; policy expectedFunctionSettings. Exclude Container package type and OS-only Runtime when proven.
- Predicate: For each in-scope Function App except proven Container-package or OS-only Runtime exceptions, compare the configured runtime, role, timeout and memory against expectedFunctionSettings using documented fields for its hosting model. PASS only when all four are measured and match; FAIL on a measured mismatch; UNKNOWN if an expected value, hosting-model field, runtime resolution or child response is unavailable. A floating extension version alone cannot prove a pinned runtime.

### azure_application_gateway_11_5_1_1_1_f56bdc2

- Resource: application_gateway_frontdoor_load_balancer_public_ip
- Data source: Paged Application Gateway, Front Door, Load Balancer and Public IP inventories; Public IP GET ddosSettings.protectionMode and plan; protected VNet association where inherited; effective App Gateway/Front Door WAF policy linkage, state and mode. Resolve WAF policy state defaults from the documented schema.
- Predicate: For every scoped public App Gateway, Front Door, Load Balancer and Public IP, verify applicable DDoS protection by exact public IP/plan or supported inherited VNet protection; for App Gateway and Front Door also verify an effective WAF policy in Prevention mode, treating omitted policy/custom-rule state as Enabled only where the API documents that default. PASS only when all applicable protections are measured; FAIL on a proven missing protection; UNKNOWN for unsupported product-level DDoS mapping, public frontend, inherited VNet, plan, WAF policy/default or incomplete inventory. No public resources is NOT_APPLICABLE.

### azure_application_gateway_1_2_5_8_33a9d21

- Resource: application_gateway
- Data source: Application Gateway GET 2023-09-01: properties.httpListeners[].properties.protocol/sslProfile.id, properties.sslProfiles[].properties.sslPolicy and properties.sslPolicy. Also collect classic Front Door and CDN/AFD HTTPS custom-domain TLS settings for source-described Front Door listeners; policy approvedSslPolicy.
- Predicate: For each applicable HTTPS Application Gateway listener resolve its SSL profile and effective policy, including policyType=Custom where the frozen rule specifies a custom SSL policy; for each applicable Front Door listener/domain resolve its resource-specific TLS policy. PASS only when all effective settings meet approved minimum protocol and cipher standards; FAIL for a measured weaker or noncustom Application Gateway policy. UNKNOWN for an uncollected Front Door family, unresolved profile/predefined policy, policy input or pagination. No HTTPS listeners is NOT_APPLICABLE.

### azure_application_gateway_app_client_certificates_on_fcca0b8

- Resource: application_gateway
- Data source: Application Gateway GET 2026-01-01 properties.httpListeners[].properties.sslCertificate.id and properties.sslCertificates[].properties.keyVaultSecretId; resolve referenced Key Vault secret/certificate version with data-plane GET and validate expiry and trust where the source requires a trusted certificate.
- Predicate: For every HTTPS Application Gateway listener, resolve properties.sslCertificate.id to the gateway sslCertificates entry. FAIL when a complete gateway response shows no certificate binding or no nonempty properties.keyVaultSecretId. PASS only when every applicable listener references a Key Vault secret and its current certificate is valid and trusted as required by the frozen rule; UNKNOWN when Key Vault status, trust chain, expiry, access or inventory cannot be checked.

### azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7

- Resource: application_gateway
- Data source: Existing azure.py application_gateway.items[] GET 2023-09-01: properties.httpListeners[].properties.protocol enum Http/Https; requestRoutingRules[].properties.httpListener.id and redirectConfiguration.id; urlPathMaps[].properties.defaultRedirectConfiguration.id/pathRules[].properties.redirectConfiguration.id; redirectConfigurations[].properties.redirectType enum Permanent/Found/SeeOther/Temporary, targetListener.id or targetUrl.
- Predicate: For each HTTP listener and every effective basic rule or path-map default/path rule, FAIL when a fully resolved route forwards without redirect or redirects to an HTTP listener or non-HTTPS target URL. PASS when all effective routes redirect to an HTTPS listener or HTTPS URL using a schema-valid redirectType (Permanent, Found, SeeOther or Temporary). UNKNOWN for unresolved references, target URL, path map, routeless listener or incomplete gateway inventory.

### azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63

- Resource: application_gateway_and_frontdoor
- Data source: Application Gateway GET api-version=2023-09-01: properties.httpListeners[].properties.protocol/sslCertificate.id, properties.sslCertificates[].id/properties; classic Front Door GET api-version=2021-06-01: properties.frontendEndpoints[].properties.customHttpsConfiguration, properties.routingRules[].properties.acceptedProtocols. For each exposed hostname perform TLS handshake and validate chain, hostname and expiry at observation time; resolve Key Vault-backed certificate material when applicable.
- Predicate: For every exposed Application Gateway or classic Front Door hostname/listener in scope, PASS only if HTTPS is configured and an associated certificate validates for that hostname, chain and observation time. FAIL on a measured HTTP-only listener, missing HTTPS binding, expired/mismatched/untrusted certificate or failed TLS validation. UNKNOWN if hostname, certificate binding/material, endpoint reachability, effective routing or inventory is unresolved. HTTP-to-HTTPS redirect alone does not satisfy the frozen requirement.

### azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17

- Resource: application_gateway_and_frontdoor
- Data source: Paged Application Gateway and Front Door inventory; Application Gateway GET listener sslProfileId, gateway properties.sslPolicy and sslProfiles[].properties.sslPolicy; Front Door GET frontend endpoint HTTPS/TLS policy settings; policy-approved predefinedPolicyName values.
- Predicate: For every in-scope Application Gateway or Front Door HTTPS listener, resolve its effective SSL policy and require policyType="Predefined" with the exact policy-approved name. PASS only if every listener is measured and matches; FAIL on a measured different policy type/name; UNKNOWN for unresolved listener/profile inheritance, unsupported Front Door policy representation, missing approved name or incomplete inventory. No applicable HTTPS listeners is NOT_APPLICABLE.

### azure_application_gateway_app_http_logs_enabled_2de0361

- Resource: application_gateway_and_load_balancer
- Data source: Collector peaso/collectors/azure.py: application_gateway and load_balancer are collected; diagnostic_setting GET {resourceId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview is collected per resource. New GET diagnosticSettingsCategories at the same resource to determine supported category names; page settings and categories, require approved destination IDs and logs[].enabled=true.
- Predicate: For every Application Gateway and Load Balancer, PASS only if a complete resource-specific category/settings inventory shows at least one supported access or operational log category enabled and the same diagnostic setting routes it to an existing Log Analytics workspace or Azure Storage account. FAIL if complete evidence shows no such category/export; UNKNOWN if destination, category support, SKU or child coverage is unresolved. Event Hub alone does not meet the frozen destination list.

### azure_azure_resource_1_3_1_46_b70e2c8

- Resource: virtual_network_gateway
- Data source: ARM Microsoft.Network/virtualNetworkGateways/{gateway}/connections LIST 2026-01-01; follow nextLink. Read each IPsec connection properties.tunnelConnectionStatus[].tunnel and .connectionStatus plus properties.virtualNetworkGateway1.id and, where applicable, virtualNetworkGateway2.id; policy expected gateway/connection IDs and exactly two tunnel identities overall. Parent connectionStatus is insufficient.
- Predicate: Across the policy-selected site-to-site VPN connection resources for the selected gateway, identify exactly the two expected tunnels by properties.tunnelConnectionStatus[].tunnel and require each .connectionStatus=Connected. FAIL when a measured expected tunnel is Disconnected or complete tunnel arrays lack an expected tunnel; PASS only when both expected tunnels are measured Connected. UNKNOWN for missing expected IDs, unsupported/absent tunnel health, incomplete pages or ambiguous tunnel identity. Connection-level Connected alone never passes.

### azure_azure_resource_keyvault_private_endpoints_c3995a6

- Resource: vnet_and_private_endpoint
- Data source: Paged ARM Microsoft.Network/virtualNetworks and privateEndpoints LIST 2026-01-01; endpoint properties.subnet.id and both properties.privateLinkServiceConnections[] and properties.manualPrivateLinkServiceConnections[], each with properties.privateLinkServiceId and privateLinkServiceConnectionState.status; policy target service ARM resource type and VNet scope.
- Predicate: For every scoped VNet, require a created private endpoint whose subnet ARM ID belongs to that VNet and whose service connection in either privateLinkServiceConnections or manualPrivateLinkServiceConnections identifies the exact target service ARM type. PASS after complete VNet, subnet and endpoint pages prove this resource exists; FAIL when complete inventory proves none exists; UNKNOWN for unresolved service ID/type, absent parameter or incomplete pages. Connection approval status is reported separately because the frozen rule asks whether the endpoint is created, not whether its connection is approved.

### azure_cdn_profile_10_3_4_1_4e40487

- Resource: cdn_profile
- Data source: Front Door and CDN profile, endpoint, route, origin-group and origin GET/LIST at supported API versions; origin-group properties.authentication, identity scope, profile identity and storage Blob RBAC; verify whether each origin is a Blob Storage container.
- Predicate: For every CDN/Front Door endpoint backed by a Blob Storage container, PASS only if the routed origin group has effective managed-identity authentication, the correct Storage token audience scope, matching enabled profile identity and required Blob RBAC. FAIL on complete evidence of missing authentication or a non-container origin where the source rule applies; UNKNOWN if product generation, route/origin mapping, preview property availability, container identity or RBAC is unresolved.

### azure_cdn_profile_1_2_8_5_ed953a0

- Resource: cdn_profile
- Data source: New paged CDN profiles/endpoints/customDomains lists 2024-02-01; properties.customHttpsProvisioningState enum Enabled/Disabled/Enabling/Disabling/Failed and customHttpsParameters.certificateSource enum Cdn/AzureKeyVault; read AzureKeyVaultCertificateSourceParameters keyVaultCertificateSourceParameters if present.
- Predicate: For each in-scope classic CDN custom domain required to serve HTTPS, PASS if properties.customHttpsProvisioningState=Enabled and properties.customHttpsParameters.certificateSource=AzureKeyVault. FAIL if the complete response shows customHttpsProvisioningState=Disabled/Failed or certificateSource=Cdn. UNKNOWN for transitional/missing HTTPS fields, unsupported profile types or incomplete profile/endpoint/domain paging. No applicable domains is NOT_APPLICABLE.

### azure_cosmos_account_10_2_1_1_13_5c115b0

- Resource: cosmos_account
- Data source: Paged Microsoft.DocumentDB/databaseAccounts LIST/GET 2024-05-15 and Microsoft.DocumentDB/mongoClusters LIST/GET; account capabilities identify Mongo API when present, while vCore Mongo clusters are separate resources. List diagnostic settings at each exact resource ID with 2021-05-01-preview; read properties.logs[].category/enabled and setting-level workspaceId/storageAccountId/eventHubAuthorizationRuleId/eventHubName. Supported account categories include MongoRequests and DataPlaneRequests; mongoClusters category is vCoreMongoRequests.
- Predicate: For every Mongo API database account or Mongo vCore cluster, PASS only if its own complete diagnostic-setting list has an enabled applicable request-log category (MongoRequests or DataPlaneRequests for account, vCoreMongoRequests for cluster) and a valid configured sink at setting level. FAIL when complete settings show no qualifying export. UNKNOWN when resource subtype, capabilities, supported category, sink validity or paging is unresolved. Complete empty Mongo inventory is NOT_APPLICABLE.

### azure_cosmos_account_10_2_1_1_23_e04a63d

- Resource: cosmos_account
- Data source: Existing cosmos_account and diagnostic_setting collections. Join each Cosmos account ID to its scoped Microsoft.Insights/diagnosticSettings LIST 2021-05-01-preview; each setting has properties.workspaceId, while properties.logs[] has category/categoryGroup and enabled. Require complete per-account child collection.
- Predicate: For each Cosmos DB account, PASS if complete per-account diagnostic settings include a setting with properties.workspaceId equal to an approved workspace and properties.logs[] entry enabled for DataPlaneRequests, or a verified category group containing it. FAIL if complete settings show no qualifying export. UNKNOWN for incomplete child/settings pages, unsupported category, missing destination policy or ambiguous category group. This is configured export evidence; actual log delivery requires a separate ingestion check.

### azure_cosmos_account_10_5_1_5_2029065

- Resource: cosmos_account
- Data source: Cosmos DB database account GET 2024-05-15: properties.backupPolicy.type Periodic/Continuous. Periodic: periodicModeProperties.backupRetentionIntervalInHours. Continuous: continuousModeProperties.tier enum Continuous7Days/Continuous30Days. Policy minRetentionDays.
- Predicate: For each scoped Cosmos DB account, map Periodic backupRetentionIntervalInHours to hours and Continuous tier Continuous7Days/Continuous30Days to 7/30 days. PASS only if every measured account retains backups for at least minRetentionDays; FAIL if a measured account is below the minimum. UNKNOWN for missing/invalid policy or field, unrecognized type/tier, or incomplete account inventory; aggregate definite FAIL before UNKNOWN. A complete empty account inventory is NOT_APPLICABLE.

### azure_devops_project_1_2_8_6_fb0e5a8

- Resource: devops_project
- Data source: Azure DevOps 7.1 complete projects LIST and per-project Git repositories LIST with includeHidden=true and includeAllUrls=true; inspect repository.remoteUrl and every validRemoteUrls[] clone URL.
- Predicate: For every repository, parse remoteUrl and all validRemoteUrls[] as URLs; FAIL if any authority contains userinfo, including username-only. PASS only when all advertised clone URLs in every visible or hidden repository are present, valid and free of userinfo. UNKNOWN on missing or malformed URL, unresolved optional URL coverage, or incomplete project/repository enumeration. Empty complete repository inventory is NOT_APPLICABLE.

### azure_devops_project_3_5_1_7_dc58423

- Resource: devops_pipeline
- Data source: Azure DevOps 7.1 paged project variable groups, build definitions and pipeline YAML/variable templates expanded at a pinned revision; inspect credential variable metadata (isSecret) for project and pipeline scopes without retaining values. Pipeline definition GET alone does not expose all variables.
- Predicate: For every in-scope project and pipeline, find AZURE_CLIENT_SECRET and other approved credential variable names in all applicable variable groups and expanded pipeline variables. FAIL if any such variable is explicitly plaintext (isSecret is not true or a YAML literal/inline value). PASS only when complete expansion and metadata prove every present credential variable is secret-backed, and required variable presence is established by policy. UNKNOWN if a template, group, definition, variable kind, continuation page or naming policy is unresolved; absence of a credential variable is not evidence that a plaintext credential is absent elsewhere.

### azure_devops_project_6_5_5_2_2908a87

- Resource: devops_project
- Data source: Azure DevOps Pipelines GET 7.1 and referenced YAML/templates at immutable repository revisions; paged pipeline inventory; optional deploymentLimit policy for later stages.
- Predicate: For every in-scope pipeline at its resolved revision, expand all YAML templates and deployment stages. The first deployment stage must contain no more than one deployment job; each later stage must not exceed the optional deploymentLimit when one is supplied by policy. FAIL on any measured over-limit stage. PASS only with complete expansion and measured stages; UNKNOWN for missing revision/templates, dynamic expressions, pipeline pages, or absent required later-stage limit.

### azure_diagnostic_setting_11_5_2_3_7959930

- Resource: metric_alert
- Data source: Paged Microsoft.Insights/metricAlerts ListBySubscription 2024-03-01-preview: properties.enabled,scopes,severity,evaluationFrequency,windowSize,criteria.odata.type and criteria.allOf[].metricName,metricNamespace,timeAggregation,operator,threshold,dimensions; actions[].actionGroupId. Resolve action-group children and expectedMetricSettings policy.
- Predicate: For every expected metric setting, require an enabled alert matching full scope, criteria type, metric namespace/name, aggregation, dimensions, operator, threshold, severity, windowSize, evaluationFrequency and an enabled action group. FAIL on a complete measured mismatch/absence; PASS only if all expected entries match; UNKNOWN if policy, alert pages, criteria shape or action-group status is unresolved.

### azure_diagnostic_setting_app_http_logs_enabled_d32e8e1

- Resource: app_service_environment
- Data source: Paged ASE inventory plus diagnosticSettings LIST 2021-05-01-preview per ASE and diagnosticSettingsCategories LIST: properties.logs[].category/categoryGroup/ enabled and setting-level properties.workspaceId; resolve approved workspace and verify log delivery.
- Predicate: For each App Service Environment, PASS only if a supported ASE platform-log category (including AppServiceEnvironmentPlatformLogs where offered, or an applicable category group) is enabled in a complete diagnostic setting with setting-level workspaceId matching an approved Log Analytics workspace, and delivery is verified where required. FAIL when complete category/settings evidence shows logging disabled or no workspace export; UNKNOWN if category support, workspace, delivery or inventory is unresolved.

### azure_directory_user_10_6_3_21_d013932

- Resource: directory_user_and_group
- Data source: Graph v1.0 paged /users?$select=id,accountEnabled and each /users/{id}/transitiveMemberOf/microsoft.graph.group?$select=id; follow @odata.nextLink for both lists.
- Predicate: For every Azure AD user in the frozen source scope, use paged Graph user and transitiveMemberOf group lists. FAIL when complete membership for a user is empty; PASS when every user has at least one group. UNKNOWN for unresolved users, membership or pagination. Exclude users only when the frozen requirement or an explicitly approved scope defines the exclusion; disabled accounts are otherwise included.

### azure_directory_user_7_2_1_19_28e2aa7

- Resource: directory_user
- Data source: Paged Graph /users, directory roleAssignments, active and eligible PIM role assignment instances/schedules; complete paged ARM roleAssignments across tenant root/management groups, subscriptions, resource groups and child resource scopes; compare principalId to user.id and resolve principal type.
- Predicate: For every directory user, FAIL if any direct active or eligible Entra directory role, PIM assignment, or Azure RBAC role assignment at any applicable scope targets that user ID. PASS only when complete user, directory, PIM and ARM assignment inventories across tenant and resource hierarchy prove no direct grants. UNKNOWN if pages, hierarchy/scope coverage, principal type or identity join is incomplete. Group-granted roles are not direct user assignments.

### azure_directory_user_7_2_4_1_712ef31

- Resource: directory_group
- Data source: Paged Graph v1.0 groups list and /groups/{id}/members list for each required group, following @odata.nextLink; use @odata.type and resolve hidden/dynamic membership permissions.
- Predicate: For every policy-required Entra group, PASS if complete paged direct membership includes at least one microsoft.graph.user. FAIL if a fully resolved direct-membership list contains no user. UNKNOWN for missing required-group policy, hidden membership, unresolved dynamic group membership, omitted @odata.type or incomplete pages. Empty required group set is NOT_APPLICABLE.

### azure_directory_user_7_2_4_2_7a90cfb

- Resource: directory_user
- Data source: Paged Graph v1.0 /users?$select=id,accountEnabled,createdDateTime,signInActivity with nullable lastSuccessfulSignInDateTime; additional per-credential issuance and last successful use evidence for password and active access credentials; policy inactiveDays and scan UTC time.
- Predicate: For every enabled user and in-scope password or active access credential, FAIL if a verified last successful use is older than inactiveDays. PASS only if complete per-credential evidence proves recent use within the threshold. UNKNOWN for never-used credentials without issuance time, missing/null sign-in activity, noninteractive credential use not measured by user signInActivity, missing policy/clock or incomplete paging. Empty applicable set is NOT_APPLICABLE.

### azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9

- Resource: directory_user
- Data source: Paged Graph v1.0 /users?$select=id,accountEnabled; /identity/conditionalAccess/policies; /policies/identitySecurityDefaultsEnforcementPolicy; transitive group membership and authentication-method registration; sign-in contexts required by policy.
- Predicate: For every enabled Entra user and each policy-required sign-in context, PASS only if complete effective enabled policy evidence requires MFA, resolving exclusions, application/client/location/device/risk conditions, groups and authentication strengths. FAIL when complete evidence proves a user/context without MFA. UNKNOWN if context, policy, membership, registration or inventory is incomplete; enabled security defaults alone does not prove every sign-in has MFA.

### azure_directory_user_entra_privileged_user_has_mfa_6f6d584

- Resource: directory_user
- Data source: Microsoft Graph /roleManagement/directory/roleAssignments, /users, /identity/conditionalAccess/policies, /policies/identitySecurityDefaultsEnforcementPolicy: principalId,roleDefinitionId,accountEnabled,state,conditions,grantControls,isEnabled
- Predicate: For every enabled effective Global Administrator, PASS only if security defaults are confirmed applicable or enforced Conditional Access requires MFA for Azure console sign-in after all relevant user/group, cloud-app, client-app, location, device, risk and authentication-flow conditions and exclusions are evaluated. FAIL when an enabled administrator has a demonstrably uncovered console sign-in path. UNKNOWN for role-group/PIM activation ambiguity, conditional grant alternatives, security-default applicability or incomplete Graph inventory.

### azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28

- Resource: service_principal
- Data source: Microsoft Graph GET /servicePrincipals?$select=id,passwordCredentials,keyCredentials; exact fields: Microsoft.Graph/servicePrincipals[].passwordCredentials[].startDateTime,endDateTime,keyCredentials[].startDateTime,endDateTime; parameter maxCredentialAgeDays.
- Predicate: For each active, unexpired service-principal passwordCredential and keyCredential, FAIL if startDateTime is older than maxCredentialAgeDays, defaulting to 90 days when the parameter is absent. PASS if every active credential is within that threshold and all principals/credentials were enumerated. UNKNOWN if dates, time basis or Graph paging is incomplete; an empty credential list passes only with complete principal scope.

### azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf

- Resource: mysql_and_postgresql_flexible_server
- Data source: Paged MySQL Flexible Server and PostgreSQL Flexible Server inventory and per-server administrators child LIST; PostgreSQL properties.authConfig.activeDirectoryAuth, MySQL properties.authConfig.activeDirectoryAuth or documented equivalent, with valid administrator principal identity.
- Predicate: For each applicable MySQL or PostgreSQL server, PASS only when Entra authentication is explicitly enabled in its documented server configuration and a valid Entra administrator is present where required. FAIL on explicit Disabled or a complete empty administrator list; UNKNOWN when the auth setting, child list, server generation or identity cannot be resolved. Admin presence by itself does not establish enabled authentication.

### azure_disk_10_3_3_12_174f526

- Resource: disk_and_backup_instance
- Data source: Paged ARM Microsoft.Compute/disks LIST 2023-10-02 and every Microsoft.DataProtection/backupVaults/backupInstances LIST 2024-04-01 across in-scope subscriptions; exact normalized disk ARM ID to properties.dataSourceInfo.resourceID and properties.policyInfo.policyId; properties.currentProtectionState enum.
- Predicate: For every managed disk, PASS only if a uniquely joined backup instance has a policyId and currentProtectionState=ProtectionConfigured. FAIL if a complete vault/instance inventory has no joined active protection or explicitly shows NotProtected, ProtectionStopped or ProtectionError. UNKNOWN for ambiguous joins, incomplete vault scope, absent fields, transient/unknown states or pagination.

### azure_firewall_policy_10_2_1_1_24_0781f5f

- Resource: azure_firewall
- Data source: Paged azureFirewalls GET 2023-09-01; per-firewall diagnosticSettings LIST 2021-05-01-preview and diagnosticSettingsCategories LIST. Use setting.properties.logs[].category/categoryGroup/enabled and setting.properties.workspaceId/storageAccountId/eventHubAuthorizationRuleId; policy requiredCategories and approved sink IDs.
- Predicate: For each Firewall, PASS only if every policy-required supported log category (or allLogs group) is enabled in its own diagnostics and routed to an approved sink; FAIL if complete category/settings lists prove a gap; UNKNOWN if requiredCategories, supported categories, sink approval or inventory is missing.

### azure_firewall_policy_1_2_8_23_59ad733

- Resource: firewall_policy
- Data source: New paged ARM GET /subscriptions/{sub}/providers/Microsoft.Network/firewallPolicies?api-version=2023-09-01 and GET {policyId}/ruleCollectionGroups?api-version=2023-09-01. Read properties.ruleCollections[].ruleCollectionType enum FirewallPolicyFilterRuleCollection/FirewallPolicyNatRuleCollection and rules[]; follow properties.basePolicy.id recursively and list its groups too. Follow every nextLink. Collector has no firewall_policy.
- Predicate: For each Firewall Policy, resolve its complete direct ruleCollectionGroups and any effective basePolicy ancestry. PASS only if a group contains a FirewallPolicyFilterRuleCollection or FirewallPolicyNatRuleCollection with at least one correctly typed rule that applies to the policy. FAIL when complete direct/inherited inventories contain no such rule collection. UNKNOWN if group paging, inheritance, type or rule array is unresolved.

### azure_firewall_policy_1_2_8_24_cc7cb8a

- Resource: firewall_policy
- Data source: Paged ARM Microsoft.Network/firewallPolicies and every policy /ruleCollectionGroups LIST/GET 2026-01-01: group id and properties.ruleCollections[].rules[]. Enumerate all policy groups in the assessed subscription, including unattached policies; follow every nextLink.
- Predicate: For every enumerated Firewall Policy Rule Collection Group, PASS only if its complete GET contains at least one rule in properties.ruleCollections[].rules[]. FAIL if any fully read group has no rules, even when the policy is unattached or another group has rules. UNKNOWN if policy/group enumeration or GET is incomplete. Complete empty group inventory is NOT_APPLICABLE.

### azure_firewall_policy_1_2_8_42_cacbd9e

- Resource: web_application_firewall_policy
- Data source: Paged Application Gateway WAF policy LIST/GET 2026-01-01 for every in-scope policy, attached or unattached: properties.customRules[] and properties.managedRules.managedRuleSets[]. Policy settings and rule state are supplementary, but the frozen requirement is structural rule presence.
- Predicate: For each in-scope WAF policy, PASS when its complete GET contains at least one customRules[] entry or one managedRules.managedRuleSets[] entry; FAIL when both collections are absent or empty in a complete response. UNKNOWN if policy inventory, policy GET, or the rule collections cannot be resolved. Include unattached policies. Disabled state and Detection mode do not negate the frozen requirement that a policy contains a rule.

### azure_firewall_policy_6_4_1_6_2ad9039

- Resource: web_application_firewall_policy
- Data source: Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies GET api-version=2023-09-01: properties.managedRules.managedRuleSets[].ruleGroupOverrides and customRules[].priority. Separately require Firewall Manager ruleGroups parameter/rank and deployed group association evidence for the exact policy. WAF custom-rule priority is not rule-group rank.
- Predicate: PASS or FAIL only from a separately supplied, authoritative Firewall Manager ruleGroups parameter and deployed association/order evidence that identifies the same WAF policy and proves every group rank (0,1,2,...). Return UNKNOWN when only Azure Application Gateway WAF GET is available, even if its customRules.priority values are 0,1,2. Also UNKNOWN for absent association, ambiguous order, missing parameter or incomplete inventory.

### azure_firewall_policy_6_4_1_7_a7975fc

- Resource: web_application_firewall_policy
- Data source: Application Gateway WAF policy GET 2026-01-01 plus Application Gateway association. Inspect policySettings.state, managedRules.managedRuleSets with ruleSetType/version, ruleGroupOverrides[].ruleGroupName/rules[].state, and the versioned managed rule-set group catalogue; customRules are not managed rule-group evidence.
- Predicate: For every in-scope attached WAF v2 policy and each effective managed rule group, FAIL if policySettings.state is Disabled or complete versioned rule-set/override evidence proves the group has no enabled effective rule. An override listing a group with an empty rules array disables the group; an override rule with omitted state defaults to Disabled. PASS only when policy state is Enabled or omitted (documented Enabled default), every applicable group has at least one enabled effective rule after defaults and overrides, and rule-set versions are fully resolved. UNKNOWN for missing association, catalogue, group/rule state, policy mode or inventory. A custom rule alone cannot make an empty managed group PASS.

### azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d

- Resource: mysql_postgresql_sql_firewall_rule
- Data source: Existing azure.py sql_server and mysql/postgresql flexible server items, sql_firewall_rule child for SQL only; new paged firewallRules list per MySQL/PostgreSQL server using each provider API; properties.startIpAddress/endIpAddress IPv4 strings.
- Predicate: For every SQL, MySQL and PostgreSQL server, evaluate all child firewall rules against the frozen rule: custom non-default rules that allow unrestricted inbound access fail. FAIL on a measured custom rule spanning the public IPv4 range, and evaluate Azure-services 0.0.0.0 sentinel separately against the rule’s approved-source policy. PASS only when all paged child lists and effective public-access settings are complete and no unrestricted custom rule exists. UNKNOWN for absent lists, malformed IPs, unresolved default-rule classification, approved-source policy or unsupported server generation. No servers is NOT_APPLICABLE.

### azure_frontdoor_1_2_5_4_ccc7b8f

- Resource: frontdoor_and_cdn_endpoint
- Data source: Enumerate classic Front Door frontend endpoints from Microsoft.Network/frontDoors GET (2019-05-01 schema) and classic CDN profile/endpoint/customDomain lists with paging. Front Door: properties.frontendEndpoints[].properties.customHttpsProvisioningState, customHttpsConfiguration.certificateSource and protocolType. CDN: each custom domain properties.customHttpsProvisioningState, customHttpsParameters.certificateSource and protocolType. Do not infer SNI from certificate type.
- Predicate: For each applicable classic Front Door frontend endpoint or classic CDN custom HTTPS domain, PASS only when customHttpsProvisioningState=Enabled, the active certificate source is AzureKeyVault, and SNI is explicitly selected (Front Door customHttpsConfiguration.protocolType=ServerNameIndication; CDN customHttpsParameters.protocolType=ServerNameIndication). FAIL when complete settings show HTTPS Disabled/Failed, FrontDoor/Cdn-managed certificate, or CDN IPBased TLS. UNKNOWN for missing/transitional fields, Standard/Premium profiles where equivalent SNI semantics are not exposed, or incomplete endpoint/domain paging. No applicable endpoints is NOT_APPLICABLE.

### azure_frontdoor_1_2_8_4_90159db

- Resource: afd_security_policy
- Data source: New paged Microsoft.Cdn/profiles/securityPolicies, customDomains, afdEndpoints/routes List 2024-02-01 and WAF policy GET 2023-09-01. Security policy properties.parameters.type, wafPolicy.id, associations[].domains[].id, patternsToMatch; WAF properties.policySettings.enabledState enum Enabled/Disabled.
- Predicate: For each publicly routed Front Door Standard/Premium domain and route pattern, PASS only if a WebApplicationFirewall security policy association covers the exact effective domain and path pattern with a valid WAF policy ID whose effective policySettings.enabledState is Enabled (including its documented omitted-state default). FAIL if complete profile, route, association and WAF inventories prove an uncovered or disabled route. UNKNOWN on unresolved associations, wildcard-pattern semantics, WAF GET failure or incomplete pages. Complete empty routed-domain scope is NOT_APPLICABLE.

### azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9

- Resource: frontdoor_and_cdn_endpoint
- Data source: Paged Classic Front Door GET 2021-06-01 routingRules; paged Microsoft.Cdn profiles, endpoints/customDomains and afdEndpoints/routes GET 2024-02-01; inspect classic acceptedProtocols/routeConfiguration, AFD supportedProtocols/httpsRedirect, and CDN endpoint/custom-domain HTTPS/protocol or rules-engine redirect configuration for each SKU.
- Predicate: For every Azure Front Door and Azure CDN public route or custom domain, PASS if it is HTTPS-only or each accepted HTTP request is effectively redirected to HTTPS. FAIL when a fully resolved route accepts HTTP and can serve or forward it without HTTPS redirect. UNKNOWN for unresolved CDN SKU/rules-engine behavior, protocol setting, route/custom-domain association or incomplete profile/endpoint/route paging.

### azure_frontdoor_app_minimum_tls_version_12_0512053

- Resource: frontdoor_and_cdn_endpoint
- Data source: Classic Microsoft.Network/frontDoors GET frontendEndpoints[].properties.minimumTlsVersion and Microsoft.Cdn/profiles/customDomains LIST/GET properties.tlsSettings.minimumTlsVersion; collect both resource families and all custom-domain pages.
- Predicate: For every HTTPS classic Front Door frontend and every CDN/AFD custom domain, compare that domain's own minimumTlsVersion against the resource-specific TLS 1.2 enum. FAIL below 1.2; PASS only when all applicable domains are TLS 1.2 or later. UNKNOWN if HTTPS state, per-domain setting, API generation or paged inventory is unresolved. No HTTPS domains is NOT_APPLICABLE.

### azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a

- Resource: frontdoor_and_cdn_endpoint
- Data source: ARM Microsoft.Insights/diagnosticSettings LIST 2021-05-01-preview at Microsoft.Network/frontDoors and Microsoft.Cdn/profiles IDs: properties.logs[].category/categoryGroup, enabled and setting-level properties.workspaceId/storageAccountId. Discover supported categories for each resource with diagnosticSettingsCategories LIST; expand allLogs groups.
- Predicate: For every classic Front Door and CDN/Front Door profile, require an enabled diagnostic setting whose explicit category or expanded categoryGroup includes the access-log category supported by that exact resource type and whose setting-level workspaceId or storageAccountId is present. Use FrontdoorAccessLog for Microsoft.Network/frontDoors; discover FrontDoorAccessLog or AzureCdnAccessLog for Microsoft.Cdn/profiles. FAIL after complete inventory if no qualifying route; UNKNOWN for unresolved category-group membership, category discovery, destination or list pages.

### azure_frontdoor_network_http_internet_access_restricted_7004685

- Resource: frontdoor_and_cdn_endpoint
- Data source: Paged classic Front Door routing rules and AFD routes with effective rule-set forwarding overrides; enumerate Microsoft.Cdn classic profiles/endpoints/origins for scope. Classic CDN endpoint GET exposes isHttpAllowed/isHttpsAllowed and origin ports but does not expose a universal origin-protocol policy; require provider-specific configuration or traffic evidence before judging its origin protocol. Resolve each enabled route/endpoint with a custom origin and all effective origin-request paths.
- Predicate: For every enabled Front Door route to a custom origin, PASS only when every effective request path forwards to the origin over HTTPS: HttpsOnly passes even if client HTTP is accepted; MatchRequest passes only if all accepted client paths are HTTPS or HTTP is redirected before forwarding. FAIL for an effective HttpOnly origin path or MatchRequest path that forwards accepted HTTP to the origin. For classic CDN endpoints, return UNKNOWN unless provider-specific origin-protocol configuration or observed origin traffic proves the same condition; isHttpAllowed/isHttpsAllowed and origin ports alone do not prove the origin protocol. UNKNOWN also for unresolved overrides, origin policy, or incomplete pages. Disabled routes are outside scope. A complete inventory with no applicable custom origins is NOT_APPLICABLE.

### azure_hdinsight_cluster_1_2_5_11_babfa1b

- Resource: hdinsight_cluster
- Data source: Paged Microsoft.HDInsight/clusters GET 2021-06-01: properties.securityProfile.directoryType,aaddsResourceId,domain and optional ldapsUrls; approvedAaddsResourceIds and any LDAPS policy.
- Predicate: For each HDInsight cluster, PASS if complete securityProfile.directoryType=ActiveDirectory and valid aaddsResourceId/domain identify an approved Microsoft Entra Domain Services deployment; require LDAPS endpoints only when the approved ESP/Kerberos configuration needs them. FAIL for a complete missing/wrong directory type, domain or unapproved AAD DS ID. UNKNOWN for optional LDAPS or security-profile data that cannot be resolved, missing approval or incomplete inventory.

### azure_log_analytics_workspace_10_5_1_4_8c74ccb

- Resource: log_analytics_workspace
- Data source: Paged Log Analytics workspaces GET 2023-09-01: properties.retentionInDays integer; optional policy MinRetentionTime days, defaulting to 365 per frozen requirement. If judging effective retention across tables, paged workspaces/tables LIST 2022-10-01 for table-level overrides.
- Predicate: For every workspace, PASS if retentionInDays is at least MinRetentionTime when specified, otherwise at least 365. FAIL if a complete numeric response is below the applicable threshold. UNKNOWN for missing/malformed value, incomplete inventory, or unresolved table-level override when effective table retention is in scope. No workspaces is NOT_APPLICABLE.

### azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b

- Resource: resource_diagnostic_setting
- Data source: Paged resource inventory and Microsoft.Insights/diagnosticSettings LIST 2021-05-01-preview at each resource: setting.properties.logs[].category/categoryGroup and enabled; setting.properties.workspaceId full ARM ID; category support LIST and approved workspace IDs.
- Predicate: For every in-scope resource, PASS if at least one supported log category or matching category group is enabled and the same diagnostic setting has a valid Log Analytics workspaceId. FAIL if a complete category/settings inventory proves no enabled log export to any Log Analytics workspace. UNKNOWN if resource scope, category support, workspace resolution or pages are incomplete. Additional required categories apply only when explicitly stated by a separate policy.

### azure_management_group_7_2_1_12_3f8ec01

- Resource: role_assignment
- Data source: ARM Microsoft.Authorization/roleAssignments ListForScope 2022-04-01 with atScope() and paging; compare each role-assignment properties.roleDefinitionId ARM resource ID (and properties.principalId, properties.scope) to policy prohibitedRoleDefinitionIds. Enumerate protected management-group and subscription scopes.
- Predicate: For each protected scope, compare normalized role-definition ARM IDs or their GUID segments from direct and inherited role assignments in properties.roleDefinitionId. FAIL on a prohibited grant to any principal type; PASS after complete scope enumeration and atScope() pagination prove none; UNKNOWN for policy, inheritance or paging gaps. Assignment fields are under properties.

### azure_management_group_7_2_1_13_50babe4

- Resource: role_assignment
- Data source: Paged ARM role assignments ListForScope 2022-04-01 at subscriptions and all management-group ancestors, with role definitions; read properties.roleDefinitionId, principalId, principalType and scope. Resolve each principal ID against Graph users, groups or service principals and expand groups if approvals are person-based. Policy supplies required role/scope assignments and authorized principals.
- Predicate: For every policy-required role and subscription/management-group scope, PASS only if at least one effective assignment exists to an authorized, currently resolvable user, group or service principal, and every selected-role assignment at that scope is authorized for its exact roleDefinitionId and inherited scope. FAIL for a fully resolved missing required assignment, unauthorized assignment, or deleted/nonconforming principal. UNKNOWN if required role/scope policy, ancestor pages, role definitions, principal lookup, group expansion or assignment fields are incomplete. An empty assignment set never vacuously PASSes a required assignment.

### azure_management_group_7_2_1_1_af95df1

- Resource: management_group
- Data source: ARM paged GET Microsoft.Management/managementGroups/{groupId}/descendants?api-version=2020-05-01: value[].type/name/id; paged subscriptions inventory; policy MasterManagementGroupId (expectedManagementGroupId).
- Predicate: For each in-scope subscription, PASS only if it appears as a subscription descendant of the policy MasterManagementGroupId in a fully paged descendants result. FAIL if absent after complete enumeration; UNKNOWN if the parameter, subscription scope, group access or any page is unavailable. An empty complete subscription scope is NOT_APPLICABLE.

### azure_ml_workspace_1_2_8_36_33f50db

- Resource: ml_workspace
- Data source: Paged ARM Microsoft.MachineLearningServices/workspaces/computes LIST 2024-04-01; for ComputeInstance use the compute-instance-specific properties.properties.subnet.id ARM ID where returned; policy approvedSubnetIds. Resolve workspace and compute inventory completely.
- Predicate: For every Azure ML ComputeInstance, PASS only if its documented subnet ARM ID is present and is in approvedSubnetIds. FAIL if a complete response explicitly identifies a different subnet or no VNet placement. UNKNOWN when policy, inventory, compute-specific subnet field or ID interpretation is unavailable; other compute types are outside this check.

### azure_ml_workspace_1_2_8_37_973721f

- Resource: ml_workspace
- Data source: Paged AML computes LIST 2024-04-01: properties.computeType, properties.properties.enableNodePublicIp and subnet.id; compute-instance network mode, effective subnet NSG/UDR, firewall/NAT egress and authorized outbound reachability evidence.
- Predicate: For each in-scope AML ComputeInstance, FAIL if public node IP is true or complete network evidence shows direct Internet egress. PASS only if public node IP is false and complete effective routing, firewall and outbound observations prove direct Internet access is blocked. UNKNOWN if IP flag, compute list, effective egress path or network policy is unresolved. A false public-IP flag alone cannot PASS.

### azure_nsg_world_ingress_approved_ports

- Resource: nsg
- Data source: Existing azure.py nsg.items[] GET 2023-09-01; properties.securityRules[] and defaultSecurityRules[] plus child securityRules list if parent omits them. Fields direction/access/protocol enum; sourceAddressPrefix(es), destinationPortRange(s), priority integers. Resolve service tags, ASGs and ordered denies.
- Predicate: For each NSG, expand protocol * to TCP and UDP and resolve ordered securityRules plus defaultSecurityRules, both singular/plural source and port fields, IPv4/IPv6, service tags and ASGs. FAIL if an effective inbound Allow from unrestricted world source to any TCP/UDP port outside approvedInternetPorts survives higher-priority Deny. PASS only with complete rules and expansions showing none. UNKNOWN for unresolved tags/ASGs, malformed ranges, missing approvedInternetPorts or incomplete inventory. A complete empty NSG inventory is NOT_APPLICABLE.

### azure_pci_10_2_1_1_16

- Resource: container_group
- Data source: Paged Container Instance group inventory and per-group GET 2023-05-01: properties.diagnostics.logAnalytics.workspaceId/logType plus properties.containers[]; container logging enablement from supported runtime configuration or fresh per-container log/ingestion evidence.
- Predicate: For every active container group, PASS only when a valid Log Analytics workspace is configured and at least one container definition has logging enabled with verified collection evidence. FAIL if complete group/container evidence proves workspace absent or all container logging disabled; UNKNOWN if per-container logging cannot be established, group GET is incomplete, workspace ID cannot be resolved or inventory is partial. logType alone does not establish logging in a container definition.

### azure_pci_10_2_1_1_25

- Resource: mysql_flexible_server
- Data source: Paged MySQL Flexible Server and per-server configurations LIST 2023-12-30: name=audit_log_enabled, properties.value string; per-server diagnosticSettings LIST 2021-05-01-preview: setting.properties.logs[].category=MySqlAuditLogs and enabled boolean, setting.properties.workspaceId; approved workspace policy and supported categories.
- Predicate: For each MySQL Flexible Server, PASS only if audit_log_enabled.properties.value="ON" and a diagnostic setting for that exact server enables MySqlAuditLogs to an approved setting-level workspaceId. FAIL for explicit OFF or complete configuration/settings proving no export. UNKNOWN for missing configuration, category support, workspace approval or inventory/paging.

### azure_pci_10_2_1_1_8

- Resource: activity_log_alert
- Data source: Paged ARM activityLogAlerts LIST 2020-10-01, metricAlerts LIST 2018-03-01, and scheduledQueryRules LIST 2021-08-01 for policy-scoped Azure Monitor alerts; inspect each alert type's action-group IDs, enabled state and scope. GET actionGroups 2023-01-01 when destination existence is required. Optional policy actionGroupId may narrow matching but is not universally required.
- Predicate: For every in-scope Azure Monitor alert, require at least one configured action group for its applicable Activated, Resolved or No Data action state as exposed by that alert type. If the frozen optional ARM action ID parameter is supplied, require a matching group ID. FAIL for a measured alert with no applicable action group or a nonmatching supplied ID; PASS only with complete relevant alert-family pages. UNKNOWN for unsupported alert types, state semantics, scope, or pagination. Do not require a prelisted alert ID or action-group ID by default.

### azure_pci_1_2_8_19

- Resource: app_service
- Data source: Paged ARM Microsoft.Web/sites LIST, kind includes functionapp; GET each site and Microsoft.Web/sites/config/web for properties.publicNetworkAccess, ipSecurityRestrictions, ipSecurityRestrictionsDefaultAction; read privateEndpointConnections child status and join to the exact app ID. Resolve service tags, priorities, SCM/main-site scope and approved sources.
- Predicate: For each Function App, PASS if publicNetworkAccess=Disabled and an approved private endpoint is verified, or if complete effective main-site access restrictions and default action permit only policy-approved source ranges. FAIL if complete effective ingress proves an unapproved public source can reach the app or neither an approved private endpoint nor restrictive access rules exists. UNKNOWN for missing config, unresolved service tags or endpoint status, source policy, or incomplete site/config pages. No Function Apps is NOT_APPLICABLE.

### azure_pci_1_2_8_39

- Resource: nsg
- Data source: Collected nsg.items[]: Microsoft.Network/networkSecurityGroups.properties.subnets[].id and properties.networkInterfaces[].id.
- Predicate: For each NSG, PASS when complete GET confirms at least one valid subnet or NIC association ID. FAIL when complete association evidence confirms both are empty or absent. UNKNOWN if association details or NSG inventory cannot be verified. No policy exemption for intentionally unused NSGs is inferred.

### azure_pci_1_3_1_33

- Resource: synapse_workspace
- Data source: Complete Synapse workspace and dedicated SQL-pool inventory; Synapse privateEndpointConnections LIST for connection status and privateEndpoint.id; Microsoft.Network/privateEndpoints GET for properties.privateLinkServiceConnections[].properties.groupIds and privateLinkServiceId. Join by exact endpoint ID and workspace ARM ID; follow all pages.
- Predicate: For each workspace with an in-scope dedicated SQL pool, PASS only if a complete Synapse connection list has an Approved connection whose exact privateEndpoint.id resolves to a Network private endpoint with a privateLinkServiceConnection targeting that workspace ARM ID and groupIds containing sql. FAIL if complete connection and endpoint inventories prove none. UNKNOWN if pool scope, status, exact endpoint join, groupIds or paging is incomplete. An approved endpoint for a different subresource cannot PASS.

### azure_pci_3_5_1_29

- Resource: synapse_workspace
- Data source: Paged Microsoft.Synapse/workspaces GET 2021-06-01: properties.encryption.cmk.status and key.name,keyVaultUrl; resolve full versioned or unversioned Key Vault key URI against approved keyVaultKeyId policy and verify key access.
- Predicate: For each Synapse workspace, PASS only when encryption CMK status=Consistent and the resolved Key Vault key identity equals the approved keyVaultKeyId, accounting for approved version policy. FAIL for complete CMK absence, disabled/inconsistent status or demonstrably different key. UNKNOWN for transitional status, ambiguous key URL/name resolution, missing approval, key access or incomplete inventory.

### azure_pci_3_7_4_5

- Resource: policy_assignment
- Data source: Key Vault data-plane GET /keys/{name}/rotationpolicy?api-version=7.4 for each required CMK; ARM Microsoft.Authorization/policyAssignments and policyDefinitions GET/LIST 2022-06-01 to verify effective key-rotation enforcement; roleAssignments/roleDefinitions and Key Vault access policies to verify rotation-management permissions. Page key and assignment inventories. Policy inputs requiredKeyIds and approved rotation interval.
- Predicate: For each required customer-managed Key Vault key, require a Rotate lifetimeAction with an approved valid interval, an effective Azure Policy assignment that enforces automatic rotation for that exact key ID without exemption, and an identity with necessary key rotation management permissions. FAIL if a complete response proves the action missing/over-limit, assignment ineffective, or permissions absent. PASS only if all three are verified for every key. UNKNOWN for missing key scope, duration policy, assignment conditions/exemptions, identity permissions or incomplete pages.

### azure_purview_account_a3_2_5_1_1_282bac6

- Resource: purview_account
- Data source: Purview Scanning data-plane 2023-09-01 paged data sources, scans ListByDataSource, and scan-result ListScanHistory per scan; read recurrence/schedule, scan ruleset/classification coverage and run status. Policy inputs: account applicability (administrator/member), in-scope source inventory, required sensitive-data classification rules and scan recency.
- Predicate: For applicable administrator accounts, PASS only if every in-scope data source has an enabled recurring scan configured to discover sensitive data with the required classification rules and a recent successful completed run within the approved window. FAIL if complete scans/runs/ruleset evidence proves automated sensitive discovery disabled, failed or overdue. UNKNOWN if account type, source scope, classification coverage, schedule, run history or paging is unresolved. Member accounts are NOT_APPLICABLE only when account type is verified.

### azure_purview_account_a3_2_5_1_2_6690c25

- Resource: purview_account
- Data source: Paged ARM Microsoft.Purview/accounts ListBySubscription 2021-12-01: location string, properties.provisioningState and optional properties.accountStatus.accountProvisioningState enum; policy requiredRegions and authoritative mapping of the source ENABLED status to Purview service availability.
- Predicate: For each required region, PASS only if a Purview account is present with provisioningState=Succeeded and authoritative service status evidence maps it to the frozen requirement ENABLED. FAIL if complete account inventory proves no account in the region or explicit failed/disabled service state. UNKNOWN if requiredRegions, status mapping, optional accountStatus, region normalization or pagination is unavailable. Provisioning Succeeded alone does not prove the source status.

### azure_recovery_vault_10_3_3_1_1f42f66

- Resource: sql_database
- Data source: Paged Microsoft.Sql/servers/databases LIST 2023-08-01: id, properties.status; child /backupShortTermRetentionPolicies/default GET 2023-08-01: properties.retentionDays. The retention policy is a child, not in database GET.
- Predicate: For each online Azure SQL user database, PASS when a successful child short-term retention policy GET shows a valid positive retentionDays, proving an automatic PITR backup policy. FAIL only when a complete successful read proves the policy absent or explicitly invalid. UNKNOWN if database inventory/status, child read, or retentionDays is unresolved. Exclude master/system databases; no applicable databases is NOT_APPLICABLE. A policy minimum is a separate control, not part of this frozen presence rule.

### azure_recovery_vault_10_3_3_2_5313a3c

- Resource: recovery_vault
- Data source: Collected backup_policy.items[] or recovery_vault.items[].backupPolicies[] from Microsoft.RecoveryServices/vaults/backupPolicies LIST: properties.schedulePolicy.scheduleRunFrequency and workload-specific properties.retentionPolicy schedules/durations; required minFrequency and minRetentionDays policy.
- Predicate: For each in-scope backup policy with a recognized workload schedule and retention schema, PASS if normalized backup frequency meets requiredMinimumFrequency and every required retention tier meets minimumRetentionDays; FAIL if complete, recognized schedule/retention values violate either. UNKNOWN if workload type, timezone, frequency normalization, retention tier, policy inventory or thresholds cannot be resolved.

### azure_recovery_vault_10_3_3_3_45b190e

- Resource: recovery_vault
- Data source: NEW: paged backup protected-items list per vault, then paged GET {protected-item-id}/recoveryPoints?api-version=2026-07-01 and GET each recovery point for properties.recoveryPointTime and properties.recoveryPointProperties.expiryTime where workload schema supplies them. Collector azure.py embeds protected items, not recovery points.
- Predicate: For each active protected item and each eligible retained recovery point, PASS iff full list and detail GET yield recoveryPointTime and expiryTime with interval >= minRetentionDays and at least one point exists. FAIL iff any fully measured point has shorter retention. UNKNOWN for unsupported workload point types, absent expiry on list/detail, empty/partial point list or missing policy. Exclude soft-deleted points explicitly.

### azure_recovery_vault_10_3_3_8_26e08d7

- Resource: sql_database
- Data source: Paged ARM Microsoft.Sql/servers/databases LIST and backupShortTermRetentionPolicies/default GET 2023-08-01 (properties.retentionDays); optional longTermRetentionPolicies and latest restore-point/backup evidence for declared backup-window test; policy minRetentionDays and backupWindow when supplied.
- Predicate: For each in-scope user SQL database, PASS only with complete platform backup applicability and policy/restore evidence that backups are enabled; when supplied, also verify minRetentionDays and backupWindow. FAIL for a measured disabled/unavailable backup, retention below the declared minimum, or a verified recovery point outside the declared window. UNKNOWN when database inventory, backup/policy read, optional window or restore evidence is missing. Do not treat a positive retentionDays alone as proof of a recent backup.

### azure_redis_cache_10_3_3_17_5912e19

- Resource: redis_cache
- Data source: Existing azure.py redis_cache.items[] GET 2024-11-01: sku.name enum Premium/Standard/Basic, properties.redisConfiguration["rdb-backup-enabled"] string, ["rdb-backup-frequency"] string minutes (15,30,60,360,720,1440), ["rdb-backup-max-snapshot-count"] string integer; policy minimumSnapshotSpanDays.; configured RDB storage account/container and paged blob snapshot metadata (creation/retention), approved retention days
- Predicate: For every in-scope Redis cache, FAIL if a complete GET shows a SKU without RDB backup support or RDB explicitly disabled, or complete artifact inventory proves actual snapshot retention below policy. PASS only for supported Premium caches with RDB enabled at a supported frequency and a configured storage destination containing successful readable snapshots spanning the required retention period. UNKNOWN for missing/malformed config, unreadable storage, incomplete artifact list or policy. A max-snapshot-count setting alone cannot PASS actual retention.

### azure_role_assignment_7_2_1_14_6743a56

- Resource: role_definition_and_assignment
- Data source: Paged ARM roleDefinitions and roleAssignments LIST 2022-04-01 at all relevant scopes: roleDefinition.properties.type, assignableScopes[], permissions[].actions/notActions; assignment.properties.roleDefinitionId/scope. Resolve exact role IDs and inherited assignments.
- Predicate: FAIL only when an assigned custom role has an exact permissions[].actions entry "*" and assignableScopes includes root "/". PASS when complete role and assignment inventories prove no such role. UNKNOWN for incomplete paging, role join or scope visibility. DataActions wildcards and narrower scopes are separate issues, not this frozen failure condition.

### azure_role_assignment_aks_cluster_rbac_enabled_1c8eacd

- Resource: role_definition
- Data source: Paged Microsoft.Authorization/roleDefinitions LIST 2022-04-01 at all applicable scopes: properties.type, permissions[].actions/notActions/dataActions/notDataActions, assignableScopes. No exception list is permitted by the frozen rule.
- Predicate: For every custom role definition in protected scopes, expand effective management and data permissions from permissions[].actions/dataActions minus notActions/notDataActions against the provider operation catalog. FAIL if any effective wildcard or equivalent permission set grants all actions on one Azure service or resource type, including resource-specific patterns such as Microsoft.Compute/virtualMachines/*. PASS only when complete role, scope and provider-operation inventories prove none does. UNKNOWN if scope, operation expansion, permission conditions or paging is unresolved. Approved exceptions do not override the frozen rule.

### azure_role_assignment_aks_cluster_rbac_enabled_675305a

- Resource: role_definition_and_assignment
- Data source: Collector peaso/collectors/azure.py: role_assignment and role_definition are paged ARM 2022-04-01 collections; fields roleAssignment.properties.roleDefinitionId, principalId and scope, roleDefinition.id and properties.roleName/type. New management-group/ancestor ListForScope calls if required tuple scope is outside collected subscription.
- Predicate: PASS if every policy-required exact principalId/roleDefinitionId/scope tuple is present in complete assignment inventory and the referenced custom role definition exists. FAIL if a required tuple is absent after all relevant scopes are completely listed. UNKNOWN if tuple policy, role definition, inherited scope, assignment pages or principal identity are unresolved.

### azure_role_assignment_iam_user_with_owner_permission_on_subscription_mfa_enabled_8bf88f9

- Resource: role_assignment
- Data source: Paged ARM role assignments and definitions at subscription and ancestor scopes, active PIM assignments, Graph users/groups and transitive membership, and paged Conditional Access policies including users/apps/client and location/device/platform/risk conditions, exclusions, grant controls and authentication strengths.
- Predicate: For each enabled human user with effective subscription Owner permission, PASS only if all relevant Azure-management sign-in paths are covered by effective MFA or an approved authentication strength after resolving direct/inherited/group/PIM assignments and every CA condition, exclusion and grant operator. FAIL on a proven uncovered path; UNKNOWN on incomplete membership, role definitions, PIM, CA conditions or policy pages. No applicable owners is NOT_APPLICABLE.

### azure_role_assignment_iam_user_with_write_permission_on_subscription_mfa_enabled_d1806c1

- Resource: role_assignment
- Data source: ARM Microsoft.Authorization/roleAssignments ListForScope and roleDefinitions ListForScope (principalId,roleDefinitionId,scope,permissions[].actions/notActions/dataActions/notDataActions); Microsoft Graph GET /users?$select=id,accountEnabled and /identity/conditionalAccess/policies (state,conditions.users,conditions.applications,grantControls.builtInControls).
- Predicate: For each enabled effective subscription writer, including inherited/custom roles, transitive groups and active PIM, PASS only if MFA is enforced across required Azure management sign-in contexts by effective Conditional Access or separately proven security-default behavior. FAIL if complete role and policy evaluation proves an uncovered writer. UNKNOWN if role permissions, PIM, group membership, exclusions, auth strength, client/app conditions or inventory is unresolved.

### azure_route_table_network_http_internet_access_restricted_5cd2484

- Resource: route_table
- Data source: Existing collected route_table.items[]: Microsoft.Network/routeTables.properties.routes[].properties.addressPrefix,nextHopType,nextHopIpAddress; policy input allowedDestinationCidrs for nondefault routes. Read associations separately if effective subnet reachability is claimed.
- Predicate: For each policy-scoped route table, FAIL if any user-defined route has addressPrefix 0.0.0.0/0 or ::/0, regardless of nextHopType; also FAIL if a route destination violates configured allowedDestinationCidrs. PASS only if the complete route list has no default route and every other destination meets the named policy. UNKNOWN for missing destination policy, incomplete routes or unresolved scope. This measures declared UDRs, not NAT gateways, system routes, or effective internet reachability.

### azure_search_service_10_6_3_27_ba08488

- Resource: search_service
- Data source: ARM Microsoft.Search/searchServices GET 2023-11-01 exposes service authentication only. Use paged ARM role assignments/definitions at service and index scopes to evaluate data-plane RBAC, plus paged data-plane index LIST/GET 2026-05-01-preview for permissionFilterOption and permissionFilter fields where policy requires document-level security. Policy names scoped indexes and the required access granularity; inspect API-key access and query-path authorization.
- Predicate: PASS only when every in-scope index meets the policy-defined fine-grained access level: effective approved index-scoped data-plane RBAC for index-level isolation, and document ACL/RBAC permission filtering with authorized query paths when document-level isolation is required. Also prove API keys or broader service-level roles cannot bypass the required boundary. FAIL for a fully observed index or query path that violates the required boundary. UNKNOWN when only service disableLocalAuth/authOptions is known, required granularity is unspecified, role inheritance/index metadata/query paths are unmeasured, or pages are incomplete. Entra authentication alone never proves fine-grained access control.

### azure_search_service_3_5_1_19_a3c75c0

- Resource: search_service
- Data source: Existing azure.py search_service.items[] GET 2023-11-01: properties.encryptionWithCmk.enforcement enum Enabled/Disabled/Unspecified and optional encryptionComplianceStatus enum Compliant/NonCompliant.
- Predicate: PASS only if encryptionWithCmk.enforcement="Enabled" and encryptionComplianceStatus="Compliant". FAIL if complete response explicitly reports enforcement="Disabled" or "Unspecified", or compliance="NonCompliant". UNKNOWN if either field is missing or contains an unrecognized value; this is CMK enforcement, not basic at-rest encryption.

### azure_security_pricing_compute_vm_security_configuration_vulnerabilities_remediated_64c8b1c

- Resource: vm_and_security_assessment
- Data source: Existing security_assessment and vm collections. Microsoft.Security/assessments List 2020-01-01: assessment.properties.resourceDetails.id, properties.status.code; use assessment key from name/id, not displayName.
- Predicate: For each scoped VM and configured baseline assessment key, join using properties.resourceDetails.id and assessment key. FAIL on a current Unhealthy code; PASS only if every required pair has current Healthy code; UNKNOWN on NotApplicable (which means the assessment did not run), missing key, join, assessment, stale result or collection coverage.

### azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3

- Resource: security_pricing
- Data source: Paged subscription ARM Microsoft.Security/pricings LIST 2024-01-01: value[].name and properties.pricingTier enum Free/Standard; policy requiredPlans tied to supported Defender plans.
- Predicate: For every required, supported plan, PASS if its pricing record is Standard; FAIL if it is Free or is authoritatively absent from a complete list of supported plans. UNKNOWN if requiredPlans, plan support, subscription scope or pages are unresolved. If the frozen Security Center enablement cannot be represented by the selected plan set, report UNKNOWN rather than inferring tenant-wide enablement from one Standard plan.

### azure_sql_database_sqlserver_auditing_enabled_77d6841

- Resource: sql_database
- Data source: ARM GET Microsoft.Sql/servers/databases; GET {databaseId}/providers/Microsoft.Insights/diagnosticSettings: properties.logs[].category/enabled,workspaceId; policy input requiredCategories.
- Predicate: For each in-scope Azure SQL database and each requiredCategories category, PASS if an enabled diagnostic log category is routed by its own setting to an approved Log Analytics workspace; FAIL if complete category/setting inventory proves at least one required category unexported. UNKNOWN if requiredCategories, approved workspace set, category availability, database/settings inventory or destination is incomplete.

### azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9

- Resource: sql_server_and_managed_instance
- Data source: Paged SQL servers, databases and managed instances; GET SQL server /administrators and managed instance /administrators child lists, api-version=2023-08-01, using properties.administratorType=ActiveDirectory and properties.sid UUID; resolve each database to its parent server. Optional Entra-only authentication child GET is a stricter separate signal.
- Predicate: For every in-scope SQL Database and Managed Instance, PASS only if its parent server or instance has a complete child administrator list containing an ActiveDirectory administrator with a valid sid, establishing Microsoft Entra authentication configuration. FAIL if the complete child list proves no such administrator. UNKNOWN if database/instance inventory, parent join, admin list or paging is incomplete. Do not require Entra-only authentication unless explicitly required by the source.

### azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5

- Resource: sql_database
- Data source: Collected sql_tde.items[] Microsoft.Sql/servers/databases/transparentDataEncryption/current GET 2023-08-01: properties.state; new Microsoft.Sql/managedInstances/databases LIST plus /transparentDataEncryption/current GET 2021-11-01: properties.state
- Predicate: FAIL if a complete transparentDataEncryption/current GET for any in-scope SQL or managed-instance database has properties.state="Disabled". PASS if every database has state="Enabled" and both inventories are complete. UNKNOWN if a TDE GET or state is missing, unreadable or neither recognized enum.

### azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a

- Resource: mysql_postgresql_sql_server
- Data source: Paged SQL Server, MySQL Flexible Server and PostgreSQL Flexible Server GET/LIST plus each server firewall-rules LIST, using the matching resource API version. Read SQL properties.publicNetworkAccess and flexible-server properties.network.publicNetworkAccess, every firewall rule startIpAddress/endIpAddress, SQL Allow Azure services special rule, and any applicable public trusted-service bypass. PublicNetworkAccess=Enabled alone is not proof of reachable ingress.
- Predicate: For every in-scope SQL, MySQL and PostgreSQL server, FAIL when publicNetworkAccess is Enabled and a complete effective firewall/bypass configuration admits an external public client, including an unrestricted 0.0.0.0-255.255.255.255 range or applicable Azure-service bypass. PASS when publicNetworkAccess is Disabled, or when it is Enabled but complete effective firewall evidence proves no external public client can connect. UNKNOWN when access mode, firewall rules, bypass semantics or pages are unresolved. Complete empty inventory is NOT_APPLICABLE.

### azure_storage_account_10_2_1_1_20_5914d2c

- Resource: servicebus_namespace
- Data source: Paged Service Bus namespace inventory including SKU and per-namespace Microsoft.Insights/diagnosticSettings LIST 2021-05-01-preview. Read setting-level properties.workspaceId/storageAccountId and properties.logs[].category/enabled. Verify approved sink. Supported categories include OperationalLogs and, for Premium data-plane access auditing, RuntimeAuditLogs.
- Predicate: For every Service Bus namespace, require complete diagnostic-setting pages and an approved resolvable Log Analytics or Storage destination. PASS only if OperationalLogs is enabled and routed; for Premium namespaces requiring data-plane access audit, also require RuntimeAuditLogs. FAIL if complete evidence proves a required category is absent or unrouted. UNKNOWN for unknown SKU, required audit scope, namespace/settings paging, unsupported category, sink or approval policy. Event Hub-only routing does not PASS.

### azure_storage_account_10_3_3_24_61d5e36

- Resource: storage_account_and_backup_instance
- Data source: Existing storage_account.blobContainers; new paged Microsoft.DataProtection backupVaults and backupInstances LIST 2024-04-01. Match properties.dataSourceInfo.resourceID to storage-account ARM ID, inspect policyInfo.policyId, currentProtectionState and policyInfo.policyParameters.backupDatasourceParametersList[].containersList; independently resolve any provider-supported automatic-selection policy from its documented API before using it as evidence.
- Predicate: For every scoped Blob container, join a Blob backup instance by properties.dataSourceInfo.resourceID to the storage account, require policyInfo.policyId and currentProtectionState=ProtectionConfigured, and verify exact container name in BlobBackupDatasourceParameters.containersList. If a deployment uses automatic container selection, PASS only with separately documented policy and selection evidence that proves coverage of the exact container. FAIL when complete instance and selection evidence proves it is uncovered or unprotected; UNKNOWN for missing container selection, unresolved policy details or incomplete pages.

### azure_storage_account_10_3_4_7_02943e9

- Resource: storage_account
- Data source: Paged Microsoft.Storage/storageAccounts/blobServices/default/containers LIST 2023-05-01, each container GET and immutabilityPolicies/default GET, plus storage-account GET 2023-05-01: container properties.immutableStorageWithVersioning.enabled, properties.immutabilityPolicy, account properties.immutabilityPolicy. Resolve effective container-level or inherited account/container default version-level retention policy and its period/state.
- Predicate: For every in-scope Blob container, PASS only if a complete read proves that newly written blobs or versions inherit an effective default immutability policy with a positive retention period, either at container scope or via a supported account/container default version-level policy. immutableStorageWithVersioning.enabled alone cannot PASS. FAIL if complete account/container/policy reads prove no effective default immutability policy. UNKNOWN if container inventory, policy inheritance, policy state, period or child reads are unresolved. Complete empty container inventory is NOT_APPLICABLE.

### azure_storage_account_10_5_1_13_2f5d4f6

- Resource: storage_account
- Data source: Paged ARM storageAccounts and blobServices/default GET 2023-05-01: blob service properties.isVersioningEnabled; paged blobContainers LIST for applicable containers; managementPolicies/default GET 2023-05-01: properties.policy.rules[].enabled/type/definition.filters and definition.actions.baseBlob/snapshot/version.
- Predicate: For each container in a versioning-enabled account, PASS only when an enabled Lifecycle rule has a supported action and its blobTypes, case-sensitive prefixMatch and blobIndexMatch filters are proven to cover the required blobs/versions in that container. A prefix for a different container, or a narrower path, is not full-container coverage; a tag filter needs blob-tag evidence. FAIL when complete policy and applicable-blob evidence prove no rule applies. UNKNOWN when blob population/tags, filters, action validity, versioning, or inventories are unresolved. No versioned containers is NOT_APPLICABLE.

### azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3

- Resource: storage_account
- Data source: Paged Blob container LIST/GET and storage account GET 2023-05-01; container properties.defaultEncryptionScope and denyEncryptionScopeOverride; account properties.encryption.keySource/keyVaultProperties; account encryptionScopes child LIST/GET with source and keyVaultProperties; resolve effective scope for each container and any permitted per-blob override.
- Predicate: For every scoped container, prove that every existing blob is encrypted with an Azure Key Vault key. Resolve the container default encryption scope, account default key, and any per-blob encryption-scope override; defaults alone cannot prove the keys of pre-existing objects. PASS only when complete blob-level scope/key evidence or an authoritative equivalent proves all existing objects use Key Vault keys and new writes cannot use a platform-managed key. FAIL on a measured blob with a Microsoft.Storage key or an effective mandatory platform-managed scope. UNKNOWN when override use, historical blob scope, scope source, key reference or container/account inventory is unresolved.

### azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa

- Resource: metric_alert
- Data source: Paged ARM Microsoft.Insights/metricAlerts ListBySubscription 2018-03-01: properties.enabled (boolean), scopes (resource IDs), criteria.allOf[].metricName/metricNamespace and criterion type; policy input specifies in-scope resource IDs and exact metric names. Follow nextLink.
- Predicate: For each policy-specified resource ID and metric, PASS if an enabled metric alert covers that exact resource and metric. FAIL if complete alert/resource inventories show no active matching alert. UNKNOWN if metric/resource policy, dynamic criteria interpretation, scope or pagination is unresolved. No specified resources is NOT_APPLICABLE.

### azure_storage_account_sqlserver_auditing_enabled_e4e4b28

- Resource: synapse_workspace
- Data source: New Synapse dedicated SQL pool auditing settings: ARM Microsoft.Synapse/workspaces/sqlPools/auditingSettings/default GET 2021-06-01 for each dedicated pool, properties.state enum Enabled/Disabled, storageEndpoint string; existing azure.py synapse_workspace.items[] and storage_account.items[] properties.primaryEndpoints.blob; policy requiredStorageAccountId. Workspace-level endpoint alone is insufficient for dedicated SQL pools.
- Predicate: For every dedicated Synapse SQL pool, PASS if its effective auditing setting is Enabled and storageEndpoint exactly resolves to required storage account blob endpoint. FAIL if complete pool/audit setting shows Disabled or a different endpoint. UNKNOWN if SQL pool inventory, endpoint resolution, policy or audit GET unavailable; no dedicated pools is not applicable.

### azure_storage_account_storage_blob_public_access_level_is_disabled_4211794

- Resource: storage_account
- Data source: Collected storage_account.items[]: Microsoft.Storage/storageAccounts.properties.allowBlobPublicAccess,publicNetworkAccess,networkAcls.defaultAction; policy input expectedSettings for each named field.
- Predicate: For each storage account, compare every applicable policy-named field in expectedSettings against the typed API value: allowBlobPublicAccess boolean, publicNetworkAccess enum Enabled/Disabled/SecuredByPerimeter, networkAcls.defaultAction Allow/Deny. Apply documented API defaults where fields are omitted; never treat omission as inherently secure. FAIL on a measured mismatch, PASS only for complete field and inventory coverage, UNKNOWN for missing policy, unsupported enum, unknown applicability or incomplete inventory.

### azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_3f8ed7f

- Resource: storage_container
- Data source: Paged storage account/container inventory, blobContainers GET/LIST 2023-05-01 for properties.publicAccess; ARM roleAssignments/roleDefinitions/denyAssignments 2022-04-01 including conditions and inherited scopes; transitive principal membership, home tenant IDs, issued SAS/account-key access evidence and approved same-account policy.
- Predicate: FAIL when a proven effective container access path grants an unapproved cross-tenant principal or public access contrary to the approved account policy. PASS only when container public access, RBAC/ACL, group membership, SAS and account-key paths are completely measured and every effective cross-tenant path conforms to the specified account policy. UNKNOWN for unenumerable SAS/key grants or unresolved tenant, condition, group or policy; RBAC grants alone cannot prove PASS.

### azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9

- Resource: eventgrid_subscription
- Data source: New paged ARM GET /subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01 or existing storage_account collector; per account new paged GET {accountId}/providers/Microsoft.EventGrid/eventSubscriptions?api-version=2022-06-15. Response properties.filter.includedEventTypes string[] (empty/default semantics must be resolved), properties.destination.endpointType enum and destination resourceId when the destination kind has one; follow nextLink.
- Predicate: For each policy-scoped storage account, PASS only when complete Event Grid child-subscription data proves the configured expected event types and approved exact destination type/ID, with successful provisioning. FAIL on a proven absent or mismatched event subscription; UNKNOWN if expected event types/destinations, includedEventTypes default semantics, destination field for its endpointType, provisioning state or pagination is unresolved. Empty policy inputs are UNKNOWN.

### azure_storage_file_share_10_3_3_15_f2d7075

- Resource: storage_file_share_and_backup_item
- Data source: Paged Microsoft.Storage/storageAccounts/fileServices/default/shares LIST api-version=2023-05-01 for every scoped storage account; paged Microsoft.RecoveryServices/vaults/backupProtectedItems LIST api-version=2024-04-01 across all accessible scoped vaults. Join protectedItem.properties.sourceResourceId to the parent account ID, friendlyName to share name, and protectedItemType=AzureFileShareProtectedItem; read policyId and protectionState.
- Predicate: For every enumerated Azure Files share, PASS only if exactly one protected item joins on normalized storage-account ID plus share name, policyId is nonempty, and protectionState="Protected". FAIL if complete share and all-vault inventories prove no matching protected item, a unique match has no policyId, or its state is ProtectionStopped, ProtectionError, ProtectionPaused or BackupsSuspended. UNKNOWN for duplicates, IRPending/Invalid/unrecognized state, missing join fields, inaccessible vaults or incomplete pages. A complete empty share inventory is NOT_APPLICABLE.

### azure_storage_file_share_10_3_3_18_d67ab34

- Resource: storage_file_share_and_netapp_volume
- Data source: Paged ARM storageAccounts/fileServices/shares LIST and every Recovery Services vault backupProtectedItems LIST 2024-04-01: properties.sourceResourceId (storage account ID), friendlyName (share name), protectedItemType, protectionState, policyId; NetApp volumes GET/LIST 2026-01-01: properties.dataProtection.backup.backupPolicyId/backupVaultId/policyEnforced. Resolve backup policy and vault existence.
- Predicate: For each Azure File Share, require one uniquely matched AzureFileShareProtectedItem by account sourceResourceId plus friendlyName and type, with protectionState=Protected and a valid policyId. For each NetApp volume, require backupPolicyId, backupVaultId and policyEnforced=true with resolvable policy/vault. FAIL on a proven unprotected resource; PASS only with complete share, volume, vault, protected-item and policy paging; UNKNOWN for ambiguous joins or unavailable state.

### azure_storage_file_share_3_5_1_15_17dc7f4

- Resource: storage_file_share
- Data source: Paged storageAccounts LIST/GET 2023-05-01: properties.encryption.keySource, keyVaultProperties.keyVaultUri/keyName/keyVersion/currentVersionedKeyIdentifier, services.file.enabled; policy approved full Key Vault key IDs (or explicit URI/name/version tuple).
- Predicate: For each in-scope Azure Files storage account, PASS only if file encryption is enabled and keySource=Microsoft.Keyvault and the resolved Key Vault key ID (vault URI plus key name and applicable version) matches an approved key. FAIL on an observed disabled Files service, different key source or resolved unapproved key; UNKNOWN if approved IDs, URI/name/version, Files encryption state or account inventory is unresolved. No per-share CMK is inferred.

### azure_synapse_workspace_10_2_1_1_28_47f4840

- Resource: synapse_workspace
- Data source: Paged Synapse workspaces and sqlPools 2021-06-01; workspace GET properties.encryption.cmk.key.name and key-vault key metadata/ID resolution; per SQL pool GET /blobAuditingPolicies/default 2021-06-01: properties.state,storageEndpoint/storageAccountAccessKey or managed identity configuration. Policy requiredKeyId and required audit sink.
- Predicate: For each in-scope Synapse workspace and dedicated SQL pool, PASS only if CMK encryption is enabled and the workspace key name resolves to the exact requiredKeyId and the pool child blob auditing policy has properties.state=Enabled with a valid approved sink. FAIL for explicitly disabled encryption, a proven different key, or a complete child policy with state Disabled. UNKNOWN for absent requiredKeyId, unresolved name-to-ID, missing key details, SQL pool inventory, audit child read or sink evidence. Never infer pool auditing from workspace GET.

### azure_synapse_workspace_10_3_3_22_15e4d4e

- Resource: synapse_workspace
- Data source: Paged Synapse SQL pool and restorePoints LIST 2021-06-01: restorePointType and creation time, plus authoritative service retention policy/evidence for each pool; policy minimumRetentionDays and maximumRetentionDays. Microsoft documents built-in automatic restore point retention as seven days and not user-configurable; restore-point LIST does not expose a configured retentionDays field.
- Predicate: PASS only if authoritative retention evidence for each in-scope dedicated SQL pool proves automatic snapshots are enabled and the service retention duration lies within both policy minimumRetentionDays and maximumRetentionDays. FAIL only for proven disabled automatic snapshots or a proven duration outside either bound or zero. UNKNOWN when policy bounds, applicability, retention evidence, pool state or paging is unavailable. A recent CONTINUOUS restore point is supplementary evidence and cannot establish retention duration.

### azure_synapse_workspace_1_2_8_29_fcdc827

- Resource: synapse_workspace
- Data source: Paged Synapse workspace and dedicated sqlPools inventory at api-version=2021-06-01; workspace properties.publicNetworkAccess enum Enabled/Disabled. SQL pool resources do not supply an independent publicNetworkAccess field in this API version.
- Predicate: For every workspace containing an in-scope dedicated SQL pool, FAIL if workspace properties.publicNetworkAccess=Enabled; PASS only if it is Disabled. UNKNOWN if pool enumeration, workspace GET or the enum value is unresolved. Firewall rules and private endpoints do not change the frozen source decision.

### azure_vault_10_3_2_3_922adc4

- Resource: log_analytics_workspace
- Data source: Existing log_analytics_workspace; add paged clusters list plus GET. Microsoft.OperationalInsights/workspaces GET 2023-09-01: properties.features.clusterResourceId; Microsoft.OperationalInsights/clusters GET 2023-09-01: properties.keyVaultProperties.keyVaultUri,keyName,keyVersion; policy approvedKeyVaultKeyIds
- Predicate: For every scoped Log Analytics workspace, resolve properties.features.clusterResourceId to a dedicated cluster and form the full Key Vault key ID from keyVaultUri, keyName and keyVersion when pinned. PASS only if cluster encryption is provisioned and active, the key ID matches approvedKeyVaultKeyIds, and key availability/access for the cluster identity are verified. FAIL if complete evidence proves no cluster link, no CMK or an unapproved key. UNKNOWN for missing approval policy, unresolved cluster/key/identity/access, provisioning state or incomplete workspace/cluster inventory. A complete empty workspace inventory is NOT_APPLICABLE.

### azure_vault_3_7_1_2_532ecd2

- Resource: key_vault_certificate
- Data source: Paged Key Vault data-plane GET /certificates and GET /certificates/{name} current issued version, with X.509 certificate bytes or backing public key used to measure actual RSA modulus. Optional GET /certificates/{name}/policy?api-version=7.4 supplies future-issuance context only.
- Predicate: For every current RSA or RSA-HSM certificate, require the actual issued X.509 public key modulus to be at least 2048 bits. FAIL on a measured smaller issued RSA key; PASS when every current RSA certificate is measured at least 2048 bits with complete inventory. UNKNOWN for unreadable current version, key type/size or incomplete pages; EC certificates are NOT_APPLICABLE. Renewal policy key_props.key_size is supporting future-issuance context and cannot substitute for the issued key measurement.

### azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3

- Resource: key_vault_certificate
- Data source: Key Vault data plane GET /certificates?api-version=7.4 (paged), then GET /certificates/{name}?api-version=7.4 for current version: attributes.enabled boolean, attributes.exp integer Unix seconds; policy expirationWithinDays.
- Predicate: For each currently enabled certificate from complete paged /certificates enumeration, GET its current version. PASS when attributes.exp is an integer Unix timestamp later than scanTime plus the approved expirationWithinDays. FAIL when a complete current certificate has no expiry or is within that window. UNKNOWN if the threshold, pages, current-version resolution or authorization is missing. No enabled certificates is NOT_APPLICABLE.

### azure_vault_keyvault_non_rbac_secret_expiration_set_0041351

- Resource: key_vault_secret
- Data source: Key Vault data-plane paged GET {vaultUri}/secrets?api-version=7.4 yields base secret IDs and attributes.enabled. Query complete AzureDiagnostics Key Vault AuditEvent history for policy unusedForDays using OperationName, ResultType, TimeGenerated and audited secret URI; match all versions by normalized vault and base secret name. Resolve versioned IDs only when an audit record requires it.
- Predicate: For each enabled base secret in a complete paged /secrets inventory, PASS if complete AuditEvent history within the policy window contains a successful SecretGet for that vault and secret name, regardless of version. FAIL only when diagnostic collection and retention cover the entire window, audit identifiers and success semantics are comparable, and no successful matching read exists. UNKNOWN if audit URI/name, timestamp/status, diagnostic route/retention, query completeness, window or secret inventory is unresolved. Aggregate definite FAIL before UNKNOWN.

### azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7

- Resource: key_vault_secret
- Data source: NEW: paged Key Vault data-plane GET /secrets?api-version=7.4 to enumerate names and current metadata; paged GET /secrets/{name}/versions?api-version=7.4 to confirm current version and created/ enabled attributes. Collector azure.py has no secret list.
- Predicate: For each in-scope enabled current secret, PASS iff the current version attributes.created (Unix seconds) is within maxDaysSinceRotation; FAIL iff its current enabled version is older. UNKNOWN if current version status, creation timestamp, name list, version list, vault scope or policy is incomplete. A newer disabled version does not count; a recent old version does not prove current rotation.

### azure_vault_keyvault_rbac_enabled_0179c48

- Resource: role_definition
- Data source: ARM Microsoft.Authorization/roleDefinitions ListForScope 2022-04-01; exact fields: Microsoft.Authorization/roleDefinitions[].properties.permissions[].actions,notActions,dataActions,notDataActions; parameter blockedKeyVaultActions.
- Predicate: For each in-scope managed custom RBAC role/policy assigned or assignable to Azure Key Vault keys, expand actions/dataActions and subtract notActions/notDataActions using provider operation semantics. FAIL if an effective operation matches blockedKeyVaultActions. PASS only when complete definitions, applicable scopes/assignments and policy prove no blocked effective operation. UNKNOWN if the prohibited action set, operation catalogue, wildcard expansion, conditions or assignment/scope inventory is unresolved.

### azure_vm_1_2_8_10_1bd35d0

- Resource: guest_configuration_assignment
- Data source: Paged Microsoft.Automation/automationAccounts/nodes LIST 2024-10-23 per account using $skip/$top and totalCount; properties.status string, nodeConfiguration.name optional string, lastSeen optional date-time. Join policy-required node IDs to properties.nodeId; policy maxHeartbeatAge.
- Predicate: For every required DSC node, PASS if a complete node record reports status=Compliant, a nonempty nodeConfiguration.name and lastSeen within maxHeartbeatAge. FAIL if a fresh node reports NotCompliant or a fresh complete node record confirms no assigned configuration. UNKNOWN for missing node, any other/unrecognized status, stale/missing lastSeen, incomplete $skip/$top pages, or absent node/age policy. No required nodes is NOT_APPLICABLE.

### azure_vm_1_4_5_1_d40be43

- Resource: vm_and_vm_scale_set
- Data source: Paged ARM virtualMachines GET/LIST 2024-07-01 (networkProfile.networkInterfaces[].id); networkInterfaces GET 2023-09-01 (ipConfigurations[].properties.publicIPAddress.id); virtualMachineScaleSets GET/LIST 2024-07-01 (virtualMachineProfile.networkProfile.networkInterfaceConfigurations[].properties.ipConfigurations[].properties.publicIPAddressConfiguration). VMSS instance NICs provide a separate drift signal.
- Predicate: For each in-scope VM NIC and each VMSS NIC template, FAIL if a NIC ipConfiguration has publicIPAddress.id or a template has publicIPAddressConfiguration. PASS when complete VM, NIC and VMSS template inventories have none. UNKNOWN for unresolved NIC references, absent ipConfiguration details or incomplete paging. Inspect VMSS instance NICs separately for runtime drift, but instance drift alone does not change the frozen default-configuration result.

### azure_vm_8_2_1_1_712e1ad

- Resource: vm
- Data source: Paged Microsoft.Compute/virtualMachines GET and instanceView 2023-09-01: properties.storageProfile.osDisk.osType, osProfile.linuxConfiguration.disablePasswordAuthentication, ssh.publicKeys[] and running state.
- Predicate: For each running Linux VM, observe storageProfile.osDisk.osType, linuxConfiguration.disablePasswordAuthentication and ssh.publicKeys, but return UNKNOWN for the overall mapped requirement until the contradictory frozen rule is resolved: its text marks a VM launched with a public SSH key NON_COMPLIANT while its title asks for SSH keys. A key-bearing VM and a password-enabled VM cannot safely receive PASS or FAIL from this contradictory requirement. Missing state or incomplete paging is also UNKNOWN. No applicable running Linux VMs is NOT_APPLICABLE.

### azure_vm_app_function_identity_is_configured_bdb10d4

- Resource: vm
- Data source: Collector peaso/collectors/azure.py: vm GET 2023-09-01 is collected; identity.type enum None/SystemAssigned/UserAssigned/SystemAssigned, UserAssigned; identity.principalId string and identity.userAssignedIdentities object keyed by ARM identity ID. Complete VM inventory and GET status required.
- Predicate: PASS if each in-scope VM has identity.type including SystemAssigned with a nonempty principalId, or including UserAssigned with at least one valid ARM identity ID key in identity.userAssignedIdentities. FAIL if a complete VM GET has no identity, type=None, or lacks the corresponding identity reference. UNKNOWN if VM detail, identity type or identity map is unreadable; a null value for a valid userAssignedIdentities map entry is allowed.

### azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679

- Resource: vm
- Data source: Collected vm.items[].id; Microsoft.Insights/diagnosticSettings LIST on each VM: properties.metrics[].category,enabled; properties.workspaceId; paged, complete VM inventory and diagnostic metric-category support
- Predicate: For every Azure VM in the complete inventory, PASS if a complete per-VM diagnostic settings list contains enabled AllMetrics (or every supported required metric category) routed to a verified destination. FAIL when complete settings prove no required performance metric export. UNKNOWN if VM enumeration, metric support, settings or destination is unresolved. An empty complete VM inventory is NOT_APPLICABLE.

### azure_vm_vm_ensure_using_managed_disks_11f205b

- Resource: disk_and_vm
- Data source: Paged Microsoft.Compute/disks GET 2023-10-02: top-level managedBy, managedByExtended[], properties.maxShares, diskState and id; paged VM GET: properties.storageProfile.osDisk.managedDisk.id, dataDisks[].managedDisk.id and attachment deleteOption; policy expectedDiskVmIds and optional deleteWithVm.
- Predicate: For each policy-required disk-to-VM attachment, PASS when the VM references the disk ID and the disk reports that VM in managedBy for a single attachment or in managedByExtended for a shared disk with maxShares>1. When deleteWithVm is required, verify the applicable VM attachment deleteOption=Delete; if incompatible with shared-disk semantics, report UNKNOWN pending policy clarification. FAIL for a complete mismatch, detached disk, missing required disk or wrong explicit delete option. UNKNOWN for absent expected mapping, missing/ambiguous attachment fields, share semantics or incomplete pages. Unmapped disks are outside scope.

### azure_vnet_gateway_10_2_1_1_14_4189d89

- Resource: vnet_gateway
- Data source: Paged ARM Microsoft.Network/virtualNetworkGateways inventory 2023-09-01; separately LIST {gatewayId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview. Read setting.properties.logs[].category/.enabled and setting.properties.workspaceId or approved eventHub/storage destination.
- Predicate: For each VPN gateway supporting point-to-site client connections, PASS only if a complete child diagnostic-setting list has P2SDiagnosticLog enabled with an approved nonempty destination on the same setting. FAIL if the complete list proves none; UNKNOWN for unsupported gateway applicability, missing destination policy, incomplete gateway/settings lists or unreadable status. GatewayDiagnosticLog and TunnelDiagnosticLog do not prove client connection logging.

### azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc

- Resource: vnet_gateway
- Data source: Paged ARM Microsoft.Network/virtualNetworkGateways LIST and per-gateway GET 2026-01-01; properties.ipConfigurations[].properties.subnet.id; parameter approvedVnetIds.
- Predicate: For every virtual network gateway, require a complete nonempty properties.ipConfigurations list and resolve each properties.ipConfigurations[].properties.subnet.id to its parent VNet. FAIL if a fully observed gateway has a subnet in a VNet outside approvedVnetIds. PASS if every observed gateway subnet resolves to an approved VNet. UNKNOWN if approvedVnetIds, ipConfigurations/subnet ID, subnet parsing or gateway inventory is missing or incomplete. Complete empty gateway inventory is NOT_APPLICABLE.

