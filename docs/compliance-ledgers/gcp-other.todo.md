# gcp-other compliance checklist

## ccc_gcp

- [x] ccc_gcp CCC.Core.CN01.AR01 - PARTIAL - gcp.ports.reference_sql_ssl_connections, gcp.claude.target_proxy.https_min_tls_1_2
- [x] ccc_gcp CCC.Core.CN01.AR02 - MANUAL - none
- [x] ccc_gcp CCC.Core.CN01.AR03 - MANUAL - none
- [x] ccc_gcp CCC.Core.CN01.AR07 - MANUAL - none
- [ ] ccc_gcp CCC.Core.CN01.AR08 - PARTIAL - none
- [ ] ccc_gcp CCC.Core.CN13.AR01 - PARTIAL - none
- [ ] ccc_gcp CCC.Core.CN13.AR02 - PARTIAL - none
- [ ] ccc_gcp CCC.Core.CN13.AR03 - PARTIAL - none
- [ ] ccc_gcp CCC.Core.CN06.AR01 - PARTIAL - none
- [ ] ccc_gcp CCC.Core.CN06.AR02 - PARTIAL - none
- [x] ccc_gcp CCC.Core.CN08.AR01 - PARTIAL - gcp.sql.backups
- [ ] ccc_gcp CCC.Core.CN08.AR02 - PARTIAL - none
- [x] ccc_gcp CCC.Core.CN09.AR01 - PARTIAL - gcp.claude.bucket.log_sink_not_public
- [x] ccc_gcp CCC.Core.CN09.AR02 - MANUAL - none
- [x] ccc_gcp CCC.Core.CN09.AR03 - MANUAL - none
- [ ] ccc_gcp CCC.Core.CN10.AR01 - PARTIAL - none
- [ ] ccc_gcp CCC.Core.CN02.AR01 - PARTIAL - gcp.claude.instance.disks_csek, gcp.claude2.bigquery_dataset.default_cmek, gcp.ports.bigquery_table_encrypted_with_cmk, gcp.ports.dataproc_cluster_encryption_with_cmek
- [ ] ccc_gcp CCC.Core.CN11.AR01 - NEW_CHECK - none
- [x] ccc_gcp CCC.Core.CN11.AR02 - PARTIAL - gcp.reviewed.kms.rotation_90_days
- [x] ccc_gcp CCC.Core.CN11.AR03 - PARTIAL - gcp.claude2.bigquery_dataset.default_cmek, gcp.ports.bigquery_table_encrypted_with_cmk, gcp.ports.dataproc_cluster_encryption_with_cmek, gcp.reviewed.bigquery.cmek, gcp.reviewed.sql.cmek
- [x] ccc_gcp CCC.Core.CN11.AR04 - PARTIAL - gcp.ports.kms_key_separation_of_duties_enforced, gcp.reviewed.kms.no_public_iam
- [x] ccc_gcp CCC.Core.CN11.AR05 - PARTIAL - gcp.reviewed.kms.rotation_90_days
- [x] ccc_gcp CCC.Core.CN11.AR06 - PARTIAL - gcp.reviewed.kms.rotation_90_days
- [x] ccc_gcp CCC.Core.CN14.AR01 - MANUAL - none
- [ ] ccc_gcp CCC.Core.CN14.AR02 - PARTIAL - gcp.sql.backups
- [ ] ccc_gcp CCC.Core.CN14.AR03 - PARTIAL - gcp.sql.backups
- [x] ccc_gcp CCC.Core.CN03.AR01 - PARTIAL - gcp.reviewed.project.os_login_2fa
- [x] ccc_gcp CCC.Core.CN03.AR02 - MANUAL - none
- [x] ccc_gcp CCC.Core.CN03.AR03 - PARTIAL - gcp.reviewed.project.os_login_2fa
- [x] ccc_gcp CCC.Core.CN03.AR04 - MANUAL - none
- [x] ccc_gcp CCC.Core.CN05.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Core.CN05.AR02 - MANUAL - none
- [x] ccc_gcp CCC.Core.CN05.AR03 - PARTIAL - gcp.claude.project.storage_vpc_service_controls
- [x] ccc_gcp CCC.Core.CN05.AR04 - PARTIAL - gcp.claude.project.storage_vpc_service_controls, gcp.claude.sql_instance.second_gen_no_public_ip, gcp.compute.no_external_ip, gcp.ports.sql_instance_not_open_to_internet, gcp.reviewed.bigquery.no_public_acl, gcp.reviewed.kms.no_public_iam, gcp.storage.no_public_iam
- [x] ccc_gcp CCC.Core.CN05.AR05 - MANUAL - none
- [x] ccc_gcp CCC.Core.CN05.AR06 - MANUAL - none
- [x] ccc_gcp CCC.Core.CN04.AR01 - PARTIAL - gcp.claude.project.audit_logs_configured
- [x] ccc_gcp CCC.Core.CN04.AR02 - PARTIAL - gcp.claude.logging.project_sink_all_entries, gcp.claude.project.audit_logs_configured, gcp.claude.project.storage_data_access_audit_logs, gcp.reviewed.storage.access_logging
- [x] ccc_gcp CCC.Core.CN04.AR03 - PARTIAL - gcp.claude.logging.project_sink_all_entries, gcp.claude.project.audit_logs_configured, gcp.claude.project.storage_data_access_audit_logs, gcp.reviewed.storage.access_logging
- [ ] ccc_gcp CCC.Core.CN07.AR01 - NEW_CHECK - none
- [x] ccc_gcp CCC.Core.CN07.AR02 - PARTIAL - gcp.claude.project.audit_logs_configured
- [x] ccc_gcp CCC.AuditLog.CN01.AR01 - MANUAL - none
- [x] ccc_gcp CCC.AuditLog.CN01.AR02 - MANUAL - none
- [x] ccc_gcp CCC.AuditLog.CN02.AR01 - PARTIAL - gcp.claude.logging.project_sink_all_entries, gcp.claude.project.audit_logs_configured
- [x] ccc_gcp CCC.AuditLog.CN03.AR01 - PARTIAL - gcp.claude.logging.metric_alert_audit_configuration_changes
- [x] ccc_gcp CCC.AuditLog.CN03.AR02 - MANUAL - none
- [x] ccc_gcp CCC.AuditLog.CN04.AR01 - MANUAL - none
- [x] ccc_gcp CCC.AuditLog.CN05.AR01 - MANUAL - none
- [x] ccc_gcp CCC.AuditLog.CN06.AR01 - MANUAL - none
- [x] ccc_gcp CCC.AuditLog.CN07.AR01 - MANUAL - none
- [x] ccc_gcp CCC.AuditLog.CN08.AR01 - PARTIAL - gcp.claude.bucket.log_sink_retention_locked
- [x] ccc_gcp CCC.AuditLog.CN09.AR01 - MANUAL - none
- [x] ccc_gcp CCC.AuditLog.CN10.AR01 - PARTIAL - gcp.storage.no_public_iam, gcp.storage.uniform_access
- [x] ccc_gcp CCC.AuditLog.CN10.AR02 - PARTIAL - gcp.storage.no_public_iam, gcp.storage.uniform_access
- [x] ccc_gcp CCC.Logging.CN01.AR01 - PARTIAL - gcp.claude.logging.project_sink_all_entries, gcp.claude.project.audit_logs_configured, gcp.reviewed.network.flow_logs
- [x] ccc_gcp CCC.Logging.CN01.AR02 - PARTIAL - gcp.ports.compute_url_map_backend_logging
- [x] ccc_gcp CCC.Logging.CN02.AR01 - PARTIAL - gcp.claude.bucket.log_sink_retention_locked, gcp.claude.bucket.retention_90_days
- [x] ccc_gcp CCC.Logging.CN02.AR02 - MANUAL - none
- [x] ccc_gcp CCC.Logging.CN03.AR01 - PARTIAL - gcp.claude.bucket.log_sink_retention_locked
- [x] ccc_gcp CCC.Logging.CN04.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Logging.CN05.AR01 - PARTIAL - gcp.storage.no_public_iam, gcp.storage.uniform_access
- [x] ccc_gcp CCC.Logging.CN05.AR02 - PARTIAL - gcp.storage.no_public_iam, gcp.storage.uniform_access
- [ ] ccc_gcp CCC.Logging.CN06.AR01 - NEW_CHECK - none
- [x] ccc_gcp CCC.Logging.CN07.AR01 - PARTIAL - gcp.claude.logging.metric_alert_audit_configuration_changes
- [x] ccc_gcp CCC.Monitor.CN01.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Monitor.CN02.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Monitor.CN03.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Monitor.CN04.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Monitor.CN05.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Monitor.CN06.AR01 - MANUAL - none
- [x] ccc_gcp CCC.ObjStor.CN01.AR01 - MANUAL - none
- [x] ccc_gcp CCC.ObjStor.CN01.AR02 - MANUAL - none
- [x] ccc_gcp CCC.ObjStor.CN01.AR03 - MANUAL - none
- [x] ccc_gcp CCC.ObjStor.CN01.AR04 - MANUAL - none
- [x] ccc_gcp CCC.ObjStor.CN03.AR01 - PARTIAL - gcp.reviewed.storage.soft_delete
- [x] ccc_gcp CCC.ObjStor.CN03.AR02 - MANUAL - none
- [x] ccc_gcp CCC.ObjStor.CN04.AR01 - MANUAL - none
- [x] ccc_gcp CCC.ObjStor.CN04.AR02 - MANUAL - none
- [x] ccc_gcp CCC.ObjStor.CN05.AR01 - PARTIAL - gcp.reviewed.storage.versioning
- [x] ccc_gcp CCC.ObjStor.CN05.AR02 - PARTIAL - gcp.reviewed.storage.versioning
- [x] ccc_gcp CCC.ObjStor.CN05.AR03 - PARTIAL - gcp.reviewed.storage.versioning
- [x] ccc_gcp CCC.ObjStor.CN05.AR04 - PARTIAL - gcp.reviewed.storage.versioning
- [x] ccc_gcp CCC.ObjStor.CN07.AR01 - NOT_APPLICABLE - none
- [x] ccc_gcp CCC.ObjStor.CN07.AR02 - NOT_APPLICABLE - none
- [x] ccc_gcp CCC.ObjStor.CN07.AR03 - PARTIAL - gcp.claude.project.storage_data_access_audit_logs
- [x] ccc_gcp CCC.ObjStor.CN02.AR01 - PARTIAL - gcp.storage.uniform_access
- [x] ccc_gcp CCC.ObjStor.CN02.AR02 - PARTIAL - gcp.storage.uniform_access
- [ ] ccc_gcp CCC.LB.CN01.AR01 - PARTIAL - none
- [x] ccc_gcp CCC.LB.CN01.AR02 - MANUAL - none
- [x] ccc_gcp CCC.LB.CN06.AR01 - MANUAL - none
- [x] ccc_gcp CCC.LB.CN04.AR01 - PARTIAL - gcp.claude.project.audit_logs_configured
- [ ] ccc_gcp CCC.LB.CN05.AR01 - PARTIAL - none
- [ ] ccc_gcp CCC.LB.CN09.AR01 - PARTIAL - none
- [ ] ccc_gcp CCC.LB.CN02.AR01 - PARTIAL - none
- [ ] ccc_gcp CCC.LB.CN07.AR01 - NEW_CHECK - none
- [ ] ccc_gcp CCC.LB.CN08.AR01 - PARTIAL - none
- [x] ccc_gcp CCC.VPC.CN01.AR01 - PARTIAL - gcp.reviewed.network.no_default_vpc
- [x] ccc_gcp CCC.VPC.CN02.AR01 - PARTIAL - gcp.compute.no_external_ip
- [ ] ccc_gcp CCC.VPC.CN03.AR01 - NEW_CHECK - none
- [x] ccc_gcp CCC.VPC.CN04.AR01 - PARTIAL - gcp.reviewed.network.flow_logs
- [ ] ccc_gcp CCC.KeyMgmt.CN01.AR01 - PARTIAL - none
- [x] ccc_gcp CCC.KeyMgmt.CN02.AR01 - PARTIAL - gcp.ports.kms_key_separation_of_duties_enforced, gcp.reviewed.kms.no_public_iam
- [x] ccc_gcp CCC.KeyMgmt.CN03.AR01 - PARTIAL - gcp.reviewed.kms.rotation_90_days
- [x] ccc_gcp CCC.KeyMgmt.CN04.AR01 - MANUAL - none
- [x] ccc_gcp CCC.SecMgmt.CN01.AR01 - MANUAL - none
- [x] ccc_gcp CCC.SecMgmt.CN02.AR01 - MANUAL - none
- [x] ccc_gcp CCC.DataWar.CN01.AR01 - MANUAL - none
- [x] ccc_gcp CCC.DataWar.CN02.AR01 - MANUAL - none
- [x] ccc_gcp CCC.DataWar.CN03.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Vector.CN01.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Vector.CN02.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Vector.CN03.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Vector.CN04.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Vector.CN05.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Vector.CN06.AR01 - MANUAL - none
- [x] ccc_gcp CCC.Vector.CN07.AR01 - MANUAL - none
- [x] ccc_gcp CCC.RDMS.CN01.AR02 - MANUAL - none
- [ ] ccc_gcp CCC.RDMS.CN02.AR01 - PARTIAL - none
- [x] ccc_gcp CCC.RDMS.CN04.AR01 - MANUAL - none
- [x] ccc_gcp CCC.RDMS.CN05.AR01 - MANUAL - none
- [ ] ccc_gcp CCC.RDMS.CN03.AR01 - PARTIAL - none
- [ ] ccc_gcp CCC.Build.CN01.AR01 - PARTIAL - none
- [ ] ccc_gcp CCC.Build.CN02.AR01 - PARTIAL - none
- [ ] ccc_gcp CCC.Build.CN03.AR01 - PARTIAL - none
- [x] ccc_gcp CCC.CntrReg.CN01.AR01 - PARTIAL - gcp.claude.project.container_scanning_api_enabled, gcp.ports.artifacts_container_analysis_enabled
- [ ] ccc_gcp CCC.CntrReg.CN02.AR01 - NEW_CHECK - none
- [x] ccc_gcp CCC.IAM.CN01.AR01 - MANUAL - none
- [x] ccc_gcp CCC.IAM.CN01.AR02 - MANUAL - none
- [x] ccc_gcp CCC.IAM.CN02.AR01 - MANUAL - none
- [x] ccc_gcp CCC.IAM.CN02.AR02 - MANUAL - none
- [x] ccc_gcp CCC.IAM.CN03.AR01 - PARTIAL - gcp.claude.iam_policy.no_project_sa_user_or_token_creator
- [x] ccc_gcp CCC.IAM.CN03.AR02 - MANUAL - none
- [x] ccc_gcp CCC.IAM.CN04.AR01 - MANUAL - none
- [x] ccc_gcp CCC.IAM.CN05.AR01 - MANUAL - none
- [x] ccc_gcp CCC.IAM.CN06.AR01 - PARTIAL - gcp.ports.iam_service_account_key_age_90
- [x] ccc_gcp CCC.IAM.CN07.AR01 - MANUAL - none
- [x] ccc_gcp CCC.IAM.CN08.AR01 - PARTIAL - gcp.claude.service_account.recently_used, gcp.claude.service_account_key.recently_used
- [x] ccc_gcp CCC.IAM.CN09.AR01 - MANUAL - none
- [x] ccc_gcp CCC.IAM.CN10.AR01 - PARTIAL - gcp.claude.logging.metric_alert_audit_configuration_changes, gcp.claude.logging.metric_alert_custom_role_changes
- [x] ccc_gcp CCC.IAM.CN10.AR02 - PARTIAL - gcp.claude.logging.project_sink_all_entries, gcp.claude.project.audit_logs_configured
- [x] ccc_gcp CCC.IAM.CN11.AR01 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN01.AR01 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN01.AR02 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN02.AR01 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN02.AR02 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN03.AR01 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN03.AR02 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN04.AR01 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN04.AR02 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN05.AR01 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN06.AR01 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN07.AR01 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN08.AR01 - MANUAL - none
- [x] ccc_gcp CCC.GenAI.CN08.AR02 - MANUAL - none
- [x] ccc_gcp CCC.MLDE.CN01.AR01 - MANUAL - none
- [ ] ccc_gcp CCC.MLDE.CN03.AR01 - NEW_CHECK - none
- [ ] ccc_gcp CCC.MLDE.CN03.AR02 - NEW_CHECK - none
- [ ] ccc_gcp CCC.MLDE.CN04.AR01 - NEW_CHECK - none
- [ ] ccc_gcp CCC.MLDE.CN04.AR02 - NEW_CHECK - none
- [ ] ccc_gcp CCC.MLDE.CN02.AR01 - NEW_CHECK - none
- [x] ccc_gcp CCC.MLDE.CN02.AR02 - MANUAL - none
- [ ] ccc_gcp CCC.MLDE.CN05.AR01 - PARTIAL - none
- [x] ccc_gcp CCC.MLDE.CN05.AR02 - MANUAL - none
- [x] ccc_gcp CCC.MLDE.CN06.AR01 - MANUAL - none
- [x] ccc_gcp CCC.MLDE.CN06.AR02 - MANUAL - none
- [ ] ccc_gcp CCC.MLDE.CN07.AR01 - NEW_CHECK - none
- [x] ccc_gcp CCC.MLDE.CN07.AR02 - MANUAL - none
- [ ] ccc_gcp CCC.MLDE.CN08.AR01 - NEW_CHECK - none
- [ ] ccc_gcp CCC.MLDE.CN08.AR02 - NEW_CHECK - none
- [ ] ccc_gcp CCC.Message.CN01.AR01 - PARTIAL - none
- [x] ccc_gcp CCC.SvlsComp.CN01.AR01 - PARTIAL - gcp.ports.function_internal_ingress_declaration
- [x] ccc_gcp CCC.SvlsComp.CN02.AR01 - MANUAL - none

## ens_rd2022_gcp

- [x] ens_rd2022_gcp op.acc.1.gcp.iam.1 - MANUAL - none
- [x] ens_rd2022_gcp op.acc.1.r1.gcp.iam.1 - MANUAL - none
- [x] ens_rd2022_gcp opc.acc.1.r1.gcp.iam.2 - MANUAL - none
- [x] ens_rd2022_gcp op.acc.2.gcp.rbak.1 - MANUAL - none
- [x] ens_rd2022_gcp opc.acc.2.gcp.iap.1 - MANUAL - none
- [x] ens_rd2022_gcp op.acc.3.gcp.org.1 - PARTIAL - gcp.ports.iam_user_separation_of_duty_scoped, gcp.ports.kms_key_separation_of_duties_enforced
- [x] ens_rd2022_gcp op.acc.3.gcp.iam.1 - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles, gcp.iam.no_user_managed_sa_keys, gcp.ports.compute_instance_with_no_default_service_account
- [x] ens_rd2022_gcp op.acc.3.r1.gcp.iam.1 - MANUAL - none
- [x] ens_rd2022_gcp opc.acc.4.gcp.iam.1 - MANUAL - none
- [x] ens_rd2022_gcp op.acc.6.gcp.ip.1 - MANUAL - none
- [x] ens_rd2022_gcp op.acc.6.r1.gcp.ip.1 - MANUAL - none
- [ ] ens_rd2022_gcp op.acc.6.r2.gcp.iam.1 - PARTIAL - gcp.reviewed.project.os_login_2fa
- [x] ens_rd2022_gcp op.acc.6.r3.gcp.iam.2 - MANUAL - none
- [x] ens_rd2022_gcp op.acc.6.r4.gcp.ip.1 - MANUAL - none
- [x] ens_rd2022_gcp op.acc.6.r5.gcp.cl.1 - PARTIAL - gcp.claude.project.audit_logs_configured
- [ ] ens_rd2022_gcp op.acc.6.r8.gcp.iam.1 - PARTIAL - gcp.reviewed.project.os_login_2fa
- [x] ens_rd2022_gcp op.acc.6.r9.gcp.api.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.1.gcp.scc.1 - MANUAL - none
- [ ] ens_rd2022_gcp op.exp.1.r1.gcp.cai.1 - NEW_CHECK - none
- [x] ens_rd2022_gcp op.exp.1.r2.gcp.cai.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.1.r3.gcp.cai.1 - MANUAL - none
- [ ] ens_rd2022_gcp op.exp.1.r4.gcp.cai.1 - NEW_CHECK - none
- [ ] ens_rd2022_gcp op.exp.4.gcp.ma.1 - NEW_CHECK - none
- [x] ens_rd2022_gcp op.exp.4.r1.gcp.ci.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.4.r2.gcp - MANUAL - none
- [x] ens_rd2022_gcp op.exp.4.r4.gcp.log.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.6.gcp.ci.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.6.r1.gcp.scc.1 - PARTIAL - gcp.claude.project.container_scanning_api_enabled, gcp.ports.artifacts_container_analysis_enabled
- [x] ens_rd2022_gcp op.exp.6.r2.gcp.scc.1 - MANUAL - none
- [ ] ens_rd2022_gcp op.exp.6.gcp.app.1 - NEW_CHECK - none
- [x] ens_rd2022_gcp op.exp.6.r4.gcp.nt.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.8.gcp.nt.1 - PARTIAL - gcp.claude.network.dns_logging
- [x] ens_rd2022_gcp op.exp.8.r1.gcp.nt.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.8.r2.gcp.wc.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.8.r3.gcp.cs.1 - PARTIAL - gcp.claude.bucket.log_sink_retention_locked
- [x] ens_rd2022_gcp op.exp.8.r4.gcp.cp.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.8.r5.gcp.cl.1 - MANUAL - none
- [x] ens_rd2022_gcp op.exp.10.gcp.kms.1 - PARTIAL - gcp.reviewed.kms.no_public_iam
- [ ] ens_rd2022_gcp op.exp.10.r1.gcp.key.1 - NEW_CHECK - none
- [x] ens_rd2022_gcp op.ext.3.gcp.log.1 - MANUAL - none
- [x] ens_rd2022_gcp op.ext.3.gcp.log.2 - MANUAL - none
- [x] ens_rd2022_gcp op.ext.4.gcp.acc.1 - MANUAL - none
- [x] ens_rd2022_gcp op.ext.4.r1.gcp.acc.1 - MANUAL - none
- [x] ens_rd2022_gcp op.cont.2.gcp.cp.1 - PARTIAL - gcp.sql.backups
- [ ] ens_rd2022_gcp op.mon.1.gcp.scc.1 - NEW_CHECK - none
- [x] ens_rd2022_gcp op.mon.1.r1.gcp.scc.1 - PARTIAL - gcp.claude.project.container_scanning_api_enabled
- [x] ens_rd2022_gcp op.mon.1.r2.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp op.mon.1.r3.gc.scc.1 - MANUAL - none
- [ ] ens_rd2022_gcp op.mon.3.gcp.scc.1 - PARTIAL - none
- [x] ens_rd2022_gcp op.mon.3.r1.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp op.mon.3.r2.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp op.mon.3.r3.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp op.mon.3.r4.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp op.mon.3.r5.gcp.dm.1 - MANUAL - none
- [x] ens_rd2022_gcp op.mon.3.r6.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.com.1.gcp.fw.1 - PARTIAL - gcp.ports.compute_firewall_rule_rdp_access_restricted
- [x] ens_rd2022_gcp mp.com.1.gcp.fw.2 - PARTIAL - gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] ens_rd2022_gcp mp.com.2.gcp.lb.1 - MANUAL - none
- [ ] ens_rd2022_gcp mp.com.2.r1.gcp.scc.1 - NEW_CHECK - none
- [x] ens_rd2022_gcp mp.com.2.r2.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.com.2.r3.gcp.key.1 - MANUAL - none
- [ ] ens_rd2022_gcp mp.com.2.r4.gcp.key.1 - NEW_CHECK - none
- [x] ens_rd2022_gcp mp.com.2.r5.gcp.key.1 - PARTIAL - gcp.claude.instance.disks_csek, gcp.claude2.bigquery_dataset.default_cmek, gcp.ports.bigquery_table_encrypted_with_cmk, gcp.ports.dataproc_cluster_encryption_with_cmek
- [x] ens_rd2022_gcp mp.com.3.gcp.net.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.com.3.r1.gcp.net.1 - MANUAL - none
- [ ] ens_rd2022_gcp mp.com.3.r2.gcp.key.1 - NEW_CHECK - none
- [x] ens_rd2022_gcp mp.com.3.r3.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.com.3.r4.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.com.4.gcp.vpc.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.com.4.gcp.vpc.2 - PARTIAL - gcp.claude.sql_instance.second_gen_no_public_ip, gcp.claude2.sql_instance.only_private_ip_addresses, gcp.compute.no_external_ip
- [x] ens_rd2022_gcp mp.com.4.r1.gcp.net.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.com.4.r2.gcp.net.1 - PARTIAL - gcp.gke.network_policy
- [x] ens_rd2022_gcp mp.com.4.r3.gcp.net.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.com.4.r4.gcp.net.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.si.2.gcp.key.1 - PARTIAL - gcp.reviewed.sql.cmek
- [x] ens_rd2022_gcp mp.si.2.r1.gcp.key.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.si.2.r2.gcp.key.1 - PARTIAL - gcp.sql.backups
- [x] ens_rd2022_gcp mp.info.3.gcp.key.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.info.3.r1.gcp.crt.1 - MANUAL - none
- [ ] ens_rd2022_gcp mp.info.3.r2.gcp.key.1 - NEW_CHECK - none
- [x] ens_rd2022_gcp mp.info.3.r3.gcp.key.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.info.3.r4.gcp.key.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.info.5.gcp.mp.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.info.6.gcp.bk.1 - PARTIAL - gcp.sql.backups
- [x] ens_rd2022_gcp mp.info.6.r1.gcp.scc.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.info.6.r2.gcp.bk.1 - PARTIAL - gcp.sql.backups
- [x] ens_rd2022_gcp mp.s.1.gcp.app.1 - MANUAL - none
- [x] ens_rd2022_gcp mp.s.2.gcp.app.1 - PARTIAL - gcp.claude.dns_zone.dnssec_enabled
- [x] ens_rd2022_gcp mp.s.2.r2.gcp.app.1 - MANUAL - none
- [ ] ens_rd2022_gcp mp.s.2.r3.gcp.app.1 - NEW_CHECK - none
- [ ] ens_rd2022_gcp mp.s.4.gcp.app.1 - PARTIAL - none
- [x] ens_rd2022_gcp mp.s.4.r1.gcp.app.1 - MANUAL - none

## hipaa_gcp

- [x] hipaa_gcp 164_308_a_1_ii_a - MANUAL - none
- [x] hipaa_gcp 164_308_a_1_ii_b - PARTIAL - gcp.claude.iam_policy.no_project_sa_user_or_token_creator, gcp.claude.instance.disks_csek, gcp.claude2.bigquery_dataset.default_cmek, gcp.compute.no_external_ip, gcp.reviewed.sql.cmek, gcp.sql.backups, gcp.storage.no_public_iam
- [x] hipaa_gcp 164_308_a_1_ii_d - MANUAL - none
- [x] hipaa_gcp 164_308_a_3_i - MANUAL - none
- [x] hipaa_gcp 164_308_a_4_i - MANUAL - none
- [x] hipaa_gcp 164_308_a_5_ii_c - MANUAL - none
- [x] hipaa_gcp 164_308_a_6_ii - MANUAL - none
- [x] hipaa_gcp 164_308_a_7_i - MANUAL - none
- [x] hipaa_gcp 164_308_a_7_ii_a - PARTIAL - gcp.reviewed.storage.versioning, gcp.sql.backups
- [x] hipaa_gcp 164_308_a_7_ii_b - PARTIAL - gcp.reviewed.storage.versioning, gcp.sql.backups
- [x] hipaa_gcp 164_308_b_1 - MANUAL - none
- [x] hipaa_gcp 164_308_b_2 - MANUAL - none
- [x] hipaa_gcp 164_310_a_1 - MANUAL - none
- [x] hipaa_gcp 164_310_d_1 - MANUAL - none
- [x] hipaa_gcp 164_312_a_1 - PARTIAL - gcp.claude.iam_policy.no_project_sa_user_or_token_creator, gcp.compute.no_external_ip, gcp.ports.sql_instance_not_open_to_internet, gcp.reviewed.bigquery.no_public_acl, gcp.storage.no_public_iam
- [x] hipaa_gcp 164_312_a_2_i - MANUAL - none
- [x] hipaa_gcp 164_312_a_2_iv - PARTIAL - gcp.claude.instance.disks_csek, gcp.claude2.bigquery_dataset.default_cmek, gcp.reviewed.sql.cmek
- [x] hipaa_gcp 164_312_b - PARTIAL - gcp.claude.logging.project_sink_all_entries
- [x] hipaa_gcp 164_312_c_1 - PARTIAL - gcp.reviewed.storage.versioning, gcp.sql.backups
- [x] hipaa_gcp 164_312_d - MANUAL - none
- [x] hipaa_gcp 164_312_e_1 - PARTIAL - gcp.ports.reference_sql_ssl_connections
- [x] hipaa_gcp 164_312_e_2_i - MANUAL - none
- [x] hipaa_gcp 164_312_e_2_ii - PARTIAL - gcp.claude.instance.disks_csek, gcp.claude2.bigquery_dataset.default_cmek, gcp.ports.reference_sql_ssl_connections, gcp.reviewed.sql.cmek

## iso27001_2022_gcp

- [x] iso27001_2022_gcp A.5.1 - MANUAL - none
- [x] iso27001_2022_gcp A.5.2 - MANUAL - none
- [x] iso27001_2022_gcp A.5.3 - PARTIAL - gcp.ports.iam_user_separation_of_duty_scoped, gcp.ports.kms_key_separation_of_duties_enforced
- [x] iso27001_2022_gcp A.5.4 - MANUAL - none
- [x] iso27001_2022_gcp A.5.5 - MANUAL - none
- [x] iso27001_2022_gcp A.5.6 - MANUAL - none
- [x] iso27001_2022_gcp A.5.7 - MANUAL - none
- [x] iso27001_2022_gcp A.5.8 - MANUAL - none
- [ ] iso27001_2022_gcp A.5.9 - PARTIAL - none
- [x] iso27001_2022_gcp A.5.10 - MANUAL - none
- [x] iso27001_2022_gcp A.5.11 - MANUAL - none
- [ ] iso27001_2022_gcp A.5.12 - PARTIAL - none
- [ ] iso27001_2022_gcp A.5.13 - PARTIAL - none
- [x] iso27001_2022_gcp A.5.14 - MANUAL - none
- [x] iso27001_2022_gcp A.5.15 - PARTIAL - gcp.claude.iam_policy.no_project_sa_user_or_token_creator, gcp.gap.iam_user_managed_sa_no_admin_roles, gcp.iam.no_user_managed_sa_keys
- [x] iso27001_2022_gcp A.5.16 - MANUAL - none
- [x] iso27001_2022_gcp A.5.17 - MANUAL - none
- [x] iso27001_2022_gcp A.5.18 - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles, gcp.ports.iam_user_separation_of_duty_scoped
- [x] iso27001_2022_gcp A.5.19 - MANUAL - none
- [x] iso27001_2022_gcp A.5.20 - MANUAL - none
- [x] iso27001_2022_gcp A.5.21 - MANUAL - none
- [x] iso27001_2022_gcp A.5.22 - MANUAL - none
- [x] iso27001_2022_gcp A.5.23 - MANUAL - none
- [x] iso27001_2022_gcp A.5.24 - MANUAL - none
- [x] iso27001_2022_gcp A.5.25 - MANUAL - none
- [x] iso27001_2022_gcp A.5.26 - MANUAL - none
- [x] iso27001_2022_gcp A.5.27 - MANUAL - none
- [x] iso27001_2022_gcp A.5.28 - MANUAL - none
- [x] iso27001_2022_gcp A.5.29 - MANUAL - none
- [x] iso27001_2022_gcp A.5.30 - MANUAL - none
- [x] iso27001_2022_gcp A.5.31 - MANUAL - none
- [x] iso27001_2022_gcp A.5.32 - MANUAL - none
- [x] iso27001_2022_gcp A.5.33 - PARTIAL - gcp.claude.bucket.log_sink_retention_locked
- [x] iso27001_2022_gcp A.5.34 - MANUAL - none
- [x] iso27001_2022_gcp A.5.35 - MANUAL - none
- [x] iso27001_2022_gcp A.5.36 - MANUAL - none
- [x] iso27001_2022_gcp A.5.37 - MANUAL - none
- [x] iso27001_2022_gcp A.6.1 - MANUAL - none
- [x] iso27001_2022_gcp A.6.2 - MANUAL - none
- [x] iso27001_2022_gcp A.6.3 - MANUAL - none
- [x] iso27001_2022_gcp A.6.4 - MANUAL - none
- [x] iso27001_2022_gcp A.6.5 - MANUAL - none
- [x] iso27001_2022_gcp A.6.6 - MANUAL - none
- [x] iso27001_2022_gcp A.6.7 - MANUAL - none
- [x] iso27001_2022_gcp A.6.8 - MANUAL - none
- [x] iso27001_2022_gcp A.7.1 - MANUAL - none
- [x] iso27001_2022_gcp A.7.2 - MANUAL - none
- [x] iso27001_2022_gcp A.7.3 - MANUAL - none
- [x] iso27001_2022_gcp A.7.4 - MANUAL - none
- [x] iso27001_2022_gcp A.7.5 - MANUAL - none
- [x] iso27001_2022_gcp A.7.6 - MANUAL - none
- [x] iso27001_2022_gcp A.7.7 - MANUAL - none
- [x] iso27001_2022_gcp A.7.8 - MANUAL - none
- [x] iso27001_2022_gcp A.7.9 - MANUAL - none
- [x] iso27001_2022_gcp A.7.10 - MANUAL - none
- [x] iso27001_2022_gcp A.7.11 - MANUAL - none
- [x] iso27001_2022_gcp A.7.12 - MANUAL - none
- [x] iso27001_2022_gcp A.7.13 - MANUAL - none
- [x] iso27001_2022_gcp A.7.14 - MANUAL - none
- [x] iso27001_2022_gcp A.8.1 - MANUAL - none
- [x] iso27001_2022_gcp A.8.2 - PARTIAL - gcp.claude.iam_policy.no_project_sa_user_or_token_creator, gcp.gap.iam_user_managed_sa_no_admin_roles, gcp.ports.iam_user_separation_of_duty_scoped
- [x] iso27001_2022_gcp A.8.3 - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles, gcp.ports.compute_instance_with_no_default_service_account_with_full_access
- [ ] iso27001_2022_gcp A.8.4 - NEW_CHECK - none
- [x] iso27001_2022_gcp A.8.5 - PARTIAL - gcp.reviewed.project.os_login_2fa
- [ ] iso27001_2022_gcp A.8.6 - PARTIAL - none
- [x] iso27001_2022_gcp A.8.7 - MANUAL - none
- [ ] iso27001_2022_gcp A.8.8 - PARTIAL - none
- [x] iso27001_2022_gcp A.8.9 - MANUAL - none
- [x] iso27001_2022_gcp A.8.10 - MANUAL - none
- [x] iso27001_2022_gcp A.8.11 - MANUAL - none
- [x] iso27001_2022_gcp A.8.12 - MANUAL - none
- [x] iso27001_2022_gcp A.8.13 - PARTIAL - gcp.sql.backups
- [x] iso27001_2022_gcp A.8.14 - MANUAL - none
- [x] iso27001_2022_gcp A.8.15 - PARTIAL - gcp.claude.logging.project_sink_all_entries
- [x] iso27001_2022_gcp A.8.16 - PARTIAL - gcp.claude.logging.metric_alert_audit_configuration_changes, gcp.claude.logging.metric_alert_bucket_iam_changes, gcp.claude.logging.metric_alert_custom_role_changes, gcp.claude.logging.metric_alert_firewall_rule_changes, gcp.claude.logging.metric_alert_network_changes, gcp.claude.logging.metric_alert_project_ownership_changes, gcp.claude.logging.metric_alert_route_changes, gcp.claude.logging.metric_alert_sql_instance_configuration_changes
- [x] iso27001_2022_gcp A.8.17 - MANUAL - none
- [x] iso27001_2022_gcp A.8.18 - MANUAL - none
- [ ] iso27001_2022_gcp A.8.19 - PARTIAL - none
- [x] iso27001_2022_gcp A.8.20 - PARTIAL - gcp.ports.compute_firewall_rule_rdp_access_restricted, gcp.ports.compute_firewall_rule_ssh_access_restricted, gcp.reviewed.network.no_default_vpc
- [x] iso27001_2022_gcp A.8.21 - PARTIAL - gcp.claude.network.dns_logging, gcp.reviewed.network.flow_logs
- [x] iso27001_2022_gcp A.8.22 - PARTIAL - gcp.claude.network.dns_logging, gcp.reviewed.network.flow_logs
- [ ] iso27001_2022_gcp A.8.23 - PARTIAL - none
- [x] iso27001_2022_gcp A.8.24 - PARTIAL - gcp.reviewed.kms.no_public_iam, gcp.reviewed.kms.rotation_enabled
- [x] iso27001_2022_gcp A.8.25 - MANUAL - none
- [x] iso27001_2022_gcp A.8.26 - MANUAL - none
- [x] iso27001_2022_gcp A.8.27 - MANUAL - none
- [x] iso27001_2022_gcp A.8.29 - MANUAL - none
- [x] iso27001_2022_gcp A.8.30 - MANUAL - none
- [x] iso27001_2022_gcp A.8.31 - MANUAL - none
- [x] iso27001_2022_gcp A.8.32 - MANUAL - none
- [x] iso27001_2022_gcp A.8.33 - MANUAL - none
- [x] iso27001_2022_gcp A.8.34 - MANUAL - none

## mitre_attack_gcp

- [x] mitre_attack_gcp T1190 - MANUAL - none
- [x] mitre_attack_gcp T1199 - MANUAL - none
- [x] mitre_attack_gcp T1078 - MANUAL - none
- [x] mitre_attack_gcp T1059 - MANUAL - none
- [ ] mitre_attack_gcp T1648 - PARTIAL - none
- [x] mitre_attack_gcp T1204 - MANUAL - none
- [x] mitre_attack_gcp T1098 - MANUAL - none
- [ ] mitre_attack_gcp T1136 - PARTIAL - none
- [ ] mitre_attack_gcp T1546 - PARTIAL - none
- [ ] mitre_attack_gcp T1651 - PARTIAL - none
- [x] mitre_attack_gcp T1525 - MANUAL - none
- [x] mitre_attack_gcp T1556 - MANUAL - none
- [x] mitre_attack_gcp T1562 - MANUAL - none
- [x] mitre_attack_gcp T1578 - MANUAL - none
- [ ] mitre_attack_gcp T1535 - PARTIAL - none
- [x] mitre_attack_gcp T1550 - MANUAL - none
- [ ] mitre_attack_gcp T1110 - PARTIAL - none
- [x] mitre_attack_gcp T1606 - MANUAL - none
- [x] mitre_attack_gcp T1621 - MANUAL - none
- [x] mitre_attack_gcp T1040 - MANUAL - none
- [x] mitre_attack_gcp T1552 - MANUAL - none
- [x] mitre_attack_gcp T1048 - MANUAL - none
- [x] mitre_attack_gcp T1537 - MANUAL - none
- [ ] mitre_attack_gcp T1119 - PARTIAL - none
- [x] mitre_attack_gcp T1530 - MANUAL - none
- [x] mitre_attack_gcp T1213 - MANUAL - none
- [x] mitre_attack_gcp T1074 - MANUAL - none
- [x] mitre_attack_gcp T1485 - MANUAL - none
- [x] mitre_attack_gcp T1486 - MANUAL - none
- [x] mitre_attack_gcp T1491 - MANUAL - none
- [x] mitre_attack_gcp T1499 - MANUAL - none
- [ ] mitre_attack_gcp T1490 - PARTIAL - gcp.sql.backups
- [x] mitre_attack_gcp T1496 - MANUAL - none
- [x] mitre_attack_gcp T1498 - MANUAL - none
- [x] mitre_attack_gcp T1087 - MANUAL - none
- [x] mitre_attack_gcp T1580 - MANUAL - none
- [x] mitre_attack_gcp T1538 - MANUAL - none
- [ ] mitre_attack_gcp T1526 - PARTIAL - none
- [ ] mitre_attack_gcp T1619 - PARTIAL - none
- [x] mitre_attack_gcp T1046 - MANUAL - none
- [x] mitre_attack_gcp T1201 - MANUAL - none
- [x] mitre_attack_gcp T1049 - MANUAL - none
- [ ] mitre_attack_gcp T1614 - PARTIAL - none
- [x] mitre_attack_gcp T1082 - MANUAL - none
- [ ] mitre_attack_gcp T1518 - PARTIAL - none
- [x] mitre_attack_gcp T1069 - MANUAL - none

## nis2_gcp

- [x] nis2_gcp 1.1.1.a - MANUAL - none
- [x] nis2_gcp 1.1.1.c - MANUAL - none
- [x] nis2_gcp 1.1.2 - MANUAL - none
- [x] nis2_gcp 1.2.1 - MANUAL - none
- [x] nis2_gcp 1.2.4 - MANUAL - none
- [x] nis2_gcp 2.1.2.e - MANUAL - none
- [x] nis2_gcp 2.1.2.g - MANUAL - none
- [x] nis2_gcp 2.1.2.h - MANUAL - none
- [x] nis2_gcp 2.2.1 - MANUAL - none
- [x] nis2_gcp 2.3.1 - MANUAL - none
- [x] nis2_gcp 3.1.2.d - MANUAL - none
- [x] nis2_gcp 3.1.3 - MANUAL - none
- [x] nis2_gcp 3.2.1 - PARTIAL - gcp.claude.logging.project_sink_all_entries, gcp.claude.project.audit_logs_configured, gcp.reviewed.network.flow_logs
- [x] nis2_gcp 3.2.3.a - PARTIAL - gcp.claude.network.dns_logging, gcp.ports.compute_url_map_backend_logging, gcp.reviewed.network.flow_logs
- [x] nis2_gcp 3.2.3.b - PARTIAL - gcp.claude.logging.metric_alert_custom_role_changes, gcp.claude.logging.metric_alert_project_ownership_changes
- [x] nis2_gcp 3.2.3.c - PARTIAL - gcp.claude.project.audit_logs_configured, gcp.ports.compute_url_map_backend_logging, gcp.reviewed.sql.postgres_log_connections
- [x] nis2_gcp 3.2.3.d - PARTIAL - gcp.reviewed.sql.postgres_log_connections
- [x] nis2_gcp 3.2.3.e - MANUAL - none
- [x] nis2_gcp 3.2.3.f - PARTIAL - gcp.claude.logging.metric_alert_audit_configuration_changes
- [x] nis2_gcp 3.2.3.g - MANUAL - none
- [x] nis2_gcp 3.2.4 - MANUAL - none
- [x] nis2_gcp 3.2.5 - PARTIAL - gcp.claude.bucket.log_sink_retention_locked, gcp.claude.logging.project_sink_all_entries
- [x] nis2_gcp 3.4.1 - MANUAL - none
- [x] nis2_gcp 3.5.3.a - MANUAL - none
- [x] nis2_gcp 3.6.2 - MANUAL - none
- [x] nis2_gcp 4.1.1 - MANUAL - none
- [x] nis2_gcp 4.1.2.f - MANUAL - none
- [x] nis2_gcp 4.1.2.g - PARTIAL - gcp.sql.backups
- [x] nis2_gcp 4.1.4 - MANUAL - none
- [x] nis2_gcp 4.2.2.b - MANUAL - none
- [x] nis2_gcp 4.2.2.e - MANUAL - none
- [x] nis2_gcp 4.2.2.f - MANUAL - none
- [x] nis2_gcp 5.1.2.a - MANUAL - none
- [x] nis2_gcp 5.1.4.f - MANUAL - none
- [x] nis2_gcp 5.1.7.d - MANUAL - none
- [x] nis2_gcp 6.1.2.b - MANUAL - none
- [x] nis2_gcp 6.2.1 - MANUAL - none
- [x] nis2_gcp 6.2.2.b - MANUAL - none
- [x] nis2_gcp 6.4.1 - MANUAL - none
- [x] nis2_gcp 6.6.1.a - MANUAL - none
- [x] nis2_gcp 6.7.2.b - PARTIAL - gcp.ports.compute_firewall_rule_rdp_access_restricted, gcp.ports.compute_firewall_rule_ssh_access_restricted, gcp.reviewed.compute.block_project_ssh_keys
- [x] nis2_gcp 6.7.2.e - MANUAL - none
- [x] nis2_gcp 6.7.2.g - MANUAL - none
- [x] nis2_gcp 6.7.2.i - PARTIAL - gcp.claude.dns_zone.dnssec_enabled, gcp.ports.compute_firewall_rule_rdp_access_restricted, gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] nis2_gcp 6.7.2.l - PARTIAL - gcp.claude.dns_zone.dnssec_enabled, gcp.claude.dns_zone.ksk_not_rsasha1, gcp.claude.dns_zone.zsk_not_rsasha1
- [x] nis2_gcp 6.9.2 - MANUAL - none
- [x] nis2_gcp 7.2.b - MANUAL - none
- [x] nis2_gcp 9.2.a - PARTIAL - gcp.claude.dns_zone.dnssec_enabled, gcp.claude.dns_zone.ksk_not_rsasha1, gcp.claude.dns_zone.zsk_not_rsasha1, gcp.claude.instance.disks_csek, gcp.claude2.bigquery_dataset.default_cmek, gcp.ports.bigquery_table_encrypted_with_cmk, gcp.ports.dataproc_cluster_encryption_with_cmek
- [x] nis2_gcp 9.2.c - MANUAL - none
- [x] nis2_gcp 9.2.c.i - MANUAL - none
- [x] nis2_gcp 9.2.c.ii - MANUAL - none
- [x] nis2_gcp 9.2.c.iv - PARTIAL - gcp.reviewed.kms.no_public_iam
- [x] nis2_gcp 9.2.c.v - PARTIAL - gcp.reviewed.kms.rotation_enabled
- [x] nis2_gcp 9.2.c.vi - MANUAL - none
- [x] nis2_gcp 9.2.c.vii - MANUAL - none
- [x] nis2_gcp 9.2.c.xii - MANUAL - none
- [x] nis2_gcp 11.1.1 - MANUAL - none
- [x] nis2_gcp 11.1.2.c - MANUAL - none
- [x] nis2_gcp 11.2.2.a - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles, gcp.ports.iam_user_separation_of_duty_scoped, gcp.ports.kms_key_separation_of_duties_enforced
- [x] nis2_gcp 11.2.2.d - MANUAL - none
- [x] nis2_gcp 11.2.2.e - MANUAL - none
- [x] nis2_gcp 11.2.2.f - PARTIAL - gcp.claude.project.audit_logs_configured
- [x] nis2_gcp 11.3.1 - MANUAL - none
- [x] nis2_gcp 11.3.2.a - MANUAL - none
- [x] nis2_gcp 11.3.2.b - MANUAL - none
- [x] nis2_gcp 11.3.2.c - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles, gcp.ports.iam_user_separation_of_duty_scoped, gcp.ports.kms_key_separation_of_duties_enforced
- [x] nis2_gcp 11.3.2.d - MANUAL - none
- [x] nis2_gcp 11.4.2.a - MANUAL - none
- [x] nis2_gcp 11.4.2.b - MANUAL - none
- [x] nis2_gcp 11.4.2.c - MANUAL - none
- [x] nis2_gcp 11.5.2.d - MANUAL - none
- [x] nis2_gcp 11.5.4 - PARTIAL - gcp.claude.service_account.recently_used, gcp.claude.service_account_key.recently_used
- [x] nis2_gcp 11.6.1 - MANUAL - none
- [x] nis2_gcp 11.6.2.a - MANUAL - none
- [x] nis2_gcp 11.6.2.c - PARTIAL - gcp.claude2.api_key.created_within_90_days, gcp.ports.iam_service_account_key_age_90
- [x] nis2_gcp 11.7.2 - MANUAL - none
- [x] nis2_gcp 12.1.2.c - MANUAL - none
- [x] nis2_gcp 12.2.2.a - MANUAL - none
- [x] nis2_gcp 12.2.2.b - MANUAL - none
- [x] nis2_gcp 12.2.2.c - PARTIAL - gcp.ports.reference_sql_ssl_connections

## prowler_threatscore_gcp

- [x] prowler_threatscore_gcp 1.1.1 - MAPPED - gcp.ports.iam_service_account_key_age_90
- [ ] prowler_threatscore_gcp 1.1.2 - NEW_CHECK - none
- [x] prowler_threatscore_gcp 1.1.3 - MAPPED - gcp.claude2.api_key.created_within_90_days
- [x] prowler_threatscore_gcp 1.2.1 - MAPPED - gcp.iam.no_user_managed_sa_keys
- [x] prowler_threatscore_gcp 1.2.2 - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles
- [x] prowler_threatscore_gcp 1.2.3 - MAPPED - gcp.reviewed.kms.no_public_iam
- [x] prowler_threatscore_gcp 1.2.4 - MAPPED - gcp.reviewed.kms.rotation_90_days
- [x] prowler_threatscore_gcp 1.2.5 - PARTIAL - gcp.ports.kms_key_separation_of_duties_enforced
- [x] prowler_threatscore_gcp 1.2.6 - PARTIAL - gcp.ports.iam_api_key_restricts_apis
- [x] prowler_threatscore_gcp 1.3.1 - MAPPED - gcp.claude.iam_policy.no_project_sa_user_or_token_creator
- [x] prowler_threatscore_gcp 1.3.2 - PARTIAL - gcp.ports.iam_user_separation_of_duty_scoped
- [x] prowler_threatscore_gcp 1.3.3 - PARTIAL - gcp.claude.project.audit_logs_configured
- [x] prowler_threatscore_gcp 1.3.4 - MAPPED - gcp.claude.logging.metric_alert_project_ownership_changes
- [x] prowler_threatscore_gcp 1.3.5 - MAPPED - gcp.claude.logging.metric_alert_audit_configuration_changes
- [x] prowler_threatscore_gcp 1.3.6 - MAPPED - gcp.claude.logging.metric_alert_custom_role_changes
- [x] prowler_threatscore_gcp 2.1.1 - MAPPED - gcp.reviewed.network.no_default_vpc
- [x] prowler_threatscore_gcp 2.1.2 - MAPPED - gcp.ports.compute_network_contains_no_legacy_network
- [x] prowler_threatscore_gcp 2.1.4 - MAPPED - gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] prowler_threatscore_gcp 2.1.5 - MAPPED - gcp.ports.compute_firewall_rule_rdp_access_restricted
- [x] prowler_threatscore_gcp 2.2.1 - MAPPED - gcp.storage.no_public_iam
- [x] prowler_threatscore_gcp 2.2.2 - MAPPED - gcp.ports.reference_sqlserver_user_connections
- [x] prowler_threatscore_gcp 2.2.3 - MAPPED - gcp.ports.reference_sqlserver_remote_access
- [x] prowler_threatscore_gcp 2.2.5 - MAPPED - gcp.ports.sql_instance_not_open_to_internet
- [x] prowler_threatscore_gcp 2.2.6 - MAPPING_FIX - gcp.sql.no_public_ip
- [x] prowler_threatscore_gcp 2.2.7 - MAPPED - gcp.reviewed.bigquery.no_public_acl
- [x] prowler_threatscore_gcp 2.3.3 - PARTIAL - gcp.ports.compute_instance_with_no_default_service_account_with_full_access
- [x] prowler_threatscore_gcp 2.3.4 - MAPPED - gcp.reviewed.compute.block_project_ssh_keys
- [x] prowler_threatscore_gcp 2.3.5 - MAPPED - gcp.reviewed.compute.no_serial_console
- [x] prowler_threatscore_gcp 2.3.6 - PARTIAL - gcp.ports.compute_instance_ip_forwarding_disabled
- [x] prowler_threatscore_gcp 2.3.7 - MAPPED - gcp.ports.compute_instance_shielded_vm_enabled
- [x] prowler_threatscore_gcp 2.3.8 - MAPPED - gcp.compute.no_external_ip
- [x] prowler_threatscore_gcp 3.1.1 - MAPPING_FIX - gcp.claude.logging.project_sink_all_entries
- [x] prowler_threatscore_gcp 3.1.2 - MAPPED - gcp.claude.logging.metric_alert_firewall_rule_changes
- [x] prowler_threatscore_gcp 3.1.3 - MAPPED - gcp.claude.logging.metric_alert_route_changes
- [x] prowler_threatscore_gcp 3.1.4 - MAPPED - gcp.claude.logging.metric_alert_network_changes
- [x] prowler_threatscore_gcp 3.1.5 - MAPPED - gcp.claude.logging.metric_alert_bucket_iam_changes
- [x] prowler_threatscore_gcp 3.1.6 - MAPPED - gcp.claude.logging.metric_alert_sql_instance_configuration_changes
- [x] prowler_threatscore_gcp 3.1.7 - PARTIAL - gcp.ports.compute_url_map_backend_logging
- [x] prowler_threatscore_gcp 3.1.8 - MAPPED - gcp.reviewed.network.flow_logs
- [x] prowler_threatscore_gcp 3.1.9 - MAPPED - gcp.reviewed.sql.postgres_log_connections
- [x] prowler_threatscore_gcp 3.1.10 - MAPPED - gcp.reviewed.sql.postgres_log_disconnections
- [x] prowler_threatscore_gcp 3.1.11 - MAPPED - gcp.reviewed.sql.postgres_log_statement
- [x] prowler_threatscore_gcp 3.1.12 - MAPPED - gcp.ports.reference_sql_pg_min_messages
- [x] prowler_threatscore_gcp 3.1.13 - MAPPED - gcp.ports.reference_sql_pg_min_error
- [x] prowler_threatscore_gcp 3.1.14 - MAPPED - gcp.ports.reference_sql_pg_min_duration
- [x] prowler_threatscore_gcp 3.1.15 - MAPPED - gcp.reviewed.sql.postgres_pgaudit
- [x] prowler_threatscore_gcp 3.2.1 - MAPPED - gcp.claude.bucket.log_sink_retention_locked
- [x] prowler_threatscore_gcp 3.3.1 - MAPPED - gcp.ports.project_service_cloudasset_api_enabled
- [x] prowler_threatscore_gcp 3.3.2 - MAPPED - gcp.ports.access_approval_explicit_enrollment
- [x] prowler_threatscore_gcp 4.1.1 - MAPPED - gcp.claude.dns_zone.dnssec_enabled
- [x] prowler_threatscore_gcp 4.1.2 - MAPPED - gcp.ports.reference_sql_ssl_connections
- [x] prowler_threatscore_gcp 4.1.3 - MAPPED - gcp.claude.dns_zone.ksk_not_rsasha1
- [x] prowler_threatscore_gcp 4.1.4 - MAPPED - gcp.claude.dns_zone.zsk_not_rsasha1
- [x] prowler_threatscore_gcp 4.2.1 - MAPPED - gcp.claude.instance.disks_csek
- [x] prowler_threatscore_gcp 4.2.2 - MAPPED - gcp.ports.dataproc_cluster_encryption_with_cmek
- [x] prowler_threatscore_gcp 4.2.3 - MAPPED - gcp.claude2.bigquery_dataset.default_cmek
- [x] prowler_threatscore_gcp 4.2.4 - MAPPED - gcp.ports.bigquery_table_encrypted_with_cmk

## rbi_cyber_security_framework_gcp

- [x] rbi_cyber_security_framework_gcp annex_i_1_1 - MANUAL - none
- [x] rbi_cyber_security_framework_gcp annex_i_1_3 - PARTIAL - gcp.claude.instance.disks_csek, gcp.claude2.bigquery_dataset.default_cmek, gcp.ports.reference_sql_ssl_connections, gcp.reviewed.kms.no_public_iam, gcp.reviewed.storage.versioning, gcp.storage.no_public_iam
- [x] rbi_cyber_security_framework_gcp annex_i_5_1 - PARTIAL - gcp.ports.compute_firewall_rule_rdp_access_restricted, gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] rbi_cyber_security_framework_gcp annex_i_6 - MANUAL - none
- [x] rbi_cyber_security_framework_gcp annex_i_7_1 - MANUAL - none
- [x] rbi_cyber_security_framework_gcp annex_i_7_2 - MANUAL - none
- [x] rbi_cyber_security_framework_gcp annex_i_7_3 - PARTIAL - gcp.ports.compute_firewall_rule_rdp_access_restricted
- [x] rbi_cyber_security_framework_gcp annex_i_7_4 - PARTIAL - gcp.claude.logging.project_sink_all_entries, gcp.claude.project.audit_logs_configured
- [x] rbi_cyber_security_framework_gcp annex_i_12 - PARTIAL - gcp.sql.backups

## secnumcloud_3.2_gcp

- [x] secnumcloud_3.2_gcp 5.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 5.2 - MANUAL - none
- [x] secnumcloud_3.2_gcp 5.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 6.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 6.2 - PARTIAL - gcp.ports.iam_user_separation_of_duty_scoped
- [x] secnumcloud_3.2_gcp 6.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 6.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 6.5 - MANUAL - none
- [x] secnumcloud_3.2_gcp 7.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 7.2 - MANUAL - none
- [x] secnumcloud_3.2_gcp 7.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 7.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 7.5 - MANUAL - none
- [x] secnumcloud_3.2_gcp 8.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 8.2 - MANUAL - none
- [ ] secnumcloud_3.2_gcp 8.3 - PARTIAL - none
- [ ] secnumcloud_3.2_gcp 8.4 - PARTIAL - none
- [x] secnumcloud_3.2_gcp 8.5 - MANUAL - none
- [x] secnumcloud_3.2_gcp 9.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 9.2 - MANUAL - none
- [x] secnumcloud_3.2_gcp 9.3 - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles, gcp.ports.iam_user_separation_of_duty_scoped
- [x] secnumcloud_3.2_gcp 9.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 9.5 - MANUAL - none
- [x] secnumcloud_3.2_gcp 9.6 - PARTIAL - gcp.ports.access_approval_explicit_enrollment, gcp.ports.compute_firewall_rule_rdp_access_restricted, gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] secnumcloud_3.2_gcp 9.7 - PARTIAL - gcp.claude.image.not_public, gcp.claude.sql_instance.second_gen_no_public_ip, gcp.claude2.sql_instance.only_private_ip_addresses, gcp.compute.no_external_ip, gcp.ports.sql_instance_not_open_to_internet, gcp.reviewed.bigquery.no_public_acl, gcp.reviewed.kms.no_public_iam, gcp.storage.no_public_iam, gcp.storage.uniform_access
- [x] secnumcloud_3.2_gcp 10.1 - PARTIAL - gcp.claude.instance.disks_csek, gcp.claude2.bigquery_dataset.default_cmek, gcp.ports.bigquery_table_encrypted_with_cmk, gcp.ports.dataproc_cluster_encryption_with_cmek
- [x] secnumcloud_3.2_gcp 10.2 - PARTIAL - gcp.ports.reference_sql_ssl_connections
- [x] secnumcloud_3.2_gcp 10.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 10.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 10.5 - PARTIAL - gcp.iam.no_user_managed_sa_keys, gcp.ports.iam_service_account_key_age_90, gcp.reviewed.kms.no_public_iam, gcp.reviewed.kms.rotation_enabled
- [x] secnumcloud_3.2_gcp 10.6 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.2 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.5 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.6 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.7 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.8 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.9 - MANUAL - none
- [x] secnumcloud_3.2_gcp 11.10 - MANUAL - none
- [x] secnumcloud_3.2_gcp 12.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 12.2 - MANUAL - none
- [x] secnumcloud_3.2_gcp 12.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 12.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 12.5 - PARTIAL - gcp.reviewed.storage.soft_delete, gcp.reviewed.storage.versioning, gcp.sql.backups
- [x] secnumcloud_3.2_gcp 12.6 - PARTIAL - gcp.claude.logging.project_sink_all_entries, gcp.claude.project.audit_logs_configured, gcp.claude.project.storage_data_access_audit_logs, gcp.reviewed.network.flow_logs, gcp.reviewed.sql.postgres_log_connections, gcp.reviewed.sql.postgres_log_disconnections
- [x] secnumcloud_3.2_gcp 12.7 - PARTIAL - gcp.claude.bucket.log_sink_retention_locked, gcp.storage.no_public_iam
- [x] secnumcloud_3.2_gcp 12.8 - MANUAL - none
- [x] secnumcloud_3.2_gcp 12.9 - MANUAL - none
- [ ] secnumcloud_3.2_gcp 12.10 - PARTIAL - none
- [x] secnumcloud_3.2_gcp 12.11 - MANUAL - none
- [x] secnumcloud_3.2_gcp 12.12 - PARTIAL - gcp.claude.project.oslogin_enabled, gcp.reviewed.compute.no_serial_console, gcp.reviewed.project.os_login_2fa
- [x] secnumcloud_3.2_gcp 12.13 - MANUAL - none
- [x] secnumcloud_3.2_gcp 12.14 - PARTIAL - gcp.reviewed.network.flow_logs
- [x] secnumcloud_3.2_gcp 13.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 13.2 - PARTIAL - gcp.claude.project.storage_vpc_service_controls, gcp.ports.compute_firewall_rule_rdp_access_restricted, gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] secnumcloud_3.2_gcp 13.3 - PARTIAL - gcp.claude.network.dns_logging, gcp.reviewed.network.flow_logs
- [x] secnumcloud_3.2_gcp 14.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 14.2 - MANUAL - none
- [x] secnumcloud_3.2_gcp 14.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 14.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 14.5 - MANUAL - none
- [x] secnumcloud_3.2_gcp 14.6 - PARTIAL - gcp.claude.project.container_scanning_api_enabled, gcp.ports.artifacts_container_analysis_enabled
- [x] secnumcloud_3.2_gcp 14.7 - MANUAL - none
- [x] secnumcloud_3.2_gcp 15.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 15.2 - MANUAL - none
- [x] secnumcloud_3.2_gcp 15.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 15.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 15.5 - MANUAL - none
- [x] secnumcloud_3.2_gcp 16.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 16.2 - MANUAL - none
- [x] secnumcloud_3.2_gcp 16.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 16.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 16.5 - MANUAL - none
- [x] secnumcloud_3.2_gcp 16.6 - MANUAL - none
- [x] secnumcloud_3.2_gcp 17.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 17.2 - PARTIAL - gcp.claude.instance_group_manager.autohealing, gcp.claude.instance_group_manager.multiple_zones, gcp.reviewed.compute.automatic_restart, gcp.reviewed.compute.maintenance_migrate
- [x] secnumcloud_3.2_gcp 17.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 17.4 - PARTIAL - gcp.claude.instance_group_manager.autohealing, gcp.claude.instance_group_manager.multiple_zones
- [x] secnumcloud_3.2_gcp 17.5 - MANUAL - none
- [x] secnumcloud_3.2_gcp 17.6 - PARTIAL - gcp.reviewed.storage.soft_delete, gcp.reviewed.storage.versioning, gcp.sql.backups
- [x] secnumcloud_3.2_gcp 18.1 - MANUAL - none
- [x] secnumcloud_3.2_gcp 18.2 - MANUAL - none
- [x] secnumcloud_3.2_gcp 18.3 - MANUAL - none
- [x] secnumcloud_3.2_gcp 18.4 - MANUAL - none
- [x] secnumcloud_3.2_gcp 19.1 - MANUAL - none
- [ ] secnumcloud_3.2_gcp 19.2 - NEW_CHECK - none
- [ ] secnumcloud_3.2_gcp 19.3 - NEW_CHECK - none
- [x] secnumcloud_3.2_gcp 19.4 - MANUAL - none
- [ ] secnumcloud_3.2_gcp 19.5 - PARTIAL - none
- [x] secnumcloud_3.2_gcp 19.6 - MANUAL - none

## soc2_gcp

- [x] soc2_gcp cc_1_3 - MANUAL - none
- [x] soc2_gcp cc_2_1 - MANUAL - none
- [x] soc2_gcp cc_3_1 - MANUAL - none
- [x] soc2_gcp cc_3_2 - MANUAL - none
- [x] soc2_gcp cc_3_3 - MANUAL - none
- [x] soc2_gcp cc_3_4 - MANUAL - none
- [x] soc2_gcp cc_4_2 - MANUAL - none
- [x] soc2_gcp cc_5_2 - MANUAL - none
- [x] soc2_gcp cc_6_1 - PARTIAL - gcp.storage.no_public_iam
- [x] soc2_gcp cc_6_2 - MANUAL - none
- [x] soc2_gcp cc_6_3 - MANUAL - none
- [x] soc2_gcp cc_6_6 - PARTIAL - gcp.compute.no_external_ip, gcp.ports.compute_firewall_rule_rdp_access_restricted, gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] soc2_gcp cc_6_7 - MANUAL - none
- [x] soc2_gcp cc_6_8 - MANUAL - none
- [x] soc2_gcp cc_7_1 - MANUAL - none
- [x] soc2_gcp cc_7_2 - PARTIAL - gcp.claude.logging.metric_alert_audit_configuration_changes, gcp.claude.logging.metric_alert_bucket_iam_changes, gcp.claude.logging.metric_alert_custom_role_changes, gcp.claude.logging.metric_alert_firewall_rule_changes, gcp.claude.logging.metric_alert_network_changes, gcp.claude.logging.metric_alert_project_ownership_changes, gcp.claude.logging.metric_alert_route_changes, gcp.claude.logging.metric_alert_sql_instance_configuration_changes
- [x] soc2_gcp cc_7_3 - MANUAL - none
- [x] soc2_gcp cc_7_4 - MANUAL - none
- [x] soc2_gcp cc_7_5 - MANUAL - none
- [x] soc2_gcp cc_8_1 - MANUAL - none
- [x] soc2_gcp cc_9_2 - MANUAL - none
- [x] soc2_gcp cc_a_1_1 - MANUAL - none
- [x] soc2_gcp cc_c_1_1 - MANUAL - none
- [x] soc2_gcp cc_c_1_2 - MANUAL - none
- [x] soc2_gcp pi_1_2 - MANUAL - none
- [x] soc2_gcp pi_1_3 - MANUAL - none
- [x] soc2_gcp pi_1_4 - MANUAL - none
- [x] soc2_gcp pi_1_5 - PARTIAL - gcp.claude.instance.disks_csek, gcp.ports.dataproc_cluster_encryption_with_cmek, gcp.sql.backups

## gcp-compliance.benchmark.hipaa

- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.audit_logging_configured_for_all_service - PARTIAL - gcp.ports.audit_logging_configured_for_all_service
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.compute_network_dns_logging_enabled - MAPPED - gcp.claude.network.dns_logging
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.compute_instance_with_no_public_ip_addresses - MAPPED - gcp.ports.compute_instance_with_no_public_ip_addresses
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.iam_user_not_assigned_service_account_user_role_project_level - MAPPED - gcp.ports.iam_user_not_assigned_service_account_user_role_project_level
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.kms_key_not_publicly_accessible - MAPPED - gcp.reviewed.kms.no_public_iam
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.kms_key_separation_of_duties_enforced - PARTIAL - gcp.ports.kms_key_separation_of_duties_enforced
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.prevent_public_ip_cloudsql - MAPPING_FIX - gcp.sql.no_public_ip
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.require_bq_table_iam - PARTIAL - gcp.reviewed.bigquery.no_public_acl
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.require_bucket_policy_only - MAPPED - gcp.storage.uniform_access
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.sql_instance_mysql_skip_show_database_flag_on - MAPPED - gcp.reviewed.sql.mysql_skip_show_database
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.sql_instance_not_publicly_accessible - MAPPED - gcp.claude.sql_instance.private_ip_only
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.sql_instance_sql_contained_database_authentication_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.sql_instance_sql_cross_db_ownership_chaining_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.storage_bucket_log_retention_policy_lock_enabled - MAPPED - gcp.claude.bucket.log_sink_retention_locked
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.sql_instance_automated_backups_enabled - MAPPED - gcp.sql.backups
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.project_service_cloudasset_api_enabled - MAPPED - gcp.ports.project_service_cloudasset_api_enabled
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.bigquery_dataset_encrypted_with_cmk - MAPPED - gcp.reviewed.bigquery.cmek
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.bigquery_table_encrypted_with_cmk - MAPPED - gcp.ports.bigquery_table_encrypted_with_cmk
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.compute_disk_encrypted_with_csk - MAPPED - gcp.ports.compute_disk_encrypted_with_csk
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.dataproc_cluster_encryption_with_cmek - MAPPED - gcp.ports.dataproc_cluster_encryption_with_cmek
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.kms_key_rotated_within_90_day - MAPPED - gcp.ports.kms_key_rotated_within_90_day
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.compute_https_load_balancer_logging_enabled - PARTIAL - gcp.ports.compute_url_map_backend_logging
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.logging_metric_alert_audit_configuration_changes - MAPPED - gcp.claude.logging.metric_alert_audit_configuration_changes
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.logging_metric_alert_custom_role_changes - MAPPED - gcp.claude.logging.metric_alert_custom_role_changes
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.logging_metric_alert_firewall_rule_changes - MAPPED - gcp.claude.logging.metric_alert_firewall_rule_changes
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.logging_metric_alert_network_changes - MAPPED - gcp.claude.logging.metric_alert_network_changes_beta_methods
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.logging_metric_alert_network_route_changes - MAPPED - gcp.claude.logging.metric_alert_route_changes
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.logging_metric_alert_project_ownership_assignment - MAPPED - gcp.claude.logging.metric_alert_project_ownership_changes
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.logging_metric_alert_sql_instance_configuration_changes - MAPPED - gcp.claude.logging.metric_alert_sql_instance_configuration_changes
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.logging_metric_alert_storage_iam_permission_changes - MAPPED - gcp.claude.logging.metric_alert_bucket_iam_changes
- [x] gcp-compliance.benchmark.hipaa gcp-compliance.control.logging_sink_configured_for_all_resource - MAPPED - gcp.claude.logging.project_sink_all_entries

## gcp-compliance.benchmark.nist_800_53_rev_5

- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_instance_oslogin_enabled - MAPPED - gcp.ports.compute_oslogin_metadata_precedence
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_instance_with_no_public_ip_addresses - MAPPED - gcp.ports.compute_instance_with_no_public_ip_addresses
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.iam_user_not_assigned_service_account_user_role_project_level - MAPPED - gcp.ports.iam_user_not_assigned_service_account_user_role_project_level
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.iam_user_separation_of_duty_enforced - PARTIAL - gcp.ports.iam_user_separation_of_duty_scoped
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.kms_key_not_publicly_accessible - MAPPED - gcp.reviewed.kms.no_public_iam
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.kms_key_separation_of_duties_enforced - PARTIAL - gcp.ports.kms_key_separation_of_duties_enforced
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.prevent_public_ip_cloudsql - MAPPING_FIX - gcp.sql.no_public_ip
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.require_bq_table_iam - PARTIAL - gcp.reviewed.bigquery.no_public_acl
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.require_bucket_policy_only - MAPPED - gcp.storage.uniform_access
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_mysql_skip_show_database_flag_on - MAPPED - gcp.reviewed.sql.mysql_skip_show_database
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_sql_contained_database_authentication_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_sql_cross_db_ownership_chaining_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_world_readable - PARTIAL - gcp.ports.sql_instance_not_open_to_internet
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.storage_bucket_log_retention_policy_lock_enabled - MAPPED - gcp.claude.bucket.log_sink_retention_locked
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.storage_bucket_not_publicly_accessible - MAPPED - gcp.storage.no_public_iam
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.iam_service_account_without_admin_privilege - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_instance_block_project_wide_ssh_enabled - PARTIAL - gcp.ports.compute_instance_block_project_wide_ssh_enabled
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_network_contains_no_default_network - MAPPED - gcp.reviewed.network.no_default_vpc
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_network_contains_no_legacy_network - MAPPED - gcp.ports.compute_network_contains_no_legacy_network
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.dns_managed_zone_dnssec_enabled - MAPPED - gcp.claude.dns_zone.dnssec_enabled
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.dnssec_prevent_rsasha1_ksk - MAPPED - gcp.claude.dns_zone.ksk_not_rsasha1
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_https_load_balancer_logging_enabled - PARTIAL - gcp.ports.compute_url_map_backend_logging
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.logging_metric_alert_audit_configuration_changes - MAPPED - gcp.claude.logging.metric_alert_audit_configuration_changes
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.logging_metric_alert_custom_role_changes - MAPPED - gcp.claude.logging.metric_alert_custom_role_changes
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.logging_metric_alert_firewall_rule_changes - MAPPED - gcp.claude.logging.metric_alert_firewall_rule_changes
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.logging_metric_alert_network_changes - MAPPED - gcp.claude.logging.metric_alert_network_changes_beta_methods
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.logging_metric_alert_network_route_changes - MAPPED - gcp.claude.logging.metric_alert_route_changes
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.logging_metric_alert_project_ownership_assignment - MAPPED - gcp.claude.logging.metric_alert_project_ownership_changes
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.logging_metric_alert_sql_instance_configuration_changes - MAPPED - gcp.claude.logging.metric_alert_sql_instance_configuration_changes
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.logging_metric_alert_storage_iam_permission_changes - MAPPED - gcp.claude.logging.metric_alert_bucket_iam_changes
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.logging_sink_configured_for_all_resource - MAPPED - gcp.claude.logging.project_sink_all_entries
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter - MAPPED - gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.alloydb_instance_log_min_error_statement_database_flag_configured - MAPPED - gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.alloydb_instance_log_min_messages_database_flag_error - MAPPED - gcp.ports.alloydb_instance_log_min_messages_database_flag_error
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_network_dns_logging_enabled - MAPPED - gcp.claude.network.dns_logging
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_postgresql_log_connections_database_flag_on - MAPPED - gcp.reviewed.sql.postgres_log_connections
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_postgresql_log_disconnections_database_flag_on - MAPPED - gcp.reviewed.sql.postgres_log_disconnections
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter - MAPPED - gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled - MAPPED - gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_postgresql_log_min_error_statement_database_flag_configured - MAPPED - gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_postgresql_log_min_messages_database_flag_error - MAPPED - gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_postgresql_log_statement_database_flag_ddl - MAPPED - gcp.reviewed.sql.postgres_log_statement
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.audit_logging_configured_for_all_service - PARTIAL - gcp.ports.audit_logging_configured_for_all_service
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_instance_ip_forwarding_disabled - PARTIAL - gcp.ports.compute_instance_ip_forwarding_disabled
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.restrict_firewall_rule_rdp_world_open - MAPPED - gcp.ports.compute_firewall_rule_rdp_access_restricted
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.restrict_firewall_rule_ssh_world_open - MAPPED - gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_sql_3625_trace_database_flag_on - MAPPED - gcp.ports.sql_instance_sql_3625_trace_database_flag_on
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_sql_user_connections_database_flag_configured - MAPPING_FIX - gcp.ports.sql_instance_sql_user_connections_database_flag_configured
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_sql_user_options_database_flag_not_configured - MAPPED - gcp.ports.sql_instance_sql_user_options_database_flag_not_configured
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_instance_serial_port_connection_disabled - MAPPED - gcp.reviewed.compute.no_serial_console
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_mysql_local_infile_database_flag_off - MAPPED - gcp.reviewed.sql.mysql_local_infile
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_sql_remote_access_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_remote_access_database_flag_off
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.sql_instance_sql_external_scripts_enabled_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.project_service_cloudasset_api_enabled - MAPPED - gcp.ports.project_service_cloudasset_api_enabled
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.bigquery_dataset_encrypted_with_cmk - MAPPED - gcp.reviewed.bigquery.cmek
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.bigquery_table_encrypted_with_cmk - MAPPED - gcp.ports.bigquery_table_encrypted_with_cmk
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_disk_encrypted_with_csk - MAPPED - gcp.ports.compute_disk_encrypted_with_csk
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_instance_confidential_computing_enabled - MAPPED - gcp.reviewed.compute.confidential_computing
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_instance_with_no_default_service_account - PARTIAL - gcp.ports.compute_instance_with_no_default_service_account
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.compute_instance_with_no_default_service_account_with_full_access - PARTIAL - gcp.ports.compute_instance_with_no_default_service_account_with_full_access
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.dataproc_cluster_encryption_with_cmek - MAPPED - gcp.ports.dataproc_cluster_encryption_with_cmek
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.kms_key_rotated_within_90_day - MAPPED - gcp.ports.kms_key_rotated_within_90_day
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.organization_essential_contacts_configured - MAPPED - gcp.ports.organization_essential_contacts_complete
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.iam_api_key_age_90 - MAPPED - gcp.ports.iam_api_key_age_90
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.iam_api_key_restricts_apis - PARTIAL - gcp.ports.iam_api_key_restricts_apis
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.project_no_api_key - MAPPED - gcp.claude.project.no_api_keys
- [x] gcp-compliance.benchmark.nist_800_53_rev_5 gcp-compliance.control.enable_network_flow_logs - MAPPED - gcp.reviewed.network.flow_logs

## gcp-compliance.benchmark.nist_csf_v10

- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.audit_logging_configured_for_all_service - PARTIAL - gcp.ports.audit_logging_configured_for_all_service
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_network_dns_logging_enabled - MAPPED - gcp.claude.network.dns_logging
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter - MAPPED - gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.alloydb_instance_log_min_error_statement_database_flag_configured - MAPPED - gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.alloydb_instance_log_min_messages_database_flag_error - MAPPED - gcp.ports.alloydb_instance_log_min_messages_database_flag_error
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_https_load_balancer_logging_enabled - PARTIAL - gcp.ports.compute_url_map_backend_logging
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.logging_metric_alert_audit_configuration_changes - MAPPED - gcp.claude.logging.metric_alert_audit_configuration_changes
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.logging_metric_alert_custom_role_changes - MAPPED - gcp.claude.logging.metric_alert_custom_role_changes
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.logging_metric_alert_firewall_rule_changes - MAPPED - gcp.claude.logging.metric_alert_firewall_rule_changes
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.logging_metric_alert_network_changes - MAPPED - gcp.claude.logging.metric_alert_network_changes_beta_methods
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.logging_metric_alert_network_route_changes - MAPPED - gcp.claude.logging.metric_alert_route_changes
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.logging_metric_alert_project_ownership_assignment - MAPPED - gcp.claude.logging.metric_alert_project_ownership_changes
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.logging_metric_alert_sql_instance_configuration_changes - MAPPED - gcp.claude.logging.metric_alert_sql_instance_configuration_changes
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.logging_metric_alert_storage_iam_permission_changes - MAPPED - gcp.claude.logging.metric_alert_bucket_iam_changes
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.logging_sink_configured_for_all_resource - MAPPED - gcp.claude.logging.project_sink_all_entries
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_postgresql_log_connections_database_flag_on - MAPPED - gcp.reviewed.sql.postgres_log_connections
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_postgresql_log_disconnections_database_flag_on - MAPPED - gcp.reviewed.sql.postgres_log_disconnections
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter - MAPPED - gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled - MAPPED - gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_postgresql_log_min_error_statement_database_flag_configured - MAPPED - gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_postgresql_log_min_messages_database_flag_error - MAPPED - gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_postgresql_log_statement_database_flag_ddl - MAPPED - gcp.reviewed.sql.postgres_log_statement
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.enable_network_flow_logs - MAPPED - gcp.reviewed.network.flow_logs
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.project_service_cloudasset_api_enabled - MAPPED - gcp.ports.project_service_cloudasset_api_enabled
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_instance_with_no_default_service_account_with_full_access - PARTIAL - gcp.ports.compute_instance_with_no_default_service_account_with_full_access
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_instance_with_no_default_service_account - PARTIAL - gcp.ports.compute_instance_with_no_default_service_account
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_instance_with_no_public_ip_addresses - MAPPED - gcp.ports.compute_instance_with_no_public_ip_addresses
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.iam_service_account_without_admin_privilege - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.iam_user_not_assigned_service_account_user_role_project_level - MAPPED - gcp.ports.iam_user_not_assigned_service_account_user_role_project_level
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.iam_user_separation_of_duty_enforced - PARTIAL - gcp.ports.iam_user_separation_of_duty_scoped
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.kms_key_not_publicly_accessible - MAPPED - gcp.reviewed.kms.no_public_iam
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.kms_key_separation_of_duties_enforced - PARTIAL - gcp.ports.kms_key_separation_of_duties_enforced
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.prevent_public_ip_cloudsql - MAPPING_FIX - gcp.sql.no_public_ip
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.require_bq_table_iam - PARTIAL - gcp.reviewed.bigquery.no_public_acl
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.require_bucket_policy_only - MAPPED - gcp.storage.uniform_access
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_mysql_skip_show_database_flag_on - MAPPED - gcp.reviewed.sql.mysql_skip_show_database
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_not_publicly_accessible - MAPPED - gcp.claude.sql_instance.private_ip_only
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_sql_contained_database_authentication_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_sql_cross_db_ownership_chaining_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.storage_bucket_log_retention_policy_lock_enabled - MAPPED - gcp.claude.bucket.log_sink_retention_locked
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.storage_bucket_not_publicly_accessible - MAPPED - gcp.storage.no_public_iam
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.bigquery_dataset_encrypted_with_cmk - MAPPED - gcp.reviewed.bigquery.cmek
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.bigquery_table_encrypted_with_cmk - MAPPED - gcp.ports.bigquery_table_encrypted_with_cmk
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_disk_encrypted_with_csk - MAPPED - gcp.ports.compute_disk_encrypted_with_csk
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_instance_confidential_computing_enabled - MAPPED - gcp.reviewed.compute.confidential_computing
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.dataproc_cluster_encryption_with_cmek - MAPPED - gcp.ports.dataproc_cluster_encryption_with_cmek
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.kms_key_rotated_within_90_day - MAPPED - gcp.ports.kms_key_rotated_within_90_day
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_instance_block_project_wide_ssh_enabled - PARTIAL - gcp.ports.compute_instance_block_project_wide_ssh_enabled
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_network_contains_no_default_network - MAPPED - gcp.reviewed.network.no_default_vpc
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.compute_network_contains_no_legacy_network - MAPPED - gcp.ports.compute_network_contains_no_legacy_network
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.dns_managed_zone_dnssec_enabled - MAPPED - gcp.claude.dns_zone.dnssec_enabled
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.dnssec_prevent_rsasha1_ksk - MAPPED - gcp.claude.dns_zone.ksk_not_rsasha1
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_mysql_local_infile_database_flag_off - MAPPED - gcp.reviewed.sql.mysql_local_infile
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_sql_3625_trace_database_flag_on - MAPPED - gcp.ports.sql_instance_sql_3625_trace_database_flag_on
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_sql_external_scripts_enabled_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_sql_user_connections_database_flag_configured - MAPPING_FIX - gcp.ports.sql_instance_sql_user_connections_database_flag_configured
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_sql_user_options_database_flag_not_configured - MAPPED - gcp.ports.sql_instance_sql_user_options_database_flag_not_configured
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.iam_api_key_age_90 - MAPPED - gcp.ports.iam_api_key_age_90
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.iam_api_key_restricts_apis - PARTIAL - gcp.ports.iam_api_key_restricts_apis
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.project_no_api_key - MAPPED - gcp.claude.project.no_api_keys
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.sql_instance_automated_backups_enabled - MAPPED - gcp.sql.backups
- [x] gcp-compliance.benchmark.nist_csf_v10 gcp-compliance.control.organization_essential_contacts_configured - MAPPED - gcp.ports.organization_essential_contacts_complete

## gcp-compliance.benchmark.nist_csf_v2

- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.audit_logging_configured_for_all_service - PARTIAL - gcp.ports.audit_logging_configured_for_all_service
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_metric_alert_audit_configuration_changes - MAPPED - gcp.claude.logging.metric_alert_audit_configuration_changes
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_metric_alert_custom_role_changes - MAPPED - gcp.claude.logging.metric_alert_custom_role_changes
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_metric_alert_firewall_rule_changes - MAPPED - gcp.claude.logging.metric_alert_firewall_rule_changes
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_metric_alert_network_changes - MAPPED - gcp.claude.logging.metric_alert_network_changes_beta_methods
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_metric_alert_network_route_changes - MAPPED - gcp.claude.logging.metric_alert_route_changes
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_metric_alert_project_ownership_assignment - MAPPED - gcp.claude.logging.metric_alert_project_ownership_changes
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_metric_alert_sql_instance_configuration_changes - MAPPED - gcp.claude.logging.metric_alert_sql_instance_configuration_changes
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_metric_alert_storage_iam_permission_changes - MAPPED - gcp.claude.logging.metric_alert_bucket_iam_changes
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_sink_configured_for_all_resource - MAPPED - gcp.claude.logging.project_sink_all_entries
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_network_dns_logging_enabled - MAPPED - gcp.claude.network.dns_logging
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.enable_network_flow_logs - MAPPED - gcp.reviewed.network.flow_logs
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.project_access_approval_settings_enabled - MAPPED - gcp.ports.access_approval_explicit_enrollment
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_api_key_age_90 - MAPPED - gcp.ports.iam_api_key_age_90
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_service_account_key_age_90 - MAPPED - gcp.ports.iam_service_account_key_age_90
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.project_service_cloudasset_api_enabled - MAPPED - gcp.ports.project_service_cloudasset_api_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_monitoring_enabled - MAPPED - gcp.claude.gke.monitoring_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.only_my_domain - PARTIAL - gcp.ports.iam_corporate_domain_declaration
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.organization_essential_contacts_configured - MAPPED - gcp.ports.organization_essential_contacts_complete
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.restrict_gmail_bigquery_dataset - MAPPED - gcp.claude.bigquery_dataset.no_gmail_access
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.restrict_googlegroups_bigquery_dataset - MAPPED - gcp.claude.bigquery_dataset.no_googlegroups_access
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_bucket_retention_policy_enabled - MAPPED - gcp.claude.bucket.log_sink_retention_locked
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.logging_metric_alert_custom_role_changes_with_iam_admin_undelete_role - MAPPED - gcp.claude.logging.metric_alert_custom_role_changes_with_undelete
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_service_account_gcp_managed_key - MAPPED - gcp.ports.iam_service_account_gcp_managed_key
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.cmek_rotation_one_hundred_days - MAPPED - gcp.claude.kms_key.rotation_100_days
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kms_key_rotated_within_90_day - MAPPED - gcp.ports.kms_key_rotated_within_90_day
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.require_bucket_policy_only - MAPPED - gcp.storage.uniform_access
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_user_not_assigned_service_account_user_role_project_level - MAPPED - gcp.ports.iam_user_not_assigned_service_account_user_role_project_level
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.denylist_public_users - MAPPED - gcp.claude.iam_policy.no_all_users
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.storage_bucket_not_publicly_accessible - MAPPED - gcp.storage.no_public_iam
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_user_kms_separation_of_duty_enforced - PARTIAL - gcp.ports.kms_key_separation_of_duties_enforced
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_user_separation_of_duty_enforced - PARTIAL - gcp.ports.iam_user_separation_of_duty_scoped
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_logging_enabled - MAPPED - gcp.claude.firewall.logging_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_logging_enabled - MAPPED - gcp.claude.gke.logging_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.sql_instance_postgresql_cloudsql_pgaudit_database_flag_enabled - MAPPED - gcp.reviewed.sql.postgres_pgaudit
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.sql_instance_postgresql_log_checkpoints_database_flag_on - MAPPED - gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.sql_instance_postgresql_log_connections_database_flag_on - MAPPED - gcp.reviewed.sql.postgres_log_connections
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.sql_instance_postgresql_log_statement_database_flag_ddl - MAPPED - gcp.reviewed.sql.postgres_log_statement
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.storage_bucket_log_not_publicly_accessible - MAPPED - gcp.claude.bucket.log_sink_not_public
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.storage_bucket_log_object_versioning_enabled - MAPPED - gcp.claude.bucket.log_sink_versioning
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.storage_bucket_log_retention_policy_enabled - MAPPED - gcp.claude.bucket.log_sink_retention_policy
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled - MAPPED - gcp.ports.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kms_key_separation_of_duties_enforced - PARTIAL - gcp.ports.kms_key_separation_of_duties_enforced
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kms_key_users_limited_to_3 - MAPPED - gcp.claude.kms_key.users_limited_to_3
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_disk_encrypted_with_csk - MAPPED - gcp.ports.compute_disk_encrypted_with_csk
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_instance_block_project_wide_ssh_enabled - PARTIAL - gcp.ports.compute_instance_block_project_wide_ssh_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_instance_confidential_computing_enabled - MAPPED - gcp.reviewed.compute.confidential_computing
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_instance_oslogin_enabled - MAPPED - gcp.ports.compute_oslogin_metadata_precedence
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_instance_serial_port_connection_disabled - MAPPED - gcp.reviewed.compute.no_serial_console
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_instance_shielded_vm_enabled - MAPPED - gcp.ports.compute_instance_shielded_vm_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_instance_with_no_default_service_account - PARTIAL - gcp.ports.compute_instance_with_no_default_service_account
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_instance_with_no_public_ip_addresses - MAPPED - gcp.ports.compute_instance_with_no_public_ip_addresses
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.project_service_container_scanning_api_enabled - MAPPED - gcp.claude.project.container_scanning_api_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_binary_authorization_enabled - MAPPED - gcp.claude.gke.binary_authorization
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_shielded_node_secure_boot_enabled - MAPPED - gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.sql_instance_sql_contained_database_authentication_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_api_key_restricts_apis - PARTIAL - gcp.ports.iam_api_key_restricts_apis
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_api_key_restricts_websites_hosts_apps - MAPPED - gcp.ports.iam_api_key_restricts_websites_hosts_apps
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_restrict_service_account_key_age_one_hundred_days - MAPPED - gcp.claude.service_account_key.age_100_days
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.iam_service_account_without_admin_privilege - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kms_key_not_publicly_accessible - MAPPED - gcp.reviewed.kms.no_public_iam
- [ ] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_client_certificate_authentication_enabled - NEW_CHECK - none
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_https_load_balancer_logging_enabled - PARTIAL - gcp.ports.compute_url_map_backend_logging
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_ssl_policy_with_no_weak_cipher - PARTIAL - gcp.ports.compute_ssl_policy_strict_declaration
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_target_https_uses_latest_tls_version - PARTIAL - gcp.ports.compute_ssl_policy_strict_declaration, gcp.claude.target_proxy.https_min_tls_1_2
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.require_ssl_sql - MAPPED - gcp.ports.sql_instance_require_ssl_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.dataproc_cluster_encryption_with_cmek - MAPPED - gcp.ports.dataproc_cluster_encryption_with_cmek
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.sql_instance_automated_backups_enabled - MAPPED - gcp.sql.backups
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.sql_instance_not_publicly_accessible - MAPPED - gcp.claude.sql_instance.private_ip_only
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_default_rule_restrict_ingress_access_except_http_and_https - MAPPED - gcp.claude.firewall.default_rules_not_open
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.storage_bucket_log_retention_policy_lock_enabled - MAPPED - gcp.claude.bucket.log_sink_retention_locked
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.cloudfunction_function_vpc_connector_enabled - MAPPED - gcp.claude2.function.vpc_connector_configured
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_allow_connections_proxied_by_iap - PARTIAL - gcp.ports.firewall_iap_tcp_proxy_source_restriction
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_allow_tcp_connections_proxied_by_iap - PARTIAL - gcp.ports.firewall_iap_tcp_proxy_source_restriction
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_dns_port_53 - MAPPED - gcp.claude.firewall.public_ingress_dns_port_53
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_ftp_port_21 - MAPPED - gcp.claude.firewall.public_ingress_ftp_port_21
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_http_port_80 - MAPPED - gcp.claude.firewall.public_ingress_http_port_80
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_microsoft_ds_port_445 - MAPPED - gcp.claude.firewall.public_ingress_microsoft_ds_port_445
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_mongo_db_port_27017 - MAPPED - gcp.claude.firewall.public_ingress_mongo_db_port_27017
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_mysql_db_port_3306 - MAPPED - gcp.claude.firewall.public_ingress_mysql_db_port_3306
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_netbios_snn_port_139 - MAPPED - gcp.claude.firewall.public_ingress_netbios_snn_port_139
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_oracle_db_port_1521 - MAPPED - gcp.claude.firewall.public_ingress_oracle_db_port_1521
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_pop3_port_110 - MAPPED - gcp.claude.firewall.public_ingress_pop3_port_110
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_postgresql_port_10250 - MAPPED - gcp.claude.firewall.public_ingress_postgresql_port_10250
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_postgresql_port_10255 - MAPPED - gcp.claude.firewall.public_ingress_postgresql_port_10255
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_postgresql_port_5432 - MAPPED - gcp.claude.firewall.public_ingress_postgresql_port_5432
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_smtp_port_25 - MAPPED - gcp.claude.firewall.public_ingress_smtp_port_25
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_137_to_139 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_137_to_139
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_27017_to_27019 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_27017_to_27019
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_61620_61621 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_61620_61621
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_636 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_636
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_6379 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_6379
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_7000_7001 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_7000_7001
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_7199 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_7199
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_8888 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_8888
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9042 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_9042
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9090 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_9090
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9160 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_9160
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9200_9300 - MAPPED - gcp.claude.firewall.public_ingress_tcp_port_9200_9300
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_11211 - MAPPED - gcp.claude.firewall.public_ingress_tcp_udp_port_11211
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_11214_to_11215 - MAPPED - gcp.claude.firewall.public_ingress_tcp_udp_port_11214_to_11215
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_2483_to_2484 - MAPPED - gcp.claude.firewall.public_ingress_tcp_udp_port_2483_to_2484
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_389 - MAPPED - gcp.claude.firewall.public_ingress_tcp_udp_port_389
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_telnet_port_23 - MAPPED - gcp.claude.firewall.public_ingress_telnet_port_23
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_restrict_ingress_all_with_no_specific_target - MAPPED - gcp.claude.firewall.public_ingress_without_target
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_firewall_rule_restrict_ingress_all - MAPPED - gcp.claude.firewall.public_ingress_all_protocols
- [ ] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_network_auto_create_subnetwork_enabled - NEW_CHECK - none
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_network_contains_no_default_network - MAPPED - gcp.reviewed.network.no_default_vpc
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.compute_network_contains_no_legacy_network - MAPPED - gcp.ports.compute_network_contains_no_legacy_network
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.enable_gke_master_authorized_networks - MAPPED - gcp.gke.authorized_networks
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.enable_network_private_google_access - MAPPED - gcp.subnetwork.private_google_access
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_network_policy_enabled - MAPPED - gcp.gke.network_policy
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_no_default_network - MAPPED - gcp.claude.gke.no_default_network
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_private_nodes_configured - MAPPED - gcp.gke.private_nodes
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_subnetwork_private_ip_google_access_enabled - MAPPED - gcp.claude.gke.subnetwork_private_google_access
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.restrict_firewall_rule_rdp_world_open - MAPPED - gcp.ports.compute_firewall_rule_rdp_access_restricted
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.restrict_firewall_rule_ssh_world_open - MAPPED - gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.restrict_firewall_rule_world_open_tcp_udp_all_ports - MAPPED - gcp.claude.firewall.public_ingress_tcp_udp
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_shielded_nodes_enabled - MAPPED - gcp.gke.shielded_nodes
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.enable_auto_repair - MAPPED - gcp.ports.kubernetes_cluster_auto_repair_enabled
- [x] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.enable_auto_upgrade - MAPPED - gcp.ports.kubernetes_cluster_auto_upgrade_enabled
- [ ] gcp-compliance.benchmark.nist_csf_v2 gcp-compliance.control.kubernetes_cluster_with_less_than_three_node_auto_upgrade_enabled - NEW_CHECK - none

## gcp-compliance.benchmark.soc_2_2017

- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.organization_essential_contacts_configured - MAPPED - gcp.ports.organization_essential_contacts_complete
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.project_service_cloudasset_api_enabled - MAPPED - gcp.ports.project_service_cloudasset_api_enabled
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.audit_logging_configured_for_all_service - PARTIAL - gcp.ports.audit_logging_configured_for_all_service
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_network_dns_logging_enabled - MAPPED - gcp.claude.network.dns_logging
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_sql_external_scripts_enabled_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_network_contains_no_default_network - MAPPED - gcp.reviewed.network.no_default_vpc
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_network_contains_no_legacy_network - MAPPED - gcp.ports.compute_network_contains_no_legacy_network
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.dns_managed_zone_dnssec_enabled - MAPPED - gcp.claude.dns_zone.dnssec_enabled
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.dnssec_prevent_rsasha1_ksk - MAPPED - gcp.claude.dns_zone.ksk_not_rsasha1
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_world_readable - PARTIAL - gcp.ports.sql_instance_not_open_to_internet
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter - MAPPED - gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.alloydb_instance_log_min_error_statement_database_flag_configured - MAPPED - gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.alloydb_instance_log_min_messages_database_flag_error - MAPPED - gcp.ports.alloydb_instance_log_min_messages_database_flag_error
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_instance_with_no_public_ip_addresses - MAPPED - gcp.ports.compute_instance_with_no_public_ip_addresses
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.iam_user_not_assigned_service_account_user_role_project_level - MAPPED - gcp.ports.iam_user_not_assigned_service_account_user_role_project_level
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.iam_user_separation_of_duty_enforced - PARTIAL - gcp.ports.iam_user_separation_of_duty_scoped
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.kms_key_not_publicly_accessible - MAPPED - gcp.reviewed.kms.no_public_iam
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.kms_key_separation_of_duties_enforced - PARTIAL - gcp.ports.kms_key_separation_of_duties_enforced
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.require_bq_table_iam - PARTIAL - gcp.reviewed.bigquery.no_public_acl
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.require_bucket_policy_only - MAPPED - gcp.storage.uniform_access
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_mysql_skip_show_database_flag_on - MAPPED - gcp.reviewed.sql.mysql_skip_show_database
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_not_publicly_accessible - MAPPED - gcp.claude.sql_instance.private_ip_only
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_postgresql_log_connections_database_flag_on - MAPPED - gcp.reviewed.sql.postgres_log_connections
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_postgresql_log_disconnections_database_flag_on - MAPPED - gcp.reviewed.sql.postgres_log_disconnections
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter - MAPPED - gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled - MAPPED - gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_postgresql_log_min_error_statement_database_flag_configured - MAPPED - gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_postgresql_log_min_messages_database_flag_error - MAPPED - gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_postgresql_log_statement_database_flag_ddl - MAPPED - gcp.reviewed.sql.postgres_log_statement
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_sql_contained_database_authentication_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_sql_cross_db_ownership_chaining_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.storage_bucket_log_retention_policy_lock_enabled - MAPPED - gcp.claude.bucket.log_sink_retention_locked
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.storage_bucket_not_publicly_accessible - MAPPED - gcp.storage.no_public_iam
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.alloydb_cluster_encrypted_with_cmk - MAPPED - gcp.ports.alloydb_cluster_encrypted_with_cmk
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.bigquery_dataset_encrypted_with_cmk - MAPPED - gcp.reviewed.bigquery.cmek
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.bigquery_table_encrypted_with_cmk - MAPPED - gcp.ports.bigquery_table_encrypted_with_cmk
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_disk_encrypted_with_csk - MAPPED - gcp.ports.compute_disk_encrypted_with_csk
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_instance_block_project_wide_ssh_enabled - PARTIAL - gcp.ports.compute_instance_block_project_wide_ssh_enabled
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_instance_confidential_computing_enabled - MAPPED - gcp.reviewed.compute.confidential_computing
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.dataproc_cluster_encryption_with_cmek - MAPPED - gcp.ports.dataproc_cluster_encryption_with_cmek
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.iam_service_account_without_admin_privilege - PARTIAL - gcp.gap.iam_user_managed_sa_no_admin_roles
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.kms_key_rotated_within_90_day - MAPPED - gcp.ports.kms_key_rotated_within_90_day
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_instance_oslogin_enabled - MAPPED - gcp.ports.compute_oslogin_metadata_precedence
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.project_oslogin_enabled - MAPPED - gcp.claude.project.oslogin_enabled
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_instance_with_no_default_service_account - PARTIAL - gcp.ports.compute_instance_with_no_default_service_account
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_instance_with_no_default_service_account_with_full_access - PARTIAL - gcp.ports.compute_instance_with_no_default_service_account_with_full_access
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_instance_ip_forwarding_disabled - PARTIAL - gcp.ports.compute_instance_ip_forwarding_disabled
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.compute_instance_serial_port_connection_disabled - MAPPED - gcp.reviewed.compute.no_serial_console
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.restrict_firewall_rule_rdp_world_open - MAPPED - gcp.ports.compute_firewall_rule_rdp_access_restricted
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.restrict_firewall_rule_ssh_world_open - MAPPED - gcp.ports.compute_firewall_rule_ssh_access_restricted
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_sql_remote_access_database_flag_off - MAPPED - gcp.ports.sql_instance_sql_remote_access_database_flag_off
- [ ] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_sql_3625_trace_database_flag_off - NEW_CHECK - none
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_sql_user_connections_database_flag_configured - MAPPING_FIX - gcp.ports.sql_instance_sql_user_connections_database_flag_configured
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.sql_instance_sql_user_options_database_flag_not_configured - MAPPED - gcp.ports.sql_instance_sql_user_options_database_flag_not_configured
- [x] gcp-compliance.benchmark.soc_2_2017 gcp-compliance.control.enable_network_flow_logs - MAPPED - gcp.reviewed.network.flow_logs

## gcp-perimeter.benchmark.iam_policy_public_access

- [x] gcp-perimeter.benchmark.iam_policy_public_access gcp-perimeter.control.bigquery_dataset_policy_prohibit_public_access - MAPPED - gcp.reviewed.bigquery.no_public_acl
- [x] gcp-perimeter.benchmark.iam_policy_public_access gcp-perimeter.control.cloud_run_service_policy_prohibit_public_access - MAPPED - gcp.ports.cloud_run_service_policy_prohibit_public_access
- [x] gcp-perimeter.benchmark.iam_policy_public_access gcp-perimeter.control.compute_image_policy_prohibit_public_access - MAPPED - gcp.claude.image.not_public
- [x] gcp-perimeter.benchmark.iam_policy_public_access gcp-perimeter.control.kms_key_policy_prohibit_public_access - MAPPED - gcp.reviewed.kms.no_public_iam
- [x] gcp-perimeter.benchmark.iam_policy_public_access gcp-perimeter.control.pubsub_snapshot_policy_prohibit_public_access - MAPPED - gcp.claude.pubsub_snapshot.not_public
- [x] gcp-perimeter.benchmark.iam_policy_public_access gcp-perimeter.control.pubsub_subscription_policy_prohibit_public_access - MAPPED - gcp.claude.pubsub_subscription.not_public
- [x] gcp-perimeter.benchmark.iam_policy_public_access gcp-perimeter.control.pubsub_topic_policy_prohibit_public_access - MAPPED - gcp.claude.pubsub_topic.not_public
- [x] gcp-perimeter.benchmark.iam_policy_public_access gcp-perimeter.control.storage_bucket_policy_prohibit_public_access - MAPPED - gcp.storage.no_public_iam

## gcp-perimeter.benchmark.iam_policy_shared_access

- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.bigtable_instance_policy_shared_access - MAPPED - gcp.ports.bigtable_instance_policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.billing_account_policy_shared_access - MAPPED - gcp.ports.billing_account_policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.cloud_function_policy_shared_access - MAPPED - gcp.ports.cloud_function_policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.cloud_run_job_policy_shared_access - MAPPED - gcp.ports.cloud_run_job_policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.cloud_run_service_policy_shared_access - MAPPED - gcp.ports.cloud_run_service_policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.compute_disk_policy_shared_access - MAPPED - gcp.claude.disk.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.compute_image_policy_shared_access - MAPPED - gcp.claude.image.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.compute_instance_policy_shared_access - MAPPED - gcp.claude.instance.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.compute_node_group_policy_shared_access - MAPPED - gcp.claude.node_group.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.compute_node_template_policy_shared_access - MAPPED - gcp.claude.node_template.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.compute_resource_policy_shared_access - MAPPED - gcp.claude.resource_policy.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.compute_subnetwork_policy_shared_access - MAPPED - gcp.claude.subnetwork.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.iam_service_account_policy_shared_access - MAPPED - gcp.claude.service_account.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.kms_key_policy_shared_access - MAPPED - gcp.claude.kms_key.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.kms_key_ring_policy_shared_access - MAPPED - gcp.claude.kms_key_ring.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.pubsub_subscription_policy_shared_access - MAPPED - gcp.claude.pubsub_subscription.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.pubsub_topic_policy_shared_access - MAPPED - gcp.claude.pubsub_topic.policy_shared_access
- [x] gcp-perimeter.benchmark.iam_policy_shared_access gcp-perimeter.control.storage_bucket_policy_shared_access - MAPPED - gcp.claude.bucket.policy_shared_access

## gcp-perimeter.benchmark.network_access

- [x] gcp-perimeter.benchmark.network_access gcp-perimeter.control.vpc_firewall_restrict_ingress_common_ports - MAPPED - gcp.claude.firewall.public_ingress_common_ports
- [x] gcp-perimeter.benchmark.network_access gcp-perimeter.control.vpc_firewall_restrict_ingress_tcp_udp_all - MAPPED - gcp.claude.firewall.public_ingress_tcp_udp
- [x] gcp-perimeter.benchmark.network_access gcp-perimeter.control.cloud_run_not_publicly_accessible - MAPPING_FIX - gcp.ports.cloud_run_not_publicly_accessible, gcp.ports.cloud_run_service_policy_prohibit_public_access
- [x] gcp-perimeter.benchmark.network_access gcp-perimeter.control.cloud_sql_not_publicly_accessible - MAPPED - gcp.sql.no_public_ip
- [x] gcp-perimeter.benchmark.network_access gcp-perimeter.control.cloudfunction_function_not_publicly_accessible - PARTIAL - gcp.ports.function_internal_ingress_declaration
- [x] gcp-perimeter.benchmark.network_access gcp-perimeter.control.gke_cluster_master_authorized_networks_not_publicly_accessible - MAPPED - gcp.claude.gke.master_authorized_networks_restricted
- [x] gcp-perimeter.benchmark.network_access gcp-perimeter.control.gke_cluster_nodes_not_publicly_accessible - MAPPED - gcp.claude.gke.private_nodes

## Proposed new checks

### gcp_api_keys_active_services_only

- Resource: api_key
- Data source: existing collected type api_key + restrictions.apiTargets[].service,deleteTime and project_service + name,state
- Predicate: FAIL when an active API key has no API targets or names a service whose project_service.state is DISABLED; UNKNOWN when target service state is not collected.
- Severity: medium
- Category: identity
- Title: API key can target an inactive service
- Description: Detects when api key can target an inactive service.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_artifact_registry_cleanup_policy

- Resource: artifact_repository
- Data source: new read-only Artifact Registry:Repositories.list with cleanupPolicies and cleanupPolicyDryRun
- Predicate: FAIL when no active DELETE cleanup policy enforces organization max_artifact_age; UNKNOWN without retention policy.
- Severity: medium
- Category: retention
- Title: Artifact repository lacks age-based cleanup
- Description: Detects when artifact repository lacks age-based cleanup.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_autoscaler_capacity_target

- Resource: autoscaler
- Data source: new read-only Compute:Autoscalers.list with autoscalingPolicy.cpuUtilization.utilizationTarget,minNumReplicas,maxNumReplicas,target
- Predicate: FAIL when utilizationTarget exceeds 0.8 or maxNumReplicas cannot add at least one instance above current size; UNKNOWN without target MIG size.
- Severity: medium
- Category: availability
- Title: Autoscaler cannot expand at 80 percent capacity
- Description: Detects when autoscaler cannot expand at 80 percent capacity.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_certificate_renewal_30_days

- Resource: certificate
- Data source: new read-only Certificate Manager:ListCertificates with name,expireTime,createTime,managed.state,managed.domains plus CertificateMaps.list and entries for deployment
- Predicate: FAIL when a deployed certificate crosses its 30-day-to-expiry threshold and no ACTIVE replacement covering its domains was deployed within 24 hours; UNKNOWN without certificate or deployment timestamps.
- Severity: high
- Category: encryption
- Title: Certificate lacks timely renewal
- Description: Detects when certificate lacks timely renewal.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_certificate_rotation_180_days

- Resource: certificate
- Data source: new read-only Certificate Manager:ListCertificates with createTime,managed.state,managed.domains and deployment association
- Predicate: FAIL when an ACTIVE deployed certificate was created more than 180 days ago; UNKNOWN when createTime or deployment association is missing.
- Severity: high
- Category: encryption
- Title: Deployed certificate exceeds 180-day rotation limit
- Description: Detects when deployed certificate exceeds 180-day rotation limit.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_certificate_rotation_90_days

- Resource: certificate
- Data source: new read-only Certificate Manager:ListCertificates with createTime,managed.state,managed.domains and deployment association
- Predicate: FAIL when an ACTIVE deployed certificate was created more than 90 days ago; UNKNOWN when createTime or deployment association is missing.
- Severity: high
- Category: encryption
- Title: Deployed certificate exceeds 90-day rotation limit
- Description: Detects when deployed certificate exceeds 90-day rotation limit.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_certificate_validity

- Resource: certificate
- Data source: new read-only Certificate Manager:ListCertificates with name,expireTime,managed.state
- Predicate: FAIL when expireTime is past or managed.state is not ACTIVE; UNKNOWN when certificate status is unavailable.
- Severity: high
- Category: encryption
- Title: Managed certificate is expired or inactive
- Description: Detects when managed certificate is expired or inactive.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloud_armor_cidr_deny

- Resource: security_policy
- Data source: new read-only Compute:SecurityPolicies.list with rules.match.expr.expression,action and associated backendServices
- Predicate: FAIL when an internet-facing backend lacks a DENY rule for requests outside approved_cidrs; UNKNOWN without the approved CIDR set.
- Severity: high
- Category: network
- Title: Load balancer allows callers outside approved CIDRs
- Description: Detects when load balancer allows callers outside approved cidrs.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloud_armor_rate_limit

- Resource: security_policy
- Data source: new read-only Compute:SecurityPolicies.list plus BackendServices.list; rules.rateLimitOptions.rateLimitThreshold.count/intervalSec, banDurationSec, action, priority and backend securityPolicy association
- Predicate: FAIL when an internet-facing backend lacks a matching throttle or rate-based ban rule with count at most 2000 per intervalSec at most 300 and banDurationSec at least 60; UNKNOWN when backend association, rule precedence, or per-client key is unavailable.
- Severity: high
- Category: network
- Title: Public backend lacks request rate limiting
- Description: Detects when public backend lacks request rate limiting.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloud_armor_waf_enabled

- Resource: security_policy
- Data source: new read-only Compute:SecurityPolicies.list with rules.match.expr.expression,action and backend association
- Predicate: FAIL when an internet-facing backend has no enabled WAF preconfigured-rule expression; UNKNOWN without backend association.
- Severity: high
- Category: network
- Title: Public backend has no web application filtering
- Description: Detects when public backend has no web application filtering.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloudbuild_private_pool

- Resource: worker_pool
- Data source: new read-only Cloud Build:WorkerPools.list with privatePoolV1Config.networkConfig.peeredNetwork and workerPool state
- Predicate: FAIL when an enabled worker pool lacks an approved peeredNetwork; UNKNOWN without an approved network list.
- Severity: high
- Category: network
- Title: Cloud Build worker pool is reachable outside approved network
- Description: Detects when cloud build worker pool is reachable outside approved network.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloudbuild_trigger_trust

- Resource: cloudbuild_trigger
- Data source: existing collected type cloudbuild_trigger + triggerTemplate,github,repositoryEventConfig,serviceAccount,disabled
- Predicate: FAIL when an enabled trigger uses a repository or service account outside approved allowlists; UNKNOWN without allowlists.
- Severity: high
- Category: supply_chain
- Title: Cloud Build trigger accepts unapproved source
- Description: Detects when cloud build trigger accepts unapproved source.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloudcdn_cache_policy

- Resource: backend_service
- Data source: new read-only Compute:BackendServices.list with enableCDN,cdnPolicy.cacheMode,cdnPolicy.clientTtl,cdnPolicy.defaultTtl
- Predicate: FAIL when CDN is enabled for a sensitive backend without an approved cacheMode and TTL; UNKNOWN without backend sensitivity policy.
- Severity: medium
- Category: data_protection
- Title: Sensitive backend has an unapproved CDN cache policy
- Description: Detects when sensitive backend has an unapproved cdn cache policy.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloudcdn_cookie_ttl

- Resource: backend_service
- Data source: new read-only Compute:BackendServices.list with sessionAffinity,affinityCookieTtlSec; CDN fields are unrelated
- Predicate: FAIL when GENERATED_COOKIE or HTTP_COOKIE affinity has affinityCookieTtlSec above 1800 seconds; UNKNOWN when cookie TTL is absent. Absolute affinity TTL cannot establish expiry after inactivity.
- Severity: medium
- Category: network
- Title: Load balancer affinity cookie exceeds 30 minutes
- Description: Detects when load balancer affinity cookie exceeds 30 minutes.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloudsql_backup_failure_alert

- Resource: project
- Data source: new read-only Logging:Metrics.list and Monitoring:AlertPolicies.list with filter,conditions,enabled
- Predicate: FAIL when no enabled alert policy covers FAILED Cloud SQL backup runs; UNKNOWN if either alert resource is unavailable.
- Severity: high
- Category: backup
- Title: Cloud SQL backup failures lack an alert
- Description: Detects when cloud sql backup failures lack an alert.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloudsql_backup_freshness

- Resource: sql_instance
- Data source: new read-only SQL Admin:BackupRuns.list with instance,status,endTime,type
- Predicate: FAIL when no SUCCESSFUL backup exists within the organization backup RPO; UNKNOWN when RPO is not supplied.
- Severity: high
- Category: backup
- Title: Cloud SQL backup is older than recovery objective
- Description: Detects when cloud sql backup is older than recovery objective.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_cloudsql_failed_attempts_lockout

- Resource: sql_instance
- Data source: new read-only SQL Admin:instances.list/get; settings.passwordValidationPolicy.enablePasswordPolicy and failedAttemptsCheck
- Predicate: FAIL when password policy or failedAttemptsCheck is false for an in-scope SQL instance; UNKNOWN when the engine or effective setting is unavailable. This is a lockout configuration signal, not a timed brute-force test.
- Severity: medium
- Category: identity
- Title: Cloud SQL password failed-attempt lockout is disabled
- Description: Cloud SQL password failed-attempt lockout is disabled.
- Remediation: Configure the named resource and verify the stated predicate.

### gcp_compute_approved_image

- Resource: instance
- Data source: existing collected instance and disk types; join instance.disks[].source to disk.selfLink and inspect disk.sourceImage or sourceSnapshot, with approved_image_projects context
- Predicate: FAIL when a VM boot disk sourceImage is outside approved_image_projects; UNKNOWN when the boot disk origin was not retained or the approval list is unavailable.
- Severity: high
- Category: compute
- Title: VM uses an unapproved image
- Description: Detects when vm uses an unapproved image.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_compute_approved_packages

- Resource: instance
- Data source: new read-only OS Config:Inventories.get with items.installedPackages and approved_packages context
- Predicate: FAIL when an installed package is absent from approved_packages or violates approved version ranges; UNKNOWN without OS inventory or the allowlist.
- Severity: medium
- Category: vulnerability
- Title: VM contains unapproved installed software
- Description: Detects when vm contains unapproved installed software.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_compute_os_patch_compliance

- Resource: instance
- Data source: new read-only OS Config:Inventories.get with updateTime,osInfo,items.availablePackages and vulnerabilityReport
- Predicate: FAIL when critical security packages remain unapplied beyond approved patch SLA; UNKNOWN without SLA or OS inventory.
- Severity: high
- Category: vulnerability
- Title: VM security patches exceed approved SLA
- Description: Detects when vm security patches exceed approved sla.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_gcs_replication_status

- Resource: bucket
- Data source: new read-only Cloud Storage Buckets.get with location, customPlacementConfig.dataLocations, replication and rpo; organizational expected_replica_locations context
- Predicate: FAIL when the declared replica locations differ from expected_replica_locations; UNKNOWN when the policy or service synchronization status is unavailable.
- Severity: medium
- Category: availability
- Title: Bucket replication topology or health is unavailable
- Description: Bucket replication topology or health is unavailable.
- Remediation: Configure the named resource and verify the stated predicate.

### gcp_gke_client_certificate_enabled

- Resource: gke_cluster
- Data source: existing collected type gke_cluster from Container API clusters.list; masterAuth.clientCertificateConfig.issueClientCertificate
- Predicate: FAIL when issueClientCertificate is false for a cluster to which this literal control applies; UNKNOWN when client certificate configuration is absent. This control requests a legacy authentication mode.
- Severity: medium
- Category: identity
- Title: GKE client certificate issuance is disabled
- Description: GKE client certificate issuance is disabled.
- Remediation: Configure the named resource and verify the stated predicate.

### gcp_gke_small_cluster_auto_upgrade

- Resource: gke_cluster
- Data source: existing collected type gke_cluster + nodePools[].management.autoUpgrade and nodePools[].instanceGroupUrls; new read-only Compute:InstanceGroupManagers.get with targetSize for each node pool group
- Predicate: FAIL when total current node pool targetSize is less than three and any node pool has management.autoUpgrade not true; PASS when total size is three or more; UNKNOWN when node count or management state is unavailable.
- Severity: medium
- Category: vulnerability
- Title: Small GKE cluster lacks node auto upgrade
- Description: Detects when small gke cluster lacks node auto upgrade.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_https_proxy_mtls_required

- Resource: target_https_proxy
- Data source: new read-only Compute:TargetHttpsProxies.list with serverTlsPolicy; Network Security:ServerTlsPolicies.get with mtlsPolicy.clientValidationMode
- Predicate: FAIL when an HTTPS proxy lacks a server TLS policy requiring REJECT_INVALID client certificates; UNKNOWN when policy resolution fails.
- Severity: high
- Category: encryption
- Title: HTTPS proxy does not require client certificates
- Description: Detects when https proxy does not require client certificates.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_iam_workforce_mfa

- Resource: workforce_pool
- Data source: new read-only IAM:WorkforcePools.list and WorkforcePoolProviders.list with attributeMapping,disabled and provider configuration
- Predicate: FAIL when an enabled workforce provider does not require a mapped MFA assurance claim; UNKNOWN when IdP assurance metadata is unavailable.
- Severity: high
- Category: identity
- Title: Workforce federation lacks MFA assurance
- Description: Detects when workforce federation lacks mfa assurance.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_kms_approved_algorithm

- Resource: kms_key_version
- Data source: new read-only Cloud KMS:CryptoKeyVersions.list with algorithm,state and key purpose
- Predicate: FAIL when an ENABLED version uses an algorithm outside organization approved_algorithms; UNKNOWN without approved_algorithms.
- Severity: high
- Category: encryption
- Title: KMS key version uses an unapproved algorithm
- Description: Detects when kms key version uses an unapproved algorithm.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_kms_key_destroy_alert

- Resource: project
- Data source: new read-only Logging:Metrics.list and Monitoring:AlertPolicies.list with filter,conditions,enabled
- Predicate: FAIL when no enabled alert references a metric covering Cloud KMS key-version disable or destroy method names; UNKNOWN on missing logging data.
- Severity: high
- Category: monitoring
- Title: KMS key disable or destroy events lack an alert
- Description: Detects when kms key disable or destroy events lack an alert.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_lb_server_header_rewrite

- Resource: url_map
- Data source: existing collected type url_map + headerAction.responseHeadersToAdd[] and pathMatchers[].routeRules[].headerAction
- Predicate: FAIL when a public URL map lacks a replace=true response header action setting Server to lb on every route; UNKNOWN when route coverage is incomplete.
- Severity: medium
- Category: network
- Title: Load balancer does not rewrite Server header
- Description: Detects when load balancer does not rewrite server header.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1110

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code,protoPayload.requestMetadata.callerIp
- Predicate: FAIL when at least 10 authentication events with nonzero protoPayload.status.code have the same principalEmail and callerIp within 300 seconds; UNKNOWN when authentication event logging or either grouping field is unavailable.
- Severity: high
- Category: threat_detection
- Title: Suspicious authentication brute force
- Description: Detects when suspicious authentication brute force.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1119

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code
- Predicate: FAIL when successful protoPayload.methodName values ending in .List or .Get for one principalEmail exceed approved_read_rate within 300 seconds; UNKNOWN without entries or the supplied rate.
- Severity: high
- Category: threat_detection
- Title: Suspicious automated data collection
- Description: Detects when suspicious automated data collection.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1136

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code
- Predicate: FAIL when a successful google.iam.admin.v1.CreateServiceAccount event has a principal outside approved_identity_admins; UNKNOWN without audit entries or the allowlist.
- Severity: high
- Category: threat_detection
- Title: Suspicious service account creation
- Description: Detects when suspicious service account creation.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1490

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.request,protoPayload.status.code
- Predicate: FAIL when a successful cloudsql.backupRuns.delete event or cloudsql.instances.update event setting settings.backupConfiguration.enabled=false has a principal outside approved_backup_admins; UNKNOWN without entries or the allowlist.
- Severity: high
- Category: threat_detection
- Title: Suspicious backup deletion or disablement
- Description: Detects when suspicious backup deletion or disablement.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1518

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code
- Predicate: FAIL when successful osconfig.inventories.get events for one principalEmail exceed approved_list_rate within 300 seconds; UNKNOWN without entries or the supplied rate.
- Severity: high
- Category: threat_detection
- Title: Suspicious software discovery
- Description: Detects when suspicious software discovery.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1526

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code
- Predicate: FAIL when successful serviceusage.services.list events for one principalEmail exceed approved_list_rate within 300 seconds; UNKNOWN without entries or the supplied rate.
- Severity: high
- Category: threat_detection
- Title: Suspicious cloud service discovery
- Description: Detects when suspicious cloud service discovery.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1546

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code
- Predicate: FAIL when a successful google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger or google.cloud.scheduler.v1.CloudScheduler.CreateJob event has a principal outside approved_automation_admins; UNKNOWN without audit entries or the allowlist.
- Severity: high
- Category: threat_detection
- Title: Suspicious event trigger creation
- Description: Detects when suspicious event trigger creation.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1614

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code
- Predicate: FAIL when successful compute.regions.list or compute.zones.list events for one principalEmail exceed approved_list_rate within 300 seconds; UNKNOWN without entries or the supplied rate.
- Severity: high
- Category: threat_detection
- Title: Suspicious region discovery
- Description: Detects when suspicious region discovery.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1619

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code
- Predicate: FAIL when successful storage.objects.list events for one principalEmail exceed approved_list_rate within 300 seconds; UNKNOWN without entries or the supplied rate.
- Severity: high
- Category: threat_detection
- Title: Suspicious storage object discovery
- Description: Detects when suspicious storage object discovery.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1648

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,resource.type,protoPayload.status.code
- Predicate: FAIL when a successful Cloud Run run.routes.invoke or Cloud Functions cloudfunctions.functions.call event has a principal outside approved_invokers; UNKNOWN without audit entries or the allowlist.
- Severity: high
- Category: threat_detection
- Title: Suspicious serverless execution
- Description: Detects when suspicious serverless execution.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_detect_t1651

- Resource: audit_log
- Data source: new read-only Cloud Logging entries.list for the project audit log with protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code
- Predicate: FAIL when a successful SetIamPolicy or UpdateProject method event has a principal outside approved_cloud_admins; UNKNOWN without audit entries or the allowlist.
- Severity: high
- Category: threat_detection
- Title: Suspicious cloud administration change
- Description: Detects when suspicious cloud administration change.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_enumeration_alert

- Resource: project
- Data source: new read-only Logging projects.metrics.list (name,filter) and Monitoring projects.alertPolicies.list (enabled,conditions[].conditionThreshold.filter,conditions[].conditionThreshold.aggregations[].perSeriesAligner,conditions[].conditionThreshold.thresholdValue,notificationChannels); audit entry protoPayload.methodName and authenticationInfo.principalEmail
- Predicate: FAIL when no enabled alert policy is linked to a log metric filtering protoPayload.methodName ending in .list or .get and grouping authenticationInfo.principalEmail, with a threshold of at most 10 events in 300 seconds and at least one notificationChannel; UNKNOWN if either inventory is unavailable.
- Severity: medium
- Category: monitoring
- Title: Cloud resource enumeration lacks an alert
- Description: Detects when cloud resource enumeration lacks an alert.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_query_rate_alert

- Resource: project
- Data source: new read-only Logging projects.metrics.list (name,filter) and Monitoring projects.alertPolicies.list (enabled,conditions[].conditionThreshold.filter,conditions[].conditionThreshold.thresholdValue,conditions[].conditionThreshold.aggregations[].alignmentPeriod,notificationChannels); audit entry protoPayload.methodName and authenticationInfo.principalEmail
- Predicate: FAIL when no enabled alert links a log metric filtering protoPayload.methodName for logging.entries.list, groups authenticationInfo.principalEmail, and alerts above the supplied approved_query_count within 300 seconds with a notificationChannel; UNKNOWN without the count or either inventory.
- Severity: medium
- Category: monitoring
- Title: Excessive log queries lack an alert
- Description: Detects when excessive log queries lack an alert.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_logging_scc_findings_alert

- Resource: organization
- Data source: new read-only Security Command Center:Findings.list and Monitoring:AlertPolicies.list with state,severity,createTime,conditions,enabled
- Predicate: FAIL when ACTIVE HIGH or CRITICAL findings have no enabled notification/alert route; UNKNOWN when SCC access is unavailable.
- Severity: high
- Category: monitoring
- Title: High severity SCC findings lack an alert route
- Description: Detects when high severity scc findings lack an alert route.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_network_auto_subnets_enabled

- Resource: network
- Data source: existing collected type network + autoCreateSubnetworks
- Predicate: FAIL when autoCreateSubnetworks is not true; UNKNOWN when the field is unavailable.
- Severity: medium
- Category: network
- Title: VPC network does not auto-create subnetworks
- Description: Detects when vpc network does not auto-create subnetworks.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_pubsub_topic_cmek

- Resource: pubsub_topic
- Data source: existing collected type pubsub_topic + kmsKeyName
- Predicate: FAIL when kmsKeyName is empty for an in-scope topic; UNKNOWN when topic metadata is missing.
- Severity: high
- Category: encryption
- Title: Pub/Sub topic has no customer-managed encryption key
- Description: Detects when pub/sub topic has no customer-managed encryption key.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_resource_approved_location

- Resource: cloud_asset
- Data source: new read-only Cloud Asset Inventory:SearchAllResources with name,assetType,location; organization approved_locations policy supplied as context
- Predicate: FAIL when a collected resource location is absent from the explicit approved_locations allowlist; UNKNOWN without a policy or location.
- Severity: high
- Category: data_residency
- Title: Resource location is not approved
- Description: Detects when resource location is not approved.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_resource_label_inventory

- Resource: cloud_asset
- Data source: new read-only Cloud Asset Inventory:SearchAllResources with name,assetType,labels
- Predicate: FAIL when an in-scope asset lacks required owner,criticality,data_classification labels; UNKNOWN when policy keys are not supplied.
- Severity: medium
- Category: asset_management
- Title: Cloud asset lacks inventory labels
- Description: Detects when cloud asset lacks inventory labels.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_source_repo_access_restricted

- Resource: source_repository
- Data source: new read-only Source Repositories:Repos.list and Repos.getIamPolicy with bindings.role,bindings.members
- Predicate: FAIL when a repository grants read or write roles to allUsers, allAuthenticatedUsers, or a principal outside approved_developers; UNKNOWN without the allowlist.
- Severity: high
- Category: identity
- Title: Source repository permits unapproved access
- Description: Detects when source repository permits unapproved access.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_sql_trace3625_off

- Resource: sql_instance
- Data source: existing collected type sql_instance from SQL Admin instances.list; settings.databaseFlags[name=3625].value and databaseVersion
- Predicate: FAIL when a SQL Server instance explicitly sets trace flag 3625 to on; UNKNOWN when the effective default or flag value cannot be established. The literal source requests off although the native on check tests the opposite.
- Severity: medium
- Category: configuration
- Title: SQL Server trace flag 3625 is enabled
- Description: SQL Server trace flag 3625 is enabled.
- Remediation: Configure the named resource and verify the stated predicate.

### gcp_vpc_peering_allowlist

- Resource: network
- Data source: existing collected type network + peerings[].network,peerings[].state; approved_peer_networks context
- Predicate: FAIL when an ACTIVE peering target is absent from approved_peer_networks; UNKNOWN without the allowlist.
- Severity: high
- Category: network
- Title: VPC peers with an unapproved network
- Description: Detects when vpc peers with an unapproved network.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_workbench_approved_image

- Resource: workbench_instance
- Data source: existing collected type workbench_instance + gceSetup.vmImage, gceSetup.containerImage
- Predicate: FAIL when the declared VM or container image is outside approved_workbench_images; UNKNOWN without an image allowlist.
- Severity: high
- Category: compute
- Title: Workbench instance uses an unapproved image
- Description: Detects when workbench instance uses an unapproved image.
- Remediation: Configure the resource to satisfy the stated predicate.

### gcp_workbench_approved_vpc

- Resource: workbench_instance
- Data source: existing collected type workbench_instance from Notebooks v2 instances.list; gceSetup.networkInterfaces[].network and approved_workbench_networks context
- Predicate: FAIL when a Workbench instance uses a VPC outside the explicit approved_workbench_networks allowlist; UNKNOWN without that allowlist or network metadata.
- Severity: medium
- Category: network
- Title: Workbench instance uses an unapproved VPC
- Description: Workbench instance uses an unapproved VPC.
- Remediation: Configure the named resource and verify the stated predicate.

### gcp_workbench_download_disabled

- Resource: workbench_instance
- Data source: existing collected type workbench_instance from Notebooks v2 instances.list; gceSetup.metadata.notebook-disable-downloads plus sensitive classification context
- Predicate: FAIL when a sensitive instance does not set notebook-disable-downloads to true; UNKNOWN without sensitivity classification or metadata.
- Severity: medium
- Category: compute
- Title: Sensitive Workbench instance allows file downloads
- Description: Sensitive Workbench instance allows file downloads.
- Remediation: Configure the named resource and verify the stated predicate.

### gcp_workbench_no_public_ip

- Resource: workbench_instance
- Data source: existing collected type workbench_instance from Notebooks v2 instances.list; gceSetup.disablePublicIp and sensitive classification context
- Predicate: FAIL when a sensitive Workbench instance does not explicitly set disablePublicIp true; UNKNOWN without sensitivity classification or this field.
- Severity: medium
- Category: network
- Title: Sensitive Workbench instance permits a public IP
- Description: Sensitive Workbench instance permits a public IP.
- Remediation: Configure the named resource and verify the stated predicate.

### gcp_workbench_root_disabled

- Resource: workbench_instance
- Data source: existing collected type workbench_instance from Notebooks v2 instances.list; gceSetup.metadata.notebook-disable-root plus sensitive classification context
- Predicate: FAIL when a sensitive instance does not set notebook-disable-root to true, or a nonsensitive instance enables root without an explicit approved exception; UNKNOWN without classification and exception context.
- Severity: medium
- Category: compute
- Title: Workbench root access violates classification policy
- Description: Workbench root access violates classification policy.
- Remediation: Configure the named resource and verify the stated predicate.

### gcp_workbench_terminal_disabled

- Resource: workbench_instance
- Data source: existing collected type workbench_instance from Notebooks v2 instances.list; gceSetup.metadata.notebook-disable-terminal plus sensitive classification context
- Predicate: FAIL when a sensitive instance does not set notebook-disable-terminal to true, or a nonsensitive instance enables terminal access without an explicit approved exception; UNKNOWN without classification and exception context.
- Severity: medium
- Category: compute
- Title: Workbench terminal access violates classification policy
- Description: Workbench terminal access violates classification policy.
- Remediation: Configure the named resource and verify the stated predicate.

