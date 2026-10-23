import type { Finding } from "./types";
import rules from "./azureObservedEvidenceRules.json" with { type: "json" };
import notApplicable from "./azureNotApplicableEvidence.json" with { type: "json" };
import notApplicableVariants from "./azureNotApplicableVariants.json" with { type: "json" };
import manualEvidence from "./azureManualEvidence.json" with { type: "json" };
import incomplete from "./azureIncompleteEvidenceReasons.json" with { type: "json" };
import activityAlerts from "./azureActivityAlertEvidence.json" with { type: "json" };
import missingFactLabels from "./azureMissingFactLabels.json" with { type: "json" };
import dependencyLabels from "./azureDependencyLabels.json" with { type: "json" };
import servicebusNetwork from "./azureServicebusNetworkEvidence.json" with { type: "json" };
import unknownGroupEffects from "./azureUnknownGroupEffects.json" with { type: "json" };
import unknownGroupById from "./azureUnknownGroupById.json" with { type: "json" };
import unknownSpecificEffects from "./azureUnknownSpecificEffects.json" with { type: "json" };
import nativeImpacts from "./azureNativeObservedImpacts.json" with { type: "json" };
import bulkImpactPatterns from "./azureBulkObservedImpactPatterns.json" with { type: "json" };
import { explainAzureNativeEvidenceObservation } from "./azureNativeEvidenceObservation";
import { azureLongSemanticEvidence } from "./azureLongSemanticEvidence";

type Rule = {
  field: string;
  configured_field?: string;
  required?: Record<string, unknown>;
  fail_value?: unknown;
  pass_value?: unknown;
  fail_array_state?: "empty" | "nonempty";
  pass_array_state?: "empty" | "nonempty";
  fail?: string[];
  pass?: string[];
  missing_reason?: string;
  unknown?: string[];
  unknown_variants?: { required: Record<string, unknown>; lines: string[] }[];
  pass_variants?: { required: Record<string, unknown>; array_states?: Record<string, "empty" | "nonempty">; lines: string[] }[];
  fail_variants?: { required: Record<string, unknown>; array_states?: Record<string, "empty" | "nonempty">; lines: string[] }[];
};

function matchesRecorded(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length &&
    expected.every((item, index) => matchesRecorded(actual[index], item));
  if (expected !== null && typeof expected === "object") {
    if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
    const recorded = actual as Record<string, unknown>;
    const target = expected as Record<string, unknown>;
    return Object.keys(recorded).length === Object.keys(target).length &&
      Object.entries(target).every(([key, value]) => Object.prototype.hasOwnProperty.call(recorded, key) &&
        matchesRecorded(recorded[key], value));
  }
  return actual === expected;
}

function singleUnknownReason(evidence: Record<string, unknown>): string | null {
  let current: Record<string, unknown> = evidence;
  for (let depth = 0; depth < 3; depth++) {
    if (current.evaluated_count !== 1 || !Array.isArray(current.outcomes) || current.outcomes.length !== 1) return null;
    const next = current.outcomes[0];
    if (!next || typeof next !== "object" || Array.isArray(next) || next.status !== "UNKNOWN") return null;
    current = next as Record<string, unknown>;
    if (typeof current.reason === "string") return current.reason;
  }
  return null;
}

/** Short Azure copy is bound to a reviewed check ID and its recorded field. */
export function formatAzureObservedEvidence(finding: Finding, _observation: string, _row: unknown): string | null {
  if (finding.provider !== "azure" || !["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "MANUAL"].includes(finding.status)) return null;
  const rule = (rules as Record<string, Rule>)[finding.check_id];
  const evidence = finding.evidence;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return null;
  if (finding.status === "MANUAL") {
    const manual = (manualEvidence as Record<string, { required: Record<string, unknown>; lines: string[] }>)[finding.check_id];
    const values = evidence as Record<string, unknown>;
    return manual && Object.entries(manual.required).every(([key, value]) => matchesRecorded(values[key], value))
      ? manual.lines.join("\n") : null;
  }
  const sourceValues = evidence as Record<string, unknown>;
  if (finding.status === "UNKNOWN" && sourceValues.reason === "authenticated complete AKS native Pod/Namespace capture unavailable") {
    if (finding.check_id === "azure_aks_cluster_7_2_1_6_93c4fab")
      return "A complete authenticated AKS Pod and Namespace record is unavailable.\nThe containers' privilege settings remain unknown.\nThe team cannot tell whether any container could run with broad access.";
    if (finding.check_id === "azure_aks_cluster_aks_cluster_rbac_enabled_db12524")
      return "A complete authenticated AKS Pod and Namespace record is unavailable.\nThe containers' run-as-user settings remain unknown.\nThe team cannot tell whether an app could run as root.";
  }
  if (finding.status === "UNKNOWN" && finding.check_id === "azure_aks_cluster_aks_cluster_rbac_enabled_db12524" && sourceValues.reason === "Windows OS, node OS or security context unresolved")
    return "The Pod OS or container security context is unresolved.\nThe container's run-as-user setting remains unknown.\nThe team cannot tell whether this app could run as root.";
  if (finding.status === "UNKNOWN" && finding.check_id === "azure.logging.aks_supported_log_categories_destination_declared" && sourceValues.reason === "native AKS diagnostic declaration incomplete, malformed or unbound")
    return "The AKS diagnostic declaration is incomplete or unbound.\nThe destination for supported log categories remains unknown.\nThe team cannot tell where the cluster activity may be recorded.";
  if (finding.check_id === "azure_nsg_world_ingress_approved_ports" && finding.status === "FAIL" &&
      Array.isArray(sourceValues.observed_nsg_paths) && sourceValues.observed_nsg_paths.length === sourceValues.evaluated) {
    const offending = sourceValues.observed_nsg_paths.flatMap(value => {
      const fact = value as Record<string, unknown>;
      if (typeof fact.nsg_id !== "string" || !Array.isArray(fact.world_source_allowed_ports) || !Array.isArray(fact.approved_ports)) return [];
      return fact.world_source_allowed_ports.filter((port: unknown) => Number.isInteger(port) && !(fact.approved_ports as unknown[]).includes(port));
    });
    if (offending.length > 0)
      return `An NSG allows world-source inbound traffic on unapproved port ${offending[0]}.\nOutside hosts may send traffic toward that port.\nThe service could face more unwanted connection attempts.`;
  }
  if (finding.check_id === "azure_recovery_vault_10_3_3_1_1f42f66" && finding.status === "FAIL" &&
      Array.isArray(sourceValues.backup_policy_facts) && sourceValues.backup_policy_facts.length === sourceValues.evaluated &&
      sourceValues.backup_policy_facts.length === 1) {
    const fact = sourceValues.backup_policy_facts[0] as Record<string, unknown>;
    if (typeof fact.database_id === "string" && fact.retention_days === 0)
      return "The SQL database has a short-term backup retention setting of zero days.\nOlder restore points may not be kept under that policy.\nPeople could have fewer ways to recover data after a mistake.";
  }
  if (finding.check_id === "azure_recovery_vault_10_3_3_8_26e08d7" && finding.status === "FAIL" &&
      Array.isArray(sourceValues.backup_window_facts) && sourceValues.backup_window_facts.length === sourceValues.evaluated &&
      sourceValues.backup_window_facts.length === 1) {
    const fact = sourceValues.backup_window_facts[0] as Record<string, unknown>;
    if (typeof fact.database_id === "string" && fact.retention_days === 0 && fact.latest_restore_point === null)
      return "The SQL database has a backup retention setting of zero days.\nThat policy may leave no older restore point to use.\nPeople could lose data after a mistake.";
  }
  if (finding.check_id === "azure_sql_database_sqlserver_auditing_enabled_77d6841" && finding.status === "FAIL" &&
      Array.isArray(sourceValues.diagnostic_facts) && sourceValues.diagnostic_facts.length === sourceValues.evaluated &&
      sourceValues.diagnostic_facts.length === 1) {
    const fact = sourceValues.diagnostic_facts[0] as Record<string, unknown>;
    if (typeof fact.resource_id === "string" && Array.isArray(fact.missing_categories) && fact.missing_categories.includes("audit"))
      return "The SQL database is missing the required audit log export category.\nSome database activity may not reach the approved workspace.\nThe team could have less detail when investigating data use.";
  }
  if (finding.check_id === "azure_c5_ops_17_02ac" && finding.status === "PASS" &&
      Array.isArray(sourceValues.direct_control_measures) && sourceValues.direct_control_measures.length === sourceValues.direct_control_measure_count &&
      sourceValues.direct_control_measures.length > 0 && sourceValues.direct_control_measures.every(value => {
        const fact = value as Record<string, unknown>;
        return typeof fact.control === "string" && typeof fact.measure_id === "string" &&
          fact.observation === "implemented" && fact.documented === true;
      }))
    return `${sourceValues.direct_control_measure_count} required log and infrastructure safeguards are documented as implemented.\nThey may protect access to logs and keep services available.\nThe team could rely on these records during an investigation.`;
  if (finding.check_id === "azure_recovery_vault_10_3_3_1_1f42f66" && finding.status === "PASS" &&
      Array.isArray(sourceValues.backup_policy_facts) && sourceValues.backup_policy_facts.length === sourceValues.evaluated &&
      sourceValues.backup_policy_facts.length === 1) {
    const fact = sourceValues.backup_policy_facts[0] as Record<string, unknown>;
    if (typeof fact.database_id === "string" && Number.isInteger(fact.retention_days) && (fact.retention_days as number) > 0)
      return `The SQL database has a ${fact.retention_days}-day short-term backup retention policy.\nThat policy may keep point-in-time recovery available for recent changes.\nPeople could have a way to restore data after a mistake.`;
  }
  if (finding.check_id === "azure_recovery_vault_10_3_3_8_26e08d7" && finding.status === "PASS" &&
      Array.isArray(sourceValues.backup_window_facts) && sourceValues.backup_window_facts.length === sourceValues.evaluated &&
      sourceValues.backup_window_facts.length === 1) {
    const fact = sourceValues.backup_window_facts[0] as Record<string, unknown>;
    if (typeof fact.database_id === "string" && Number.isInteger(fact.retention_days) && (fact.retention_days as number) > 0 &&
        typeof fact.latest_restore_point === "string" && typeof fact.captured_at === "string" &&
        Number.isFinite(Date.parse(fact.latest_restore_point)) && Number.isFinite(Date.parse(fact.captured_at)) &&
        Date.parse(fact.latest_restore_point) <= Date.parse(fact.captured_at))
      return `The SQL database has a ${fact.retention_days}-day backup policy and a recorded restore point.\nThat restore point may cover a recent data loss.\nPeople could have a way to recover their data.`;
  }
  if (finding.check_id === "azure.claude.storage_vhd_accounts_cmk" && finding.status === "UNKNOWN" &&
      sourceValues.reason === "VHD selected subscription identity malformed")
    return "The VHD record has no valid selected subscription identity.\nIts backing storage account cannot be matched to that subscription.\nThe team cannot tell which key protects the disk file.";
  if (finding.check_id === "azure.sql.minimum_tls" && finding.status === "UNKNOWN" &&
      sourceValues.reason === "SQL minimum TLS declaration unavailable")
    return "The SQL server record has no usable minimum TLS declaration.\nThe permitted connection version is unclear.\nPeople may not know whether older connections are allowed.";
  if (finding.check_id === "azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled" && finding.status === "FAIL" &&
      Array.isArray(sourceValues.outcomes) && sourceValues.outcomes.length === 1) {
    const group = sourceValues.outcomes[0] as Record<string, unknown>;
    if (group.status === "FAIL" && Array.isArray(group.outcomes)) {
      const path = group.outcomes.find(value => {
        const fact = value as Record<string, unknown>;
        return fact.status === "FAIL" && fact.reason === "permitted sign-in path without MFA" &&
          typeof fact.principal_id === "string" && typeof fact.context_id === "string";
      }) as Record<string, unknown> | undefined;
      if (path) return `The ${path.context_id} sign-in path permits ${path.principal_id} without MFA.\nA password alone may be enough on that path.\nSomeone with a stolen password could enter as that user.`;
    }
  }
  if (finding.check_id === "azure_c5_ops_13_01b" && finding.status === "PASS" &&
      Array.isArray(sourceValues.verified_source_ids) && sourceValues.verified_source_ids.length === sourceValues.verified_sources &&
      sourceValues.verified_source_ids.length > 0 && sourceValues.verified_source_ids.every(id => typeof id === "string" && id.length > 0) &&
      typeof sourceValues.approved_destination_id === "string" && sourceValues.correlation_verified === true &&
      sourceValues.incident_workflow_verified === true && sourceValues.safeguard_inventory_documented === true)
    return `${sourceValues.verified_source_ids.join(", ")} logs have verified export and ingestion to the approved SIEM destination.\nThe central log may keep those events together.\nThe team could investigate changes to these services sooner.`;
  if (finding.check_id === "azure_vm_vm_ensure_using_managed_disks_11f205b" && finding.status === "PASS" &&
      Array.isArray(sourceValues.observed_disk_mappings) && sourceValues.observed_disk_mappings.length === sourceValues.checked_mappings &&
      sourceValues.observed_disk_mappings.length > 0 && sourceValues.observed_disk_mappings.every(value => {
        const fact = value as Record<string, unknown>;
        return typeof fact.disk_id === "string" && typeof fact.vm_id === "string" && fact.attached === true && fact.owner_matches === true && typeof fact.delete_with_vm === "boolean";
      }))
    return `${sourceValues.checked_mappings === 1 ? "The mapped managed disk is attached to its expected VM, and its owner matches." : `All ${sourceValues.checked_mappings} mapped managed disks are attached to their expected VMs, and their owners match.`}\nEach disk may remain linked to its intended workload.\nVM users could face fewer unexpected disk changes.`;
  if (finding.check_id === "azure_nsg_world_ingress_approved_ports" && finding.status === "PASS" &&
      Array.isArray(sourceValues.observed_nsg_paths) && sourceValues.observed_nsg_paths.length === sourceValues.evaluated &&
      sourceValues.observed_nsg_paths.length > 0 && sourceValues.observed_nsg_paths.every(value => {
        const fact = value as Record<string, unknown>;
        return typeof fact.nsg_id === "string" && Array.isArray(fact.world_source_allowed_ports) &&
          Array.isArray(fact.approved_ports) && fact.world_source_allowed_ports.every((port: unknown) => (fact.approved_ports as unknown[]).includes(port));
      })) {
    const pathCount = sourceValues.observed_nsg_paths.reduce((sum, value) => sum + (value as { world_source_allowed_ports: unknown[] }).world_source_allowed_ports.length, 0);
    return pathCount > 0
      ? "The recorded NSGs allow world-source inbound traffic only on approved ports.\nOther ports may stay closed to those sources.\nServices could receive fewer unwanted connection attempts."
      : "The recorded NSGs have no effective world-source inbound Allow paths.\nOutside hosts may have fewer direct paths to these networks.\nServices could receive fewer unwanted connection attempts.";
  }
  if (finding.check_id === "azure_sql_database_sqlserver_auditing_enabled_77d6841" && finding.status === "PASS" &&
      Array.isArray(sourceValues.diagnostic_facts) && sourceValues.diagnostic_facts.length === sourceValues.evaluated &&
      sourceValues.diagnostic_facts.length > 0 && sourceValues.diagnostic_facts.every(value => {
        const fact = value as Record<string, unknown>;
        return typeof fact.resource_id === "string" && Array.isArray(fact.required_categories) &&
          fact.required_categories.length > 0 && Array.isArray(fact.covered_categories) &&
          Array.isArray(fact.missing_categories) && fact.missing_categories.length === 0 &&
          fact.required_categories.every((name: unknown) => (fact.covered_categories as unknown[]).includes(name));
      }))
    return "The SQL databases route their required audit log categories to an approved Log Analytics workspace.\nThose database events may be available in one place.\nThe team could investigate use of the data sooner.";
  if (finding.check_id === "azure.claude.managed_hsm_audit_logging" && finding.status === "UNKNOWN" &&
      sourceValues.audit_archive_declared === true && sourceValues.diagnostic_retention_retired_on === "2025-09-30")
    return "An AuditEvent storage destination is declared for this Managed HSM.\nThe record has no current retention setting for those logs.\nThe team cannot tell how long key activity would remain available.";
  if (finding.check_id === "azure.claude.storage_access_keys_rotated_90" && finding.status === "FAIL" &&
      sourceValues.key_age_days && typeof sourceValues.key_age_days === "object" && !Array.isArray(sourceValues.key_age_days) &&
      sourceValues.threshold_seconds === 90 * 86400 && typeof sourceValues.captured_at === "string") {
    const ages = sourceValues.key_age_days as Record<string, unknown>;
    const old = Object.entries(ages).find(([key, age]) => ["key1", "key2"].includes(key) && typeof age === "number" && age > 90);
    if (old) return `Storage access key ${old[0]} was created about ${Math.round(old[1] as number)} days before this capture.\nAn old exposed key may stay useful if it is still valid.\nSomeone holding it could reach stored files.`;
  }
  if (finding.check_id === "azure.claude.synapse_workspace_vulnerability_assessment" && finding.status === "FAIL" &&
      Array.isArray(sourceValues.recurring_scans) && sourceValues.recurring_scans.length === 1 && sourceValues.recurring_scans[0] === false)
    return "The Synapse workspace has a recurring vulnerability scan policy set to disabled.\nNew weak settings may stay unseen between manual scans.\nThe team could review risks to data later than needed.";
  if (finding.check_id === "azure.claude.vm_windows_secure_boot" && finding.status === "NOT_APPLICABLE" && sourceValues.os_type === "Linux")
    return "This VM runs Linux.\nThe Windows Secure Boot setting does not apply to it.\nIts users are outside the scope of that Windows setting.";
  if (["azure.claude2.nsg_flow_logs_to_log_analytics", "azure.claude2.vnet_flow_logs_to_log_analytics"].includes(finding.check_id) &&
      finding.status === "UNKNOWN" && sourceValues.reason === "flow log target not uniquely resolved in selected network inventory")
    return "The flow log target has no unique match in the network records.\nIts Log Analytics route remains unclear.\nThe team cannot tell whether those flow records are available for review.";
  if (finding.check_id === "azure.claude.recovery_vault_backup_retention_30_days" && finding.status === "FAIL" &&
      Array.isArray(sourceValues.short_policies) && sourceValues.short_policies.length > 0) {
    const policy = sourceValues.short_policies[0] as Record<string, unknown>;
    if (typeof policy.policy === "string" && Number.isInteger(policy.count) &&
        typeof policy.duration_type === "string" && ["Days", "Weeks", "Months", "Years"].includes(policy.duration_type))
      return `The ${policy.policy} daily backup policy keeps recovery points for ${policy.count} ${policy.duration_type.toLowerCase()}.\nOlder restore points may disappear sooner.\nPeople could have fewer chances to recover lost data.`;
  }
  if (finding.check_id === "azure.gap.monitor_log_profile_retention_365_days" && finding.status === "PASS" &&
      Number.isInteger(sourceValues.profile_count) && Array.isArray(sourceValues.observed_retention_profiles) &&
      sourceValues.observed_retention_profiles.length === sourceValues.profile_count &&
      sourceValues.observed_retention_profiles.length > 0 &&
      sourceValues.observed_retention_profiles.every(value => {
        const profile = value as Record<string, unknown>;
        return typeof profile.profile_id === "string" && profile.enabled === true &&
          typeof profile.retention_days === "number" && profile.retention_days >= 365;
      })) {
    const days = Math.min(...sourceValues.observed_retention_profiles.map(value =>
      (value as Record<string, number>).retention_days));
    return `A legacy log profile is enabled with at least ${days} days of retention.\nOlder activity records may stay available for review.\nThat could help the team trace problems affecting users.`;
  }
  if (finding.check_id === "azure.claude2.app_gateway_min_tls_12" && sourceValues.ssl_policy === null &&
      typeof sourceValues.default_policy_name === "string") {
    const name = sourceValues.default_policy_name;
    if (finding.status === "PASS" && ["AppGwSslPolicy20170401S", "AppGwSslPolicy20220101", "AppGwSslPolicy20220101S"].includes(name))
      return `This gateway has no custom TLS policy and names ${name} as its default.\nThat policy requires TLS 1.2 or newer.\nUsers may avoid older, weaker connections.`;
    if (finding.status === "FAIL" && ["AppGwSslPolicy20150501", "AppGwSslPolicy20170401"].includes(name))
      return `This gateway has no custom TLS policy and names ${name} as its default.\nThat policy may allow a TLS version below 1.2.\nUsers' connections could have weaker protection.`;
  }
  if (finding.check_id === "azure.claude2.sql_server_threat_detection_all_alerts" && finding.status === "PASS" &&
      Array.isArray(sourceValues.observed_policies) && sourceValues.observed_policies.length > 0 &&
      sourceValues.observed_policies.every(value => {
        const policy = value as Record<string, unknown>;
        return typeof policy.policy === "string" && policy.state === "Enabled" &&
          Array.isArray(policy.disabled_alerts) &&
          (policy.disabled_alerts.length === 0 ||
           (policy.disabled_alerts.length === 1 && policy.disabled_alerts[0] === ""));
      }))
    return "The SQL server has enabled threat policies with no alert types disabled.\nDefender may warn about suspicious database actions.\nThe team could respond sooner to threats to stored data.";
  if ((finding.check_id === "azure.claude.network_watcher_flow_logs_retention_90" ||
       finding.check_id === "azure.claude.network_watcher_flow_logs_traffic_analytics") &&
      finding.status === "PASS" && Array.isArray(sourceValues.observed_flow_logs) &&
      sourceValues.observed_flow_logs.length > 0) {
    const logs = sourceValues.observed_flow_logs as Record<string, unknown>[];
    if (finding.check_id.endsWith("retention_90") && logs.every(log =>
        typeof log.flow_log === "string" && log.enabled === true &&
        typeof log.retention_days === "number" &&
        (log.retention_days === 0 || log.retention_days >= 90)))
      return "Each recorded Network Watcher flow log is enabled with at least 90 days of retention or no end date.\nNetwork traffic may leave a longer history.\nThe team could trace suspicious connections affecting users.";
    if (finding.check_id.endsWith("traffic_analytics") && logs.every(log =>
        typeof log.flow_log === "string" && log.enabled === true && log.traffic_analytics_enabled === true))
      return "Each recorded Network Watcher flow log is enabled with Traffic Analytics.\nTraffic patterns may be summarized for the team.\nThey could spot unusual traffic sooner.";
  }
  const longSemantic = azureLongSemanticEvidence(finding);
  if (longSemantic) return longSemantic;
  if (finding.check_id === "azure.claude.network_watcher_in_vnet_region" &&
      typeof sourceValues.region === "string" && Array.isArray(sourceValues.network_watcher_regions) &&
      (sourceValues.network_watcher_regions as unknown[]).every(value => typeof value === "string")) {
    const region = sourceValues.region as string;
    const regions = sourceValues.network_watcher_regions as string[];
    if (finding.status === "PASS" && regions.includes(region))
      return `A Network Watcher is recorded in the VNet's ${region} region.\nNetwork diagnostics may be available there.\nThe team could review traffic problems affecting users.`;
    if (finding.status === "FAIL" && !regions.includes(region))
      return `The VNet is in ${region}, with no Network Watcher recorded there.\nNetwork diagnostics may be limited in that region.\nThe team could have less detail to solve traffic problems.`;
  }
  if (finding.check_id === "azure.claude.recovery_vault_backup_retention_30_days" &&
      finding.status === "PASS" && Number.isInteger(sourceValues.evaluated_policies) &&
      Array.isArray(sourceValues.observed_daily_policies) &&
      sourceValues.observed_daily_policies.length === sourceValues.evaluated_policies &&
      sourceValues.observed_daily_policies.length > 0 &&
      sourceValues.observed_daily_policies.every(value =>
        typeof (value as Record<string, unknown>).policy === "string" &&
        typeof (value as Record<string, unknown>).minimum_retention_days === "number" &&
        ((value as Record<string, unknown>).minimum_retention_days as number) >= 30)) {
    const days = Math.min(...sourceValues.observed_daily_policies.map(value =>
      (value as Record<string, number>).minimum_retention_days));
    return `The vault's daily backup policies retain recovery points for at least ${days} days.\nThe policies may keep older points available for that time.\nPeople could have more options to restore lost data.`;
  }
  if (finding.check_id === "azure.claude.vmss_managed_disks" && finding.status === "PASS" &&
      sourceValues.managed_os_disk === true && sourceValues.data_disk_count === sourceValues.managed_data_disk_count &&
      Number.isInteger(sourceValues.data_disk_count))
    return sourceValues.data_disk_count === 0
      ? "The VM scale set declares a managed OS disk and no data disks.\nAzure handles storage placement for that disk.\nThat may reduce storage errors affecting the service."
      : "The VM scale set declares managed OS and data disks.\nAzure handles storage placement for those disks.\nThat may reduce storage errors affecting the service.";
  if (finding.check_id === "azure.vm.managed_disks" && finding.status === "PASS" &&
      Number.isInteger(sourceValues.disk_count) && sourceValues.disk_count === sourceValues.managed_disk_count &&
      (sourceValues.disk_count as number) > 0)
    return sourceValues.disk_count === 1
      ? "The VM declares a managed OS disk and no data disks.\nAzure handles storage placement for that disk.\nThat may reduce storage errors affecting users' data."
      : "The VM declares managed OS and data disks.\nAzure handles storage placement for those disks.\nThat may reduce storage errors affecting users' data.";
  if (finding.check_id === "azure.claude2.nsg_flow_log_retention_90" && finding.status === "PASS" &&
      Array.isArray(sourceValues.observed_flow_logs) && sourceValues.observed_flow_logs.length > 0 &&
      sourceValues.observed_flow_logs.every(value => {
        const log = value as Record<string, unknown>;
        return typeof log.flow_log === "string" && log.enabled === true &&
          typeof log.retention_days === "number" &&
          (sourceValues.vnet_flow_logs ? (log.retention_days === 0 || log.retention_days >= 90) : log.retention_days >= 90);
      })) {
    const days = Math.min(...sourceValues.observed_flow_logs.map(value =>
      (value as Record<string, number>).retention_days));
    const kind = sourceValues.vnet_flow_logs ? "A covering VNet flow log" : "An NSG flow log";
    const duration = days === 0 ? "indefinitely" : `for at least ${days} days`;
    return `${kind} is enabled and retains records ${duration}.\nNetwork traffic may leave a longer history.\nThe team could trace suspicious connections affecting users.`;
  }
  if ((finding.check_id === "azure.claude.activity_log_storage_cmk" ||
       finding.check_id === "azure.claude.activity_log_storage_private") &&
      Array.isArray(sourceValues.storage_accounts) && sourceValues.storage_accounts.length > 0 &&
      Array.isArray(sourceValues.observed_storage_settings) && sourceValues.observed_storage_settings.length > 0) {
    const values = sourceValues.observed_storage_settings as Record<string, unknown>[];
    const storageAccounts = sourceValues.storage_accounts as unknown[];
    if (values.every(item => typeof item.storage_account_id === "string" &&
        storageAccounts.includes(item.storage_account_id))) {
      if (finding.check_id === "azure.claude.activity_log_storage_cmk") {
        if (finding.status === "PASS" && values.every(item => item.setting === "Microsoft.Keyvault"))
          return "The storage account for activity logs uses a Key Vault customer key.\nThat key may protect stored activity logs.\nThe owner may control access to the key for those logs.";
        if (finding.status === "FAIL" && values.some(item => item.setting === "Microsoft.Storage"))
          return "An activity-log storage account uses a Microsoft-managed key.\nThe owner may have less control over the encryption key.\nThat could limit how they protect logs used to investigate incidents.";
      } else {
        if (finding.status === "PASS" && values.every(item => item.setting === false))
          return "The activity-log storage account has public Blob access disabled.\nA public Blob grant may be blocked.\nThat could help keep activity records private.";
        if (finding.status === "FAIL" && values.some(item => item.setting === true))
          return "An activity-log storage account allows public Blob access.\nA container could be shared publicly if its own setting allows it.\nThat could expose activity records to unwanted readers.";
      }
    }
  }
  if (finding.check_id === "azure.claude.sql_va_reports_configured" &&
      typeof sourceValues.email_subscription_admins === "boolean" &&
      Number.isInteger(sourceValues.email_count) && (sourceValues.email_count as number) >= 0) {
    if (finding.status === "PASS" && sourceValues.email_subscription_admins === true)
      return "SQL vulnerability reports email subscription administrators.\nA report may reach someone who can review it.\nThe team could learn about database weaknesses.";
    if (finding.status === "PASS" && (sourceValues.email_count as number) > 0)
      return "SQL vulnerability reports have a listed email recipient.\nA report may reach that address.\nThe team could learn about database weaknesses.";
    if (finding.status === "FAIL" && sourceValues.email_subscription_admins === false && sourceValues.email_count === 0)
      return "SQL vulnerability reports have no admin or listed email recipient.\nA scan report may not reach a responder by email.\nThe team could miss database weaknesses.";
  }
  if (finding.check_id === "azure.cis.resource_manager_delete_locks_applied_storage_accounts" && sourceValues.accounts === 1) {
    const facts = finding.status === "PASS" ? sourceValues.observed_pass_facts : sourceValues.observed_fail_facts;
    if (Array.isArray(facts) && facts.length === 1) {
      const fact = facts[0] as Record<string, unknown>;
      if (typeof fact.account_id === "string" && Array.isArray(fact.effective_lock_ids)) {
        if (finding.status === "PASS" && fact.effective_lock_ids.length > 0)
          return "A storage account has an effective delete lock.\nAn accidental or unwanted delete may be blocked.\nThat could help keep stored files available to their users.";
        if (finding.status === "FAIL" && fact.effective_lock_ids.length === 0)
          return "A storage account has no effective delete lock.\nAn accidental or unwanted delete may remove it.\nPeople could lose access to files kept there.";
      }
    }
  }
  if (finding.check_id === "azure.gap.compute_vm_remote_access_restricted_all_ports" && finding.status === "PASS" &&
      sourceValues.evaluated_ip_configurations === 1 && Array.isArray(sourceValues.observed_restricted_paths) &&
      sourceValues.observed_restricted_paths.length > 0 && sourceValues.observed_restricted_paths.every(value => {
        const path = value as Record<string, unknown>;
        return typeof path.ip_configuration === "string" && typeof path.nsg_id === "string" && path.effective_public_allow === false;
      }))
    return "A VM's attached network rules have no effective public inbound allow path.\nUnwanted internet traffic may be stopped at those rules.\nThat could reduce exposure of the VM's services.";
  if (finding.check_id === "azure.other.entra_app_secret_age_90" && finding.status === "PASS" &&
      sourceValues.active_credential_count === 1 && Array.isArray(sourceValues.observed_active_credentials) &&
      sourceValues.observed_active_credentials.length === 1) {
    const credential = sourceValues.observed_active_credentials[0] as Record<string, unknown>;
    if (typeof credential.application_id === "string" && typeof credential.key_id === "string" &&
        typeof credential.age_days === "number" && credential.age_days >= 0 && credential.age_days < 90)
      return `An active Entra app secret is ${credential.age_days} days old.\nSomeone has had less time to copy this secret.\nThat may reduce unwanted access to data the app can reach.`;
  }
  if (finding.check_id === "azure.other.message_namespace_cmk" && finding.status === "PASS" &&
      sourceValues.namespace_count === 1 && Array.isArray(sourceValues.observed_approved_keys) &&
      sourceValues.observed_approved_keys.length === 1) {
    const key = sourceValues.observed_approved_keys[0] as Record<string, unknown>;
    if (typeof key.namespace_id === "string" && typeof key.key_uri === "string" &&
        key.key_usable === true && key.publish_without_cmk_rejected === true)
      return "A messaging namespace uses an approved Key Vault key, and a publish without that key was rejected.\nThe key may protect messages stored by the namespace.\nThat could give the owner more control over access to message data.";
  }
  if (finding.check_id === "azure.other.entra_password_baseline" && finding.status === "PASS" &&
      sourceValues.newly_provisioned_identity_count === 1 &&
      Array.isArray(sourceValues.observed_password_policies) && sourceValues.observed_password_policies.length === 1) {
    const policy = sourceValues.observed_password_policies[0] as Record<string, unknown>;
    const settings = policy.verified_settings as Record<string, unknown> | undefined;
    if (policy.authentication_type === "Managed" && settings?.minimumLength === 14 &&
        settings.complexity === true && settings.lockoutThreshold === 10)
      return "A new Entra identity has a 14-character minimum, complexity enabled, and a lockout threshold of 10.\nA weak or guessed password may be harder to use.\nThat could reduce unwanted access to the person's account.";
  }
  if (finding.check_id === "azure.cis.agentless_discovery_kubernetes_component_status" && finding.status === "PASS" &&
      sourceValues.cluster_count === 1 && Array.isArray(sourceValues.observed_enabled_plans) &&
      sourceValues.observed_enabled_plans.length === 1 &&
      Array.isArray((sourceValues.observed_enabled_plans[0] as Record<string, unknown>).enabled_plans) &&
      ((sourceValues.observed_enabled_plans[0] as Record<string, unknown>).enabled_plans as unknown[]).includes("Containers"))
    return "An AKS cluster has AgentlessDiscoveryForKubernetes enabled under the Containers plan.\nDefender may discover cluster assets without a node agent.\nThe team could find exposed workloads sooner.";
  if (finding.check_id === "azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk" &&
      sourceValues.encryption_type === "AzureKeyVault" && sourceValues.key_approved === true &&
      typeof sourceValues.key_uri === "string" && typeof sourceValues.assigned_identity === "string") {
    if (finding.status === "FAIL" && sourceValues.identity_attached === false)
      return "A PostgreSQL server names an approved Key Vault key, but its assigned identity is not attached.\nIt may be unable to use that key.\nDatabase data may lack the intended customer-key protection.";
    if (finding.status === "PASS" && sourceValues.identity_attached === true)
      return "A PostgreSQL server names an approved Key Vault key and has the assigned identity attached.\nIt may use that customer key for stored data.\nThe owner may control access to the key protecting database data.";
  }
  if (finding.check_id === "azure.gap.compute_vm_scale_set_endpoint_protection_solution_installed" &&
      Array.isArray(sourceValues.outcomes) && sourceValues.outcomes.length === 1) {
    const group = sourceValues.outcomes[0] as Record<string, unknown>;
    const outcomes = group.outcomes;
    if (Array.isArray(outcomes) && outcomes.length === 1) {
      const leaf = outcomes[0] as Record<string, unknown>;
      if (finding.status === "FAIL" && leaf.endpoint_agent_installed === false && leaf.status === "FAIL")
        return "A VM scale set instance has no endpoint protection agent installed.\nThreats on that instance may be harder to detect.\nPeople's data or service may face more risk.";
      if (finding.status === "PASS" && leaf.endpoint_agent_installed === true && leaf.status === "PASS")
        return "A VM scale set instance has its endpoint protection agent installed.\nThe agent may detect harmful activity.\nThe team could protect users' data or service sooner.";
    }
  }
  if (finding.check_id === "azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled" &&
      finding.status === "PASS" && Array.isArray(sourceValues.outcomes) && sourceValues.outcomes.length === 1) {
    const group = sourceValues.outcomes[0] as Record<string, unknown>;
    const outcomes = group.outcomes;
    if (Array.isArray(outcomes) && outcomes.length === 2 &&
        outcomes.every(value => (value as Record<string, unknown>).mfa_required === true &&
          (value as Record<string, unknown>).allowed_path_count === 1) &&
        outcomes.some(value => (value as Record<string, unknown>).context_id === "browser") &&
        outcomes.some(value => (value as Record<string, unknown>).context_id === "cli"))
      return "A subscription reader must use MFA for browser and CLI sign-ins.\nA stolen password alone may not let someone sign in.\nThat could protect data the reader can access.";
  }
  if (finding.check_id === "azure.other.ml_download_audit" &&
      typeof sourceValues.recorded_download_count === "number" &&
      typeof sourceValues.unrecorded_download_count === "number" &&
      sourceValues.recorded_download_count + sourceValues.unrecorded_download_count > 0) {
    if (finding.status === "FAIL" && sourceValues.unrecorded_download_count > 0)
      return "An ML download has no matching audit record after the allowed delay.\nThe team may miss who took a file.\nThey could struggle to trace unwanted data access.";
    if (finding.status === "PASS" && sourceValues.unrecorded_download_count === 0 && sourceValues.recorded_download_count > 0)
      return "An ML download has a matching audit record in the approved destination.\nThe team may trace who took a file.\nThat could help them review unusual data access.";
  }
  if (finding.check_id === "azure.other.diagnostic_destination_alert" && finding.status === "PASS" &&
      typeof sourceValues.control_test_count === "number" && sourceValues.control_test_count > 0 &&
      sourceValues.redirection_prevented_count === sourceValues.control_test_count &&
      typeof sourceValues.delivered_case_count === "number" && sourceValues.delivered_case_count > 0)
    return "Recorded diagnostic redirection attempts did not take effect, and related alerts were delivered.\nUnwanted destination changes may be stopped and reported.\nThe team may keep logs available for review.";
  if (finding.check_id === "azure.other.retention_change_alert") {
    if (finding.status === "FAIL" &&
        sourceValues.reason === "Complete definitions prove no enabled actionable alert for a required operation/scope/status")
      return "No enabled alert covers the required retention change event.\nA similar change may lack a timely notice.\nThe team could miss an attempt to erase logs.";
    if (sourceValues.required_case_count === 1 &&
        sourceValues.delivered_case_count === 1 && sourceValues.missed_case_count === 0 && finding.status === "PASS")
      return "One retention change event delivered an alert on time.\nA similar change may warn the team.\nThey could respond sooner to a threat to stored logs.";
    if (sourceValues.required_case_count === 1 &&
        sourceValues.delivered_case_count === 0 && sourceValues.missed_case_count === 1 && finding.status === "FAIL")
      return "One retention change event had no timely alert delivery.\nA similar change may go unnoticed.\nThe team could respond later to a threat to stored logs.";
  }
  if (finding.check_id === "azure.gap.compute_vm_image_builder_uses_private_link") {
    const facts = finding.status === "PASS" ? sourceValues.observed_pass_facts : sourceValues.observed_fail_facts;
    if (Array.isArray(facts) && facts.length === 1 && typeof (facts[0] as Record<string, unknown>).configured_subnet === "string") {
      const fact = facts[0] as Record<string, unknown>;
      if (finding.status === "FAIL" && fact.reason === "subnet outside approved set")
        return "An image template uses a build subnet outside the approved list.\nBuild traffic may leave the intended network.\nCode or secrets used in builds may have less network isolation.";
      if (finding.status === "PASS" &&
          fact.semantics === "Approved isolated build subnet signal; dependency Private Link paths unverified")
        return "An image template uses an approved isolated build subnet.\nBuild traffic may stay within the intended network.\nCode or secrets used in builds may have more network isolation.";
    }
  }
  if (finding.check_id === "azure.gap.network_subnet_protected_by_firewall" && finding.status === "PASS" &&
      Array.isArray(sourceValues.approved_firewall_routes) && sourceValues.approved_firewall_routes.length === sourceValues.route_count &&
      sourceValues.approved_firewall_routes.length > 0 && sourceValues.approved_firewall_routes.every(route =>
        Array.isArray(route) && route.length === 3 && typeof route[2] === "string"))
    return "The subnet's recorded Internet routes point to approved Azure Firewalls.\nOutbound traffic may pass through those firewalls.\nTheir rules could help protect apps and data on this subnet.";
  if (finding.check_id === "azure.cis.private_endpoint_should_mariadb_servers") {
    const facts = finding.status === "PASS" ? sourceValues.observed_pass_facts : sourceValues.observed_fail_facts;
    if (Array.isArray(facts) && facts.length === 1) {
      const fact = facts[0] as Record<string, unknown>;
      if (finding.status === "FAIL" && fact.approved_private_endpoint_count === 0)
        return "No approved private endpoint is recorded for a MariaDB server.\nClients may lack the intended private path to it.\nPeople may have trouble reaching their database data.";
      if (finding.status === "PASS" && typeof fact.approved_private_endpoint_count === "number" &&
          fact.approved_private_endpoint_count > 0 && fact.public_network_access === "Disabled")
        return "A MariaDB server has an approved private endpoint and public network access disabled.\nClients may use its private path.\nTheir database traffic may stay within the connected network.";
    }
  }
  if (finding.status === "PASS" && Array.isArray(sourceValues.observed_pass_facts) &&
      sourceValues.observed_pass_facts.length === 1) {
    const fact = sourceValues.observed_pass_facts[0] as Record<string, unknown>;
    if (finding.check_id === "azure.other.monitor_dashboard_access" &&
        typeof fact.approved_viewer_count === "number" && fact.public_share_enabled === false)
      return `A sensitive dashboard has ${fact.approved_viewer_count} approved viewer and public sharing disabled.\nOther users may be unable to open it.\nThat could keep dashboard data from unwanted readers.`;
    if (finding.check_id === "azure.other.vault_key_approved_algorithm" && Array.isArray(fact.approved_versions) &&
        fact.approved_versions.length === 1) {
      const version = fact.approved_versions[0] as Record<string, unknown>;
      if (version.key_type === "EC" && version.curve === "P-256" && version.origin === "generated")
        return "An enabled Key Vault key version uses a generated EC P-256 key.\nData protected with it may use the approved curve.\nThat could make stored data harder to read without the key.";
    }
    if (finding.check_id === "azure.other.vnet_peering_allowlist" &&
        Array.isArray(fact.approved_peer_targets) && fact.approved_peer_targets.length === 1 &&
        sourceValues.enforced_deny_policy === true)
      return "A VNet peers with one approved VNet, and an enforced policy denies unapproved peers.\nNew peer requests outside the approved list may be blocked.\nThat could keep data paths within the team's approved networks.";
  }
  if (finding.status === "PASS" && Array.isArray(sourceValues.observed_pass_facts) &&
      sourceValues.observed_pass_facts.length === 1) {
    const fact = sourceValues.observed_pass_facts[0] as Record<string, unknown>;
    if (finding.check_id === "azure.cis.key_vaults_store_secrets" && fact.storage === "key_vault" &&
        fact.resolution_status === "Resolved" && typeof fact.secret_id === "string")
      return "A workload secret reference points to Key Vault and resolves there.\nThe app may read the secret when needed.\nIts value may stay out of the app's saved settings.";
    if (finding.check_id === "azure.other.function_invoke_rate_limit" && typeof fact.calls === "number" &&
        typeof fact.renewal_period === "number" && fact.beyond_threshold_status === 429 && fact.policy_denial === true)
      return `A function accepted ${fact.calls} calls in ${fact.renewal_period} seconds, then denied the next call with 429.\nA busy caller may be slowed.\nOther people may have more room to use the function.`;
    if (finding.check_id === "azure.other.monitor_alert_ack_authorization" &&
        Array.isArray(fact.unapproved_principals) && fact.unapproved_principals.length === 0 &&
        typeof fact.workflow_id === "string")
      return "No unapproved principal has effective alert acknowledgment access in this workflow.\nOnly approved responders may close its alerts.\nThe team may keep important alerts visible until an approved responder acts.";
    if (finding.check_id === "azure.other.storage_immutability" && fact.protection === "Locked" &&
        typeof fact.retention_days === "number" && typeof fact.premature_changes_denied === "number" &&
        fact.premature_changes_denied > 0)
      return `A locked container has ${fact.retention_days} days of retention and denied early changes.\nStored records may remain available during that period.\nPeople may recover them after unwanted deletion attempts.`;
    if (finding.check_id === "azure.other.vault_old_secret_disabled" && fact.outcome === "denied" &&
        typeof fact.version_id === "string")
      return "A read of an old secret version was denied.\nThat version may be harder to reuse.\nPeople's data may face less risk from an old leaked credential.";
  }
  if (finding.status === "PASS" && finding.check_id === "azure.other.gateway_affinity_cookie_timeout" &&
      Array.isArray(sourceValues.measured_routes) && sourceValues.measured_routes.length === 1) {
    const route = sourceValues.measured_routes[0] as Record<string, unknown>;
    if (typeof route.idle_seconds === "number" && route.idle_seconds > 1800 && route.same_session_accepted === false)
      return `A gateway affinity route rejected the same session after ${route.idle_seconds} idle seconds.\nOld routing affinity may stop being reused.\nPeople may reach an available backend sooner.`;
  }
  if (finding.status === "PASS" && finding.check_id === "azure.other.gateway_client_rate_limit" &&
      sourceValues.sliding_five_minute_limit_enforced === true && Array.isArray(sourceValues.qualifying_thresholds) &&
      sourceValues.qualifying_thresholds.length === 1 && typeof sourceValues.qualifying_thresholds[0] === "number" &&
      typeof sourceValues.measured_block_seconds === "number" && sourceValues.measured_block_seconds >= 60)
    return `A gateway enforced a ${sourceValues.qualifying_thresholds[0]} request limit over five minutes.\nHigh-rate clients may be blocked for at least ${sourceValues.measured_block_seconds} seconds.\nOther people may have more room to use the service.`;
  if (finding.status === "PASS" && finding.check_id === "azure.other.gateway_server_header_rewrite" &&
      Array.isArray(sourceValues.sampled_paths) && sourceValues.sampled_paths.length === 1 &&
      (sourceValues.sampled_paths[0] as Record<string, unknown>).server_header === "lb")
    return "A gateway response sample shows the Server header set to lb.\nCallers may see fewer backend details.\nThat could give outsiders less information about the service.";
  if (finding.status === "PASS" && finding.check_id === "azure.other.gateway_throttle_log_alert" &&
      Array.isArray(sourceValues.correlated_log_delays_seconds) && sourceValues.correlated_log_delays_seconds.length === 1 &&
      typeof sourceValues.correlated_log_delays_seconds[0] === "number" &&
      sourceValues.correlated_log_delays_seconds[0] >= 0 && sourceValues.correlated_log_delays_seconds[0] <= 300)
    return `A throttled gateway request appeared in logs after ${sourceValues.correlated_log_delays_seconds[0]} seconds.\nThe team may find similar blocked requests in time.\nThey could respond sooner to unusual traffic.`;
  if (finding.status === "PASS" && finding.check_id === "azure.other.lb_certificate_auto_renew" &&
      sourceValues.served_within_24_hours === true && Array.isArray(sourceValues.new_version_served_delays_seconds) &&
      sourceValues.new_version_served_delays_seconds.length === 1 &&
      typeof sourceValues.new_version_served_delays_seconds[0] === "number" &&
      sourceValues.new_version_served_delays_seconds[0] >= 0 && sourceValues.new_version_served_delays_seconds[0] <= 86400)
    return "A new gateway certificate version was served within 24 hours of its renewal trigger.\nThe service may avoid using an expiring certificate.\nPeople may have fewer connection failures.";
  if (finding.status === "PASS" && finding.check_id === "azure.other.ml_public_access_exception" &&
      sourceValues.public_ip_enabled === true && sourceValues.classification === "non_sensitive" &&
      sourceValues.current_approved_exception === true && sourceValues.effective_ingress_paths_compliant === true)
    return "Non-sensitive ML compute has public IP access under a current approved exception.\nOutside requests may use its reviewed network paths.\nThe team may keep that access within its approved limits.";
  if (finding.status === "PASS" &&
      ["azure.other.ml_sensitive_subnet_allowlist", "azure.other.ml_subnet_baseline"].includes(finding.check_id) &&
      typeof sourceValues.subnet_id === "string" && typeof sourceValues.network_security_group_id === "string" &&
      Array.isArray(sourceValues.required_control_names) && sourceValues.required_control_names.length > 0 &&
      sourceValues.effective_controls_compliant === true) {
    if (finding.check_id === "azure.other.ml_sensitive_subnet_allowlist" &&
        sourceValues.classification === "sensitive" && sourceValues.sensitive_subnet_approved === true)
      return "Sensitive ML compute uses an approved subnet with an attached network security group.\nIts required network controls may shape incoming traffic.\nThat could help keep sensitive work within approved paths.";
    if (finding.check_id === "azure.other.ml_subnet_baseline" && sourceValues.classification === "non_sensitive")
      return "ML compute uses a subnet with an attached network security group and approved controls.\nIts traffic may follow the team's network rules.\nThat could reduce unwanted paths to the workload.";
  }
  if (finding.check_id === "azure.gap.asset_inventory_required_metadata" &&
      Array.isArray(sourceValues.metadata_facts) && sourceValues.metadata_facts.length === 1) {
    const fact = sourceValues.metadata_facts[0] as Record<string, unknown>;
    if (Array.isArray(fact.required_tag_keys) && fact.required_tag_keys.includes("owner") &&
        Array.isArray(fact.missing_tag_keys)) {
      if (finding.status === "FAIL" && fact.missing_tag_keys.includes("owner"))
        return "A resource inventory entry has no owner tag.\nThe team may not know who owns it.\nA problem with its data could take longer to resolve.";
      if (finding.status === "PASS" && fact.missing_tag_keys.length === 0)
        return "A resource inventory entry has its required owner tag.\nThe team may find who is responsible for it.\nThey could resolve data or service problems sooner.";
    }
  }
  if (finding.check_id === "azure.gap.audit_diagnostic_setting" &&
      Array.isArray(sourceValues.diagnostic_facts) && sourceValues.diagnostic_facts.length === 1) {
    const fact = sourceValues.diagnostic_facts[0] as Record<string, unknown>;
    if (Array.isArray(fact.required_categories) && fact.required_categories.includes("audit") &&
        Array.isArray(fact.missing_categories)) {
      if (finding.status === "FAIL" && fact.missing_categories.includes("audit"))
        return "A resource's Audit logs are not routed to an approved sink.\nImportant activity may be missing from the team's logs.\nThey could take longer to understand a problem.";
      if (finding.status === "PASS" && fact.missing_categories.length === 0)
        return "A resource's required Audit logs are routed to an approved sink.\nThe team may see changes to that resource.\nThey could understand a problem sooner.";
    }
  }
  if (finding.check_id === "azure.gap.sql_database_long_term_geo_redundant_backup_enabled" &&
      Array.isArray(sourceValues.ltr_facts) && sourceValues.ltr_facts.length === 1) {
    const fact = sourceValues.ltr_facts[0] as Record<string, unknown>;
    if (Array.isArray(fact.backup_redundancies) && fact.backup_redundancies.length === 1) {
      const redundancy = fact.backup_redundancies[0];
      if (finding.status === "FAIL" && (redundancy === "Local" || redundancy === "Zone"))
        return `A SQL long-term backup uses ${redundancy} storage redundancy.\nA wider outage may leave fewer usable copies.\nPeople could wait longer to recover database data.`;
      if (finding.status === "PASS" && (redundancy === "Geo" || redundancy === "GeoZone"))
        return `A SQL long-term backup uses ${redundancy} storage redundancy.\nA copy may remain available after a local outage.\nPeople could recover database data sooner.`;
    }
  }
  const reviewSubject: Record<string, string> = {
    "azure.cis.access_review_up_external_users_in_entra_privileged_identity_694482": "external privileged user",
    "azure.cis.guest_users_reviewed_monthly_basis": "guest user",
    "azure.cis.guest_users_reviewed_regular_basis": "guest user",
    "azure.cis.non_privileged_role_assignments_periodically_reviewed": "nonprivileged role assignment",
    "azure.cis.privileged_role_assignments_periodically_reviewed": "privileged role assignment",
    "azure.cis.tenant_creator_role_assignments_periodically_reviewed": "Tenant Creator role assignment",
  };
  if (finding.status === "PASS" && reviewSubject[finding.check_id] &&
      typeof sourceValues.applicable_subject_count === "number" && sourceValues.applicable_subject_count > 0 &&
      sourceValues.reviewed_subject_count === sourceValues.applicable_subject_count)
    return `${sourceValues.reviewed_subject_count} ${reviewSubject[finding.check_id]}${sourceValues.reviewed_subject_count === 1 ? "" : "s"} ${sourceValues.reviewed_subject_count === 1 ? "was" : "were"} covered by completed access reviews.\nThe team may spot access that should change.\nThis could reduce continued access that people no longer need.`;
  if (finding.check_id === "azure.gap.capacity_usage_alerts" && finding.status === "PASS" &&
      Array.isArray(sourceValues.observed_forecasts) && sourceValues.observed_forecasts.length === 1) {
    const forecast = sourceValues.observed_forecasts[0] as Record<string, unknown>;
    if (forecast.baseline_matches === true && forecast.forecast_breached === false)
      return "The approved capacity baseline matches measured use, and the forecast stays within limits.\nThe component may have room for expected demand.\nPeople may face fewer capacity slowdowns.";
    if (forecast.baseline_matches === true && forecast.forecast_breached === true && forecast.change_initiated === true)
      return "The capacity forecast exceeded a limit, and a related change was started.\nThe team may add capacity before demand rises.\nPeople may face fewer capacity slowdowns.";
  }
  if (finding.check_id === "azure.other.gateway_backend_health_alert" && finding.status === "PASS" &&
      Array.isArray(sourceValues.observed_gateways) && sourceValues.observed_gateways.length === 1) {
    const gateway = sourceValues.observed_gateways[0] as Record<string, unknown>;
    if (typeof gateway.threshold_crossings === "number" && gateway.threshold_crossings > 0 &&
        gateway.timely_deliveries === gateway.threshold_crossings)
      return `${gateway.threshold_crossings} gateway health ${gateway.threshold_crossings === 1 ? "drop triggered a" : "drops triggered"} timely delivered ${gateway.threshold_crossings === 1 ? "alert" : "alerts"}.\nA similar drop may warn the team.\nThey could respond before users face long service problems.`;
  }
  const guestPrefix = "azure.gap.compute_vm_";
  if (finding.check_id.startsWith(guestPrefix)) {
    const guestKind = finding.check_id.slice(guestPrefix.length);
    if (finding.status === "FAIL" && sourceValues.reason === "complete current inventory proves required assignment absent" &&
        ["administrators_group_with_extra_accounts_windows", "password_file_permissions_0644_linux"].includes(guestKind))
      return "The required guest configuration assignment is absent from this VM.\nIts local baseline may go unchecked.\nThe team could miss unsafe changes to the VM.";
    if (Array.isArray(sourceValues.baseline_facts) && sourceValues.baseline_facts.length === 1) {
      const fact = sourceValues.baseline_facts[0] as Record<string, unknown>;
      const violations = fact.violating_members;
      if (fact.kind === "administrators" && Array.isArray(violations) &&
          Array.isArray(fact.observed_members) && Array.isArray(fact.policy_members)) {
        const count = violations.length;
        if (guestKind === "administrators_group_with_extra_accounts_windows") {
          if (finding.status === "FAIL" && count > 0)
            return `${count} local Administrators group ${count === 1 ? "member is" : "members are"} outside the approved list.\nThose accounts may control the VM.\nTheir users could change or read data on it.`;
          if (finding.status === "PASS" && count === 0 && fact.compliance_status === "Compliant")
            return "All listed local Administrators group members are approved.\nLocal admin access may stay with those users.\nThat could reduce unwanted changes to VM data.";
        }
        if (guestKind === "administrators_group_with_no_specified_members_windows") {
          if (finding.status === "FAIL" && count > 0)
            return `${count} required local ${count === 1 ? "Administrator is" : "Administrators are"} absent from the group.\nThose people may be unable to manage the VM.\nOthers may wait longer for needed support.`;
          if (finding.status === "PASS" && count === 0 && fact.compliance_status === "Compliant")
            return "All required local Administrators are present in the group.\nThey may manage the VM when needed.\nPeople may get support sooner when problems arise.";
        }
        if (guestKind === "administrators_group_with_specified_members_windows") {
          if (finding.status === "FAIL" && count > 0)
            return `${count} prohibited ${count === 1 ? "member is" : "members are"} present in the local Administrators group.\nThose accounts may control the VM.\nTheir users could change or read data on it.`;
          if (finding.status === "PASS" && count === 0 && fact.compliance_status === "Compliant")
            return "No prohibited member is present in the local Administrators group.\nThose accounts may lack local admin access through this group.\nThat could reduce unwanted changes to VM data.";
        }
      }
      if (guestKind === "with_no_specified_certificates_in_trusted_root_windows" && fact.kind === "trusted_root" &&
          Array.isArray(fact.missing_thumbprints)) {
        const count = fact.missing_thumbprints.length;
        if (finding.status === "FAIL" && count > 0)
          return `${count} required ${count === 1 ? "certificate is" : "certificates are"} absent from the VM trusted-root store.\nSoftware needing that trust root may reject connections.\nPeople could lose access to a service that uses it.`;
        if (finding.status === "PASS" && count === 0 && fact.compliance_status === "Compliant")
          return "The required certificates are present in the VM trusted-root store.\nSoftware using those trust roots may validate connections.\nPeople may be able to use services that rely on them.";
      }
      if (guestKind === "password_file_permissions_0644_linux" && fact.kind === "passwd_permissions" &&
          typeof fact.observed_mode === "string" && /^0[0-7]{3}$/.test(fact.observed_mode)) {
        if (finding.status === "FAIL" && fact.observed_mode !== "0644")
          return `The /etc/passwd file mode is ${fact.observed_mode}, while the required mode is 0644.\nLocal tools may read it differently than expected.\nPeople may have trouble using tools that need account records.`;
        if (finding.status === "PASS" && fact.observed_mode === "0644")
          return "The /etc/passwd file mode is 0644.\nLocal tools may read account records as expected.\nPeople may have fewer account lookup problems.";
      }
    }
  }
  if (finding.check_id === "azure.other.gateway_vmss_autoscale" && finding.status === "PASS") {
    const leaf = Array.isArray(sourceValues.results) && sourceValues.results.length === 1
      ? sourceValues.results[0] as Record<string, unknown> : sourceValues;
    if (Array.isArray(leaf.scale_out_observations) && leaf.scale_out_observations.length === 1) {
      const event = leaf.scale_out_observations[0] as Record<string, unknown>;
      if (typeof event.serving_instances_before === "number" && typeof event.serving_instances_after === "number" &&
          typeof event.scale_out_seconds === "number" && event.serving_instances_after > event.serving_instances_before &&
          event.scale_out_seconds >= 0 && event.scale_out_seconds <= 300)
        return `A gateway grew from ${event.serving_instances_before} to ${event.serving_instances_after} serving instances within ${event.scale_out_seconds} seconds of high demand.\nMore requests may have space to run.\nPeople may see fewer slowdowns during a similar demand rise.`;
    }
  }
  if (finding.check_id === "azure.other.snapshot_sharing_scope" && finding.status === "PASS") {
    const leaf = Array.isArray(sourceValues.results) && sourceValues.results.length === 1
      ? sourceValues.results[0] as Record<string, unknown> : sourceValues;
    if (Array.isArray(leaf.approved_recipient_ids) && Array.isArray(leaf.granted_recipient_ids) &&
        leaf.granted_recipient_ids.every(id => (leaf.approved_recipient_ids as unknown[]).includes(id)) &&
        leaf.current_unauthorized_test_denied === true && leaf.public_network_access === "Disabled")
      return "Snapshot grants go only to approved recipients, and an outside sharing test was denied.\nOthers may have a harder time using the tested sharing path.\nThis could reduce unintended access to saved data.";
  }
  if (finding.check_id === "azure.other.monitor_stream_auth" && finding.status === "PASS" &&
      Array.isArray(sourceValues.outcomes) && sourceValues.outcomes.length === 1) {
    const group = sourceValues.outcomes[0] as Record<string, unknown>;
    const outcomes = group.outcomes;
    if (Array.isArray(outcomes) && outcomes.length === 1) {
      const leaf = outcomes[0] as Record<string, unknown>;
      if (leaf.authorized_publisher_accepted === true && leaf.anonymous_publisher_rejected === true &&
          leaf.wrong_type_publisher_rejected === true)
        return "The stream accepted an approved publisher and rejected anonymous and wrong-type tests.\nUnapproved senders may be unable to add data through that path.\nThis could help keep monitoring data trustworthy.";
    }
  }
  if (finding.check_id === "azure.other.nsg_port_protocol_assignment" &&
      Array.isArray(sourceValues.observed_service_pairs) && sourceValues.observed_service_pairs.length === 1) {
    const pair = sourceValues.observed_service_pairs[0] as Record<string, unknown>;
    if ((pair.protocol === "Tcp" || pair.protocol === "Udp") && typeof pair.port === "number" &&
        Number.isInteger(pair.port) && pair.port > 0 && pair.port <= 65535 &&
        typeof pair.measured_service === "string" && /^[A-Za-z0-9_-]+$/.test(pair.measured_service)) {
      if (finding.status === "FAIL" && pair.assignment_matches === false)
        return `An exposed ${pair.protocol} port ${pair.port} path carries measured ${pair.measured_service} traffic.\nThat service differs from the assigned port use.\nThe team may miss an unexpected service on a known port.`;
      if (finding.status === "PASS" && pair.assignment_matches === true)
        return `An exposed ${pair.protocol} port ${pair.port} path carries measured ${pair.measured_service} traffic, matching its assigned use.\nThe service on that port may be easier to identify.\nThe team could spot a later unexpected service sooner.`;
    }
  }
  if (finding.check_id === "azure.other.gateway_api_cidr_allowlist" &&
      sourceValues.outside_approved_ranges_empty === false && Array.isArray(sourceValues.effective_paths) &&
      sourceValues.effective_paths.length === 1 && Array.isArray(sourceValues.approved_cidrs)) {
    const path = sourceValues.effective_paths[0] as Record<string, unknown>;
    const rules = path.remote_addr_rules;
    if (path.policy_state === "Enabled" && path.policy_mode === "Prevention" &&
        Array.isArray(rules) && rules.length > 0) {
      const first = rules[0] as Record<string, unknown>;
      const matches = first.remote_addr_matches;
      const match = Array.isArray(matches) && matches.length === 1 ? matches[0] as Record<string, unknown> : null;
      if (match && Array.isArray(match.cidrs)) {
        if (finding.status === "PASS" && path.decision === "PASS" && first.action === "Block" && match.negated === true &&
            JSON.stringify(match.cidrs) === JSON.stringify(sourceValues.approved_cidrs))
          return "An enabled gateway rule blocks source IPs outside the approved ranges.\nRequests from other ranges may stop at the gateway.\nThis could reduce unwanted API traffic.";
        if (finding.status === "FAIL" && path.decision === "FAIL" && first.action === "Allow" && match.negated === false &&
            match.cidrs.length === 1 && match.cidrs[0] === "0.0.0.0/0")
          return "An enabled gateway rule allows source IPs from all IPv4 ranges.\nOutside callers may send requests toward the API.\nThe team could face more unwanted API traffic.";
      }
    }
  }
  if (finding.check_id === "azure.other.runtime_public_ip" && finding.status === "FAIL" &&
      sourceValues.reason === "Explicit node public IP allocation" && Array.isArray(sourceValues.compute_ids) &&
      sourceValues.compute_ids.length > 0 && sourceValues.compute_ids.every(id => typeof id === "string"))
    return "Sensitive ML compute has an explicit node public IP allocation.\nOutside hosts may send traffic toward that node.\nThe team could face more unwanted connection attempts.";
  if (finding.check_id === "azure.other.monitor_stream_auth" && finding.status === "FAIL" &&
      Array.isArray(sourceValues.outcomes) && sourceValues.outcomes.length === 1) {
    const group = sourceValues.outcomes[0] as Record<string, unknown>;
    const outcomes = group.outcomes;
    if (Array.isArray(outcomes) && outcomes.length === 1 &&
        (outcomes[0] as Record<string, unknown>).accepted_credential_kind === "anonymous")
      return "A monitoring stream accepted an anonymous publisher.\nSomeone without a named credential may send data to it.\nThat could make the team's monitoring data less trustworthy.";
  }
  if (finding.check_id === "azure.other.nsg_port_protocol_assignment" && finding.status === "PASS" &&
      sourceValues.exposed_paths === 0)
    return "No exposed NSG paths were recorded.\nNo service and port pair is exposed on those paths.\nThe team may have fewer open services to manage.";
  if (finding.check_id === "azure.other.region_allowlist" && Array.isArray(sourceValues.observed_locations) &&
      sourceValues.observed_locations.length === 1 && Array.isArray(sourceValues.approved_regions)) {
    const observed = sourceValues.observed_locations[0] as Record<string, unknown>;
    const location = observed.location;
    if (typeof location === "string" && /^[a-z0-9]+$/.test(location)) {
      if (finding.status === "FAIL" && !sourceValues.approved_regions.includes(location))
        return `A resource is in ${location}, outside the approved regions.\nIts data or operations may use that region.\nThis could affect where the team expects them to stay.`;
      if (finding.status === "PASS" && sourceValues.approved_regions.includes(location) &&
          sourceValues.disallowed_deployment_denied === true && sourceValues.unauthorized_region_secret_denied === true &&
          sourceValues.eu_operations_verified === true)
        return `A resource is in approved region ${location}, and regional controls passed.\nNew resources may stay within approved regions.\nThe team may have better control over where data and operations run.`;
    }
  }
  if ((finding.check_id === "azure.other.backup_freshness_14_days" || finding.check_id === "azure.other.backup_freshness_30_days") &&
      Array.isArray(sourceValues.observed_items) && sourceValues.observed_items.length === 1 &&
      (sourceValues.freshness_days === 14 || sourceValues.freshness_days === 30)) {
    const item = sourceValues.observed_items[0] as Record<string, unknown>;
    if (typeof item.last_recovery_point === "string" && /^\d{4}-\d{2}-\d{2}T/.test(item.last_recovery_point) &&
        item.last_backup_status === "Completed" && item.protection_state === "Protected") {
      const date = item.last_recovery_point.slice(0, 10);
      if (finding.status === "FAIL" && item.outcome === "stale")
        return `The last recovery point is dated ${date}, older than ${sourceValues.freshness_days} days.\nA restore may lose newer changes.\nPeople may have to redo work or recover missing data.`;
      if (finding.status === "PASS" && item.outcome === "fresh")
        return `A completed backup has a recovery point dated ${date}.\nA restore may recover recent changes.\nPeople may lose less work if this resource fails.`;
    }
  }
  if (finding.check_id === "azure.other.activity_alert" &&
      Number.isInteger(sourceValues.required_case_count) && Number.isInteger(sourceValues.delivered_case_count) &&
      Number.isInteger(sourceValues.missed_case_count) && sourceValues.required_case_count === 1 &&
      (sourceValues.delivered_case_count as number) + (sourceValues.missed_case_count as number) === 1) {
    if (finding.status === "PASS" && sourceValues.delivered_case_count === 1)
      return "One activity alert test delivered a notice on time.\nA similar activity event may warn the team.\nThey could respond sooner to unwanted changes.";
    if (finding.status === "FAIL" && sourceValues.missed_case_count === 1)
      return "One activity alert test had no timely delivery.\nA similar activity event may go unnoticed.\nThe team could respond later to unwanted changes.";
  }
  if (finding.check_id === "azure.other.azure_activity_anomaly" && sourceValues.detector_count === 2 &&
      Array.isArray(sourceValues.delivered_detector_kinds) && Array.isArray(sourceValues.missed_detector_kinds)) {
    const delivered = sourceValues.delivered_detector_kinds as unknown[];
    const missed = sourceValues.missed_detector_kinds as unknown[];
    const expected = ["per_principal_log_query_volume", "suspicious_api_requests"];
    if (JSON.stringify([...delivered, ...missed].sort()) === JSON.stringify(expected)) {
      if (finding.status === "PASS" && missed.length === 0)
        return "The suspicious API and per-user query detectors delivered alerts.\nSimilar activity may warn the team.\nThey could respond sooner to unwanted changes.";
      if (finding.status === "FAIL" && missed.includes("suspicious_api_requests"))
        return "The suspicious API request detector missed its alert.\nSimilar API activity may go unnoticed.\nThe team could respond later to unwanted changes.";
      if (finding.status === "FAIL" && missed.includes("per_principal_log_query_volume"))
        return "The per-user query detector missed its alert.\nSimilar query activity may go unnoticed.\nThe team could respond later to unwanted changes.";
    }
  }
  if (finding.check_id === "azure.other.runtime_public_ip" &&
      Number.isInteger(sourceValues.compute_count) && Number.isInteger(sourceValues.public_path_count) &&
      Number.isInteger(sourceValues.private_path_count) && (sourceValues.compute_count as number) > 0 &&
      (sourceValues.public_path_count as number) + (sourceValues.private_path_count as number) ===
        (sourceValues.compute_count as number) * 4) {
    const count = sourceValues.public_path_count as number;
    if (finding.status === "FAIL" && count > 0)
      return `${count} ML network ${count === 1 ? "path has" : "paths have"} public IP access.\nOutside hosts may send traffic toward those paths.\nThe team could face more unwanted connection attempts.`;
    if (finding.status === "PASS" && count === 0)
      return `${sourceValues.private_path_count} ML network paths have public IP access disabled.\nOutside hosts may have fewer paths toward this compute.\nThat could reduce unwanted connection attempts.`;
  }
  if (finding.check_id === "azure.claude.servicebus_namespace_network_restricted") {
    const values = evidence as Record<string, unknown>;
    const branch = servicebusNetwork.find(item => item.status === finding.status &&
      Object.entries(item.required).every(([key, value]) => matchesRecorded(values[key], value)));
    if (branch) return branch.lines.join("\n");
  }
  const alert = (activityAlerts as Record<string, { event: string; impact: string }>)[finding.check_id];
  if (alert && (finding.status === "PASS" || finding.status === "FAIL")) {
    const values = evidence as Record<string, unknown>;
    if (finding.status === "FAIL" && values.reason === "no matching enabled activity log alert")
      return `No enabled activity log alert is recorded when ${alert.event}.\nThat event may go unnoticed.\nThe team could review ${alert.impact} later than needed.`;
    if (finding.status === "PASS" && typeof values.alert === "string" &&
        values.alert.toLowerCase().includes("/providers/microsoft.insights/activitylogalerts/"))
      return `An enabled activity log alert is configured to run when ${alert.event}.\nIt may notify the team about that event.\nThat could help them review ${alert.impact} sooner.`;
  }
  if (finding.status === "NOT_APPLICABLE") {
    const values = evidence as Record<string, unknown>;
    const variant = (notApplicableVariants as Record<string, { required: Record<string, unknown>; lines: string[] }[]>)[finding.check_id]?.find(item =>
      Object.entries(item.required).every(([key, value]) => matchesRecorded(values[key], value)));
    if (variant) return variant.lines.join("\n");
    const appliesTo = values.applies_to;
    const osType = values.os_type;
    if ((appliesTo === "Windows" || appliesTo === "Linux") &&
        (osType === "Windows" || osType === "Linux") && appliesTo !== osType)
      return `This VM runs ${osType}.\nThis setting applies to ${appliesTo} VMs.\nIts users are outside the scope of that setting.`;
    const diskState = values.disk_state;
    if ((appliesTo === "attached" || appliesTo === "unattached") &&
        (diskState === "Attached" || diskState === "Unattached") && appliesTo !== diskState.toLowerCase())
      return `This disk is ${diskState.toLowerCase()}.\nThis setting applies to ${appliesTo} disks.\nData on this disk is outside that setting’s scope.`;
    const reason = values.reason;
    return typeof reason === "string"
      ? (notApplicable as Record<string, string[]>)[reason]?.join("\n") || null : null;
  }
  if (finding.status === "UNKNOWN") {
    const values = evidence as Record<string, unknown>;
    if (rule?.missing_reason && values.reason === rule.missing_reason) return rule.unknown?.join("\n") || null;
    const variant = rule?.unknown_variants?.find(item =>
      Object.entries(item.required).every(([key, value]) => matchesRecorded(values[key], value)));
    if (variant) return variant.lines.join("\n");
    const reason = values.reason || singleUnknownReason(values);
    if (typeof reason !== "string") return null;
    const effects = (unknownSpecificEffects as Record<string, string[]>)[finding.check_id] ||
      (unknownGroupEffects as Record<string, string[]>)[(unknownGroupById as Record<string, string>)[finding.check_id]];
    if (reason.startsWith("missing fact:")) {
      const path = reason.slice("missing fact:".length).trim();
      const first = (missingFactLabels as Record<string, string>)[path] || "The record is missing a required value.";
      return effects ? [first, ...effects].join("\n") : `${first}\nThat leaves the resource condition unknown.\nThe team cannot tell whether this resource needs attention.`;
    }
    for (const [prefix, ending] of [
      ["dependency incomplete or unavailable: ", "is incomplete or unavailable."],
      ["dependency not collected: ", "was not collected."],
    ]) {
      if (reason.startsWith(prefix)) {
        const label = (dependencyLabels as Record<string, string>)[reason.slice(prefix.length)];
        if (label) {
          const first = `The related ${label} record ${ending}`;
          return effects ? [first, ...effects].join("\n") : `${first}\nThat leaves the resource condition unknown.\nThe team cannot tell whether this resource needs attention.`;
        }
      }
    }
    const first = (incomplete.exact as Record<string, string>)[reason] ||
      Object.entries(incomplete.prefixes).find(([prefix]) =>
        reason.startsWith(prefix) && reason.length > prefix.length)?.[1];
    return first ? (effects ? [first, ...effects].join("\n") : `${first}\nThat leaves the resource condition unknown.\nThe team cannot tell whether this resource needs attention.`) : null;
  }
  const nativeImpact = (nativeImpacts as Record<string, Record<string, string[] | { first: string; impact: string[] }>>)[finding.check_id]?.[finding.status];
  if (nativeImpact) {
    const first = Array.isArray(nativeImpact) ? null : nativeImpact.first;
    const impact = Array.isArray(nativeImpact) ? nativeImpact : nativeImpact.impact;
    const nativeObservation = explainAzureNativeEvidenceObservation(finding.check_id, evidence, finding.status);
    if (nativeObservation && nativeObservation === _observation)
      return [first || nativeObservation, ...impact].join("\n");
    const pattern = (bulkImpactPatterns as Record<string, Record<string, string>>)[finding.check_id]?.[finding.status];
    if (pattern && new RegExp(`^${pattern}$`).test(_observation))
      return [first || _observation, ...impact].join("\n");
  }
  if (!rule) return null;
  const branch = finding.status === "PASS" ? "pass" : "fail";
  const values = evidence as Record<string, unknown>;
  const variant = (branch === "pass" ? rule.pass_variants : rule.fail_variants)?.find(item =>
    Object.entries(item.required).every(([key, value]) => matchesRecorded(values[key], value)) &&
    Object.entries(item.array_states || {}).every(([key, state]) =>
      Array.isArray(values[key]) && ((values[key] as unknown[]).length > 0) === (state === "nonempty")));
  if (variant) return variant.lines.join("\n");
  const expected = branch === "pass" ? rule.pass_value : rule.fail_value;
  const arrayState = branch === "pass" ? rule.pass_array_state : rule.fail_array_state;
  const lines = rule[branch];
  if (!lines || (!arrayState && !Object.prototype.hasOwnProperty.call(rule, `${branch}_value`))) return null;
  const actual = values[rule.field];
  if (arrayState) {
    if (!Array.isArray(actual) || (actual.length > 0) !== (arrayState === "nonempty")) return null;
  } else if (!matchesRecorded(actual, expected)) return null;
  if (rule.configured_field && values.field !== rule.configured_field) return null;
  if (rule.required && Object.entries(rule.required).some(([key, value]) => !matchesRecorded(values[key], value))) return null;
  return lines.join("\n");
}
