import type { Finding } from "./types";

/** Facts saved by the native Azure evaluators for success branches. */
export function azureLongSemanticEvidence(finding: Finding): string | null {
  if (finding.provider !== "azure" || (finding.status !== "PASS" && finding.status !== "FAIL") ||
      !finding.evidence || typeof finding.evidence !== "object" || Array.isArray(finding.evidence)) return null;
  const e = finding.evidence as Record<string, unknown>;
  if (finding.status === "FAIL") {
    if (finding.check_id === "azure_api_management_3_5_1_1_345bdac" &&
        Array.isArray(e.effective_path_states) && e.effective_path_states.includes("FAIL"))
      return "A required API path lacks an approved encrypted cache setting.\nIts cached response may have less protection than intended.\nThat could expose data returned to users.";
    if (finding.check_id === "azure_devops_project_1_2_8_6_fb0e5a8" &&
        Array.isArray(e.observed_fail_facts) && e.observed_fail_facts.some(row => row && typeof row === "object" &&
          typeof row.repository_id === "string" && row.clone_url_has_credentials === true))
      return "A DevOps repository clone URL contains embedded credentials.\nSomeone who gets the URL may also get a sign-in secret.\nThat could expose the project code.";
    if (finding.check_id === "azure_devops_project_6_5_5_2_2908a87" &&
        Array.isArray(e.observed_fail_facts) && e.observed_fail_facts.some(row => row && typeof row === "object" &&
          Number.isInteger(row.deployment_job_count) && Number.isInteger(row.approved_job_limit) &&
          row.deployment_job_count > row.approved_job_limit))
      return "A deployment stage allows more jobs than its approved limit.\nMore deployments may run at the same time than intended.\nThat could increase unwanted changes to services people use.";
    if (finding.check_id === "azure_ml_workspace_1_2_8_36_33f50db" &&
        Array.isArray(e.other_subnet_bindings) && e.other_subnet_bindings.length > 0 &&
        e.other_subnet_bindings.every(row => row && typeof row === "object" && typeof row.compute_id === "string"))
      return "An ML compute instance lacks an approved subnet binding.\nIt may use a different network path than intended.\nThat could expose the instance to unwanted requests.";
    if (finding.check_id === "azure_ml_workspace_1_2_8_37_973721f" &&
        Array.isArray(e.direct_egress_compute_ids) && e.direct_egress_compute_ids.length > 0 &&
        e.direct_egress_compute_ids.every(value => typeof value === "string" && value))
      return "An ML compute instance has a direct internet egress path.\nIt may send requests outside the approved network route.\nThat could expose data handled by the instance.";
    if (finding.check_id === "azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa" &&
        Array.isArray(e.violations) && e.violations.length > 0 && e.violations.every(row => row && typeof row === "object" &&
          typeof row.metricName === "string"))
      return `The required ${e.violations[0].metricName} metric lacks an enabled alert.\nA change in that metric may go unnoticed.\nThat could delay the team’s response to a service problem.`;
    return null;
  }
  if (finding.check_id === "azure_aks_cluster_aks_cluster_rbac_enabled_db12524") {
    const rows = e.nonroot_container_uids;
    if (Number.isInteger(e.linux_pods) && (e.linux_pods as number) > 0 && Array.isArray(rows) && rows.length > 0 &&
        rows.every(row => row && typeof row === "object" && typeof row.container === "string" && row.container &&
          Number.isInteger(row.uid) && row.uid > 0)) {
      const first = rows[0] as { container: string; uid: number };
      return `Linux container ${first.container} declares user ID ${first.uid}.\nIt is set to run without root user privileges.\nThat may limit what someone controlling it can change.`;
    }
  }
  if (finding.check_id === "azure_api_management_3_5_1_1_345bdac") {
    const states = e.effective_path_states;
    if (Array.isArray(states) && states.length > 0 && states.every(state => state === "PASS") &&
        e.effective_path_count === states.length && Number.isInteger(e.required_operation_count) &&
        (e.required_operation_count as number) > 0)
      return "Every recorded required API path uses an approved encrypted cache.\nCached responses may stay protected by its recorded settings.\nThat could help protect data returned to users.";
  }
  if (finding.check_id === "azure_application_gateway_1_2_5_8_33a9d21") {
    const listeners = e.approved_https_listener_ids;
    const domains = e.approved_front_door_domain_ids;
    if (Array.isArray(listeners) && listeners.length > 0 && listeners.every(value => typeof value === "string" && value) &&
        e.https_listener_count === listeners.length && Array.isArray(domains) &&
        domains.every(value => typeof value === "string" && value) && e.front_door_domain_count === domains.length &&
        (e.approved_minimum_protocol === "TLSv1_2" || e.approved_minimum_protocol === "TLSv1_3"))
      return `The HTTPS listeners use approved TLS settings at or above ${e.approved_minimum_protocol}.\nThose settings may protect traffic to the gateway.\nThat could help keep users’ data private in transit.`;
  }
  if (finding.check_id === "azure_application_gateway_app_client_certificates_on_fcca0b8") {
    const listeners = e.validated_key_vault_listener_ids;
    if (Array.isArray(listeners) && listeners.length > 0 && listeners.every(value => typeof value === "string" && value) &&
        e.listener_count === listeners.length)
      return "The HTTPS listeners have validated Key Vault certificate bindings.\nTheir server certificates may support trusted connections.\nThat could help users connect to the intended gateway.";
  }
  if (finding.check_id === "azure_cosmos_account_10_2_1_1_13_5c115b0" ||
      finding.check_id === "azure_cosmos_account_10_2_1_1_23_e04a63d") {
    const facts = e.observed_pass_facts;
    if (Number.isInteger(e.assessed_count) && (e.assessed_count as number) > 0 && Array.isArray(facts) &&
        facts.length === e.assessed_count && facts.every(row => row && typeof row === "object" &&
          typeof row.resource_id === "string" && Array.isArray(row.qualifying_diagnostic_ids) &&
          row.qualifying_diagnostic_ids.length > 0 && row.qualifying_diagnostic_ids.every((v: unknown) => typeof v === "string" && v) &&
          Array.isArray(row.required_categories) && row.required_categories.length > 0)) {
      const kind = finding.check_id.endsWith("13_5c115b0") ? "Mongo request" : "data-plane request";
      return `The Cosmos account has a diagnostic setting for ${kind} logs.\nThose logs may help trace use of its data.\nThe team could review unusual requests affecting users.`;
    }
  }
  if (finding.check_id === "azure_devops_project_1_2_8_6_fb0e5a8" ||
      finding.check_id === "azure_devops_project_6_5_5_2_2908a87") {
    const facts = e.observed_pass_facts;
    if (Number.isInteger(e.assessed_count) && (e.assessed_count as number) > 0 && Array.isArray(facts) &&
        facts.length === e.assessed_count) {
      if (finding.check_id.endsWith("6_fb0e5a8") && facts.every(row => row && typeof row === "object" &&
          Number.isInteger(row.repository_count) && row.repository_count >= 0 && row.clone_urls_with_credentials === 0) &&
          facts.some(row => row.repository_count > 0))
        return "The recorded DevOps repository clone URLs contain no embedded credentials.\nA copied URL may be less likely to reveal a sign-in secret.\nThat could help keep project code private.";
      if (finding.check_id.endsWith("2_2908a87") && facts.every(row => row && typeof row === "object" &&
          Number.isInteger(row.pipeline_count) && row.pipeline_count >= 0 &&
          Number.isInteger(row.checked_deployment_stages) && row.checked_deployment_stages >= 0 &&
          row.stages_over_limit === 0) && facts.some(row => row.checked_deployment_stages > 0))
        return "The recorded deployment stages stay within their approved job limits.\nA pipeline may run fewer deployments at once.\nThat could reduce unwanted changes to services people use.";
    }
  }
  if (finding.check_id === "azure_c5_ops_20_01b" || finding.check_id === "azure_c5_ops_25_02b") {
    const facts = e.observed_pass_facts;
    if (Number.isInteger(e.assessed_count) && (e.assessed_count as number) > 0 && Array.isArray(facts) &&
        facts.length === e.assessed_count) {
      if (finding.check_id.endsWith("20_01b") && facts.every(row => row && typeof row === "object" &&
          Number.isInteger(row.reviewed_incident_count) && row.reviewed_incident_count >= 0 &&
          (row.process_steps_verified === true || row.continuous_coverage === true)))
        return "The Sentinel workspace has verified incident handling or continuous coverage.\nSecurity events may receive a recorded response.\nThat could help protect people when an incident occurs.";
      if (finding.check_id.endsWith("25_02b") && facts.every(row => row && typeof row === "object" &&
          (row.assessment_state === "NotApplicable" ||
            ((row.assessment_state === "Healthy" || row.assessment_state === "Unhealthy") && row.criteria_matched === true))))
        return "The applicable security assessments match the approved severity criteria.\nTheir ratings may help the team order needed work.\nThat could help people address serious data risks sooner.";
    }
  }
  if (finding.check_id === "azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d") {
    const rows = e.observed_pass_facts;
    if (Number.isInteger(e.evaluated_count) && (e.evaluated_count as number) > 0 && Array.isArray(rows) &&
        rows.length === e.evaluated_count && rows.every(row => row && typeof row === "object" &&
          typeof row.server_id === "string" && row.server_id && Array.isArray(row.unrestricted_rules) &&
          row.unrestricted_rules.length === 0))
      return "The reviewed database servers have no unrestricted firewall rules.\nTheir recorded rules do not allow every public IP address.\nThat may limit who can send requests to the databases.";
  }
  if (finding.check_id === "azure_vm_1_4_5_1_d40be43") {
    const rows = e.observed_pass_facts;
    if (Number.isInteger(e.evaluated_count) && (e.evaluated_count as number) > 0 && Array.isArray(rows) &&
        rows.length === e.evaluated_count && rows.every(row => row && typeof row === "object" &&
          ((typeof row.vm_id === "string" && Array.isArray(row.public_ip_ids) && row.public_ip_ids.length === 0) ||
           (typeof row.vm_scale_set_id === "string" && Array.isArray(row.public_ip_templates) && row.public_ip_templates.length === 0)))) {
      const subject = rows.every(row => "vm_id" in row) ? "VM network interfaces" :
        rows.every(row => "vm_scale_set_id" in row) ? "VM scale set templates" : "VM interfaces and scale set templates";
      return `The reviewed ${subject} have no public IP assignment.\nTheir recorded settings avoid a direct public address.\nThat may reduce unwanted requests to these workloads.`;
    }
  }
  if (finding.check_id === "azure_ml_workspace_1_2_8_36_33f50db") {
    const rows = e.approved_subnet_bindings;
    if (Number.isInteger(e.compute_instance_count) && (e.compute_instance_count as number) > 0 && Array.isArray(rows) &&
        rows.length === e.compute_instance_count && rows.every(row => row && typeof row === "object" &&
          typeof row.compute_id === "string" && row.compute_id && typeof row.subnet_id === "string" && row.subnet_id))
      return "The ML compute instances use approved virtual network subnets.\nTheir recorded network placement follows the chosen subnet list.\nThat may reduce unwanted routes to the compute instances.";
  }
  if (finding.check_id === "azure_ml_workspace_1_2_8_37_973721f") {
    const ids = e.blocked_egress_compute_ids;
    if (Number.isInteger(e.compute_count) && (e.compute_count as number) > 0 && Array.isArray(ids) &&
        ids.length === e.compute_count && ids.every(value => typeof value === "string" && value))
      return "The ML compute instances have no direct internet egress path.\nTheir recorded outbound attempts were blocked.\nThat may limit unwanted connections from those instances.";
  }
  if (finding.check_id === "azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa") {
    const rows = e.matched_metrics;
    if (Number.isInteger(e.required_metric_count) && (e.required_metric_count as number) > 0 && Array.isArray(rows) &&
        rows.length === e.required_metric_count && rows.every(row => row && typeof row === "object" &&
          typeof row.resource_id === "string" && typeof row.metric_name === "string" &&
          Array.isArray(row.enabled_alert_ids) && row.enabled_alert_ids.length > 0))
      return "The required storage metrics have enabled alerts.\nThose alerts may flag changes to the recorded resources.\nThat could help the team respond to unwanted changes.";
  }
  if (finding.check_id === "azure_diagnostic_setting_11_5_2_3_7959930") {
    const rows = e.matched_settings;
    if (Number.isInteger(e.expected_setting_count) && (e.expected_setting_count as number) > 0 && Array.isArray(rows) &&
        new Set(rows.map(row => row?.expected_setting)).size === e.expected_setting_count &&
        Array.from({length: e.expected_setting_count as number}, (_, i) => i).every(i => rows.some(row => row?.expected_setting === i)) &&
        rows.every(row => row && typeof row === "object" && typeof row.enabled_alert_id === "string" &&
          row.enabled_alert_id && Array.isArray(row.routed_action_group_ids) && row.routed_action_group_ids.length > 0))
      return "The expected metric alerts are enabled and routed to action groups.\nThe recorded groups may receive the matching metric events.\nThat could help the team respond to service changes.";
  }
  if (finding.check_id === "azure_storage_account_sqlserver_auditing_enabled_e4e4b28" ||
      finding.check_id === "azure_synapse_workspace_10_2_1_1_28_47f4840") {
    const ids = e.approved_pool_ids;
    if (Number.isInteger(e.pool_count) && (e.pool_count as number) > 0 && Array.isArray(ids) &&
        ids.length === e.pool_count && ids.every(value => typeof value === "string" && value)) {
      if (finding.check_id === "azure_storage_account_sqlserver_auditing_enabled_e4e4b28")
        return "The dedicated SQL pool audit policies are enabled for the required storage account.\nTheir recorded settings may store SQL audit events there.\nThat could help the team review changes to data.";
      return "The Synapse workspace key and SQL pool audit policies match the required settings.\nTheir recorded settings may protect and record data use.\nThat could help the team review unwanted changes.";
    }
  }
  return null;
}
