import type { Finding } from "./types";

/** Preserve fractional 90-day decisions without printing long decimal ages. */
export function azureReviewObservation(finding: Finding): string | undefined {
  const configuration = nativeConfigurationObservation(finding);
  if (configuration) return configuration;
  if (finding.provider !== "azure" || finding.check_id !== "azure.claude.storage_access_keys_rotated_90" || !["PASS", "FAIL"].includes(finding.status)) return;
  const e = finding.evidence as Record<string, unknown>;
  if (!e || typeof e !== "object" || e.time_source !== "scan_capture" || e.threshold_seconds !== 7776000) return;
  const ages = e.key_age_seconds as Record<string, unknown>;
  const times = e.key_creation_time as Record<string, unknown>;
  if (!ages || !times || Array.isArray(ages) || Array.isArray(times) || Object.keys(ages).sort().join() !== "key1,key2" || Object.keys(times).sort().join() !== "key1,key2") return;
  const stamp = (v: unknown) => typeof v === "string" && /(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(v) ? Date.parse(v) : NaN;
  const now = stamp(e.captured_at);
  if (!Number.isFinite(now)) return;
  for (const key of ["key1", "key2"]) {
    const value = ages[key], then = stamp(times[key]);
    // Date.parse retains milliseconds; native duration evidence retains the
    // exact sub-millisecond decision. Require agreement within parser precision.
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || !Number.isFinite(then) || then > now || Math.abs((now - then) / 1000 - value) > 0.0011) return;
  }
  const old = ["key1", "key2"].filter(key => (ages[key] as number) > 7776000);
  if (!!old.length !== (finding.status === "FAIL")) return;
  return old.length ? `Storage ${old.join(" and ")} ${old.length === 1 ? "is" : "are"} older than 90 days at collection.`
    : "Both storage access keys were created within 90 days before collection.";
}


function nativeConfigurationObservation(finding: Finding): string | undefined {
  if (finding.provider !== "azure" || !["PASS", "FAIL"].includes(finding.status)) return;
  const e = finding.evidence as Record<string, unknown>;
  if (!e || typeof e !== "object" || Array.isArray(e)) return;
  const failed = finding.status === "FAIL";
  const edgeText: Record<string, readonly [string, string]> = {
  "azure_application_gateway_11_5_1_1_1_f56bdc2": [
    "The assessed public resources declare their applicable DDoS and WAF protection.",
    "Some public resources lack the required declared DDoS or WAF protection."
  ],
  "azure_application_gateway_app_http_logs_enabled_2de0361": [
    "Application Gateways declare enabled HTTP access-log export to inventoried destinations.",
    "Some Application Gateways have no enabled HTTP access-log export to an inventoried destination."
  ],
  "azure.review.devops.visible_clone_urls_without_userinfo": [
    "Visible clone URLs returned for the selected Azure DevOps projects contain no user information.",
    "A visible Azure DevOps clone URL contains user information; the value was redacted."
  ]
};
  if (Object.hasOwn(edgeText, finding.check_id)) {
    if (e.native_review_id !== finding.check_id || typeof e.native_review_satisfied !== "boolean" || e.native_review_satisfied === failed || e.runtime_protection !== "not_tested") return;
    return edgeText[finding.check_id][failed ? 1 : 0];
  }
  const declared: Record<string, readonly [string, string]> = {
  "azure.logging.aks_supported_log_categories_destination_declared": [
    "AKS declares destinations for all supported control-plane log categories.",
    "Some supported AKS control-plane log categories have no enabled destination declaration."
  ],
  "azure.logging.managed_hsm_audit_destination_declared": [
    "Managed HSM declares AuditEvent logging to Storage or Log Analytics.",
    "Managed HSM has no enabled AuditEvent destination declaration to Storage or Log Analytics."
  ],
  "azure.encryption.log_analytics_cluster_cmk_declared": [
    "The Log Analytics cluster declares a customer-managed key and managed identity.",
    "The Log Analytics cluster lacks a customer-managed key reference or managed identity."
  ],
  "azure.encryption.stream_analytics_job_storage_cmk_declared": [
    "The selected Stream Analytics storage account declares a customer-managed key and managed identity.",
    "The selected Stream Analytics storage account lacks a customer-managed key reference or managed identity."
  ]
};
  if (Object.hasOwn(declared, finding.check_id)) {
    if (e.native_declaration_id !== finding.check_id || typeof e.native_declaration_satisfied !== "boolean" || e.native_declaration_satisfied === failed || e.effective_access !== "not_tested") return;
    return declared[finding.check_id][failed ? 1 : 0];
  }
  if (["azure.encryption.automation_cmk_declared", "azure.logging.aci_log_analytics_declared"].includes(finding.check_id)) {
    if (e.criterion !== finding.check_id || typeof e.configured !== "boolean" || e.configured === failed || e.effective_access !== "not_tested") return;
    if (finding.check_id === "azure.encryption.automation_cmk_declared") {
      if (failed) return "Automation lacks a complete customer-managed key reference or attached system identity.";
      if (e.key_source !== "Microsoft.Keyvault" || !["SystemAssigned", "SystemAssigned, UserAssigned"].includes(e.identity_type as string) ||
          [e.vault_hostname, e.key_name, e.key_version].some(v => typeof v !== "string" || !v)) return;
      return "Automation declares a customer-managed key reference and an attached system identity.";
    }
    if (failed) return "The container group has no complete Log Analytics destination declaration.";
    if (typeof e.workspace_customer_id !== "string" || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(e.workspace_customer_id) ||
        e.workspace_customer_id.replaceAll("-", "") === "0".repeat(32) || !["ContainerInsights", "ContainerInstanceLogs"].includes(e.log_type as string)) return;
    return "The container group declares a Log Analytics workspace customer UUID and supported log type.";
  }
  if (finding.check_id === "azure.review.managed_hsm.audit_storage_destination") {
    const configured = e.audit_storage_configured, destinations = e.storage_destination_references ?? [];
    if (e.criterion !== "declared_audit_storage_destination" || typeof configured !== "boolean" || configured === failed ||
        !Array.isArray(destinations) || destinations.some(v => typeof v !== "string" || !v) || !!destinations.length !== configured) return;
    return configured ? "AuditEvent logging is configured to an Azure Storage destination." : "No enabled AuditEvent logging to Azure Storage is configured.";
  }
  if (finding.check_id !== "azure.network.acr_public_ip_ranges_restricted" || e.criterion !== "declared_public_ipv4_union" || e.effective_access !== "not_tested" || !["None", "AzureServices"].includes(e.trusted_service_bypass as string)) return;
  if (e.public_network_access === "Disabled") return !failed && e.allows_all_ipv4 !== true ? "The registry declares public network access disabled." : undefined;
  if (e.public_network_access !== "Enabled" || !["Allow", "Deny"].includes(e.default_action as string) ||
      typeof e.allows_all_ipv4 !== "boolean" || e.allows_all_ipv4 !== failed || e.default_action === "Allow" && !failed) return;
  if (e.default_action === "Deny") {
    const ranges = e.collapsed_ipv4_ranges;
    if (!Array.isArray(ranges) || ranges.length > 200 || ranges.some(v => typeof v !== "string") || ranges.includes("0.0.0.0/0") !== failed) return;
  }
  const text = failed ? "The registry's public endpoint allows every IPv4 address in its declared network rules." : "Public IPv4 access is restricted by the registry's declared rules.";
  return text + (e.trusted_service_bypass === "AzureServices" ? " Trusted Azure service bypass is enabled." : " Trusted Azure service bypass is disabled.");
}
