import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainAzureFindingEvidence, REVIEWED_AZURE_EVIDENCE_CHECKS } from "../src/azureFindingEvidence";

type Observation = { check_id: string; status: string; evidence: Record<string, unknown> };
const observations = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/azure-reviewed-evidence.json", import.meta.url)), "utf8")) as Observation[];
const summarize = (slug: string, evidence: Record<string, unknown>, status = "FAIL") => explainAzureFindingEvidence("azure.claude." + slug, evidence, status);

test("all644 reviewed Azure controls have concise summaries for their real positive and negative native shapes", () => {
  expect(REVIEWED_AZURE_EVIDENCE_CHECKS).toHaveLength(644);
  expect(new Set(observations.map(row => row.check_id))).toEqual(new Set(REVIEWED_AZURE_EVIDENCE_CHECKS));
  expect(observations).toHaveLength(1288);
  const missing = observations.filter(row => ["PASS", "FAIL"].includes(row.status)).filter(row => !explainAzureFindingEvidence(row.check_id, row.evidence, row.status)).map(row => row.check_id + " " + row.status);
  expect(missing).toEqual([]);
  for (const row of observations.filter(row => ["PASS", "FAIL"].includes(row.status))) {
    const result = explainAzureFindingEvidence(row.check_id, row.evidence, row.status);
    expect(result!.length, row.check_id).toBeLessThan(250);
    expect(result).not.toMatch(/upstream|cross.join|semantics|Not supplied|Observed evidence|\{"/i);
  }
});

test("unknown and malformed facts preserve the uncertainty-aware fallback instead of manufacturing a verdict", () => {
  for (const row of observations) {
    expect(explainAzureFindingEvidence(row.check_id, row.evidence, "UNKNOWN")).toBeUndefined();
    expect(explainAzureFindingEvidence(row.check_id, null, "FAIL")).toBeUndefined();
    expect(explainAzureFindingEvidence(row.check_id, {}, "FAIL")).toBeUndefined();
  }
  expect(explainAzureFindingEvidence("azure.app.https_only", { field: "properties.httpsOnly", configured: "true" }, "PASS")).toBeUndefined();
  expect(explainAzureFindingEvidence("azure.sql.minimum_tls", { field: "properties.minimalTlsVersion", configured: "1.3" }, "PASS")).toBeUndefined();
  expect(summarize("storage_encryption_scope_cmk", { source: "unexpected" })).toBeUndefined();
  expect(summarize("unreviewed.new_check", { configured: true })).toBeUndefined();
});

test("public-port summaries state the exact declared ingress without claiming a packet test", () => {
  expect(summarize("nsg_internet_http_https", { direction: "Inbound", exposed_rules: [{ protocol: "tcp", port: 443 }] })).toBe("Internet-source ingress is allowed on tcp/443.");
  expect(summarize("nsg_internet_icmp", { direction: "Inbound", exposed_rules: [{ protocol: "icmp", port: "all" }] })).toBe("Internet-source ingress is allowed on ICMP.");
  expect(summarize("nsg_outbound_restricted", { direction: "Outbound", exposed_rules: [{ protocol: "*", port: "all" }] })).toBe("Outbound Allow rules cover all protocols and ports.");
  expect(summarize("nsg_internet_ssh", { exposed_rules: [] }, "PASS")).toBe("No matching public-source Allow rule was found.");
});

test("existence approval authentication and encryption observations remain separate", () => {
  expect(summarize("storage_private_endpoint_present", { connection_states: ["Pending"] }, "PASS")).toBe("Private endpoint connection states: Pending.");
  expect(summarize("storage_private_link_all_approved", { connection_states: [] })).toBe("No private endpoint connections are listed.");
  expect(summarize("storage_container_no_public_access", { public_access: "Container" })).toBe("The container public-access ACL is Container.");
  expect(summarize("storage_encryption_scope_cmk", { source: "Microsoft.Storage" })).toBe("The encryption scope uses a platform-managed storage key.");
  expect(summarize("sql_firewall_no_internet_or_azure_services", { start_ip: "0.0.0.0", end_ip: "0.0.0.0" })).toBe("The firewall rule allows connections from Azure services across tenants.");
  expect(summarize("storage_key_expiration_policy_90", { key_expiration_period_days: null })).toBe("No storage key-expiration policy is declared.");
  expect(summarize("storage_access_keys_rotated_90", { key_age_days: { key1: 5, key2: 200 } })).toBe("The oldest reported storage key is 200 days old.");
});

test("absence false and zero remain meaningful observations without technical boilerplate", () => {
  expect(summarize("storage_blob_and_container_soft_delete_7_365", { blob_retention_days: 7, container_retention_days: null })).toBe("Soft delete: blobs 7 days; containers disabled.");
  expect(summarize("postgresql_flexible_entra_authentication", { active_directory_auth: "Enabled", administrators: 0 })).toBe("Entra authentication is enabled with 0 listed administrators.");
  expect(summarize("servicebus_premium_namespace_vnet_rules", { virtual_network_rule_count: 0, semantics: "Do not display implementation boilerplate." })).toBe("0 virtual-network rules are listed.");
  expect(explainAzureFindingEvidence("azure.app.https_only", { field: "properties.httpsOnly", configured: false }, "FAIL")).toBe("HTTPS-only access is disabled.");
});

test("new270 families retain source-specific limitations without inventing a more severe condition", () => {
  expect(explainAzureFindingEvidence("azure.port.keyvault_public_network_access_disabled", { default_action: "Allow", connection_count: 1 }, "FAIL")).toBe("The vault network ACL default action is allow.");
  expect(explainAzureFindingEvidence("azure.port.search_service_uses_managed_identity", { identity_type: "SystemAssigned, UserAssigned" }, "FAIL")).toBe("Search identity type is SystemAssigned, UserAssigned.");
  expect(explainAzureFindingEvidence("azure.port.cognitive_account_restrict_public_access", { capabilities: [] }, "PASS")).toContain("does not evaluate isolation");
  expect(explainAzureFindingEvidence("azure.port.keyvault_logging_enabled", { enabled_category_groups: ["allLogs"] }, "FAIL")).toBe("Enabled vault log groups: allLogs.");
  expect(explainAzureFindingEvidence("azure.port.keyvault_with_rbac_key_expiration_set", { enabled: false }, "PASS")).toContain("object is disabled");
  expect(summarize("servicefabric_cluster_entra_auth", { entra_configured: true }, "PASS")).toBe("An Entra configuration object is declared.");
  expect(summarize("sql_database_long_term_retention", { retention: { weeklyRetention: "P0W", monthlyRetention: "P0M", yearlyRetention: "PT0S" } })).toContain("all disabled");
  expect(summarize("logic_app_workflow_diagnostic_logging", { diagnostic_logging_enabled: false })).toBe("Diagnostic logging is disabled.");
  expect(summarize("mssql_managed_instance_vulnerability_assessment", { recurring_scans_enabled: true }, "PASS")).toBe("Default vulnerability-assessment scan scheduling is enabled.");
});
