/** Brief observations for twelve reviewed GCP scalar settings, not runtime proofs. */
const settings: Record<string, { field: string; label: string; states?: Record<string, string> }> = {
  "gcp.compute.shielded_vtpm": { field: "shieldedInstanceConfig.enableVtpm", label: "The VM’s virtual TPM" },
  "gcp.compute.integrity_monitoring": { field: "shieldedInstanceConfig.enableIntegrityMonitoring", label: "Shielded VM integrity monitoring" },
  "gcp.compute.secure_boot": { field: "shieldedInstanceConfig.enableSecureBoot", label: "Secure Boot" },
  "gcp.sql.backups": { field: "settings.backupConfiguration.enabled", label: "Automatic Cloud SQL backup scheduling" },
  "gcp.sql.no_public_ip": { field: "settings.ipConfiguration.ipv4Enabled", label: "Public IPv4 for this Cloud SQL instance" },
  "gcp.gke.secrets_encryption": { field: "databaseEncryption.state", label: "Application-layer Secrets encryption", states: { ENCRYPTED: "enabled", DECRYPTED: "disabled" } },
  "gcp.network.custom_subnets": { field: "autoCreateSubnetworks", label: "The VPC subnet mode", states: { true: "auto", false: "custom" } },
  "gcp.reviewed.compute.deletion_protection": { field: "deletionProtection", label: "VM deletion protection" },
  "gcp.reviewed.compute.automatic_restart": { field: "scheduling.automaticRestart", label: "Automatic restart after a host failure" },
  "gcp.reviewed.compute.maintenance_migrate": { field: "scheduling.onHostMaintenance", label: "The VM host maintenance policy", states: { MIGRATE: "MIGRATE", TERMINATE: "TERMINATE" } },
  "gcp.reviewed.compute.confidential_computing": { field: "confidentialInstanceConfig.enableConfidentialCompute", label: "Confidential Computing" },
  "gcp.reviewed.loadbalancer.backend_logging": { field: "logConfig.enable", label: "Backend service logging" },
};

export function explainGcpFindingEvidence(checkId: string, evidence: unknown, status: string): string | undefined {
  const setting = settings[checkId];
  if (!setting || !["PASS", "FAIL"].includes(status) || !evidence || typeof evidence !== "object" || Array.isArray(evidence)) return;
  const item = evidence as Record<string, unknown>;
  if (item.field !== setting.field) return;
  let state: string | undefined;
  if (setting.states && (typeof item.configured === "string" || typeof item.configured === "boolean")) {
    state = Object.hasOwn(setting.states, String(item.configured)) ? setting.states[String(item.configured)] : undefined;
  } else if (!setting.states && typeof item.configured === "boolean") {
    state = item.configured ? "enabled" : "disabled";
  }
  if (state) return `${setting.label} is ${state}.`;
}
