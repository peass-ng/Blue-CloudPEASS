import type { Finding } from "./types";

/** Interpret deciding ARM values; never reuse arbitrary observed prose. */
export function azureAIServiceObservation(finding: Finding): string | undefined {
  if (finding.provider !== "azure" || !["PASS", "FAIL"].includes(finding.status)) return;
  const e = finding.evidence as Record<string, unknown>;
  if (!e || typeof e !== "object" || Array.isArray(e)) return;
  const pass = finding.status === "PASS";
  switch (finding.check_id) {
    case "azure.review.ai_services.audit_logging": {
      const n = e.qualifying_log_entries;
      if (typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && (n > 0) === pass)
        return `Audit logs ${n ? "have" : "do not have"} a configured diagnostic destination.`;
      break;
    }
    case "azure.review.ai_services.managed_identity": {
      const mode = e.identity_type;
      if (typeof mode === "string" && ["None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"].includes(mode) && (mode !== "None") === pass)
        return mode === "None" ? "The account has no managed identity." : `The account has ${mode} identity.`;
      break;
    }
    case "azure.review.ai_services.outbound_restriction":
      if (typeof e.restrict_outbound_network_access === "boolean" && e.restrict_outbound_network_access === pass)
        return `Outbound network restrictions are ${pass ? "enabled" : "disabled"}.`;
      break;
    case "azure.review.ai_services.prompt_shield": {
      const results = e.deployment_results;
      if (!Array.isArray(results) || !results.length || !results.every(v => ["PASS", "FAIL", "UNKNOWN"].includes(v))) return;
      if (!pass && results.includes("FAIL")) return "At least one text deployment policy lacks enabled blocking Prompt Shields.";
      if (pass && results.every(v => v === "PASS")) return "All assessed text deployment policies enable blocking Prompt Shields.";
    }
  }
}
