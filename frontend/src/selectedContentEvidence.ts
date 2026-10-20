import { selectedConfigurationContentObservation } from "./selectedConfigurationContentEvidence";
import type { Finding } from "./types";

const subjects: Record<string, { provider: string; subject: string; image?: boolean }> = {
  "azure.review.app_service.selected_app_settings_secret_indicators": { provider: "azure", subject: "selected literal app settings" },
  "azure.review.acr.selected_image_secret_indicators": { provider: "azure", subject: "the selected immutable ACR image", image: true },
  "k8s.review.selected_literals.secret_indicators": { provider: "k8s", subject: "selected workload and ConfigMap literals" },
  "aws.review.lambda.selected_environment_secret_indicators": { provider: "aws", subject: "selected Lambda environment variables" },
};
const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** Interpret complete detector facts; saved status/free text supplies no proof. */
export function selectedContentObservation(finding: Finding): string | undefined {
  const current = selectedConfigurationContentObservation(finding);
  if (current) return current;
  const rule = subjects[finding.check_id], e = finding.evidence;
  if (!rule || rule.provider !== finding.provider || !["PASS", "FAIL"].includes(finding.status) || !object(e)) return;
  const environment = finding.check_id === "aws.review.lambda.selected_environment_secret_indicators";
  if (e.complete !== true || e.credential_validation !== "not_attempted"
      || e.coverage !== (environment ? "selected_observed_literal_environment_only" : rule.image ? "selected_observed_image_content_only" : "selected_observed_literals_only")) return;
  const count = environment ? e.variable_count : e.literal_count;
  if (!rule.image && (typeof count !== "number" || !Number.isInteger(count) || count < 1)) return;
  const parts = environment ? [{ complete: true, engines: e.engines }] : e.parts;
  if (!Array.isArray(parts) || (rule.image ? parts.length < 2 : parts.length !== 1)) return;
  if (rule.image && (!object(parts[0]) || parts[0].part !== "manifest" || !object(parts[1]) || parts[1].part !== "config")) return;
  for (const part of parts) {
    if (!object(part) || part.complete !== true || !Array.isArray(part.engines) || part.engines.length !== 2) return;
    const versions: Record<string, string> = { kingfisher: "1.4.0", trufflehog: "3.92.5" };
    const names = new Set<string>();
    for (const engine of part.engines) {
      if (!object(engine) || typeof engine.engine !== "string" || versions[engine.engine] !== engine.version || engine.status !== "complete") return;
      names.add(engine.engine);
    }
    if (names.size !== 2) return;
  }
  if (!Array.isArray(e.secret_leaks) || (finding.status === "FAIL") !== (e.secret_leaks.length > 0)) return;
  if (!e.secret_leaks.every(leak => object(leak) && typeof leak.fingerprint === "string"
      && /^[0-9a-f]{64}$/.test(leak.fingerprint) && Array.isArray(leak.locations) && leak.locations.length > 0)) return;
  return e.secret_leaks.length ? `A likely secret was detected in ${rule.subject}.`
    : `Both offline detectors found no supported secret in ${rule.subject}.`;
}
