import type { Finding } from "./types";
import reviewedCopy from "./reviewedEvidenceCopy.json" with { type: "json" };

type EvidenceReview = {
  purpose: string;
  limit?: string;
  missing_observation?: string;
  manual_observation?: string;
  not_applicable_observation?: string;
};
const reviews: Record<string, Record<string, EvidenceReview>> = reviewedCopy;

/** Add the exact check's reviewed interpretation to a typed native observation.
 * The server and browser use the same per-ID prose; no title/category matching
 * infers what a check means or turns a saved verdict into an observed setting.
 */
export function explainObservedEvidence(finding: Finding, observation: string): string {
  if (finding.guidance_refresh?.allow_summary === false) return observation;
  if (finding.evidence_summary_format === "natural-language-v2" && finding.evidence_summary === observation) return observation;
  const row = reviews[finding.provider]?.[finding.check_id];
  if (!row || observation.includes(row.purpose)) return observation;
  if (finding.provider === "azure") {
    if (["UNKNOWN", "DENIED", "EMPTY"].includes(finding.status)) observation = row.missing_observation || observation;
    else if (finding.status === "MANUAL") observation = row.manual_observation || observation;
    else if (finding.status === "NOT_APPLICABLE") observation = row.not_applicable_observation || observation;
    else if (/^(?:Observed evidence:|semantics:|The recorded evidence|resource ids is)/i.test(observation))
      observation = row.missing_observation || observation;
  }
  if (/^(No observed evidence|No readable evidence|The recorded evidence has no concise)/i.test(observation)) {
    observation = row.missing_observation
      || "No usable deciding evidence was recorded.";
    if (["UNKNOWN", "DENIED"].includes(finding.status)) observation += " The check remains undetermined.";
  }
  const purpose = [row.purpose, finding.status === "UNKNOWN" || finding.status === "DENIED" ? "" : row.limit]
    .filter(Boolean).join(" ");
  const text = observation.trim();
  return `${text}${/[.!?]$/.test(text) ? "" : "."} ${purpose}`;
}
