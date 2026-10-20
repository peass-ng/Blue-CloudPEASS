import type { Finding } from "./types";
import declared from "../../peaso/checks/k8s_kubelet_declaration_observed_20261020.json" with { type: "json" };
import uncertain from "../../peaso/checks/k8s_kubelet_declaration_unknown_observed_20261020.json" with { type: "json" };
const rules: Record<string, { field: string; PASS: string; FAIL: string }> = declared;
export function kubeletDeclarationObservation(finding: Finding): string | undefined {
  const row = rules[finding.check_id];
  const evidence = finding.evidence as Record<string, unknown> | undefined;
  if (finding.provider !== "k8s" || !row || !evidence) return undefined;
  if (finding.status === "UNKNOWN") {
    const keys = Object.keys(evidence).sort().join(",");
    if (keys === "observed" && evidence.observed === uncertain.empty_native) return uncertain.empty_brief;
    if (keys === "observed,raw_content_retained,scope" && evidence.observed === uncertain.unknown_native
        && evidence.scope === "native_named_configmap_declaration_only" && evidence.raw_content_retained === false)
      return uncertain.unknown_brief;
    return undefined;
  }
  if (!["PASS", "FAIL"].includes(finding.status)) return undefined;
  const sentence = row[finding.status as "PASS" | "FAIL"];
  return evidence.scope === "native_named_configmap_declaration_only" && evidence.raw_content_retained === false
    && evidence.field === row.field && evidence.observed === sentence ? sentence : undefined;
}
