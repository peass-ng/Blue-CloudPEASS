/** Turn evaluator condition keys into short, readable reasons for a map edge. */
export function explainPrivescCondition(code: string, description?: string): string {
  if (description?.trim()) return description.trim();
  const selector = /^selector_(.+)_(?:not_evaluated|unknown)$/.exec(code);
  if (selector) return `The ${words(selector[1])} target selector could not be verified from this snapshot.`;
  const missing = /^(.+)_(?:not_collected|not_in_snapshot)$/.exec(code);
  if (missing) return `${capital(words(missing[1]))} was not collected in this snapshot.`;
  const blocker = /^blocker_(.+)_possibly_enforced$/.exec(code);
  if (blocker) return `${capital(words(blocker[1]))} may block this path.`;
  const lifted = /^blocker_(.+)_lifted_via_(.+)$/.exec(code);
  if (lifted) return `${capital(words(lifted[1]))} may be lifted through ${words(lifted[2])}.`;
  if (code.endsWith("_not_evaluated"))
    return `${capital(words(code.slice(0, -"_not_evaluated".length)))} was not evaluated.`;
  return `${capital(words(code))}.`;
}

function words(value: string): string {
  return value.replaceAll("_", " ").replace(/\s+/g, " ").trim()
    .replace(/\bscp\b/gi, "SCP")
    .replace(/\biam\b/gi, "IAM")
    .replace(/\bpassrole\b/gi, "PassRole")
    .replace(/\baws\b/gi, "AWS")
    .replace(/\bgcp\b/gi, "GCP")
    .replace(/\bk8s\b/gi, "Kubernetes");
}

function capital(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
