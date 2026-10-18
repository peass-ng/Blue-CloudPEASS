const label = (key: string) =>
  key.replaceAll("_", " ").replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\bKms\b/g, "KMS").replace(/\bId\b/g, "ID");
const concise = (value: string) =>
  value.length > 120 ? `${value.slice(0, 117)}…` : value;
const sensitive = (key: string) =>
  /(?:secret|password|private.?key|credential|access.?token|refresh.?token|session.?token|api.?key|sa_json)/i.test(key);
const bracketedIpv6 = (value: string) => /^\[[0-9a-fA-F:.%]+\](?::\d{1,5})?$/.test(value);
const structuredText = (value: string) =>
  /^[\[{]/.test(value.trim()) && !bracketedIpv6(value.trim());
const scalarItem = (value: unknown) =>
  typeof value === "number" || typeof value === "boolean" ||
  (typeof value === "string" && !structuredText(value));

/** The internet path check describes one asset. Surface its decisive facts first. */
export function explainInternetExposure(evidence: unknown, status: string): { summary: string; reasons: string[] } {
  const item = evidence && typeof evidence === "object" && !Array.isArray(evidence)
    ? evidence as Record<string, unknown> : {};
  const strings = (value: unknown) => Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string" && !!entry).slice(0, 8) : [];
  const ports = strings(item.exposed_ports);
  const addresses = strings(item.public_addresses);
  const external = strings(item.external_scope_ids);
  const path = Array.isArray(item.path) ? item.path.filter((step): step is Record<string, unknown> =>
    !!step && typeof step === "object" && !Array.isArray(step)) : [];
  const unresolved = Array.isArray(item.unresolved) ? item.unresolved.filter((step): step is Record<string, unknown> =>
    !!step && typeof step === "object" && !Array.isArray(step)) : [];
  const gaps = Array.isArray(item.gaps) ? item.gaps.filter((step): step is Record<string, unknown> =>
    !!step && typeof step === "object" && !Array.isArray(step)) : [];
  const location = addresses.length ? ` at ${addresses.join(", ")}` : "";
  let summary: string;
  if (status === "FAIL") {
    if (external.length) summary = `Shared with external scope ${external.join(", ")}.`;
    else if (item.data_exposure) summary = `Public data access is allowed${location}.`;
    else if (ports.length) summary = `Internet access to ${ports.join(", ")}${location} is allowed.`;
    else summary = `A public path${location} is allowed; open technical evidence for its exact route.`;
  } else if (status === "PASS") {
    summary = typeof item.blocked_by === "string" && item.blocked_by
      ? `Public path${location} is blocked by ${label(item.blocked_by)}.`
      : `No open public path was found${location}.`;
  } else {
    summary = `Internet exposure for this asset could not be determined${location}.`;
  }
  const reasons = status === "UNKNOWN"
    ? [
        ...unresolved.map((step) => [step.layer, step.reason].filter((part) => typeof part === "string" && part).join(": ")),
        ...gaps.map((step) => [step.type, step.status].filter((part) => typeof part === "string" && part).join(": ")),
        ...(typeof item.reason === "string" ? [item.reason] : []),
      ]
    : path.filter((step) => step.decision === (status === "PASS" ? "block" : "allow"))
      .map((step) => {
        const detail = typeof step.reason === "string" ? step.reason :
          typeof step.source_ranges === "string" ? step.source_ranges :
          Array.isArray(step.source_ranges) ? step.source_ranges.join(", ") : "";
        return [step.layer, detail].filter((part) => typeof part === "string" && part).join(": ");
      });
  return { summary, reasons: [...new Set(reasons)].slice(0, 5).map((reason) => concise(reason)) };
}

function valueText(value: unknown): string | undefined {
  if (typeof value === "string") return concise(value.trim()) || undefined;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  if (Array.isArray(value) && value.length) {
    const preview = value.slice(0, 3);
    if (preview.every(scalarItem))
      return `${preview.map((item) => concise(String(item))).join(", ")}${value.length > 3 ? `; ${value.length - 3} more supplied` : ""}`;
  }
  return undefined;
}

function scalarFacts(evidence: Record<string, unknown>): string[] {
  const facts: string[] = [];
  let inspected = 0;
  const visit = (value: unknown, path: string[], depth: number) => {
    if (facts.length >= 4 || inspected++ >= 40 || depth > 4) return;
    const key = path.at(-1) || "Value";
    if (path.some(sensitive)) return;
    const name = path.filter((part) => !/^(attributes|properties|data|value)$/i.test(part))
      .map(label).join(" ") || label(key);
    if (value === "") {
      facts.push(`${name} is empty in the supplied snapshot`);
      return;
    }
    if (value === null) {
      facts.push(`${name} has no recorded value`);
      return;
    }
    if (typeof value === "string" && structuredText(value)) {
      try {
        visit(JSON.parse(value), path, depth + 1);
      } catch {
        facts.push(`${name} contains a structured value that could not be summarized`);
      }
      return;
    }
    const readable = valueText(value);
    if (readable) {
      facts.push(["reason", "message", "semantics"].includes(key)
        ? `${name}: ${readable}` : `${name} is ${readable}`);
      return;
    }
    if (Array.isArray(value)) {
      facts.push(`${name} contains ${value.length} supplied record${value.length === 1 ? "" : "s"}`);
      for (const [index, item] of value.slice(0, 2).entries())
        if (typeof item === "string" && structuredText(item) || item && typeof item === "object")
          visit(item, [...path, `item ${index + 1}`], depth + 1);
      return;
    }
    if (value && typeof value === "object")
      for (const [child, item] of Object.entries(value)) visit(item, [...path, child], depth + 1);
  };
  for (const [key, value] of Object.entries(evidence).sort(([a], [b]) =>
    Number(["reason", "message", "semantics"].includes(b)) -
    Number(["reason", "message", "semantics"].includes(a)))) visit(value, [key], 0);
  return facts;
}

/** Describe only supplied facts. Keep nested records available in technical details. */
export function explainFindingEvidence(evidence: unknown, status: string): string {
  if (evidence == null || evidence === "")
    return ["UNKNOWN", "DENIED", "EMPTY", "MANUAL", "NOT_APPLICABLE"].includes(
      status.toUpperCase(),
    )
      ? "No observed evidence was supplied for this undetermined result."
      : "No observed evidence was supplied.";

  if (typeof evidence === "string" && structuredText(evidence)) {
    try {
      return explainFindingEvidence(JSON.parse(evidence), status);
    } catch {
      return "Observed evidence contains a structured value that could not be summarized. Open technical details for its recorded form.";
    }
  }

  const scalar = valueText(evidence);
  if (scalar) return `Observed value: ${scalar}.`;
  if (Array.isArray(evidence))
    return evidence.length
      ? `${evidence.length} evidence records were supplied. Open technical details to review them.`
      : "No observed evidence was supplied.";
  if (typeof evidence !== "object") return "No readable evidence was supplied.";

  const entries = Object.entries(evidence as Record<string, unknown>);
  const record = evidence as Record<string, unknown>;
  if (record.source === "Explicit demo fixture" &&
      typeof record.encryption === "string" &&
      /missing in fixture snapshot/i.test(record.encryption))
    return "Missing in fixture snapshot: encryption information was not supplied, so this demo evidence does not establish the configuration.";
  if (typeof record.default_encryption_configuration === "boolean") {
    const presence = record.default_encryption_configuration ? "present" : "absent";
    const count = typeof record.rule_count === "number"
      ? ` ${record.rule_count} rule${record.rule_count === 1 ? "" : "s"} recorded.`
      : "";
    return `Collected default encryption configuration is ${presence}.${count}`;
  }
  const facts = scalarFacts(record);
  if (!facts.length)
    return entries.length
      ? "The recorded evidence has no concise non-sensitive values to summarize. Open technical details for available fields."
      : "No observed evidence was supplied.";
  const displayed = facts.slice(0, 3).join("; ");
  return facts.length > 3
    ? `Observed evidence: ${displayed}. More recorded details are available below.`
    : `Observed evidence: ${displayed}.`;
}
