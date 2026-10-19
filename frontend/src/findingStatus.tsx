export const findingStatusOptions = [
  { value: "FAIL", label: "Failed" },
  { value: "PASS", label: "Passed" },
  { value: "UNKNOWN,MANUAL", label: "Needs review" },
  { value: "DENIED", label: "Access denied" },
  { value: "NOT_APPLICABLE,EMPTY", label: "Not applicable" },
] as const;

export function matchesFindingStatus(status: string, filter: string): boolean {
  return !filter || filter.split(",").includes(status.toUpperCase());
}

function presentation(status: string): { label: string; tone: string } {
  switch (status.toUpperCase()) {
    case "FAIL": return { label: "Failed", tone: "fail" };
    case "PASS": return { label: "Passed", tone: "pass" };
    case "UNKNOWN":
    case "MANUAL": return { label: "Needs review", tone: "review" };
    case "DENIED": return { label: "Access denied", tone: "access_denied" };
    case "NOT_APPLICABLE":
    case "EMPTY": return { label: "Not applicable", tone: "not_applicable" };
    default: return { label: status.replaceAll("_", " ").toLowerCase(), tone: "info" };
  }
}

export function FindingStatusBadge({ status }: { status: string }) {
  const { label, tone } = presentation(status);
  return <span className={`badge ${tone}`} title={`Recorded result: ${status.replaceAll("_", " ")}`}>
    {label}
  </span>;
}

export function findingStatusCounts(counts: Record<string, number>): { label: string; count: number; tone: string }[] {
  const grouped = new Map<string, { label: string; count: number; tone: string }>();
  for (const [status, count] of Object.entries(counts)) {
    if (count <= 0) continue;
    const { label, tone } = presentation(status);
    const current = grouped.get(label);
    if (current) current.count += count;
    else grouped.set(label, { label, count, tone });
  }
  const rank = (label: string) => {
    const index = findingStatusOptions.findIndex(option => option.label === label);
    return index < 0 ? findingStatusOptions.length : index;
  };
  return [...grouped.values()].sort((a, b) => rank(a.label) - rank(b.label));
}
