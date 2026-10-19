import type { Connector, Scan } from "./types";

function scanDate(scan: Scan): Date | undefined {
  const value = new Date(scan.created_at);
  return Number.isNaN(value.getTime()) ? undefined : value;
}

function fallbackName(scan: Scan, connector?: Connector): string {
  const date = scanDate(scan)?.toISOString().slice(0, 10).split("-").reverse();
  const day = date ? `${date[0]}.${date[1]}.${date[2].slice(-2)}` : "undated";
  return `${scan.connector_name || connector?.name || "Assessment"} · ${day}`;
}

export function scanNames(scans: Scan[], connectors: Connector[]): Map<string, string> {
  const byConnector = new Map(connectors.map(connector => [connector.id, connector]));
  const base = new Map(scans.map(scan => [scan.id,
    (scan.connector_name || byConnector.has(scan.connector_id))
      ? fallbackName(scan, byConnector.get(scan.connector_id))
      : scan.display_name || fallbackName(scan),
  ]));
  const counts = new Map<string, number>();
  for (const name of base.values()) counts.set(name, (counts.get(name) || 0) + 1);
  const result = new Map<string, string>();
  for (const scan of scans) {
    const name = base.get(scan.id)!;
    const time = scanDate(scan)?.toISOString().slice(11, 19);
    result.set(scan.id, (counts.get(name) || 0) > 1 && time ? `${name} · ${time} UTC` : name);
  }
  // Concurrent scans can share a timestamp too. Keep labels distinct without IDs.
  const groups = new Map<string, Scan[]>();
  for (const scan of scans) {
    const name = result.get(scan.id)!;
    const group = groups.get(name);
    if (group) group.push(scan);
    else groups.set(name, [scan]);
  }
  for (const [name, group] of groups) if (group.length > 1) {
    group.sort((a, b) => a.id.localeCompare(b.id)).forEach((scan, index) => result.set(scan.id, `${name} (${index + 1})`));
  }
  return result;
}
