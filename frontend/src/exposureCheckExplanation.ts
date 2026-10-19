/** Explain the particular access layers recorded for one asset. */
export function explainExposureCheck(evidence: unknown): string {
  const item = evidence && typeof evidence === "object" && !Array.isArray(evidence)
    ? evidence as Record<string, unknown> : {};
  const source = item.source && typeof item.source === "object" && !Array.isArray(item.source)
    ? item.source as Record<string, unknown> : {};
  if (item.exposure_kind === "external_share" || String(source.resource_type || "").includes("snapshot"))
    return "Checks the snapshot’s restore or sharing attributes for public access or grants to other accounts.";
  const names: Record<string, string> = {
    route: "routes", nacl: "network ACLs", security_group: "security groups",
    nsg: "network security groups", firewall: "firewall rules", listener: "listeners",
    policy: "resource policies", authorization: "route authorization", invoker: "invoker permissions",
    cloud_armor: "Cloud Armor rules", access_restrictions: "access restrictions",
    attributes: "sharing attributes", backend: "backend configuration",
  };
  const path = Array.isArray(item.path) ? item.path : [];
  const layers = [...new Set(path.flatMap((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
    const layer = (entry as Record<string, unknown>).layer;
    return typeof layer === "string" && Object.hasOwn(names, layer) ? [names[layer]] : [];
  }))];
  if (layers.length) {
    const shown = layers.slice(0, 4);
    if (layers.length > 4) shown.push("other access layers");
    const list = shown.length === 1 ? shown[0] : `${shown.slice(0, -1).join(", ")} and ${shown.at(-1)}`;
    return `Checks the collected ${list} for an allowed Internet path. No traffic is sent.`;
  }
  return "Evaluates this asset’s collected access configuration for a public path. Missing required layers keep the result undetermined.";
}
