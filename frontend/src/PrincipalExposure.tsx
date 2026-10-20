import { Badge } from "./ui";

export type PrincipalExposure = {
  kind: string;
  state: "declared" | "conditional" | "unknown";
  caller?: string;
  classification?: string;
  issuer?: string;
  subject?: string;
  resource_id?: string;
  workload_resource?: string;
  endpoint_resource?: string;
  ports?: string[];
  public_addresses?: string[];
  conditions?: unknown;
  unresolved?: unknown[];
  limitations?: string[];
};
const labels: Record<string, string> = {
  external_assumption: "External account trust",
  external_impersonation: "External impersonation grant",
  external_identity: "External identity",
  federated_trust: "Federated identity trust",
  internet_workload: "Internet-facing workload",
};
export function ExposureBadges({ exposures = [] }: { exposures?: PrincipalExposure[] }) {
  return <>{[...new Set(exposures.map(e => e.kind))].map(kind => <span className="count-pill" key={kind}>{labels[kind] || kind}</span>)}</>;
}
export function ExposureDetails({ exposures = [], severity, baseSeverity }: {
  exposures?: PrincipalExposure[]; severity?: string; baseSeverity?: string;
}) {
  if (!exposures.length) return null;
  return <section aria-label="Principal exposure"><h3>Principal exposure</h3>
    {severity && <p><Badge value={severity} />{baseSeverity && severity !== baseSeverity && ` Raised from ${baseSeverity} due to the entry point below.`}</p>}
    {exposures.map((e, i) => <article key={i}>
      <h4>{labels[e.kind] || e.kind} · {e.state === "declared" ? "Declared path" : e.state === "conditional" ? "Conditional" : "Unresolved"}</h4>
      {e.caller && <p>Caller: <code>{e.caller}</code></p>}
      {e.classification && <p>Trust boundary: {e.classification.replaceAll("_", " ")}</p>}
      {e.issuer && <p>Issuer: {e.issuer}{e.subject && ` · Subject: ${e.subject}`}</p>}
      {e.ports?.length ? <p>Ports: {e.ports.join(", ")}</p> : null}
      {e.public_addresses?.length ? <p>Addresses: {e.public_addresses.join(", ")}</p> : null}
      {e.kind === "internet_workload" && <p>Application compromise is required to obtain this workload identity. Port exposure alone does not grant impersonation.</p>}
      {e.resource_id && <p>Evidence: <code>{e.resource_id}</code></p>}
      {e.endpoint_resource && e.endpoint_resource !== e.resource_id && <p>Endpoint: <code>{e.endpoint_resource}</code></p>}
      {e.conditions != null && <details><summary>Trust conditions</summary><pre>{JSON.stringify(e.conditions, null, 2)}</pre></details>}
      {!!e.unresolved?.length && <details><summary>Unresolved path evidence</summary><pre>{JSON.stringify(e.unresolved, null, 2)}</pre></details>}
      {e.limitations?.map((limit) => <p key={limit}>{limit}</p>)}
    </article>)}
  </section>;
}
