import { Badge } from "./ui";
import { Globe, KeyRound, ArrowUpRight } from "lucide-react";
import "./PrincipalExposure.css";

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
  resource_label?: string;
  workload_resource_label?: string;
  endpoint_resource_label?: string;
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
  const readable = (label?: string, id?: string) => { const value = label || id; return value && !value.startsWith("sha256:") ? value : undefined; };
  return <section className="principal-exposure-cards" aria-label="Principal exposure"><div className="principal-exposure-heading"><h3>Identity entry points</h3>
    {severity && <p><Badge value={severity} />{baseSeverity && severity !== baseSeverity && <span>Raised from {baseSeverity} due to the entry point below.</span>}</p>}</div>
    {exposures.map((e, i) => <article className={`principal-entry entry-${e.state}`} key={i}>
      <div className="principal-entry-title"><span className="principal-entry-icon">{e.kind === "internet_workload" ? <Globe size={19} /> : <KeyRound size={19} />}</span>
        <h4>{labels[e.kind] || e.kind}</h4><span className="principal-entry-state">{e.state === "declared" ? "Declared path" : e.state === "conditional" ? "Conditional" : "Unresolved"}</span></div>
      <dl>{e.caller && <><dt>External principal</dt><dd><code>{e.caller}</code></dd></>}
        {e.classification && <><dt>Trust boundary</dt><dd>{e.classification.replaceAll("_", " ")}</dd></>}
        {e.issuer && <><dt>Identity provider</dt><dd>{e.issuer}{e.subject && <small>Subject: {e.subject}</small>}</dd></>}
        {readable(e.workload_resource_label || e.resource_label, e.workload_resource || e.resource_id) && <><dt>Workload / resource</dt><dd>{readable(e.workload_resource_label || e.resource_label, e.workload_resource || e.resource_id)}</dd></>}
        {readable(e.endpoint_resource_label, e.endpoint_resource) && <><dt>Public endpoint</dt><dd>{readable(e.endpoint_resource_label, e.endpoint_resource)}</dd></>}
        {!!e.ports?.length && <><dt>Exposed ports</dt><dd className="principal-entry-ports">{e.ports.map(port => <span key={port}>{port}</span>)}</dd></>}
        {!!e.public_addresses?.length && <><dt>Public addresses</dt><dd>{e.public_addresses.join(", ")}</dd></>}
      </dl>
      {e.kind === "internet_workload" && <p className="principal-entry-impact"><ArrowUpRight size={15} />Application compromise is required to obtain this workload identity.</p>}
      {e.conditions != null && <details><summary>Trust conditions</summary><pre>{JSON.stringify(e.conditions, null, 2)}</pre></details>}
      {!!e.unresolved?.length && <details><summary>Missing path information</summary>{e.unresolved.map((item, index) => {
        const value = item as { layer?: string; reason?: string };
        return value?.reason ? <p key={index}>{value.layer && `${value.layer}: `}{value.reason}</p> : null;
      })}</details>}
    </article>)}
  </section>;
}
