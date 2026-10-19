import { useState } from "react";
import type { RemediationDetails } from "./types";
import { EvidenceFields } from "./ui";
import "./Remediation.css";

type Props = { legacy: unknown; details?: RemediationDetails; compact?: boolean };

function safeReference(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}
function structuredExample(value: string): unknown | null {
  const trimmed = value.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}
function ExampleBody({ code, className }: { code: string; className?: string }) {
  const structured = structuredExample(code);
  if (structured) return <EvidenceFields data={structured} />;
  if (/^[\[{]/.test(code.trim()))
    return <p className="muted">The structured example could not be parsed for display. Use the copy control to review its original text.</p>;
  return <pre className={className}><code>{code}</code></pre>;
}

export function Remediation({ legacy, details, compact = false }: Props) {
  const [copied, setCopied] = useState<number | null>(null);
  const summary = details?.summary || (typeof legacy === "string" ? legacy : "");
  if (!summary) return <p>No remediation guidance is available for this finding.</p>;
  const commands = details?.cli?.length ? <>
    {!compact && <h4>Command examples</h4>}
    <p className="remediation-note">Inspect the named resource and review each change before running a command. Replace any remaining placeholders.</p>
    {details.cli.map((command, index) => (
      <div className="remediation-command" key={`${command.label}-${index}`}>
        <div className="remediation-command-heading">
          <span>{command.label}</span>
          <button type="button" className="button" aria-label={`Copy ${command.label} command`} onClick={() => {
            void navigator.clipboard.writeText(command.code).then(() => setCopied(index)).catch(() => setCopied(null));
          }}>{copied === index ? "Copied" : "Copy"}</button>
        </div>
        <ExampleBody code={command.code} />
      </div>
    ))}
  </> : null;
  const extra = details?.iac || details?.caveats?.length ? <>
    {details?.iac ? <>
      <h4>Infrastructure as code</h4>
      {typeof details.iac === "string" ? <p>{details.iac}</p> : <>
        <div className="remediation-command-heading">
          <span>{details.iac.label}</span>
          <button type="button" className="button" aria-label="Copy infrastructure as code guidance" onClick={() => {
            void navigator.clipboard.writeText(details.iac && typeof details.iac !== "string" ? details.iac.code : "").then(() => setCopied(-1)).catch(() => setCopied(null));
          }}>{copied === -1 ? "Copied" : "Copy"}</button>
        </div>
        <ExampleBody code={details.iac.code} className="remediation-iac" />
      </>}
    </> : null}
    {details?.caveats?.length ? <><h4>Change considerations</h4><ul>{details.caveats.map((item, index) => <li key={index}>{item}</li>)}</ul></> : null}
  </> : null;
  return (
    <section className="remediation" aria-label="Defensive remediation guidance">
      {!compact && !!details?.steps?.length && <p className="remediation-summary">{summary}</p>}
      <ul className="remediation-actions">{(details?.steps?.length ? details.steps : [summary]).map((step, index) => <li key={index}>{step}</li>)}</ul>
      {compact ? <>
        {commands && <details className="remediation-expand"><summary>Commands ({details?.cli?.length})</summary><div>{commands}{extra}</div></details>}
        {!commands && details?.iac && <details className="remediation-expand"><summary>Configuration example</summary><div>{extra}</div></details>}
      </> : <>{commands}{extra}</>}
      {details?.references?.some(({ url }) => safeReference(url)) ? <>
        <h4>References</h4>
        <ul className="remediation-references">{details.references.filter(({ url }) => safeReference(url)).map(({ title, url }) => <li key={url}><a href={url} target="_blank" rel="noopener noreferrer">{title}</a></li>)}</ul>
      </> : null}
    </section>
  );
}
