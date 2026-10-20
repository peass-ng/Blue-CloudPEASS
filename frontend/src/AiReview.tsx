import "./AiReview.css";
import { useRef, useState } from "react";
import { ChevronRight, Search } from "lucide-react";
import { useApi } from "./api";
import { FindingStatusBadge } from "./findingStatus";
import { Evidence, Inspector, Panel, State } from "./ui";
import type { Finding } from "./types";
type Action = { rank: number; title: string; resource_ids: string[]; finding_ids: string[]; rationale: string; steps: string[]; verification: string };
type NetworkResult = { status: string; explanation: string; findings: (Finding & { verification?: string })[]; total?: number };
type Result = { network?: NetworkResult; actions: Action[] };

function NetworkReviewPanel({ data, offset, setOffset }: { data?: NetworkResult; offset: number; setOffset: (offset: number) => void }) {
  if (!data) return null;
  const total = data.total ?? data.findings.length;
  return <Panel title="Network findings" kicker="AI REVIEW">
    {data.explanation && <section className="network-architecture" aria-label="Network architecture">{data.explanation.split(/\n\s*\n/).filter(text => text.trim()).map((text, index) => <p key={index}>{text}</p>)}</section>}
    {data.status === "unavailable" && <p>The network review could not be completed. Run a scan with AI enabled to retry it.</p>}
    {total > 50 && <div className="button-row"><button className="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous network findings</button><span>{offset + 1}–{Math.min(offset + 50, total)} of {total}</span><button className="button" disabled={offset + 50 >= total} onClick={() => setOffset(offset + 50)}>Next network findings</button></div>}
    {!total && data.status === 'completed' && <p>No additional architecture or segmentation issues were identified.</p>}
    {data.findings.map(row => <details key={row.id}><summary>{row.title} · {row.severity} · <FindingStatusBadge status={row.status} /></summary>
      <p>{row.description}</p><p>{row.rationale}</p><p>Resource: {row.native_resource_id || row.resource_id} · {row.scope}</p>
      <Evidence data={Object.fromEntries(Object.entries(row.evidence || {}).filter(([key]) => key !== "limitations"))} /><h4>Mitigation</h4><p>{String(row.remediation)}</p>{row.verification && <><h4>Verification</h4><p>{row.verification}</p></>}
    </details>)}
  </Panel>;
}

export function NetworkAiReview({ scanId, demo }: { scanId: string; demo: boolean }) {
  const [offset, setOffset] = useState(0);
  const query = useApi<Result>(`/scans/${encodeURIComponent(scanId)}/ai?offset=${offset}&limit=50`, demo, !!scanId && !demo);
  if (demo) return null;
  if (!scanId) return <Panel title="Network findings"><p>Select a completed scan.</p></Panel>;
  if (query.isPending || query.error) return <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data?.network) return <Panel title="Network findings"><p>No network review is available for this scan. Run a scan with AI enabled to generate network findings.</p></Panel>;
  return <NetworkReviewPanel data={query.data?.network} offset={offset} setOffset={setOffset} />;
}
export function AiReview({ scanId, demo }: { scanId: string; demo: boolean }) {
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Action>();
  const trigger = useRef<HTMLButtonElement | null>(null);
  function openPlan(action: Action, button: HTMLButtonElement) {
    trigger.current = button;
    setSelected(action);
  }
  function closePlan() {
    setSelected(undefined);
    requestAnimationFrame(() => trigger.current?.focus());
  }
  const query = useApi<Result>(`/scans/${encodeURIComponent(scanId)}/ai?offset=0&limit=50`, demo, !!scanId && !demo);
  if (demo) return <Panel title="AI review"><p>AI reviews are available for live scans.</p></Panel>;
  if (!scanId) return <Panel title="AI review"><p>Select a completed scan.</p></Panel>;
  if (query.isPending || query.error) return <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />;
  const data = query.data;
  if (!data) return null;
  const term = search.trim().toLocaleLowerCase();
  const actions = [...data.actions].sort((a, b) => a.rank - b.rank).filter(action =>
    [action.title, action.rationale, ...action.resource_ids, ...action.finding_ids,
      ...action.steps, action.verification].join(" ").toLocaleLowerCase().includes(term));
  return <div className="ai-review-view">
    <Panel className="findings-panel actions-panel">
      <div className="filters">
        <div className="search-field"><Search size={17} />
          <input aria-label="Search actions" value={search} onChange={event => setSearch(event.target.value)} placeholder="Search actions, resources or findings…" />
        </div>
        {search && <button className="text-button" onClick={() => setSearch("")}>Clear search</button>}
        <span className="count-pill" aria-live="polite">{term ? `${actions.length} / ${data.actions.length}` : data.actions.length} actions</span>
      </div>
      <div className="table-scroll" role="region" aria-label="Prioritized actions" tabIndex={0}>
        <table className="findings-table actions-table"><thead><tr><th scope="col">Action</th><th scope="col">Reason & benefit</th><th scope="col">Plan</th></tr></thead>
          <tbody>{actions.map(action => <tr key={action.rank}>
            <td><button className="finding-title action-title" aria-haspopup="dialog" title={action.title} onClick={event => openPlan(action, event.currentTarget)}>{action.title}</button></td>
            <td><p className="action-summary">{action.rationale}</p></td>
            <td><button className="text-button action-open" aria-label={`Review plan: ${action.title}`} aria-haspopup="dialog" onClick={event => openPlan(action, event.currentTarget)}>View plan <ChevronRight size={15} aria-hidden="true" /></button></td>
          </tr>)}
          {!actions.length && <tr><td colSpan={3} className="actions-empty">{term ? "No actions match your search." : "No recommended actions are available for this scan."}</td></tr>}
          </tbody>
        </table>
      </div>
    </Panel>
    {selected && <Inspector title={selected.title} onClose={closePlan} className="action-inspector">
      <h3>Reason & benefit</h3><p>{selected.rationale}</p>
      <h3>Implementation plan</h3><ol className="action-steps">{selected.steps.map((step, index) => <li key={index}>{step}</li>)}</ol>
      <h3>Verification</h3><p>{selected.verification}</p>
      <details className="action-references"><summary>Supporting evidence</summary>
        <h3>Resources</h3>{selected.resource_ids.length ? <ul>{selected.resource_ids.map(id => <li key={id}><code>{id}</code></li>)}</ul> : <p>Account-wide</p>}
        <h3>Findings</h3>{selected.finding_ids.length ? <ul>{selected.finding_ids.map(id => <li key={id}><code>{id}</code></li>)}</ul> : <p>Graph evidence</p>}
      </details>
    </Inspector>}
  </div>;
}
