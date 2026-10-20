import "./AiReview.css";
import { useRef, useState } from "react";
import { ChevronRight, Search } from "lucide-react";
import { useApi } from "./api";
import { FindingStatusBadge, matchesFindingStatus } from "./findingStatus";
import { Badge, Evidence, Inspector, Panel, State } from "./ui";
import { Remediation } from "./Remediation";
import type { Finding } from "./types";
type Action = { rank: number; title: string; resource_ids: string[]; finding_ids: string[]; rationale: string; steps: string[]; verification: string };
type NetworkResult = { status: string; explanation: string; findings: (Finding & { verification?: string })[]; total?: number };
type Result = { network?: NetworkResult; actions: Action[] };

type NetworkFinding = NonNullable<NetworkResult["findings"]>[number];
const networkAsset = (row: NetworkFinding) => row.resource_name || row.native_resource_id || row.resource_id;
const networkSeverity = ["critical", "high", "medium", "low", "info"];
const NETWORK_PAGE_SIZE = 25;

function NetworkReviewPanel({ data }: { data: NetworkResult }) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [sort, setSort] = useState<{ field: "severity" | "title" | "service" | "resource" | "scope" | "status"; descending: boolean }>({ field: "severity", descending: false });
  const [selected, setSelected] = useState<NetworkFinding>();
  const trigger = useRef<HTMLButtonElement | null>(null);
  const term = search.trim().toLocaleLowerCase();
  const rows = data.findings.filter(row => (!severity || row.severity === severity) && matchesFindingStatus(row.status, status) &&
    [row.title, row.description, row.rationale, row.evidence_summary, row.resource_name, row.native_resource_id, row.resource_id,
      row.provider, row.scope, row.service, row.remediation, row.verification, JSON.stringify(row.evidence)].join(" ").toLocaleLowerCase().includes(term))
    .sort((a, b) => {
      const value = sort.field === "severity" ? networkSeverity.indexOf(a.severity) - networkSeverity.indexOf(b.severity) :
        (sort.field === "resource" ? networkAsset(a) : a[sort.field]).localeCompare(sort.field === "resource" ? networkAsset(b) : b[sort.field]);
      return (sort.descending ? -value : value) || a.title.localeCompare(b.title);
    });
  const currentPage = Math.min(page, Math.max(0, Math.ceil(rows.length / NETWORK_PAGE_SIZE) - 1));
  const offset = currentPage * NETWORK_PAGE_SIZE;
  function closeFinding() {
    setSelected(undefined);
    requestAnimationFrame(() => trigger.current?.focus());
  }
  const columns = [{ field: "severity", label: "Severity" }, { field: "title", label: "Finding" }, { field: "service", label: "Service" },
    { field: "resource", label: "Asset" }, { field: "scope", label: "Scope" }, { field: "status", label: "Status" }] as const;
  return <div className="ai-review-view">
    {data.explanation && <Panel title="Network architecture"><section className="network-architecture" aria-label="Network architecture">{data.explanation.split(/\n\s*\n/).filter(text => text.trim()).map((text, index) => <p key={index}>{text}</p>)}</section></Panel>}
    <Panel className="findings-panel network-findings-panel">
      {data.status === "unavailable" && <p>The network review could not be completed. Run a scan with AI enabled to retry it.</p>}
      <div className="filters">
        <div className="search-field"><Search size={17} /><input aria-label="Search network findings" placeholder="Search findings, assets or evidence…" value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /></div>
        <select aria-label="Network finding severity" value={severity} onChange={event => { setSeverity(event.target.value); setPage(0); }}><option value="">All severities</option>{networkSeverity.map(value => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}</select>
        <select aria-label="Network finding status" value={status} onChange={event => { setStatus(event.target.value); setPage(0); }}><option value="">All statuses</option><option value="FAIL">Failed</option><option value="UNKNOWN,MANUAL">Needs review</option></select>
        <button className="text-button" onClick={() => { setSearch(""); setSeverity(""); setStatus(""); setPage(0); }}>Reset filters</button>
        <span className="count-pill" aria-live="polite">{rows.length} / {data.findings.length} findings</span>
      </div>
      <div className="table-scroll" role="region" aria-label="Network findings table" tabIndex={0}>
        <table className="findings-table network-findings-table"><thead><tr>{columns.map(({ field, label }) => <th key={field} scope="col" aria-sort={sort.field === field ? sort.descending ? "descending" : "ascending" : "none"}><button className="text-button" onClick={() => { setSort({ field, descending: sort.field === field && !sort.descending }); setPage(0); }}>{label}</button></th>)}</tr></thead>
          <tbody>{rows.slice(offset, offset + NETWORK_PAGE_SIZE).map(row => <tr key={row.id}>
            <td><Badge value={row.severity} /></td>
            <td><button className="finding-title" aria-haspopup="dialog" onClick={event => { trigger.current = event.currentTarget; setSelected(row); }}>{row.title}</button><p className="network-finding-summary">{row.evidence_summary || (row.evidence as { summary?: string } | null)?.summary || row.description}</p></td>
            <td><span className="service-cell" title={row.service}>{row.service}</span></td>
            <td><div className="asset-cell"><span className="truncate" title={networkAsset(row)}>{networkAsset(row)}</span>{row.resource_name && row.native_resource_id && row.resource_name !== row.native_resource_id && <span className="native-asset-id" title={row.native_resource_id}>{row.native_resource_id}</span>}</div></td>
            <td><span className="network-finding-scope">{row.provider.toUpperCase()}<br />{row.scope}</span></td>
            <td><FindingStatusBadge status={row.status} /></td>
          </tr>)}
          {!rows.length && <tr><td colSpan={6} className="actions-empty">{data.findings.length ? "No network findings match your filters." : data.status === "completed" ? "No additional architecture or segmentation issues were identified." : "No network findings are available for this scan."}</td></tr>}
          </tbody>
        </table>
      </div>
      {rows.length > NETWORK_PAGE_SIZE && <div className="service-page-controls"><span>{offset + 1}–{Math.min(offset + NETWORK_PAGE_SIZE, rows.length)} of {rows.length} findings</span><button className="text-button" disabled={!currentPage} onClick={() => setPage(currentPage - 1)}>Previous page</button><button className="text-button" disabled={offset + NETWORK_PAGE_SIZE >= rows.length} onClick={() => setPage(currentPage + 1)}>Next page</button></div>}
    </Panel>
    {selected && <Inspector title={selected.title} onClose={closeFinding} className="network-finding-inspector">
      <div className="button-row"><Badge value={selected.severity} /><FindingStatusBadge status={selected.status} /></div>
      <h3>Affected resource</h3><p>{networkAsset(selected)}</p>{selected.resource_name && selected.native_resource_id && selected.resource_name !== selected.native_resource_id && <p>{selected.native_resource_id}</p>}<p>{selected.provider.toUpperCase()} · {selected.service} · {selected.scope}</p>
      <h3>Finding</h3><p>{selected.description}</p><h3>Why it matters</h3><p>{selected.rationale}</p>
      <h3>Evidence</h3><Evidence data={Object.fromEntries(Object.entries(selected.evidence || {}).filter(([key]) => key !== "limitations"))} />
      <h3>Remediation</h3><Remediation legacy={selected.remediation} details={selected.remediation_details} />
      {selected.verification && <><h3>Verification</h3><p>{selected.verification}</p></>}
    </Inspector>}
  </div>;
}

export function NetworkAiReview({ scanId, demo }: { scanId: string; demo: boolean }) {
  // The agent contract caps Network findings at 100. Load the complete set so
  // search, sorting and filters cover every finding rather than one API page.
  const query = useApi<Result>(`/scans/${encodeURIComponent(scanId)}/ai?offset=0&limit=100`, demo, !!scanId && !demo);
  if (demo) return null;
  if (!scanId) return <Panel title="Network findings"><p>Select a completed scan.</p></Panel>;
  if (query.isPending || query.error) return <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data?.network) return <Panel title="Network findings"><p>No network review is available for this scan. Run a scan with AI enabled to generate network findings.</p></Panel>;
  return <NetworkReviewPanel key={scanId} data={query.data.network} />;
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
