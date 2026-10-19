import "./AiReview.css";
import { useState } from "react";
import { useApi } from "./api";
import { FindingStatusBadge } from "./findingStatus";
import { Evidence, Panel, State } from "./ui";
import type { Finding } from "./types";
type Review = { finding_id: string; verdict: string; reason: string };
type Action = { rank: number; title: string; resource_ids: string[]; finding_ids: string[]; rationale: string; steps: string[]; verification: string };
type NetworkResult = { status: string; explanation: string; findings: (Finding & { verification?: string })[]; limitations?: string[]; total?: number };
type Result = { network?: NetworkResult; review_totals?: Record<string, number>; status: string; reason?: string; actions: Action[]; reviews: { hardening?: Review[]; exposure?: Review[] }; limitations?: string[]; coverage?: { reviewed: number; total: number }; auth_source?: string };

function NetworkReviewPanel({ data, offset, setOffset }: { data?: NetworkResult; offset: number; setOffset: (offset: number) => void }) {
  if (!data) return null;
  const total = data.total ?? data.findings.length;
  return <Panel title="Network findings" kicker="AI REVIEW">
    {data.explanation && <p>{data.explanation}</p>}
    {data.limitations?.map((text, index) => <p className="muted small" key={index}>{text}</p>)}
    <p className="muted small">AI suggestions · {data.status.replaceAll("_", " ")} · {total} findings. Validate workload dependencies before changing connectivity.</p>
    {total > 50 && <div className="button-row"><button className="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous network findings</button><span>{offset + 1}–{Math.min(offset + 50, total)} of {total}</span><button className="button" disabled={offset + 50 >= total} onClick={() => setOffset(offset + 50)}>Next network findings</button></div>}
    {!total && <p>No network findings were generated.</p>}
    {data.findings.map(row => <details key={row.id}><summary>{row.title} · {row.severity} · <FindingStatusBadge status={row.status} /></summary>
      <p>{row.description}</p><p>{row.rationale}</p><p>Resource: {row.native_resource_id || row.resource_id} · {row.scope}</p>
      <Evidence data={row.evidence} /><h4>Mitigation</h4><p>{String(row.remediation)}</p>{row.verification && <><h4>Verification</h4><p>{row.verification}</p></>}
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
  const [offset, setOffset] = useState(0);
  const query = useApi<Result>(`/scans/${encodeURIComponent(scanId)}/ai?offset=${offset}&limit=50`, demo, !!scanId && !demo);
  if (demo) return <Panel title="AI review"><p>AI reviews are available for live scans.</p></Panel>;
  if (!scanId) return <Panel title="AI review"><p>Select a completed scan.</p></Panel>;
  if (query.isPending || query.error) return <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />;
  const data = query.data;
  if (!data) return null;
  const total = Math.max(...Object.values(data.review_totals || {}), 0);
  return <div className="ai-review-view">
    <Panel title="Top 15 Recommended Actions" kicker="AI REVIEW">
      <p>Status: {data.status.replaceAll("_", " ")}{data.auth_source ? ` · ${data.auth_source} Codex account` : ""}. {data.coverage && `${data.coverage.reviewed} of ${data.coverage.total} failed findings reached a conclusion.`}</p>
      {data.reason && <p>{data.reason.replaceAll("_", " ")}</p>}
      {data.limitations?.map((text, i) => <p className="muted small" key={i}>{text}</p>)}
      <p className="muted small">Review recommendations before applying them. AI reviews are recorded alongside the original scanner findings.</p>
      {!!data.actions.length && <div className="table-scroll"><table><thead><tr><th>Order</th><th>Action</th><th>Reason & benefit</th><th>Plan</th></tr></thead><tbody>{data.actions.map(action => <tr key={action.rank}>
        <td>{action.rank}</td><td>{action.title}</td><td>{action.rationale}</td><td><details><summary>Review plan</summary><p>Resources: {action.resource_ids.join(", ") || "Account-wide"}</p><p>Findings: {action.finding_ids.join(", ") || "Graph evidence"}</p><ol>{action.steps.map((step, i) => <li key={i}>{step}</li>)}</ol><p>Verify: {action.verification}</p></details></td>
      </tr>)}</tbody></table></div>}
    </Panel>
    {total > 50 && <div className="button-row"><button className="button" disabled={offset === 0} onClick={() => setOffset(value => Math.max(0, value - 50))}>Previous reviews</button><span>Reviews {offset + 1}–{Math.min(offset + 50, total)} of {total}</span><button className="button" disabled={offset + 50 >= total} onClick={() => setOffset(value => value + 50)}>Next reviews</button></div>}
    {(["hardening", "exposure"] as const).map(kind => <Panel title={`${kind === "hardening" ? "Hardening" : "Exposure"} verification`} key={kind}>
      {!data.reviews[kind]?.length ? <p>{data.review_totals?.[kind] ? "No reviews on this page." : "No failed findings were reviewed in this category."}</p> : <div className="table-scroll"><table><thead><tr><th>Finding</th><th>AI verdict</th><th>Reason</th></tr></thead><tbody>{data.reviews[kind]?.map(row => <tr key={row.finding_id}><td>{row.finding_id}</td><td><FindingStatusBadge status={row.verdict} /></td><td>{row.reason}</td></tr>)}</tbody></table></div>}
    </Panel>)}
  </div>;
}
