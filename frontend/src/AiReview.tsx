import "./AiReview.css";
import { useState } from "react";
import { useApi } from "./api";
import { FindingStatusBadge } from "./findingStatus";
import { Evidence, Panel, State } from "./ui";
import type { Finding } from "./types";
type Action = { rank: number; title: string; resource_ids: string[]; finding_ids: string[]; rationale: string; steps: string[]; verification: string };
type NetworkResult = { status: string; explanation: string; findings: (Finding & { verification?: string })[]; limitations?: string[]; total?: number };
type Result = { network?: NetworkResult; actions: Action[] };

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
  const query = useApi<Result>(`/scans/${encodeURIComponent(scanId)}/ai?offset=0&limit=50`, demo, !!scanId && !demo);
  if (demo) return <Panel title="AI review"><p>AI reviews are available for live scans.</p></Panel>;
  if (!scanId) return <Panel title="AI review"><p>Select a completed scan.</p></Panel>;
  if (query.isPending || query.error) return <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />;
  const data = query.data;
  if (!data) return null;
  return <div className="ai-review-view">
    <Panel title="Top 15 Actions" kicker="AI REVIEW">
      {!!data.actions.length && <div className="table-scroll"><table><thead><tr><th>Action</th><th>Reason & benefit</th><th>Plan</th></tr></thead><tbody>{data.actions.map(action => <tr key={action.rank}>
        <td>{action.title}</td><td>{action.rationale}</td><td><details><summary>Review plan</summary><p>Resources: {action.resource_ids.join(", ") || "Account-wide"}</p><p>Findings: {action.finding_ids.join(", ") || "Graph evidence"}</p><ol>{action.steps.map((step, i) => <li key={i}>{step}</li>)}</ol><p>Verify: {action.verification}</p></details></td>
      </tr>)}</tbody></table></div>}
    </Panel>
  </div>;
}
