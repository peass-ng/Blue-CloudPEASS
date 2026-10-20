import { useState } from "react";
import { ChevronRight, Search, ShieldCheck } from "lucide-react";
import { useApi } from "./api";
import { Inspector, Panel, ProviderIcon, State } from "./ui";
import "./LeastPrivilege.css";
import { ExposureBadges, ExposureDetails, type PrincipalExposure } from "./PrincipalExposure";
import { Badge } from "./ui";

type Suggestion = {
  kind: "permission" | "service" | "role" | "role_review";
  value: string;
  scope: string;
  source: string;
  evidence_id?: string;
  replacement?: string[];
  last_accessed?: string;
  last_refreshed?: string;
  confidence: "provider_recommendation" | "declared_grant_only";
};
type Principal = {
  id: string;
  principal: string;
  label?: string;
  scopes: string[];
  provider: string;
  recommendation_count: number;
  severity?: string;
  base_severity?: string;
  exposures?: PrincipalExposure[];
  suggestions: Suggestion[];
};
type Page = {
  items: Principal[];
  total: number;
  next_offset: number | null;
  coverage: { limitations: string[]; unused_access_analyzers?: number };
};

export function LeastPrivilege({ scanId, demo }: { scanId: string; demo: boolean }) {
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [exposure, setExposure] = useState("");
  const [selected, setSelected] = useState<Principal>();
  const page = useApi<Page>(`/scans/${encodeURIComponent(scanId)}/least-privilege?search=${encodeURIComponent(search)}${exposure ? `&exposure=${exposure}` : ""}&offset=${offset}&limit=100`, demo, !!scanId);
  const rows = page.data?.items || [];
  return <div className="least-page">
    <div className="section-top">
      <p>Review excess access by identity. Each suggestion links to evidence collected in this assessment.</p>
      <span className="count-pill">{page.data?.total ?? 0} principals</span>
    </div>
    <Panel className="least-panel">
      <div className="least-toolbar">
        <label className="search-field">
          <Search size={17} />
          <input aria-label="Search principals" value={search} placeholder="Search principal or scope…"
            onChange={(event) => { setSearch(event.target.value); setOffset(0); }} />
        </label>
        <select aria-label="Principal exposure filter" value={exposure} onChange={event => { setExposure(event.target.value); setOffset(0); }}>
          <option value="">All entry points</option>
          <option value="external">External accounts or identities</option>
          <option value="federated">Federated identity trust</option>
          <option value="internet">Internet-facing workload</option>
          <option value="unresolved">Unresolved exposure</option>
        </select>
      </div>
      {!scanId ? <State empty title="Select a scan to review identities" /> :
        <State loading={page.isPending} error={page.error} onRetry={() => void page.refetch()}>
          {rows.length ? <div className="least-list" role="list" aria-label="Principals with access to review">
            {rows.map((principal) => <button type="button" role="listitem" className="least-row" key={principal.id}
              onClick={() => setSelected(principal)}>
              <span className="least-provider"><ProviderIcon provider={principal.provider} size={22} /></span>
              <span className="least-identity"><strong>{principal.label || principal.principal.split("/").pop() || principal.principal}</strong><small>{principal.principal} · {principal.scopes.length} scope{principal.scopes.length === 1 ? "" : "s"}</small></span>
              <span className={`least-row-count${principal.recommendation_count ? " recommended" : ""}`}>{principal.recommendation_count
                ? `${principal.recommendation_count} suggested changes`
                : principal.suggestions.length ? `${principal.suggestions.length} grants to review` : "Exposure to review"}</span>
              <ExposureBadges exposures={principal.exposures} />
              {principal.severity && <Badge value={principal.severity} />}
              <ChevronRight size={18} aria-hidden="true" />
            </button>)}
          </div> : <div className="least-empty"><ShieldCheck size={24} /><h3>No principal suggestions in this scan</h3>
            <p>{search ? "Try another principal or scope." : "This does not establish that all grants are necessary. Review the evidence coverage below."}</p></div>}
          {page.data && page.data.total > 100 && <div className="least-pagination">
            <button className="button" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</button>
            <span>{offset + 1}–{Math.min(offset + 100, page.data.total)} of {page.data.total}</span>
            <button className="button" type="button" disabled={page.data.next_offset == null} onClick={() => setOffset(page.data!.next_offset!)}>Next</button>
          </div>}
        </State>}
    </Panel>
    {page.data?.coverage && <div className="least-coverage"><strong>Evidence boundaries</strong>
      {page.data.coverage.limitations.map((item) => <p key={item}>{item}</p>)}
      {page.data.coverage.unused_access_analyzers === 0 && <p>No active unused access analyzer was observed in the scan.</p>}
    </div>}
    {selected && <Inspector title="Principal access review" onClose={() => setSelected(undefined)} className="least-inspector">
      <div className="least-detail">
        <h2>{selected.label || selected.principal}</h2>
        <p>{selected.label && selected.label !== selected.principal ? `${selected.principal} · ` : ""}{selected.scopes.join(" · ")}</p>
        <ExposureDetails exposures={selected.exposures} severity={selected.severity} baseSeverity={selected.base_severity} />
        <h3>{selected.recommendation_count ? "Suggested changes" : "Grants to review"}</h3>
        <div className="least-suggestions">{selected.suggestions.map((item, index) => <article key={`${item.scope}-${item.value}-${index}`}>
          <span className="least-source">{item.source}</span>
          <h4>{item.kind === "permission" ? `Review removing ${item.value}`
            : item.kind === "service" ? `Review ${item.value} service access`
              : item.kind === "role" ? `Remove or replace ${item.value}` : `Review broad ${item.value} assignment`}</h4>
          {item.replacement?.length ? <p>Suggested replacement: {item.replacement.join(", ")}</p> : null}
          {item.confidence === "declared_grant_only" && <p>Usage was not established. Validate the role with its owner before proposing removal.</p>}
          <dl><dt>Scope</dt><dd>{item.scope}</dd>
            {item.last_accessed && <><dt>Last accessed</dt><dd>{item.last_accessed}</dd></>}
            {item.last_refreshed && <><dt>Recommendation refreshed</dt><dd>{item.last_refreshed}</dd></>}
            {item.evidence_id && <><dt>Evidence ID</dt><dd>{item.evidence_id}</dd></>}</dl>
        </article>)}</div>
        <p className="least-caution">Confirm business need, inherited grants and the workload's usage window before changing access. This view does not modify permissions.</p>
      </div>
    </Inspector>}
  </div>;
}
