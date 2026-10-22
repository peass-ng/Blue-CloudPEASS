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
type RiskPermission = {
  permission: string; severity: string; source: string; scope: string; resources: string[];
  conditions?: unknown; exclusions?: string[]; last_accessed?: string; usage_basis?: "permission" | "service"; days_since_last_access?: number;
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
  high_risk_permissions?: RiskPermission[];
  permission_definitions_missing?: string[];
  observed_at?: string;
  identity_last_used?: string;
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
  const [sort, setSort] = useState("severity:desc");
  const [permissionSearch, setPermissionSearch] = useState("");
  const [selected, setSelected] = useState<Principal>();
  const page = useApi<Page>(`/scans/${encodeURIComponent(scanId)}/least-privilege?search=${encodeURIComponent(search)}${exposure ? `&exposure=${exposure}` : ""}&sort_by=${sort.split(":")[0]}&sort_order=${sort.split(":")[1]}&offset=${offset}&limit=100`, demo, !!scanId);
  const details = useApi<Principal>(`/scans/${encodeURIComponent(scanId)}/least-privilege/principals/${encodeURIComponent(selected?.id || "")}`, demo, !!scanId && !!selected);
  const detail = selected ? (details.data?.id === selected.id ? { ...selected, ...details.data } : selected) : undefined;
  const permissions = detail?.high_risk_permissions || [];
  const visiblePermissions = permissions.filter(item => [item.permission, item.source, item.scope, ...item.resources].join(" ").toLowerCase().includes(permissionSearch.trim().toLowerCase()));
  const rows = page.data?.items || [];
  return <div className="least-page">
    <div className="section-top">
      <p>Review high-impact permissions, usage history and identity entry points.</p>
      <span className="count-pill">{page.data?.total ?? 0} principals</span>
    </div>
    <Panel className="least-panel">
      <div className="least-toolbar">
        <label className="search-field">
          <Search size={17} />
          <input aria-label="Search principals" value={search} placeholder="Search principal or scope…"
            onChange={(event) => { setSearch(event.target.value); setOffset(0); }} />
        </label>
        <select aria-label="Sort principals" value={sort} onChange={event => { setSort(event.target.value); setOffset(0); }}>
          <option value="severity:desc">Criticality: highest first</option><option value="severity:asc">Criticality: lowest first</option>
          <option value="principal:asc">Principal: A–Z</option><option value="principal:desc">Principal: Z–A</option>
          <option value="recommendations:desc">Most suggested changes</option>
        </select>
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
          {rows.length ? <div className="least-list table-scroll" tabIndex={0} role="list" aria-label="Principals with access to review">
            {rows.map((principal) => <button type="button" role="listitem" className="least-row" key={principal.id}
              onClick={() => { setSelected(principal); setPermissionSearch(""); }}>
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
            <p>{search ? "Try another principal or scope." : "No principal suggestions were recorded for this selection."}</p></div>}
          {page.data && page.data.total > 100 && <div className="least-pagination">
            <button className="button" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</button>
            <span>{offset + 1}–{Math.min(offset + 100, page.data.total)} of {page.data.total}</span>
            <button className="button" type="button" disabled={page.data.next_offset == null} onClick={() => setOffset(page.data!.next_offset!)}>Next</button>
          </div>}
        </State>}
    </Panel>
    {detail && <Inspector title="Principal access review" onClose={() => setSelected(undefined)} className="least-inspector">
      <div className="least-detail">
        <div className="least-detail-identity"><div><span className="least-eyebrow">IDENTITY ACCESS</span><h2>{detail.label || detail.principal}</h2>
          <p>{detail.principal}</p></div>{detail.severity && <Badge value={detail.severity} />}</div>
        <div className="least-detail-stats"><span><strong>{details.isPending ? "…" : details.error ? "—" : permissions.length}</strong> high / critical grants</span><span><strong>{permissions.filter(p => p.severity === "critical").length}</strong> critical</span><span><strong>{detail.exposures?.length || 0}</strong> entry points</span></div>
        <ExposureDetails exposures={detail.exposures} severity={detail.severity} baseSeverity={detail.base_severity} />
        <section className="least-permissions" aria-label="High and critical permissions">
          <h3>High & critical permissions</h3>
          <p>Declared permissions, including collected policy attachments and inherited role or group grants.</p>
          {details.isPending ? <p role="status">Loading permission details…</p> : details.error ? <State error={details.error} onRetry={() => void details.refetch()} /> : <>
            <label className="search-field"><Search size={16} /><input aria-label="Filter high-risk permissions" placeholder="Filter permissions, policies or scopes…" value={permissionSearch} onChange={event => setPermissionSearch(event.target.value)} /></label>
            <div className="least-permissions-scroll"><table className="least-permissions-table"><thead><tr><th>Permission & granting policy</th><th>Criticality</th><th>Applies to</th><th>Last use</th></tr></thead><tbody>
              {visiblePermissions.map((item, index) => <tr key={`${item.permission}-${item.scope}-${index}`}>
                <td><code>{item.permission}</code><small>{item.source}</small>{item.conditions != null && <details><summary>Grant conditions</summary><pre>{JSON.stringify(item.conditions, null, 2)}</pre></details>}
                  {!!item.exclusions?.length && <details><summary>Exclusions</summary><p>{item.exclusions.join(", ")}</p></details>}</td>
                <td><Badge value={item.severity} /></td><td><span>{item.scope}</span>{item.resources.map(resource => <small key={resource}>{resource}</small>)}</td>
                <td>{item.days_since_last_access != null ? <div className={`least-usage ${item.days_since_last_access > 90 ? "stale" : "recent"}`}>
                  <strong>{item.days_since_last_access} {item.days_since_last_access === 1 ? "day" : "days"} ago</strong><small>{item.usage_basis === "service" ? "Service activity · action usage unknown" : "Permission last used"}</small><time dateTime={item.last_accessed}>{item.last_accessed}</time>
                </div> : <span className="least-usage unknown">Usage not available</span>}</td>
              </tr>)}
              {!visiblePermissions.length && <tr><td colSpan={4}>{permissionSearch ? "No permissions match this filter." : "No high or critical permissions were resolved from the collected definitions."}</td></tr>}
            </tbody></table></div>
          </>}
          {!!detail.permission_definitions_missing?.length && <details className="least-missing"><summary>Permission definitions not collected ({detail.permission_definitions_missing.length})</summary><p>These grants are recorded, but their permission definitions are unavailable:</p><ul>{detail.permission_definitions_missing.map(role => <li key={role}>{role}</li>)}</ul></details>}
          {detail.identity_last_used && <p className="least-identity-usage">Identity last used: <time dateTime={detail.identity_last_used}>{detail.identity_last_used}</time>. This is identity activity, not individual permission usage.</p>}
        </section>
        {detail.suggestions.some(item => item.value !== "high-impact declared access") && <section className="least-recommendations"><h3>Access recommendations</h3>
          <div className="least-suggestions">{detail.suggestions.filter(item => item.value !== "high-impact declared access").map((item, index) => <article key={`${item.scope}-${item.value}-${index}`}>
            <span className="least-source">{item.source}</span><h4>{item.kind === "permission" ? `Review removing ${item.value}` : item.kind === "service" ? `Review ${item.value} service access` : item.kind === "role" ? `Remove or replace ${item.value}` : `Review ${item.value}`}</h4>
            {item.replacement?.length ? <p>Suggested replacement: {item.replacement.join(", ")}</p> : null}
            <p>{item.scope}</p>{item.last_accessed && <p>Last accessed: {item.last_accessed}</p>}
          </article>)}</div>
        </section>}
      </div>
    </Inspector>}

  </div>;
}
