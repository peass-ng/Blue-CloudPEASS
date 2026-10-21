import { useMemo, useState } from "react";
import "./ImagesFindingsTable.css";

export type ImageFinding = {
  id: string;
  provider: string;
  scope: string;
  image_reference: string;
  image_digest: string;
  severity: "HIGH" | "CRITICAL";
  vulnerability_id: string;
  package: string;
  installed_version: string;
  fixed_versions: string[];
  affected_assets: { resource_id: string; kind: string; namespace?: string }[];
  affected_asset_count?: number;
  assets_truncated?: boolean;
  coverage: "COMPLETE" | "UNKNOWN";
};

export type ImageAssetPage = {
  items: ImageFinding["affected_assets"];
  total: number;
  offset: number;
  next_offset: number | null;
  coverage: "COMPLETE" | "UNKNOWN";
};

export type ImagesFindingsTableProps = {
  rows: ImageFinding[];
  /** Assessment-level coverage. Omission means the image scan is unconfirmed. */
  coverage?: "COMPLETE" | "UNKNOWN" | "NOT_SCANNED";
  coverageWarning?: string;
  loading?: boolean;
  error?: string | Error | null;
  onRetry?: () => void;
  total?: number;
  hasMore?: boolean;
  loadingMore?: boolean;
  loadMoreError?: boolean;
  onLoadMore?: () => void;
  loadAssets?: (row: ImageFinding, offset: number) => Promise<ImageAssetPage>;
};

function AffectedAssets({ row, loadAssets }: {
  row: ImageFinding;
  loadAssets?: ImagesFindingsTableProps["loadAssets"];
}) {
  const [page, setPage] = useState<ImageAssetPage>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const count = row.affected_asset_count ?? row.affected_assets.length;
  const needsFetch = row.assets_truncated || count > row.affected_assets.length;
  const assets = page?.items || row.affected_assets;
  async function fetchPage(offset: number) {
    if (!loadAssets || loading) return;
    setLoading(true);
    setError(false);
    try {
      const next = await loadAssets(row, offset);
      setPage((previous) => offset === 0 ? next : {
        ...next,
        items: [...(previous?.items || []), ...next.items],
      });
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }
  if (!count) return <span className="images-findings-secondary">No assets listed</span>;
  return <details onToggle={(event) => {
    if (event.currentTarget.open && needsFetch && !page && !loading && !error) void fetchPage(0);
  }}>
    <summary>{count} {count === 1 ? "asset" : "assets"}</summary>
    <ul>{assets.map((asset, index) => <li key={`${asset.resource_id}:${asset.kind}:${asset.namespace || ""}:${index}`}>
      <span className="images-findings-break">{asset.resource_id}</span>
      <span className="images-findings-secondary">{asset.kind}{asset.namespace ? ` · ${asset.namespace}` : ""}</span>
    </li>)}</ul>
    {loading && <span className="images-findings-secondary" role="status">Loading assets…</span>}
    {error && <span className="images-findings-secondary" role="alert">Assets could not be loaded. <button type="button" className="text-button" onClick={() => void fetchPage(page?.next_offset ?? 0)}>Retry</button></span>}
    {page?.next_offset != null && <button type="button" className="text-button" disabled={loading} onClick={() => void fetchPage(page.next_offset!)}>Load more assets</button>}
    {needsFetch && !loadAssets && <span className="images-findings-secondary">Showing {assets.length} of {count} assets</span>}
  </details>;
}

export function filterImageFindings(rows: ImageFinding[], query: string, severity: string, provider: string): ImageFinding[] {
  const needle = query.trim().toLocaleLowerCase();
  return rows.filter((row) => {
    if (severity && row.severity !== severity) return false;
    if (provider && row.provider !== provider) return false;
    if (!needle) return true;
    return [row.vulnerability_id, row.package, row.installed_version, row.image_reference,
      row.image_digest, row.scope, row.provider,
      ...row.affected_assets.flatMap((asset) => [asset.resource_id, asset.kind, asset.namespace || ""])]
      .some((value) => value.toLocaleLowerCase().includes(needle));
  });
}

export function ImagesFindingsTable({ rows, coverage, coverageWarning, loading = false, error, onRetry,
  total = rows.length, hasMore = false, loadingMore = false, loadMoreError = false, onLoadMore, loadAssets }: ImagesFindingsTableProps) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [provider, setProvider] = useState("");
  const providers = useMemo(() => [...new Set(rows.map((row) => row.provider))].sort(), [rows]);
  const visible = useMemo(() => filterImageFindings(rows, query, severity, provider), [rows, query, severity, provider]);
  const coverageUnknown = coverage !== "COMPLETE" || rows.some((row) => row.coverage === "UNKNOWN");
  const filtered = !!(query.trim() || severity || provider);

  if (loading) return <div className="images-findings-state" role="status">Loading image findings…</div>;
  if (error) return <div className="images-findings-state" role="alert">
    <p>Image findings could not be loaded.</p>
    {onRetry && <button type="button" className="button" onClick={onRetry}>Retry</button>}
  </div>;

  return <section className="images-findings" aria-label="Images Findings">
    {coverageUnknown && <p className="images-findings-coverage" role="status">
      {coverageWarning || (coverage === "NOT_SCANNED"
        ? "Image scanning was not selected for this assessment."
        : "Image scan coverage is incomplete. Findings shown here may be missing.")}
    </p>}
    <div className="images-findings-toolbar">
      <label>Search image findings
        <input type="search" value={query} onChange={(event) => setQuery(event.target.value)}
          placeholder="CVE, package, image, asset…" />
      </label>
      <label>Severity
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">All</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option>
        </select>
      </label>
      <label>Provider
        <select value={provider} onChange={(event) => setProvider(event.target.value)}>
          <option value="">All</option>
          {providers.map((value) => <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <span className="images-findings-count" aria-live="polite">{visible.length} shown · {rows.length} loaded of {total} findings</span>
    </div>
    {hasMore && <p className="images-findings-loaded-note">Filters search loaded findings only.</p>}
    {visible.length === 0 ? <p className="images-findings-state" role="status">
      {filtered ? hasMore ? "No loaded image findings match these filters." : "No image findings match these filters." : coverage === "NOT_SCANNED"
        ? "No image scan results are available." : coverageUnknown
          ? "No image findings were reported; scan coverage is incomplete."
          : "No high or critical image vulnerabilities found."}
    </p> : <div className="images-findings-scroll">
      <table className="images-findings-table">
        <caption>High and critical vulnerabilities grouped by image digest, package, version and vulnerability within each provider and scope</caption>
        <thead><tr><th scope="col">Severity</th><th scope="col">CVE / package</th><th scope="col">Installed / fix</th><th scope="col">Image</th><th scope="col">Affected assets</th></tr></thead>
        <tbody>{visible.map((row) => <tr key={row.id}>
          <td><span className={`badge ${row.severity.toLowerCase()}`}>{row.severity}</span></td>
          <td><strong>{row.vulnerability_id}</strong><span className="images-findings-secondary">{row.package}</span></td>
          <td><span>{row.installed_version}</span><span className="images-findings-secondary">{row.fixed_versions.length ? `Fix: ${row.fixed_versions.join(", ")}` : "No fix listed"}</span></td>
          <td><span className="images-findings-break">{row.image_reference.split("@")[0]}</span>
            <span className="images-findings-secondary" title={row.image_digest}>{row.image_digest.slice(0, 19)}…</span>
            <span className="images-findings-secondary">{row.provider} · {row.scope}</span>
            <details className="images-findings-identity"><summary>Full image identity</summary>
              <code className="images-findings-break">{row.image_reference}</code>
            </details></td>
          <td><AffectedAssets row={row} loadAssets={loadAssets} /></td>
        </tr>)}</tbody>
      </table>
    </div>}
    {(hasMore || loadingMore || loadMoreError) && <div className="images-findings-more">
      {loadMoreError && <span role="alert">More findings could not be loaded. </span>}
      <button type="button" className="button" disabled={loadingMore || !onLoadMore} onClick={onLoadMore}>
        {loadingMore ? "Loading more findings…" : loadMoreError ? "Retry loading more" : "Load more findings"}
      </button>
    </div>}
  </section>;
}
