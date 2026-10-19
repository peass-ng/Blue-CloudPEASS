import {
  ArrowUpRight,
  Cloud,
  ShieldCheck,
  Radar,
  ScanLine,
  ArrowRight,
  CircleDot,
} from "lucide-react";
import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { BoundedPager } from "./BoundedPager";
import { request } from "./api";
import type { Connector, Report, Scan } from "./types";
import { Badge, date, Evidence, Panel, ProviderIcon, State } from "./ui";
export function Dashboard({
  connectors,
  scans,
  report,
  loading,
  error,
  onNavigate,
  scanId,
  demo,
  onRetry,
}: {
  connectors: Connector[];
  scans: Scan[];
  report?: Report;
  scanId: string;
  demo: boolean;
  loading: boolean;
  error: unknown;
  onNavigate: (page: string) => void;
  onRetry: () => void;
}) {
  const findings = report?.findings || [];
  const failures = findings.filter((f) =>
    ["fail", "failed", "review", "open"].includes(f.status.toLowerCase()),
  );
  const critical = failures.filter((f) =>
    ["critical", "high"].includes(f.severity),
  );
  const services = Array.from(new Set(findings.map((f) => f.service)));
  const statusCounts = report?.stats?.by_status as
    | Record<string, number>
    | undefined;
  const severityCounts = report?.stats?.by_severity as
    | Record<string, number>
    | undefined;
  const pass = statusCounts
    ? Object.entries(statusCounts)
        .filter(([key]) => ["pass", "passed"].includes(key.toLowerCase()))
        .reduce((sum, [, n]) => sum + n, 0)
    : findings.filter((f) =>
        ["pass", "passed"].includes(f.status.toLowerCase()),
      ).length;
  const reviewCount = statusCounts
    ? Object.entries(statusCounts)
        .filter(([key]) =>
          ["fail", "failed", "review", "open", "manual"].includes(
            key.toLowerCase(),
          ),
        )
        .reduce((sum, [, n]) => sum + n, 0)
    : failures.length;
  const criticalCount = severityCounts
    ? (severityCounts.critical || 0) + (severityCounts.high || 0)
    : critical.length;
  const assetCount = Number(
    report?.stats?.resource_count ?? report?.resources?.length ?? 0,
  );
  const total = Number(report?.stats?.finding_count ?? findings.length);
  const passPercent = total ? Math.round((pass / total) * 100) : null;
  return (
    <>
      <div className="hero panel">
        <div className="hero-copy">
          <span className="eyebrow">
            <span className="status-dot" />
            CLOUD SECURITY, IN FOCUS
          </span>
          <h2>
            Your cloud.
            <br />
            <span>A clearer perspective.</span>
          </h2>
          <p>
            Understand your posture, reduce exposure,
            <br className="desktop-break" /> and follow the evidence across
            every cloud.
          </p>
          <div className="button-row">
            <button
              className="button primary"
              onClick={() => onNavigate("Scans")}
            >
              <ScanLine size={17} />
              Launch an assessment
            </button>
            <button
              className="text-button"
              onClick={() => onNavigate("Connectors")}
            >
              Manage environments
              <ArrowUpRight size={16} />
            </button>
          </div>
        </div>
        <div className="orb-scene" aria-hidden="true">
          <div className="orb-halo" />
          <img className="orb" src="/icons/peaso-badge.svg" alt="" />
        </div>
      </div>
      <State loading={loading} error={error} onRetry={onRetry}>
        <>
          <div className="metrics-grid">
            {[
              {
                label: "Connected environments",
                value: connectors.length,
                icon: Cloud,
                detail: "Configured connectors",
                color: "mint",
              },
              {
                label: "Observed assets",
                value: report ? assetCount : "—",
                icon: Radar,
                detail: report
                  ? "In selected snapshot"
                  : "Awaiting first snapshot",
                color: "blue",
              },
              {
                label: "Findings to review",
                value: report ? reviewCount : "—",
                icon: ShieldCheck,
                detail: report
                  ? `${criticalCount} critical or high severity`
                  : "No assessment evidence",
                color: "amber",
              },
              {
                label: "Completed scans",
                value: scans.filter((s) => s.status === "completed").length,
                icon: ScanLine,
                detail: "Recorded assessments",
                color: "violet",
              },
            ].map((m) => (
              <div className="metric panel" key={m.label}>
                <div className="metric-top">
                  <span>{m.label}</span>
                  <m.icon className={m.color} size={19} />
                </div>
                <strong>{m.value}</strong>
                <p>
                  <CircleDot size={11} />
                  {m.detail}
                </p>
              </div>
            ))}
          </div>
          <div className="dashboard-grid">
            <Panel
              title="Assessment posture"
              kicker="SELECTED SNAPSHOT"
              action={
                <button
                  className="icon-button"
                  aria-label="Open hardening findings"
                  onClick={() => onNavigate("Hardening Findings")}
                >
                  <ArrowUpRight size={18} />
                </button>
              }
            >
              <div className="posture">
                <div
                  className="posture-ring"
                  style={{
                    background: `conic-gradient(#a6e3d4 0 ${passPercent || 0}%, #d9b77a ${passPercent || 0}% ${Math.min(100, (passPercent || 0) + (total ? reviewCount / total * 100 : 0))}%, #26343b 0)`,
                  }}
                >
                  <div>
                    <strong>
                      {passPercent === null ? "—" : `${passPercent}%`}
                    </strong>
                    <span>observed checks pass</span>
                  </div>
                </div>
                <div className="posture-legend">
                  <p>
                    <span className="legend-dot mint-bg" />
                    Passing<span>{report ? pass : "—"}</span>
                  </p>
                  <p>
                    <span className="legend-dot amber-bg" />
                    Review required<span>{report ? reviewCount : "—"}</span>
                  </p>
                  <p>
                    <span className="legend-dot slate-bg" />
                    Other / unknown
                    <span>{report ? total - pass - reviewCount : "—"}</span>
                  </p>
                </div>
              </div>
              <p className="muted small">
                {report
                  ? "Calculated from finding statuses, not a compliance certification."
                  : "No assessment yet. Your posture will appear after a completed scan."}
              </p>
            </Panel>
            <Panel
              title="Your environments"
              kicker="MULTI-CLOUD VISIBILITY"
              action={
                <button
                  className="text-button"
                  onClick={() => onNavigate("Connectors")}
                >
                  Manage
                  <ArrowRight size={14} />
                </button>
              }
            >
              {connectors.length ? (
                <div className="environment-list">
                  {connectors.slice(0, 4).map((c) => (
                    <div className="environment-row" key={c.id}>
                      <ProviderIcon provider={c.provider} />
                      <div className="grow">
                        <strong>{c.name}</strong>
                        <p>{c.scopes?.join(" · ") || "Default scope"}</p>
                      </div>
                      <Badge value={c.status || "configured"} />
                    </div>
                  ))}
                </div>
              ) : (
                <div className="compact-empty">
                  <Cloud />
                  <div>
                    <h3>A connected view starts here</h3>
                    <p>Add your first cloud environment.</p>
                    <button
                      className="text-button"
                      onClick={() => onNavigate("Connectors")}
                    >
                      Connect a cloud
                      <ArrowRight size={14} />
                    </button>
                  </div>
                </div>
              )}
            </Panel>
          </div>
          <div className="dashboard-grid">
            <Panel
              title="Recent assessments"
              action={
                <button
                  className="text-button"
                  onClick={() => onNavigate("Scans")}
                >
                  View history
                  <ArrowRight size={14} />
                </button>
              }
            >
              {scans.length ? (
                scans.slice(0, 3).map((s) => (
                  <div className="recent-scan" key={s.id}>
                    <ScanLine size={18} />
                    <div className="grow">
                      <strong>{s.id}</strong>
                      <p>{date(s.created_at)}</p>
                    </div>
                    <Badge value={s.status} />
                  </div>
                ))
              ) : (
                <div className="compact-empty">
                  <ScanLine />
                  <div>
                    <h3>No scans recorded</h3>
                    <p>Assess an environment to collect evidence.</p>
                  </div>
                </div>
              )}
            </Panel>
            <Panel
              title="Collection coverage"
              kicker={
                report
                  ? "COLLECTOR STATUS & LIMITATIONS"
                  : "VISIBILITY & LIMITATIONS"
              }
            >
              {report ? (
                <CoverageView scanId={scanId} demo={demo} />
              ) : (
                <div className="compact-empty">
                  <Radar />
                  <div>
                    <h3>Coverage is not available yet</h3>
                    <p>Run a scan to see what was checked.</p>
                  </div>
                </div>
              )}
            </Panel>
          </div>
        </>
      </State>
    </>
  );
}
export function Coverage({ data }: { data: unknown }) {
  if (!data)
    return (
      <p className="muted">The report did not include coverage information.</p>
    );
  if (Array.isArray(data))
    return (
      <div className="coverage-list">
        {data.map((row, i) => {
          const code = row.error_code || row.code || row.error?.code;
          const account = row.account || row.scope;
          const knownReason =
            code === "duplicate_account_target"
              ? `Skipped: another role already audits account ${String(account)}.`
              : code === "external_id_not_required_by_trust"
                ? "Role refused: its trust policy does not require an ExternalID. Add the sts:ExternalId condition shown in onboarding."
                : code === "platform_owned_account"
                  ? "Role refused: this account belongs to the CSPM platform."
                  : code === "role_target_limit"
                    ? "Skipped: the scan reached its role-target limit."
                    : null;
          const reason =
            row.reason ||
            (typeof row.error === "string" ? row.error : null) ||
            knownReason ||
            (row.error && typeof row.error === "object" ? row.error : code || row.error);
          const heading = [row.check_id, row.type, row.level, row.service, row.scope]
            .find((value) => typeof value === "string" || typeof value === "number");
          const resource = row.resource_ref || row.role_arn;
          return (
            <div className="coverage-row" key={i}>
              <strong>{String(heading || `Collection ${i + 1}`)}</strong>
              <Badge value={typeof row.status === "string" ? row.status : "unknown"} />
              {resource && (typeof resource === "object" ? <Evidence data={resource} /> : <p>{String(resource)}</p>)}
              {reason && (
                typeof reason === "object"
                  ? <Evidence data={reason} />
                  : <p>{String(reason)}{typeof code === "string" && reason !== code && <> <code>{code}</code></>}</p>
              )}
            </div>
          );
        })}
      </div>
    );
  return <Evidence data={data} />;
}

export function CoverageView({
  scanId,
  demo,
}: {
  scanId: string;
  demo: boolean;
}) {
  return <CoverageWindow key={`${demo ? "demo" : "live"}:${scanId}`} scanId={scanId} demo={demo} />;
}

function CoverageWindow({ scanId, demo }: { scanId: string; demo: boolean }) {
  type CoveragePage = {
    items: unknown[];
    offset?: number;
    total?: number;
    next_offset?: number | null;
  };
  const pageSize = 200;
  const [anchorOffset, setAnchorOffset] = useState(0);
  const query = useInfiniteQuery({
    queryKey: [demo ? "demo" : "live", "coverage", scanId, anchorOffset],
    initialPageParam: anchorOffset,
    queryFn: ({ pageParam, signal }) =>
      request<CoveragePage>(
        `/scans/${encodeURIComponent(scanId)}/coverage?limit=${pageSize}&offset=${pageParam}`,
        { signal },
        demo,
      ),
    getNextPageParam: (page) => page.next_offset ?? undefined,
    getPreviousPageParam: (first, _pages, firstParam) => {
      const offset = Number(first.offset ?? firstParam);
      return offset > 0 ? Math.max(0, offset - pageSize) : undefined;
    },
    maxPages: 2,
    enabled: !!scanId,
    retry: 0,
  });
  const rows = query.data?.pages.flatMap((p) => p.items) || [];
  const total = query.data?.pages[0]?.total ?? rows.length;
  const first = Number(query.data?.pages[0]?.offset ?? query.data?.pageParams[0] ?? anchorOffset);
  const last = first + rows.length;
  return (
    <State
      loading={query.isPending}
      error={query.error && !query.data ? query.error : undefined}
      onRetry={() => void query.refetch()}
    >
      <Coverage data={rows} />
      <BoundedPager first={rows.length ? first + 1 : 0} last={last} total={total} unit="Coverage records" pageSize={pageSize}
        loading={query.isFetchingNextPage || query.isFetchingPreviousPage || query.isPending}
        canPrevious={!!query.hasPreviousPage} canNext={!!query.hasNextPage}
        error={query.error && query.data ? "Coverage page could not be loaded." : undefined}
        statusText={first === 0 && rows.length < total ? `${rows.length} of ${total} coverage records loaded` : undefined}
        onPrevious={() => void query.fetchPreviousPage({ cancelRefetch: false })}
        onNext={() => void query.fetchNextPage({ cancelRefetch: false })}
        onRetry={() => void (query.isFetchPreviousPageError ? query.fetchPreviousPage({ cancelRefetch: false }) : query.fetchNextPage({ cancelRefetch: false }))}
        onJump={setAnchorOffset} nextLabel="Load more coverage" compact />
    </State>
  );
}
