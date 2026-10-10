import {
  ArrowUpRight,
  Cloud,
  ShieldCheck,
  Radar,
  ScanLine,
  ArrowRight,
  CircleDot,
} from "lucide-react";
import type { Connector, Report, Scan } from "./types";
import { Badge, date, Evidence, Panel, ProviderIcon, State } from "./ui";
export function Dashboard({
  connectors,
  scans,
  report,
  loading,
  error,
  onNavigate,
  onRetry,
}: {
  connectors: Connector[];
  scans: Scan[];
  report?: Report;
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
  const pass = findings.filter((f) =>
    ["pass", "passed"].includes(f.status.toLowerCase()),
  ).length;
  const total = findings.length;
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
          <svg className="orb" viewBox="0 0 320 320">
            <defs>
              <radialGradient id="orb-fill">
                <stop offset="0" stopColor="#204a48" stopOpacity=".18" />
                <stop offset=".8" stopColor="#70dfc6" stopOpacity=".1" />
                <stop offset="1" stopColor="#89ffe0" stopOpacity=".24" />
              </radialGradient>
            </defs>
            <circle
              cx="160"
              cy="160"
              r="120"
              fill="url(#orb-fill)"
              stroke="#78d7c3"
              strokeOpacity=".5"
            />
            <g fill="none" stroke="#78d7c3" strokeOpacity=".23">
              <ellipse cx="160" cy="160" rx="120" ry="40" />
              <ellipse cx="160" cy="160" rx="120" ry="80" />
              <ellipse cx="160" cy="160" rx="40" ry="120" />
              <ellipse cx="160" cy="160" rx="80" ry="120" />
              <path d="M40 160h240M160 40v240" />
            </g>
            <g fill="#9effdd">
              <circle cx="99" cy="102" r="4" />
              <circle cx="228" cy="136" r="4" />
              <circle cx="167" cy="230" r="4" />
            </g>
            <path
              d="m99 102 129 34-61 94Z"
              fill="#99ffdb"
              fillOpacity=".04"
              stroke="#99ffdb"
              strokeOpacity=".5"
              strokeDasharray="3 4"
            />
          </svg>
          <span className="orb-chip chip-one">
            <ShieldCheck size={14} />
            Native evidence
          </span>
          <span className="orb-chip chip-two">
            <Cloud size={14} />
            Four cloud providers
          </span>
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
                value: report ? (report.resources?.length ?? 0) : "—",
                icon: Radar,
                detail: report
                  ? "In selected snapshot"
                  : "Awaiting first snapshot",
                color: "blue",
              },
              {
                label: "Findings to review",
                value: report ? failures.length : "—",
                icon: ShieldCheck,
                detail: report
                  ? `${critical.length} critical or high severity`
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
                    background: `conic-gradient(#99f2ce ${passPercent || 0}%, #203039 0)`,
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
                    Review required<span>{report ? failures.length : "—"}</span>
                  </p>
                  <p>
                    <span className="legend-dot slate-bg" />
                    Other / unknown
                    <span>{report ? total - pass - failures.length : "—"}</span>
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
                  ? `${services.length} SERVICES WITH FINDINGS`
                  : "VISIBILITY & LIMITATIONS"
              }
            >
              {report ? (
                <Coverage data={report.coverage} />
              ) : (
                <div className="compact-empty">
                  <Radar />
                  <div>
                    <h3>Coverage is not available yet</h3>
                    <p>
                      Collector status, denied permissions and unobserved scope
                      will appear here.
                    </p>
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
        {data.map((row, i) => (
          <div className="coverage-row" key={i}>
            <strong>
              {String(
                row.service ||
                  row.type ||
                  row.check_id ||
                  row.scope ||
                  `Collection ${i + 1}`,
              )}
            </strong>
            <Badge value={String(row.status || "unknown")} />
            {(row.reason || row.error) && (
              <p>{String(row.reason || row.error)}</p>
            )}
          </div>
        ))}
      </div>
    );
  return <Evidence data={data} />;
}
