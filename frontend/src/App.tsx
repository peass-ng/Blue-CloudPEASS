import { Component, lazy, Suspense, useEffect, useState } from "react";
import type { ErrorInfo, ReactNode } from "react";
import {
  Activity,
  ArrowUpRight,
  ChevronDown,
  Cloud,
  Gauge,
  HelpCircle,
  Layers,
  Network,
  ScanLine,
  Settings as SettingsIcon,
  Shield,
  ShieldCheck,
  Target,
  Waypoints,
  Route,
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, items, useApi } from "./api";
import { Connectors } from "./Connectors";
import { Dashboard, CoverageView } from "./Dashboard";
import { Findings } from "./Findings";
const GraphView = lazy(() =>
  import("./GraphView").then((m) => ({ default: m.GraphView })),
);
const PrivescMap = lazy(() =>
  import("./PrivescMap").then((m) => ({ default: m.PrivescMap })),
);
import { Scans } from "./Scans";
import { Settings } from "./Settings";
import type { Connector, Report, Scan } from "./types";
import { Panel, State, date, sourceHref } from "./ui";
const pages = [
  {
    label: "Dashboard",
    icon: Gauge,
    group: "WORKSPACE",
    description: "An evidence-led view of your cloud security.",
  },
  {
    label: "Connectors",
    icon: Cloud,
    description: "Connect your environments with confidence.",
  },
  {
    label: "Scans",
    icon: ScanLine,
    description: "Assess, monitor and revisit your cloud posture.",
  },
  {
    label: "Hardening Findings",
    icon: ShieldCheck,
    group: "SECURITY INSIGHTS",
    description: "Review configuration controls across your cloud estate.",
  },
  {
    label: "Exposure",
    icon: Target,
    description: "Understand your observed external exposure.",
  },
  {
    label: "Least Privilege",
    icon: Shield,
    description: "Review identity permissions and reduce unnecessary access.",
  },
  {
    label: "IAM Risk Map",
    icon: Waypoints,
    description: "Defensive IAM risk map · observed access relationships.",
  },
  {
    label: "Privilege Escalation Map",
    icon: Route,
    description:
      "Which identities can escalate to others or to admin · catalog-driven attack paths.",
  },
  {
    label: "Network Map",
    icon: Network,
    description: "See the connections behind your infrastructure.",
  },
  {
    label: "Settings",
    icon: SettingsIcon,
    group: "ADMINISTRATION",
    description: "Account, quota, supported scope and help.",
  },
];
export function App() {
  const [page, setPage] = useState(() => {
    const raw = decodeURIComponent(location.hash.slice(1));
    const p = raw;
    return pages.some((x) => x.label === p) ? p : "Dashboard";
  });
  const [demo, setDemo] = useState(false);
  const [selected, setSelected] = useState("");
  const client = useQueryClient();
  const health = useApi<{ status: string; source_url?: string }>(
    "/health",
    demo,
  );
  const connectors = useApi<{ items: Connector[] }>("/connectors", demo);
  const scans = useApi<{ items: Scan[] }>("/scans", demo, true, true);
  const available = items(scans.data);
  const scanId =
    selected || available.find((s) => s.status === "completed")?.id || "";
  const current = available.find((s) => s.id === scanId);
  const report = useApi<Report>(
    `/scans/${encodeURIComponent(scanId)}/summary`,
    demo,
    !!scanId && current?.status === "completed",
  );
  const pageInfo = pages.find((p) => p.label === page) || pages[0];
  function navigate(p: string) {
    setPage(p);
    location.hash = encodeURIComponent(p);
  }
  useEffect(() => {
    const change = () => {
      const raw = decodeURIComponent(location.hash.slice(1));
      const p = raw;
      if (pages.some((x) => x.label === p)) setPage(p);
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  const unauthorized = [connectors.error, scans.error].some(
    (e) => e instanceof ApiError && e.status === 401,
  );
  function switchDemo() {
    setDemo(!demo);
    setSelected("");
    client.removeQueries({ queryKey: [!demo ? "demo" : "live"] });
  }
  const insight = [
    "Hardening Findings",
    "Exposure",
    "Least Privilege",
    "IAM Risk Map",
    "Privilege Escalation Map",
    "Network Map",
  ].includes(page);
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className="sidebar">
        <a
          className="brand"
          href="#Dashboard"
          onClick={() => navigate("Dashboard")}
        >
          <img src="/icons/peaso.svg" alt="" width={34} height={36} />
          <div>
            PEASO<span>CLOUD SECURITY</span>
          </div>
        </a>
        <div className="workspace-chip">
          <div className="workspace-avatar">
            <Layers size={18} />
          </div>
          <div>
            <strong>Security workspace</strong>
            <span>{demo ? "Fixture demo" : "Native cloud assessments"}</span>
          </div>
          <ChevronDown size={14} />
        </div>
        <nav aria-label="Primary navigation">
          {pages.map((p) => (
            <div key={p.label}>
              {p.group && <div className="nav-group">{p.group}</div>}
              <button
                className={`nav-item ${page === p.label ? "active" : ""}`}
                onClick={() => navigate(p.label)}
                aria-label={p.label}
                aria-current={page === p.label ? "page" : undefined}
              >
                <p.icon size={18} />
                <span>{p.label}</span>
                {p.label === "Hardening Findings" && report.data && (
                  <span className="nav-count">
                    {Number(
                      (
                        report.data.stats?.by_category as
                          | Record<string, number>
                          | undefined
                      )?.hardening ??
                        report.data.findings?.filter(
                          (f) => f.category === "hardening",
                        ).length ??
                        0,
                    )}
                  </span>
                )}
              </button>
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="engine-chip">
            <span className="status-dot" />
            <span>Native snapshot engine</span>
            <Activity size={13} />
          </div>
          <button className="nav-item" onClick={() => navigate("Settings")}>
            <HelpCircle size={18} />
            Help & documentation
            <ArrowUpRight size={14} />
          </button>
          <div className="version-line">
            PEASO v1.0<span>Built by HackTricks</span>
          </div>
        </div>
      </aside>
      <div className="workspace-main">
        <header className="topbar">
          <span className="breadcrumb">
            Workspace <span>/</span> {page}
          </span>
          <div className="topbar-actions">
            <label className="demo-switch">
              <input type="checkbox" checked={demo} onChange={switchDemo} />
              <span className="switch-track" />
              Fixture demo
            </label>
            <span className={`api-status ${health.error ? "offline" : ""}`}>
              <span className="status-dot" />
              {demo
                ? "Demo data"
                : health.isPending
                  ? "Connecting"
                  : health.error
                    ? "API unavailable"
                    : "Live API"}
            </span>
            <button
              className="account-button"
              aria-label="Account settings"
              onClick={() => navigate("Settings")}
            >
              HT
            </button>
          </div>
        </header>
        <main id="main-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">PEASO INTELLIGENCE</div>
              <h1>{page}</h1>
              <p>{pageInfo.description}</p>
            </div>
            {(insight || page === "Dashboard") && (
              <label className="scan-picker">
                <span>Selected assessment</span>
                <select
                  aria-label="Selected assessment"
                  value={scanId}
                  onChange={(e) => setSelected(e.target.value)}
                >
                  <option value="">
                    {available.length
                      ? "Choose a completed scan"
                      : "No completed scans"}
                  </option>
                  {available
                    .filter((s) => s.status === "completed")
                    .map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.id} · {date(s.created_at)}
                      </option>
                    ))}
                </select>
              </label>
            )}
          </div>
          {demo && (
            <div className="demo-banner" role="status">
              <ShieldCheck size={17} />
              <strong>Fixture demo</strong>
              <span>
                Illustrative data only. No cloud assessment has been run.
                Changes are disabled.
              </span>
              <button className="text-button" onClick={switchDemo}>
                Return to live API
              </button>
            </div>
          )}
          {!demo && current?.input_mode && current.input_mode !== "live" && (
            <div className="demo-banner" role="status">
              <ShieldCheck size={17} />
              <strong>
                {current.input_mode === "demo"
                  ? "Offline demo assessment"
                  : "Imported offline snapshot"}
              </strong>
              <span>
                {current.input_mode === "demo"
                  ? "Illustrative native demo snapshot; no live cloud evidence."
                  : "This assessment analyzed an imported snapshot. Collection provenance and coverage are recorded in the report."}
              </span>
            </div>
          )}
          {unauthorized && !demo && page !== "Settings" && (
            <div className="auth-banner" role="alert">
              <Shield size={18} />
              <span>Authenticate your workspace to load private evidence.</span>
              <button className="button" onClick={() => navigate("Settings")}>
                Set up authentication
              </button>
            </div>
          )}
          {page === "Dashboard" && (
            <Dashboard
              connectors={items(connectors.data)}
              scans={available}
              report={report.data}
              scanId={scanId}
              demo={demo}
              loading={
                connectors.isPending ||
                scans.isPending ||
                (!!scanId && report.isPending)
              }
              error={connectors.error || scans.error || report.error}
              onRetry={() => {
                void connectors.refetch();
                void scans.refetch();
                if (scanId) void report.refetch();
              }}
              onNavigate={navigate}
            />
          )}
          {page === "Connectors" && <Connectors demo={demo} />}
          {page === "Scans" && (
            <Scans
              demo={demo}
              onSelect={(s) => {
                setSelected(s.id);
                navigate("Hardening Findings");
              }}
            />
          )}
          {["Hardening Findings", "Exposure", "Least Privilege"].includes(
            page,
          ) && (
            <>
              <State
                error={scans.error}
                loading={scans.isPending}
                onRetry={() => void scans.refetch()}
              >
                <Findings
                  scanId={scanId}
                  category={
                    page === "Hardening Findings"
                      ? "hardening"
                      : page === "Exposure"
                        ? "exposure"
                        : "least_privilege"
                  }
                  demo={demo}
                />
              </State>
              {report.data && (
                <Panel title="Coverage & limitations">
                  <CoverageView scanId={scanId} demo={demo} />
                </Panel>
              )}
            </>
          )}
          {page === "IAM Risk Map" && (
            <State
              error={scans.error}
              loading={scans.isPending}
              onRetry={() => void scans.refetch()}
            >
              <Suspense fallback={<State loading />}>
                <GraphView scanId={scanId} kind="iam" demo={demo} />
              </Suspense>
            </State>
          )}
          {page === "Privilege Escalation Map" && (
            <State
              error={scans.error}
              loading={scans.isPending}
              onRetry={() => void scans.refetch()}
            >
              <Suspense fallback={<State loading />}>
                <PrivescMap
                  scanId={scanId}
                  demo={demo}
                  categories={current?.categories}
                  onNavigate={navigate}
                />
              </Suspense>
            </State>
          )}
          {page === "Network Map" && (
            <State
              error={scans.error}
              loading={scans.isPending}
              onRetry={() => void scans.refetch()}
            >
              <Suspense fallback={<State loading />}>
                <GraphView scanId={scanId} kind="network" demo={demo} />
              </Suspense>
            </State>
          )}
          {page === "Settings" && <Settings demo={demo} />}
          <footer className="footer">
            <span>
              <ShieldCheck size={13} />
              Evidence first. Confidence follows.
            </span>
            <span>
              <a
                href={
                  sourceHref(health.data?.source_url) ||
                  "https://github.com/carlospolop/Blue-CloudPEASS"
                }
                target="_blank"
                rel="noopener noreferrer"
              >
                Source code
              </a>{" "}
              · PEASO · HackTricks Cloud
            </span>
          </footer>
        </main>
      </div>
    </div>
  );
}
export class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: boolean }
> {
  state = { error: false };
  static getDerivedStateFromError() {
    return { error: true };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("UI render error", error.name, info.componentStack);
  }
  render() {
    return this.state.error ? (
      <div className="state" role="alert">
        <h1>The workspace could not be displayed</h1>
        <p>Reload the page to reconnect with your API.</p>
        <button className="button" onClick={() => location.reload()}>
          Reload workspace
        </button>
      </div>
    ) : (
      this.props.children
    );
  }
}
