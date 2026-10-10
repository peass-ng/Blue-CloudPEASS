import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ExternalLink, KeyRound, ShieldCheck, Code2 } from "lucide-react";
import { tokenKey, useApi } from "./api";
import type { Catalog, Me } from "./types";
import { Badge, Evidence, Panel, State, sourceHref } from "./ui";
export function Settings({ demo }: { demo: boolean }) {
  const me = useApi<Me>("/me", demo);
  const health = useApi<{ source_url?: string; source_version?: string }>(
    "/health",
    demo,
  );
  const releaseSource = sourceHref(health.data?.source_url);
  const catalog = useApi<Catalog>("/catalog", demo);
  const client = useQueryClient();
  const [token, setToken] = useState("");
  const [saved, setSaved] = useState(false);
  const [catalogSearch, setCatalogSearch] = useState("");
  function save() {
    if (!token.trim()) return;
    sessionStorage.setItem(tokenKey, token.trim());
    setToken("");
    setSaved(true);
    void client.invalidateQueries({ queryKey: ["live"] });
  }
  function clear() {
    sessionStorage.removeItem(tokenKey);
    setSaved(false);
    void client.invalidateQueries({ queryKey: ["live"] });
  }
  const checks = Array.isArray(catalog.data?.checks) ? catalog.data.checks : [];
  return (
    <>
      <div className="section-top">
        <p>Your account, assessment coverage and workspace controls.</p>
        <span className="count-pill">Native engine</span>
      </div>
      <div className="dashboard-grid">
        <Panel title="Account & quota" kicker="WORKSPACE">
          <State
            loading={me.isPending}
            error={me.error}
            onRetry={() => void me.refetch()}
          >
            <div className="account-details">
              <ShieldCheck size={30} />
              <h3>
                {String(
                  me.data?.email ||
                    me.data?.tenant_id ||
                    me.data?.name ||
                    "PEASO workspace",
                )}
              </h3>
              <Badge
                value={String(me.data?.plan || me.data?.mode || "Account")}
              />
              {typeof me.data?.weekly_limit === "number" && (
                <>
                  <p className="quota-value">
                    {String(me.data.weekly_used ?? 0)}{" "}
                    <span>/ {me.data.weekly_limit}</span>
                  </p>
                  <p className="muted">Assessments used this week</p>
                </>
              )}
              {me.data?.quota !== undefined && (
                <Evidence data={me.data.quota} />
              )}
            </div>
          </State>
          <div className="button-row">
            <a
              className="button"
              href="https://tools.hacktricks.wiki/login.html"
            >
              Sign in
              <ExternalLink size={13} />
            </a>
            <a
              className="button"
              href="https://tools.hacktricks.wiki/register.html"
            >
              Create account
              <ExternalLink size={13} />
            </a>
          </div>
          <a
            className="text-button small"
            href="https://tools.hacktricks.wiki/forgot-password.html"
          >
            Forgot password
          </a>
          <p className="muted small">
            Hosted account authentication uses the existing HackTricks identity
            flow. Your API verifies account access and quota.
          </p>
        </Panel>
        <Panel title="Local API authentication" kicker="THIS BROWSER SESSION">
          <form
            className="form"
            onSubmit={(e) => {
              e.preventDefault();
              save();
            }}
          >
            <label>
              API bearer token
              <input
                aria-label="API bearer token"
                type="password"
                value={token}
                autoComplete="off"
                onChange={(e) => {
                  setToken(e.target.value);
                  setSaved(false);
                }}
                placeholder="Enter the token from your local server"
                disabled={demo}
              />
            </label>
            <p className="muted small">
              Stored in sessionStorage for this tab. Cloud connector credentials
              are never saved in browser storage.
            </p>
            <div className="button-row">
              <button
                className="button primary"
                type="submit"
                disabled={demo || !token.trim()}
              >
                <KeyRound size={15} />
                Use token
              </button>
              <button
                className="button"
                type="button"
                disabled={demo}
                onClick={clear}
              >
                Clear token
              </button>
            </div>
            {saved && (
              <p role="status" className="mint">
                Token saved for this session.
              </p>
            )}
          </form>
        </Panel>
      </div>
      <Panel title="Native check catalog" kicker="SUPPORTED SCOPE">
        <p className="muted">
          The live API catalog is the source of truth for supported checks.
          Upstream checks that have not been ported are coverage gaps and never
          run in this app.
        </p>
        <input
          className="catalog-search"
          aria-label="Search check catalog"
          placeholder="Search checks, providers and coverage status…"
          value={catalogSearch}
          onChange={(e) => setCatalogSearch(e.target.value)}
        />
        <State
          loading={catalog.isPending}
          error={catalog.error}
          onRetry={() => void catalog.refetch()}
        >
          {checks.length ? (
            <div className="catalog-list">
              {checks
                .filter((c) =>
                  JSON.stringify(c)
                    .toLowerCase()
                    .includes(catalogSearch.toLowerCase()),
                )
                .map((c, i) => (
                  <div className="catalog-row" key={String(c.id || i)}>
                    <div>
                      <strong>
                        {String(c.title || c.id || c.check_id || "Check")}
                      </strong>
                      <p>
                        {String(c.provider || "")} · {String(c.service || "")} ·{" "}
                        {String(c.id || c.check_id || "")}
                      </p>
                    </div>
                    <Badge
                      value={String(
                        c.status ||
                          (c.supported === false ? "unported" : "supported"),
                      )}
                    />
                  </div>
                ))}
            </div>
          ) : (
            <p>No supported-check list supplied by the API.</p>
          )}
          <div className="notice">
            <p>
              Unported upstream coverage: only checks listed as supported in
              this native catalog are available. No upstream runtime is
              integrated. Framework mappings are review guidance, not
              certification.
            </p>
          </div>
          <details>
            <summary>Full catalog and coverage metadata</summary>
            <Evidence data={catalog.data} />
          </details>
        </State>
      </Panel>
      <div className="dashboard-grid">
        <Panel title="Help & evidence">
          <p className="muted">
            Start with a read-only connector, launch a scan, then review
            findings alongside collector coverage. Graphs show observed
            configuration relationships; effective access may require additional
            evidence.
          </p>
          <a
            className="button"
            href="https://cloud.hacktricks.wiki/"
            target="_blank"
            rel="noopener noreferrer"
          >
            HackTricks Cloud
            <ExternalLink size={14} />
          </a>
        </Panel>
        <Panel title="Source & license" kicker="TRANSPARENT BY DESIGN">
          <Code2 size={25} className="mint" />
          <p className="muted">
            PEASO is built on Blue-CloudPEASS. Source code and license terms are
            available with the project, including the source corresponding to
            this UI.
          </p>
          <a
            className="button"
            href={
              releaseSource || "https://github.com/carlospolop/Blue-CloudPEASS"
            }
            target="_blank"
            rel="noopener noreferrer"
          >
            {releaseSource
              ? "Download deployment source"
              : "View source repository"}
            <ExternalLink size={14} />
          </a>
          {health.data?.source_version && (
            <p className="muted small">
              Source release: {health.data.source_version}
            </p>
          )}
        </Panel>
      </div>
    </>
  );
}
