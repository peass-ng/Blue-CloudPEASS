import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ExternalLink, KeyRound, ShieldCheck } from "lucide-react";
import { ApiError, tokenKey, useApi } from "./api";
import type { Me } from "./types";
import { Badge, Inspector, Panel, State } from "./ui";
import { ApiKeys } from "./ApiKeys";
import { Workspaces } from "./Workspaces";

const quotaValue = (value: unknown) => typeof value === "number" ? value : undefined;

export function Settings({ demo, workspaceId = "personal", onWorkspaceCreated = () => {} }: { demo: boolean; workspaceId?: string; onWorkspaceCreated?: (id: string) => void }) {
  const me = useApi<Me>("/me", demo);
  const health = useApi<{ auth_mode?: string }>("/health", demo);
  const client = useQueryClient();
  const [token, setToken] = useState("");
  const [tokenDialog, setTokenDialog] = useState(false);
  const authRequired = !demo && me.error instanceof ApiError && me.error.status === 401;
  const localMode = health.data?.auth_mode === "local";
  useEffect(() => { if (authRequired && localMode) setTokenDialog(true); }, [authRequired, localMode]);
  const quota = me.data?.quota && typeof me.data.quota === "object" ? me.data.quota as Record<string, unknown> : {};
  const used = quotaValue(me.data?.weekly_used) ?? quotaValue(quota.weekly_used);
  const limit = quotaValue(me.data?.weekly_limit) ?? quotaValue(quota.weekly_limit);
  const expiryEpoch = me.data?.plan_expires_at;
  const grantExpiry = typeof expiryEpoch === "number" && Number.isFinite(expiryEpoch)
    ? new Date(expiryEpoch * 1000) : null;
  const currentPlan = me.data?.plan;
  const expiryValid = expiryEpoch == null || (grantExpiry !== null && !Number.isNaN(grantExpiry.getTime()));
  const activeAdminGrant = me.data?.plan_source === "administrator_comped_qa" &&
    typeof currentPlan === "string" && currentPlan.toLowerCase() !== "free" &&
    expiryValid && (!grantExpiry || grantExpiry.getTime() > Date.now());
  function refresh() {
    void client.resetQueries({ queryKey: ["live"] });
  }
  function save() {
    if (!token.trim()) return;
    sessionStorage.setItem(tokenKey, token.trim());
    setToken("");
    setTokenDialog(false);
    refresh();
  }
  function clear() {
    sessionStorage.removeItem(tokenKey);
    setTokenDialog(false);
    refresh();
  }
  return (
    <>
      <Panel title="Account & quota" kicker="WORKSPACE" className="account-panel">
        {me.isPending ? <State loading /> : authRequired ? (
          <div className="account-details">
            <p>Sign in to view your account and assessment quota.</p>
            <div className="button-row">
              <a className="button primary" href="https://tools.hacktricks.wiki/login.html">Sign in <ExternalLink size={13} /></a>
              <a className="button" href="https://tools.hacktricks.wiki/register.html">Create account <ExternalLink size={13} /></a>
            </div>
            <a className="text-button small" href="https://tools.hacktricks.wiki/forgot-password.html">Forgot password</a>
            {localMode && <button className="button" onClick={() => setTokenDialog(true)}>Use local API token</button>}
          </div>
        ) : me.error ? <State error={me.error} onRetry={() => void me.refetch()} /> : (
          <div className="account-details">
            <div className="account-summary">
              <ShieldCheck size={20} aria-hidden="true" />
              <h3>{String(me.data?.email || me.data?.name || me.data?.tenant_id || "Workspace account")}</h3>
              {(me.data?.plan || me.data?.mode) && <Badge value={String(me.data.plan || me.data.mode)} />}
            </div>
            {me.data?.email && me.data.email_verified === false && <p className="muted small">Email address is not verified with the identity provider.</p>}
            {activeAdminGrant && <p className="muted small">Temporary paid access (administrator grant){grantExpiry ? ` · Expires ${grantExpiry.toLocaleString()}` : ""}</p>}
            {used !== undefined && limit !== undefined ? <div className="quota-summary"><p className="muted">Assessments used this week</p><p className="quota-value">{used} <span>/ {limit}</span></p></div> : <p className="muted">Weekly assessment quota was not supplied by this API.</p>}
            {localMode && !demo && <button className="text-button small" onClick={() => setTokenDialog(true)}>Manage local API token</button>}
          </div>
        )}
      </Panel>
      {!demo && me.data && !me.error && (me.data as Me & { auth_kind?: string }).auth_kind !== "api_key" && <Workspaces me={me.data} workspaceId={workspaceId} onWorkspaceCreated={onWorkspaceCreated} />}
      {!demo && me.data && !me.error && (me.data as Me & { auth_kind?: string }).auth_kind !== "api_key" && <ApiKeys />}
      {tokenDialog && localMode && !demo && <Inspector title="Local API authentication" onClose={() => setTokenDialog(false)}>
        <form className="form" onSubmit={(event) => { event.preventDefault(); save(); }}>
          <p className="muted small">Enter a token issued by your local API. It is kept in this browser tab only.</p>
          <label>API bearer token<input aria-label="API bearer token" type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} /></label>
          <div className="button-row"><button className="button primary" type="submit" disabled={!token.trim()}><KeyRound size={15} /> Use token</button><button className="button" type="button" onClick={clear}>Clear token</button></div>
        </form>
      </Inspector>}
    </>
  );
}
