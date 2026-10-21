import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, KeyRound, ShieldCheck } from "lucide-react";
import { ApiError, request, tokenKey, useApi } from "./api";
import type { Me } from "./types";
import { Badge, Inspector, Panel, State, humanError } from "./ui";
import { ApiKeys } from "./ApiKeys";
import { CodexSettings } from "./CodexSettings";
import { Workspaces } from "./Workspaces";
import { authLink } from "./authLinks";

const quotaValue = (value: unknown) => typeof value === "number" ? value : undefined;

export function Settings({ demo, workspaceId = "personal", onWorkspaceCreated = () => {} }: { demo: boolean; workspaceId?: string; onWorkspaceCreated?: (id: string) => void }) {
  const me = useApi<Me>("/me", demo);
  const workspaces = useApi<{ items: { id: string; role: string }[] }>("/workspaces", demo, !demo);
  const health = useApi<{ auth_mode?: string }>("/health", demo);
  const client = useQueryClient();
  const [token, setToken] = useState("");
  const [tokenDialog, setTokenDialog] = useState(false);
  const [deleteDialog, setDeleteDialog] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [deleteMessage, setDeleteMessage] = useState("");
  const cleanup = useMutation({
    mutationFn: async () => {
      let remaining = true;
      let batches = 0;
      while (remaining) {
        if (++batches > 200) throw new Error("Cleanup has removed 1,000 scans. Run it again to continue.");
        const result = await request<{ remaining: boolean }>("/workspace-data?confirmation=DELETE", { method: "DELETE", headers: { "X-Workspace-Id": workspaceId } });
        remaining = result.remaining;
      }
    },
    onSuccess: () => { setDeleteDialog(false); setConfirmation(""); setDeleteMessage("Workspace scan data deleted."); void client.resetQueries({ queryKey: ["live"] }); },
    onError: () => { void client.invalidateQueries({ queryKey: ["live"] }); },
  });
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
  const showWorkspaceTools = !demo && !!me.data && !me.error && (me.data as Me & { auth_kind?: string }).auth_kind !== "api_key";
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
      <div className={`settings-grid${showWorkspaceTools ? "" : " settings-grid-single"}`}>
      <div className="settings-column">
      <Panel title="Account & quota" kicker="WORKSPACE" className="account-panel">
        {me.isPending ? <State loading /> : authRequired ? (
          <div className="account-details">
            <p>Sign in to view your account and assessment quota.</p>
            <div className="button-row">
              <a className="button primary" href={authLink("login")}>Sign in <ExternalLink size={13} /></a>
              <a className="button" href={authLink("register")}>Create account <ExternalLink size={13} /></a>
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
            {used !== undefined && limit !== undefined ? <div className="quota-summary"><p className="muted">Assessments used this week</p><p className="quota-value">{used} <span>/ {limit}</span></p><div className="quota-segments" aria-hidden="true">{Array.from({ length: 5 }, (_, index) => <span key={index} className={index < Math.ceil(5 * used / Math.max(1, limit)) ? "used" : ""} />)}</div></div> : <p className="muted">Weekly assessment quota was not supplied by this API.</p>}
            {localMode && !demo && <button className="text-button small" onClick={() => setTokenDialog(true)}>Manage local API token</button>}
          </div>
        )}
      </Panel>
      {showWorkspaceTools && <CodexSettings />}
      {showWorkspaceTools && (workspaceId === "personal" || workspaces.data?.items.some(workspace => workspace.id === workspaceId && workspace.role === "admin")) && <Panel title="Delete workspace data" kicker="DATA">
        <p className="muted small">Permanently remove all scans, evidence, connectors, stored cloud credentials and schedules in this workspace. Your account, membership, API keys and billing stay in place. Cloud resources are not changed.</p>
        {deleteMessage && <p role="status">{deleteMessage}</p>}
        <button className="button danger" onClick={() => { cleanup.reset(); setConfirmation(""); setDeleteDialog(true); }}>Delete workspace data</button>
      </Panel>}
      </div>
      {showWorkspaceTools && <div className="settings-column"><Workspaces me={me.data} workspaceId={workspaceId} onWorkspaceCreated={onWorkspaceCreated} /><ApiKeys /></div>}
      </div>
      {deleteDialog && <Inspector title="Delete workspace data" onClose={() => { if (!cleanup.isPending) setDeleteDialog(false); }}>
        <div className="form">
        <p>This permanently deletes the selected workspace’s scans, evidence, connectors, stored cloud credentials and schedules. It cannot be undone. Cancel active scans first.</p>
        <label>Type DELETE to confirm<input aria-label="Type DELETE to confirm" value={confirmation} disabled={cleanup.isPending} onChange={event => setConfirmation(event.target.value)} /></label>
        {cleanup.error && <p role="alert">{humanError(cleanup.error)} Some completed deletions may already have taken effect; you can retry.</p>}
        <button className="button danger" disabled={confirmation !== "DELETE" || cleanup.isPending} onClick={() => cleanup.mutate()}>{cleanup.isPending ? "Deleting workspace data…" : "Permanently delete workspace data"}</button>
        </div>
      </Inspector>}
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
