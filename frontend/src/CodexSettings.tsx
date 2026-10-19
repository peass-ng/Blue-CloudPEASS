import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { json, request, useApi } from "./api";
import { Panel, State, humanError } from "./ui";
type Login = { verification_url: string; user_code: string; interval: number; expires_at: number };
export function CodexSettings() {
  const connection = useApi<{ connected: boolean; source: string; platform_configured: boolean; available: boolean; isolation_available?: boolean }>("/ai/codex", false);
  const [login, setLogin] = useState<Login>();
  const [message, setMessage] = useState("");
  const start = useMutation({ mutationFn: () => request<Login>("/ai/codex/login", json({})), onSuccess: value => { setLogin(value); setMessage(""); } });
  const disconnect = useMutation({ mutationFn: () => request("/ai/codex", { method: "DELETE" }), onSuccess: () => { setLogin(undefined); setMessage(""); void connection.refetch(); } });
  useEffect(() => {
    if (!login) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      if (!login || stopped) return;
      if (Date.now() / 1000 >= login.expires_at) { setLogin(undefined); setMessage("Sign-in expired. Try again."); return; }
      try {
        const result = await request<{ status: string }>("/ai/codex/login/poll", json({}));
        if (stopped) return;
        if (result.status === "connected") { setLogin(undefined); void connection.refetch(); return; }
      } catch (error) { if (!stopped) { setMessage(humanError(error)); setLogin(undefined); } return; }
      if (!stopped) timer = setTimeout(() => void poll(), login.interval * 1000);
    }
    timer = setTimeout(() => void poll(), login.interval * 1000);
    return () => { stopped = true; clearTimeout(timer); };
  }, [login]);
  return <Panel title="AI review · Codex">
    <p>AI can recheck failed findings and recommend up to 15 prioritized security actions after each scan.</p>
    {connection.error ? <State error={connection.error} onRetry={() => void connection.refetch()} /> : <p>{connection.data?.isolation_available === false ? "AI review is unavailable until the platform administrator configures isolated agent execution. Connecting Codex does not remove this requirement." : connection.data?.available ? connection.data.connected ? "Your Codex account is connected. Scans you launch use your account." : "Scans use the platform Codex account by default." : connection.data?.connected ? "Your Codex connection is unavailable. Reconnect to enable AI review." : "Connect Codex to enable AI review."}</p>}
    <p className="muted small">AI-enabled scans share scan evidence with Codex and allow read-only verification of the scanned cloud accounts. You can turn AI off when launching or scheduling a scan.</p>
    {login && <div role="status"><p>Open <a href={login.verification_url} target="_blank" rel="noreferrer">Codex sign-in</a> and enter <strong>{login.user_code}</strong>.</p><p>Waiting for sign-in. The code expires in 15 minutes. Enable device code login in your ChatGPT security settings if needed.</p></div>}
    {message && <p role="alert">{message}</p>}
    {(start.error || disconnect.error) && <p role="alert">{humanError(start.error || disconnect.error)}</p>}
    <div className="button-row"><button className="button" disabled={start.isPending || !!login || disconnect.isPending} onClick={() => start.mutate()}>{connection.data?.connected ? "Reconnect Codex" : "Sign in with Codex"}</button>
    {(connection.data?.connected || login) && <button className="button" disabled={disconnect.isPending} onClick={() => disconnect.mutate()}>{login ? "Cancel sign-in" : "Disconnect Codex"}</button>}</div>
  </Panel>;
}
