import { useEffect, useState } from "react";
import { ShieldAlert, CheckCircle2 } from "lucide-react";
import { items, json, request, useApi } from "./api";
import type { Connector } from "./types";
import { Panel, State } from "./ui";

type SourceKind = "aws_event_history" | "aws_cloudtrail_s3" | "gcp_audit" | "gke_audit" | "azure_activity_log" | "entra_directory_audit";
type Access = { status: "pass" | "warning" | "blocked"; source_status?: string; reason?: string; note?: string; account_id?: string; project_id?: string; subscription_id?: string; coverage?: string | Record<string, unknown>; check_token?: string };
type Detection = { rule_id: string; title: string; description: string; legitimate_context: string[]; severity: string; technique_id: string; event_id?: string; event_time?: string; account_id?: string; actor_id?: string; target_id?: string; evidence: Record<string, unknown> };
type Analysis = { coverage: { events_read: number; objects_read?: number; truncated: boolean; source?: SourceKind; region?: string; detection_status?: string }; detections: Detection[] };

export function AttackAnalysis({ demo, canWrite, onNavigate }: { demo: boolean; canWrite: boolean; onNavigate: (page: string) => void }) {
  const connectors = useApi<{ items: Connector[] }>("/connectors", demo, !demo);
  const [connectorId, setConnectorId] = useState("");
  const [kind, setKind] = useState<SourceKind>("aws_event_history");
  const [region, setRegion] = useState("us-east-1");
  const [roleArn, setRoleArn] = useState("");
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("");
  const [kmsKeyArn, setKmsKeyArn] = useState("");
  const [day, setDay] = useState(() => new Date().toISOString().slice(0, 10));
  const [projectId, setProjectId] = useState("");
  const [clusterId, setClusterId] = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");
  const [access, setAccess] = useState<Access | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [busy, setBusy] = useState<"check" | "run" | null>(null);
  const [error, setError] = useState("");
  const liveConnectors = items(connectors.data).filter((item) => ["aws", "gcp", "azure"].includes(item.provider) && item.input_mode === "live");
  const selected = liveConnectors.find((item) => item.id === connectorId);
  const provider = selected?.provider || "aws";
  const roles = selected?.onboarding?.target_role_arns || [];
  const roleName = /^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/.test(roleArn) ? roleArn.split("/").pop() || "" : "";
  const usesAccessKeys = Array.isArray(selected?.auth?.fields) && selected.auth.fields.includes("aws_access_key_id") && !selected.auth.fields.includes("role_arn");
  const validKmsKeyArn = /^arn:aws:kms:[a-z0-9-]+:\d{12}:key\/[A-Za-z0-9-]+$/.test(kmsKeyArn);
  const s3Policy = bucket && prefix && (!kmsKeyArn || validKmsKeyArn) ? JSON.stringify({ Version: "2012-10-17", Statement: [
    { Sid: "ListSelectedCloudTrailPrefix", Effect: "Allow", Action: "s3:ListBucket", Resource: `arn:aws:s3:::${bucket}`, Condition: { StringLike: { "s3:prefix": `${prefix}*` } } },
    { Sid: "ReadSelectedCloudTrailObjects", Effect: "Allow", Action: "s3:GetObject", Resource: `arn:aws:s3:::${bucket}/${prefix}*` },
    ...(validKmsKeyArn ? [{ Sid: "DecryptSelectedCloudTrailKey", Effect: "Allow", Action: "kms:Decrypt", Resource: kmsKeyArn }] : []),
  ] }, null, 2) : "";
  const awsIdentityCommand = roleName ? `--role-name '${roleName}'` : usesAccessKeys ? "--user-name 'REPLACE_WITH_IAM_USER_NAME'" : "";
  const awsPermissionCommand = awsIdentityCommand && (kind === "aws_event_history"
    ? `aws iam attach-${roleName ? "role" : "user"}-policy ${awsIdentityCommand} --policy-arn arn:aws:iam::aws:policy/AWSCloudTrail_ReadOnlyAccess`
    : s3Policy ? `cat > hacktricks-cspm-cloudtrail-logs.json <<'JSON'\n${s3Policy}\nJSON\naws iam put-${roleName ? "role" : "user"}-policy ${awsIdentityCommand} --policy-name HackTricksCspmCloudTrailLogs --policy-document file://hacktricks-cspm-cloudtrail-logs.json` : "") || "";
  const gcpPrincipal = selected?.gcp_onboarding?.service_account_email || "REPLACE_WITH_CONNECTOR_SERVICE_ACCOUNT_EMAIL";
  const gcpPermissionCommand = /^[a-z][a-z0-9-]{4,79}$/.test(projectId) ? `gcloud projects add-iam-policy-binding '${projectId}' --member='serviceAccount:${gcpPrincipal}' --role='roles/logging.viewer'\ngcloud projects add-iam-policy-binding '${projectId}' --member='serviceAccount:${gcpPrincipal}' --role='roles/logging.privateLogViewer'` : "";
  const azurePermissionCommand = kind === "azure_activity_log" && /^[0-9a-fA-F-]{36}$/.test(subscriptionId) ? `az role assignment create --assignee 'REPLACE_WITH_CONNECTOR_PRINCIPAL_OBJECT_ID' --role 'Monitoring Reader' --scope '/subscriptions/${subscriptionId}'` : "";
  const permissionCommand = provider === "aws" ? awsPermissionCommand : provider === "gcp" ? gcpPermissionCommand : azurePermissionCommand;
  useEffect(() => { if (!connectorId && liveConnectors[0]) setConnectorId(liveConnectors[0].id); }, [connectorId, liveConnectors]);
  useEffect(() => { setAccess(null); setAnalysis(null); setError(""); }, [connectorId, kind, region, roleArn, bucket, prefix, day, projectId, clusterId, subscriptionId]);
  const source = { connector_id: connectorId, kind, region: region.trim(), role_arn: roleArn || null,
    ...(kind === "aws_cloudtrail_s3" ? { bucket: bucket.trim(), prefix: prefix.trim(), day } : {}),
    ...(kind === "gcp_audit" || kind === "gke_audit" ? { project_id: projectId.trim(), cluster_id: kind === "gke_audit" ? clusterId.trim() || null : null } : {}),
    ...(kind === "azure_activity_log" ? { subscription_id: subscriptionId.trim() } : {}) };

  async function checkAccess() {
    setBusy("check"); setError(""); setAccess(null); setAnalysis(null);
    try { setAccess(await request<Access>("/attack-analysis/check-access", json(source))); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not check log access."); }
    finally { setBusy(null); }
  }
  async function analyze() {
    if (!access?.check_token) return;
    setBusy("run"); setError("");
    try { setAnalysis(await request<Analysis>("/attack-analysis/run", json({ ...source, check_token: access.check_token }))); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Log analysis failed."); }
    finally { setBusy(null); }
  }
  function downloadAnalysis() {
    if (!analysis) return;
    const blob = new Blob([JSON.stringify({ source, ...analysis }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `hacktricks-cspm-attack-analysis-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  if (demo) return <Panel><div className="state"><ShieldAlert size={28} /><h3>Sign in to review audit logs</h3><p>Connect your cloud account to analyze its audit logs.</p></div></Panel>;
  return <div className="attack-analysis">
    <Panel>
      <div className="attack-intro"><ShieldAlert size={22} /><div><h2>Find suspicious actions in audit logs</h2><p>Review concrete permission changes and credential activity. A matching event needs human investigation; it does not prove malicious intent.</p></div></div>
      <State loading={connectors.isPending} error={connectors.error} onRetry={() => void connectors.refetch()}>
        <div className="attack-form-grid">
          <label>Connector<select value={connectorId} onChange={(event) => { const next = liveConnectors.find((item) => item.id === event.target.value); setConnectorId(event.target.value); setRoleArn(""); setKind(next?.provider === "gcp" ? "gcp_audit" : next?.provider === "azure" ? "azure_activity_log" : "aws_event_history"); setProjectId(next?.provider === "gcp" ? (next.scopes[0] || "").replace(/^projects\//, "") : ""); setSubscriptionId(next?.provider === "azure" ? (next.scopes[0] || "").replace(/^\/subscriptions\//, "") : ""); }}><option value="">Choose a connector</option>{liveConnectors.map((connector) => <option key={connector.id} value={connector.id}>{connector.name} · {connector.provider.toUpperCase()}</option>)}</select></label>
          <label>Audit source<select value={kind} onChange={(event) => setKind(event.target.value as SourceKind)}>{provider === "aws" ? <><option value="aws_event_history">AWS Event History · last 90 days</option><option value="aws_cloudtrail_s3">CloudTrail files in S3</option></> : provider === "gcp" ? <><option value="gcp_audit">GCP Audit Logs</option><option value="gke_audit">GKE Kubernetes audit logs</option></> : <><option value="azure_activity_log">Azure Activity Log</option><option value="entra_directory_audit">Microsoft Entra directory audit · Global Administrator grants</option></>}</select></label>
          {provider === "aws" && <><label>AWS Region<input value={region} onChange={(event) => setRegion(event.target.value)} placeholder="us-east-1" /></label>{roles.length > 0 ? <label>Account role<select value={roleArn} onChange={(event) => setRoleArn(event.target.value)}><option value="">Choose an account role</option>{roles.map((role) => <option key={role} value={role}>{role}</option>)}</select></label> : <label>Account role ARN, if this connector uses a target role<input value={roleArn} onChange={(event) => setRoleArn(event.target.value)} placeholder="arn:aws:iam::123456789012:role/ReadOnly" /></label>}</>}
          {kind === "aws_cloudtrail_s3" && <><label>S3 bucket<input value={bucket} onChange={(event) => setBucket(event.target.value)} placeholder="security-log-archive" /></label><label>CloudTrail base prefix<input value={prefix} onChange={(event) => setPrefix(event.target.value)} placeholder="AWSLogs/123456789012/CloudTrail/" /></label><label>Log day<input type="date" value={day} max={new Date().toISOString().slice(0, 10)} onChange={(event) => setDay(event.target.value)} /></label><label>KMS key ARN, if encrypted<input value={kmsKeyArn} onChange={(event) => setKmsKeyArn(event.target.value)} placeholder="arn:aws:kms:us-east-1:123456789012:key/..." /></label></>}
          {provider === "gcp" && <><label>Project ID<input value={projectId} onChange={(event) => setProjectId(event.target.value)} placeholder="customer-project-id" /></label>{kind === "gke_audit" && <label>GKE cluster name<input value={clusterId} onChange={(event) => setClusterId(event.target.value)} placeholder="production-cluster" /></label>}</>}
          {kind === "azure_activity_log" && <label>Subscription ID<input value={subscriptionId} onChange={(event) => setSubscriptionId(event.target.value)} placeholder="00000000-0000-0000-0000-000000000000" /></label>}
        </div>
        {kind === "aws_cloudtrail_s3" && <p className="muted small">Enter the base prefix ending in CloudTrail/ for the target account; the Region and day are appended automatically. Organization trails may reside in a separate logging account. The connector role needs s3:ListBucket on the bucket, s3:GetObject on the files and kms:Decrypt on the KMS key when encrypted.</p>}
        {kind === "aws_cloudtrail_s3" && kmsKeyArn && !validKmsKeyArn && <p className="form-error">Enter a complete KMS key ARN to generate the permission command.</p>}
        {kind === "aws_event_history" && <p className="muted small">No bucket is needed. The connector role needs cloudtrail:LookupEvents. Event History covers management events in this Region for up to 90 days; data events require a trail or another log destination.</p>}
        {provider === "gcp" && <p className="muted small">The project must be accessible to this GCP connector. GKE audit logs are read from Cloud Logging; a Kubernetes API connector alone does not expose audit logs. This preview reads a bounded recent window.</p>}
        {kind === "azure_activity_log" && <p className="muted small">Azure Activity Log records subscription control-plane activity. This preview reviews confirmed Owner or User Access Administrator self-assignments and successful deletions of subscription Activity Log export settings.</p>}
        {kind === "entra_directory_audit" && <p className="muted small">This reads Microsoft Graph directory audits for the connector tenant. The current rule reviews successful direct Global Administrator grants to the acting user. Other Entra activities are outside this analysis.</p>}
        <details className="attack-permissions"><summary>How to grant log access</summary><p>{provider === "aws" ? kind === "aws_event_history" ? "The hosted customer-role template already includes cloudtrail:LookupEvents. For a manually managed role or IAM user missing it, attach the AWS managed CloudTrail read-only policy in the target account. If the connector uses temporary credentials, grant the permission to their source role." : "Add this narrow S3 read policy to the account role or IAM user. A central bucket policy must also permit that identity. SSE-KMS objects additionally require kms:Decrypt in IAM and the KMS key policy. For temporary credentials, grant the permission to their source role." : provider === "gcp" ? "Grant the connector service account Logging Viewer on the selected project. Private Log Viewer is also needed for Data Access records. Replace the placeholder email if this is a manually configured identity." : kind === "entra_directory_audit" ? "Grant the connector application Microsoft Graph AuditLog.Read.All application permission and tenant admin consent. Azure subscription roles do not grant access to Entra directory audits." : "Grant Monitoring Reader at the selected subscription to the connector principal. Replace the object ID placeholder with the identity used by this connector."}</p>{permissionCommand ? <><pre>{permissionCommand}</pre><button className="button" type="button" onClick={() => void navigator.clipboard.writeText(permissionCommand)}>Copy CLI</button></> : kind !== "entra_directory_audit" && <p>Choose the required source details to show a command.</p>}</details>
        <div className="button-row"><button className="button" type="button" onClick={() => onNavigate("Connectors")}>Create or edit connector</button><button className="button" type="button" disabled={!canWrite || !connectorId || busy !== null} onClick={() => void checkAccess()}>{busy === "check" ? "Checking…" : "Check log access"}</button><button className="button primary" type="button" disabled={!canWrite || access?.status !== "pass" || busy !== null} onClick={() => void analyze()}>{busy === "run" ? "Analyzing…" : "Start analysis"}</button></div>
        {!liveConnectors.length && <p className="form-error">Create a live AWS, GCP or Azure connector to begin.</p>}
        {error && <p className="form-error" role="alert">{error}</p>}
        {access && <div className={`attack-access ${access.status}`} role="status">{access.status === "pass" ? <CheckCircle2 size={18} /> : <ShieldAlert size={18} />}<div><strong>{access.status === "pass" ? `Log access verified · ${access.account_id || access.project_id || access.subscription_id || "selected scope"}` : kind === "entra_directory_audit" && access.source_status === "accessible" ? "Directory audit access verified" : access.status === "warning" ? "Log source is empty" : access.source_status === "accessible" ? "Analysis unavailable" : "Log access blocked"}</strong><p>{access.reason || access.note || (typeof access.coverage === "string" ? access.coverage : "")}</p></div></div>}
      </State>
    </Panel>
    {analysis && <Panel><div className="attack-result-heading"><h2>Analysis results</h2><button className="button" type="button" onClick={downloadAnalysis}>Download results</button></div><p>{analysis.coverage.events_read.toLocaleString()} events read{analysis.coverage.objects_read ? ` from ${analysis.coverage.objects_read} objects` : ""} · {analysis.detections.length} actions to review</p>{analysis.coverage.truncated && <p className="form-error">This bounded preview stopped at its event, page or size limit. It does not cover the entire source.</p>}{analysis.coverage.detection_status === "not_implemented" && <p>Log access was verified, but no reviewed detection rule runs on this source yet.</p>}{analysis.coverage.detection_status === "global_admin_self_grants_only" && <p>Entra coverage currently includes direct Global Administrator self-grants only.</p>}{!analysis.detections.length && analysis.coverage.detection_status !== "not_implemented" && <p>No matching actions in the events read. This does not establish that the account is attack free.</p>}<div className="attack-results">{analysis.detections.map((item, index) => <article className="attack-result" key={`${item.event_id || index}:${item.rule_id}:${item.target_id || ""}`}><span className="badge">{item.severity}</span><div><h3>{item.title}</h3><p>{item.actor_id || "Unknown actor"} → {item.target_id || "Unknown target"}</p><small>{item.event_time ? `${item.event_time} · ` : ""}Event {item.event_id || "ID unavailable"} · Scope {item.account_id || "unknown"}</small><small>Rule {item.rule_id} · HackTricks technique {item.technique_id}</small><p>{item.description}</p>{item.legitimate_context.length > 0 && <details><summary>Possible authorized context</summary><ul>{item.legitimate_context.map((context) => <li key={context}>{context}</li>)}</ul></details>}<details><summary>Evidence used</summary><pre>{JSON.stringify(item.evidence, null, 2)}</pre></details></div></article>)}</div></Panel>}
    <Panel><h2>Coverage boundaries</h2><p>Each run reads at most 2,000 events, and an S3 run reads at most five objects. Entra currently reviews direct Global Administrator self-grants; exported Log Analytics data and generic Kubernetes file/webhook audit backends need separate integrations. A successful check proves source readability, not complete logging or absence of attacks.</p></Panel>
  </div>;
}
