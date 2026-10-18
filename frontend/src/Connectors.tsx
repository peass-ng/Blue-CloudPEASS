import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2, KeyRound, Check, Copy } from "lucide-react";
import { items, json, request, useApi } from "./api";
import { authGuides, gcpRoles } from "./authGuides";
import { providers } from "./types";
import type { Connector, Me, Provider } from "./types";
import { Badge, humanError, Inspector, Panel, ProviderIcon, State } from "./ui";
const COLLECTOR_ROLE_ARN = "arn:aws:iam::202533532952:role/HackTricks-CSPM";
const ROLE_ARN = /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/;
const TEMPLATE_URL = "https://cspm.hacktricks.wiki/aws/customer-role.json";
const BACKUP_POLICY_SCOPE = /^[0-9]{12}\/[a-z]{2}(?:-[a-z]+)+-[0-9]$/;
const K8S_NAMESPACE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const K8S_OBSERVED_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$/;
const GCP_POLICY_PROJECT = /^projects\/[A-Za-z0-9_-]+$/;
const GCP_AUDIT_SERVICES = ["spanner.googleapis.com", "pubsub.googleapis.com"] as const;
function malformedGcpDirectPrincipal(value: string): boolean {
  if (!value.startsWith("user:") && !value.startsWith("serviceAccount:")) return false;
  const email = value.slice(value.indexOf(":") + 1);
  const at = email.indexOf("@");
  return at <= 0 || at === email.length - 1 || email.indexOf("@", at + 1) !== -1 ||
    /[\s\x00-\x1f\x7f-\x9f]/u.test(value);
}
type GcpAuditRecord = { scope: string; service: string; sourceRef: string; principals: string };
const emptyGcpAuditRecord = (): GcpAuditRecord => ({ scope: "", service: "", sourceRef: "", principals: "" });

function savedBackupPlanPolicy(connector: Connector | null): Record<string, unknown> | null {
  const policy = connector?.options?.compliance_policy;
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) return null;
  const plan = (policy as Record<string, unknown>).aws_backup_plan;
  return plan && typeof plan === "object" && !Array.isArray(plan)
    ? plan as Record<string, unknown> : null;
}

function savedK8sNamespacePolicy(connector: Connector | null): Record<string, unknown> | null {
  if (connector?.provider !== "k8s") return null;
  const policy = connector.options?.compliance_policy;
  return policy && typeof policy === "object" && !Array.isArray(policy)
    ? policy as Record<string, unknown> : null;
}

function savedGcpAuditPolicy(connector: Connector | null): GcpAuditRecord[] | null {
  if (connector?.provider !== "gcp") return null;
  const records = connector.options?.gcp_data_access_required_principals;
  if (!Array.isArray(records)) return null;
  return records.map((value) => {
    const row = value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown> : {};
    return {
      scope: typeof row.scope === "string" ? row.scope : "",
      service: typeof row.service === "string" ? row.service : "",
      sourceRef: typeof row.source_ref === "string" ? row.source_ref : "",
      principals: Array.isArray(row.principals) && row.principals.every((p) => typeof p === "string")
        ? row.principals.join("\n") : "",
    };
  });
}

function roleTargets(lines: string, hosted: boolean) {
  const targets: { role_arn: string; external_id?: string }[] = [];
  const seen = new Set<string>();
  for (const line of lines.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const parts = line.split("|").map((part) => part.trim());
    if (parts.length > 2 || !ROLE_ARN.test(parts[0]) || (hosted && parts.length > 1))
      throw new Error("Enter one valid AWS role ARN per line" + (hosted ? "." : "; optional External ID follows |."));
    if (parts[1] && (parts[1].length < 2 || parts[1].length > 1224))
      throw new Error("Each External ID must contain 2–1224 characters.");
    if (!seen.has(parts[0])) {
      seen.add(parts[0]);
      targets.push({ role_arn: parts[0], ...(parts[1] ? { external_id: parts[1] } : {}) });
    }
  }
  if (targets.length > 50) throw new Error("Enter at most 50 distinct target roles.");
  return targets;
}
type Field = {
  key: string;
  label: string;
  secret?: boolean;
  required?: boolean;
  multiline?: boolean;
  placeholder?: string;
};
type Mode = {
  id: string;
  label: string;
  fields: Field[];
  localOnly?: boolean;
  method?: string;
};
const field = (
  key: string,
  label: string,
  required = false,
  secret = false,
  multiline = false,
): Field => ({ key, label, required, secret, multiline });
export const authModes: Record<Provider, Mode[]> = {
  aws: [
    {
      id: "default",
      label: "Default credential chain (local server)",
      fields: [],
      localOnly: true,
    },
    {
      id: "profile",
      localOnly: true,
      label: "Named profile (local server)",
      fields: [field("profile", "Profile name", true)],
    },
    {
      id: "sso",
      localOnly: true,
      label: "SSO / federated profile",
      fields: [field("profile", "Profile name", true)],
    },
    {
      id: "access_keys",
      label: "Access keys / session token",
      fields: [
        field("aws_access_key_id", "Access key ID", true, true),
        field("aws_secret_access_key", "Secret access key", true, true),
        field("aws_session_token", "Session token (optional)", false, true),
      ],
    },
    {
      id: "assume_role",
      label: "Assume role from default chain / profile",
      fields: [
        field("role_arn", "Role ARN", true),
        field("profile", "Source profile (optional)"),
        field("external_id", "External ID", false, true),
        field("role_session_name", "Session name"),
      ],
    },
    {
      id: "web_identity",
      localOnly: true,
      label: "Server web identity federation",
      fields: [],
    },
    {
      id: "container",
      localOnly: true,
      label: "Container / task role",
      fields: [],
    },
    { id: "instance", localOnly: true, label: "Instance profile", fields: [] },
  ],
  gcp: [
    {
      id: "adc",
      localOnly: true,
      label: "Application default credentials",
      fields: [],
    },
    {
      id: "gcloud",
      localOnly: true,
      label: "gcloud CLI session",
      fields: [field("account", "Account email (optional)")],
    },
    {
      id: "platform-service-account",
      label: "HackTricks CSPM service account",
      fields: [],
    },
    {
      id: "service-account",
      label: "Service account JSON",
      fields: [field("sa_json", "Service account JSON", true, true, true)],
    },
    {
      id: "impersonation",
      label: "Service account impersonation",
      fields: [
        field("target_principal", "Target service account", true),
        field("delegates", "Delegate accounts (comma separated)"),
      ],
    },
    {
      id: "external-account",
      localOnly: true,
      label: "Workload identity federation",
      fields: [
        field(
          "external_account_file",
          "External account config path on server",
          true,
        ),
      ],
    },
    {
      id: "metadata",
      localOnly: true,
      label: "Attached workload service account",
      fields: [
        field("service_account_email", "Service account email (optional)"),
      ],
    },
    {
      id: "token",
      label: "Temporary access token",
      fields: [field("token", "Access token", true, true)],
    },
  ],
  azure: [
    {
      id: "client-cert-inline",
      method: "client-cert",
      label: "Service principal certificate (inline)",
      fields: [
        field("tenant_id", "Tenant ID", true),
        field("client_id", "Client ID", true),
        field("certificate_data", "Certificate PEM", true, true, true),
        field("certificate_password", "Certificate password", false, true),
      ],
    },
    {
      id: "workload-identity-inline",
      method: "workload-identity",
      label: "Workload federation (inline assertion)",
      fields: [
        field("tenant_id", "Tenant ID", true),
        field("client_id", "Client ID", true),
        field("federated_token", "Federated OIDC assertion", true, true, true),
      ],
    },
    {
      id: "az-cli",
      localOnly: true,
      label: "Azure CLI session",
      fields: [field("tenant_id", "Tenant ID (optional)")],
    },
    {
      id: "client-secret",
      label: "Service principal secret",
      fields: [
        field("tenant_id", "Tenant ID", true),
        field("client_id", "Client ID", true),
        field("client_secret", "Client secret", true, true),
      ],
    },
    {
      id: "client-cert",
      localOnly: true,
      label: "Service principal certificate",
      fields: [
        field("tenant_id", "Tenant ID", true),
        field("client_id", "Client ID", true),
        field("certificate_path", "Certificate path on server", true),
        field("certificate_password", "Certificate password", false, true),
      ],
    },
    {
      id: "managed-identity",
      localOnly: true,
      label: "Managed identity",
      fields: [field("client_id", "User-assigned client ID (optional)")],
    },
    {
      id: "workload-identity",
      localOnly: true,
      label: "Workload identity federation",
      fields: [
        field("tenant_id", "Tenant ID", true),
        field("client_id", "Client ID", true),
        field("token_file", "Identity token path on server", true),
      ],
    },
    {
      id: "token",
      label: "Temporary ARM / Graph tokens",
      fields: [
        field("arm_token", "ARM token", true, true),
        field("graph_token", "Graph token (optional)", false, true),
      ],
    },
    {
      id: "default",
      label: "Default credential chain (local server)",
      fields: [],
      localOnly: true,
    },
  ],
  k8s: [
    {
      id: "kubeconfig-inline",
      method: "inline",
      label: "Kubeconfig YAML (inline)",
      fields: [
        field("kubeconfig_data", "Kubeconfig YAML", true, true, true),
        field("context", "Context name"),
      ],
    },
    {
      id: "certificate-inline",
      method: "client-cert",
      label: "Client certificate (inline PEM)",
      fields: [
        field("server", "HTTPS API server", true),
        field("client_cert_data", "Client certificate PEM", true, false, true),
        field("client_key_data", "Private key PEM", true, true, true),
        field(
          "ca_cert_data",
          "CA certificate PEM / base64",
          false,
          false,
          true,
        ),
      ],
    },
    {
      id: "kubeconfig",
      localOnly: true,
      label: "Kubeconfig & context",
      fields: [
        field("kubeconfig", "Kubeconfig path on server"),
        field("context", "Context name"),
      ],
    },
    {
      id: "in_cluster",
      localOnly: true,
      label: "In-cluster identity",
      fields: [],
    },
    {
      id: "token",
      label: "API server & bearer token",
      fields: [
        field("server", "HTTPS API server", true),
        field("token", "Bearer token", true, true),
        field(
          "ca_cert_data",
          "CA certificate PEM / base64",
          false,
          false,
          true,
        ),
      ],
    },
    {
      id: "certificate",
      localOnly: true,
      label: "Client certificate",
      fields: [
        field("server", "HTTPS API server", true),
        field("client_cert", "Client certificate path on server", true),
        field("client_key", "Client private key path on server", true),
        field(
          "ca_cert_data",
          "CA certificate PEM / base64",
          false,
          false,
          true,
        ),
      ],
    },
  ],
};
for (const { id: provider } of providers) {
  for (const mode of authModes[provider]) {
    if (!authGuides[provider][mode.id]) throw new Error(`Missing ${provider} authentication setup guide for ${mode.id}`);
  }
}
export function Connectors({ demo, canWrite = true }: { demo: boolean; canWrite?: boolean }) {
  const query = useApi<{ items: Connector[] }>("/connectors", demo);
  const client = useQueryClient();
  const [edit, setEdit] = useState<Connector | null | undefined>();
  const [onboarding, setOnboarding] = useState<Connector>();
  const [remove, setRemove] = useState<Connector>();
  const del = useMutation({
    mutationFn: (id: string) =>
      request(
        `/connectors/${encodeURIComponent(id)}`,
        { method: "DELETE" },
        demo,
      ),
    onSuccess: () => {
      setRemove(undefined);
      void client.invalidateQueries({
        queryKey: [demo ? "demo" : "live"],
      });
    },
  });
  return (
    <>
      <div className="section-top">
        <p>Give HackTricks CSPM a read-only view of your environments.</p>
        <button
          className="button primary"
          disabled={demo || !canWrite}
          onClick={() => setEdit(null)}
        >
          <Plus size={16} />
          Add connector
        </button>
      </div>
      <div className="provider-grid">
        {providers.map((p) => (
          <div className="provider-summary" key={p.id}>
            <ProviderIcon provider={p.id} />
            <div>
              <strong>{p.name}</strong>
              <span>{p.detail}</span>
            </div>
            <span className="provider-count">
              {items(query.data).filter((c) => c.provider === p.id).length}
            </span>
          </div>
        ))}
      </div>
      <Panel title="Connected environments" kicker="YOUR CLOUD ESTATE">
        <State
          loading={query.isPending}
          error={query.error}
          onRetry={() => void query.refetch()}
          empty={!query.isPending && !query.error && !items(query.data).length}
          title="Connect your first environment"
        >
          <button
            className="button primary"
            disabled={demo || !canWrite}
            onClick={() => setEdit(null)}
          >
            Add a connector
          </button>
        </State>
        {items(query.data).length > 0 && (
          <div className="card-list">
            {items(query.data).map((c) => (
              <article className="connector-card" key={c.id}>
                <ProviderIcon provider={c.provider} size={36} />
                <div className="grow">
                  <h3>{c.name}</h3>
                  <p>
                    {c.scopes?.join(" · ") || "Default accessible scope"} ·{" "}
                    {c.auth_mode ||
                      String(c.auth?.mode || "Configured credentials")}
                  </p>
                </div>
                <Badge
                  value={
                    c.input_mode && c.input_mode !== "live"
                      ? c.input_mode
                      : c.status || "configured"
                  }
                />
                {(c.onboarding || c.gcp_onboarding) && (
                  <button className="button" onClick={() => setOnboarding(c)}>
                    Onboarding
                  </button>
                )}
                <button
                  className="icon-button"
                  aria-label={`Edit ${c.name}`}
                  disabled={demo || !canWrite}
                  onClick={() => setEdit(c)}
                >
                  <Pencil size={17} />
                </button>
                <button
                  className="icon-button danger"
                  aria-label={`Delete ${c.name}`}
                  disabled={demo || !canWrite}
                  onClick={() => setRemove(c)}
                >
                  <Trash2 size={17} />
                </button>
              </article>
            ))}
          </div>
        )}
      </Panel>
      <div className="notice">
        <KeyRound size={19} />
        <p>
          Credentials are encrypted by the API, redacted in responses, and
          cleared from this form after submission. Default chains and local
          profiles run on the server hosting HackTricks CSPM.
        </p>
      </div>
      {onboarding && (
        <Inspector
          title={onboarding.gcp_onboarding ? "Google Cloud onboarding" : "Hosted role onboarding"}
          onClose={() => setOnboarding(undefined)}
        >
          {onboarding.gcp_onboarding
            ? <GcpOnboarding details={onboarding.gcp_onboarding} />
            : <HostedOnboarding details={onboarding.onboarding!} />}
        </Inspector>
      )}
      {edit !== undefined && (
        <ConnectorForm
          connector={edit}
          demo={demo}
          onClose={() => setEdit(undefined)}
        />
      )}
      {remove && (
        <Inspector
          title="Remove connector"
          onClose={() => setRemove(undefined)}
        >
          <p>
            Remove “{remove.name}”? Existing scan evidence is retained by the
            API.
          </p>
          {del.error && <p role="alert">{humanError(del.error)}</p>}
          <button
            className="button danger"
            disabled={del.isPending}
            onClick={() => del.mutate(remove.id)}
          >
            Remove connector
          </button>
        </Inspector>
      )}
    </>
  );
}
function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return <div>
    <strong>{label}</strong>
    <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{value}</pre>
    <button type="button" className="button" onClick={() => {
      void navigator.clipboard.writeText(value).then(() => setCopied(true));
    }}>{copied ? "Copied" : `Copy ${label}`}</button>
  </div>;
}
function GuideCommand({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return <div className="auth-guide-command">
    <div className="auth-guide-command-heading">
      <strong>{label.replace(/^(AWS CLI|Azure CLI|gcloud CLI|kubectl): /, "")}</strong>
      <button type="button" aria-label={`Copy ${label}`} onClick={() => {
        void navigator.clipboard.writeText(value).then(() => setCopied(true)).catch(() => setCopied(false));
      }}><Copy size={15} aria-hidden="true" />{copied ? "Copied" : "Copy"}</button>
    </div>
    <pre>{value}</pre>
  </div>;
}
type PreparedSetup = { prepared_id: string; external_id?: string; collector_role_arn?: string; template_url?: string; service_account_email?: string; project_label_key?: string; project_label_value?: string };
type AccessCheck = { status: "pass" | "warning" | "blocked"; check_token?: string; issues: { severity: "critical" | "advisory"; scope: string; message: string }[]; principals: { scope: string; principal: string }[] };
function AuthSetupGuide({ provider, method, label, hosted, prepared }: { provider: Provider; method: string; label: string; hosted: boolean; prepared?: PreparedSetup | null }) {
  const guide = authGuides[provider][method];
  const hostedAwsRole = hosted && provider === "aws" && method === "assume_role";
  const hostedGcp = hosted && provider === "gcp" && method === "platform-service-account";
  const externalId = prepared?.external_id || "REPLACE_WITH_EXTERNAL_ID_FROM_THIS_GUIDE";
  const collectorArn = prepared?.collector_role_arn || COLLECTOR_ROLE_ARN;
  const hostedAwsAccess = { label: "AWS CLI: create role and grant access", value: [
    `curl -fsSL '${prepared?.template_url || TEMPLATE_URL}' -o hacktricks-cspm-customer-role.json`,
    `aws cloudformation create-stack --stack-name HackTricksCspmReadOnly --template-body file://hacktricks-cspm-customer-role.json --capabilities CAPABILITY_NAMED_IAM --parameters ParameterKey=ExternalId,ParameterValue=${externalId}`,
  ].join("\n") };
  const gcpEmail = prepared?.service_account_email || "hacktricks-cspm-sa-acc-third-p@billing-static-info-no-delete.iam.gserviceaccount.com";
  const gcpKey = prepared?.project_label_key || "REPLACE_WITH_CONNECTOR_APPROVAL_LABEL";
  const gcpAccess = { label: "gcloud CLI: approve customer project for this connector", value: [
    `gcloud alpha projects update REPLACE_WITH_CUSTOMER_PROJECT_ID --update-labels='${gcpKey}=approved'`,
  ].join("\n") };
  const gcpGrant = { label: "gcloud CLI: grant project inventory roles", value: [
    `for ROLE in ${gcpRoles.join(" ")}; do`,
    `  gcloud projects add-iam-policy-binding REPLACE_WITH_CUSTOMER_PROJECT_ID --member=serviceAccount:${gcpEmail} --role="$ROLE" --quiet`,
    "done",
  ].join("\n") };
  const accessCommands = hostedAwsRole ? [hostedAwsAccess] : hostedGcp ? [gcpAccess] : guide.commands.slice(0, guide.accessCommandCount);
  const grantCommands = hostedGcp ? [gcpGrant] : guide.commands.slice(guide.accessCommandCount);
  return <details key={`${provider}-${method}`} className="auth-setup-guide">
    <summary>How to set up {label}</summary>
    <div className="auth-guide-content">
      <section className="auth-guide-step">
        <span className="auth-guide-step-number">1</span>
        <div className="auth-guide-step-body">
          <h4>{hostedAwsRole ? "Create role and grant access" : "Create access"}</h4><p>{hostedAwsRole ? `In each customer AWS account, review and deploy the template. It creates a role that trusts ${collectorArn} using this connector's External ID, and attaches all four collector read policies. Enter the resulting role ARN below.` : hostedGcp ? `The scanning identity already exists: ${gcpEmail}. Add this connector's approval label to each customer project. The platform project is excluded.` : guide.access}</p>
          {accessCommands.map((command) => <GuideCommand key={command.label} label={command.label} value={command.value} />)}
        </div>
      </section>
      {!hostedAwsRole && <section className="auth-guide-step">
        <span className="auth-guide-step-number">2</span>
        <div className="auth-guide-step-body">
          <h4>Grant permissions</h4>
          <p>{hostedGcp ? "Grant the shared scanning service account these seven project roles in each customer project. Repeat for each selected project." : guide.permissions}</p>
          {guide.permissionIds && <ul className="auth-guide-policy-list">
            {guide.permissionIds.map((id) => <li key={id}><code>{id}</code></li>)}
          </ul>}
          {grantCommands.map((command) => <GuideCommand key={command.label} label={command.label} value={command.value} />)}
        </div>
      </section>}
      {guide.optionalSetup && <details className="auth-guide-optional">
        <summary>{guide.optionalSetup.title}</summary>
        <p>{guide.optionalSetup.description}</p>
        {guide.optionalSetup.commands.map((command) => <GuideCommand key={command.label} label={command.label} value={command.value} />)}
      </details>}
      <a className="auth-guide-link" href={guide.url} target="_blank" rel="noopener noreferrer">{guide.link} ↗</a>
    </div>
  </details>;
}
function HostedOnboarding({ details }: { details: NonNullable<Connector["onboarding"]> }) {
  const trust = JSON.stringify({ Version: "2012-10-17", Statement: [{
    Effect: "Allow", Principal: { AWS: details.collector_role_arn || COLLECTOR_ROLE_ARN },
    Action: "sts:AssumeRole", Condition: { StringEquals: { "sts:ExternalId": details.external_id } },
  }] }, null, 2);
  const template = details.template_url || TEMPLATE_URL;
  const quickCreate = details.quick_create_template_url
    ? `https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=${encodeURIComponent(details.quick_create_template_url)}&stackName=HackTricksCspmReadOnly&param_ExternalId=${encodeURIComponent(details.external_id)}`
    : null;
  const cli = `curl -fsSL '${template}' -o hacktricks-cspm-customer-role.json\naws cloudformation create-stack --stack-name HackTricksCspmReadOnly --template-body file://hacktricks-cspm-customer-role.json --capabilities CAPABILITY_NAMED_IAM --parameters ParameterKey=ExternalId,ParameterValue=${details.external_id}`;
  return <div className="form">
    <p>Trust the HackTricks CSPM IAM collector role in each target account. The server generated this connector’s ExternalID.</p>
    <CopyValue label="Collector role ARN" value={details.collector_role_arn || COLLECTOR_ROLE_ARN} />
    <CopyValue label="ExternalID" value={details.external_id} />
    <CopyValue label="Target role ARNs" value={(details.target_role_arns || []).join("\n")} />
    <section className="evidence-policy-statement">
      <h3>Role trust policy</h3>
      <dl className="evidence-fields">
        <div className="evidence-field"><dt>Trusted principal</dt><dd>{details.collector_role_arn || COLLECTOR_ROLE_ARN}</dd></div>
        <div className="evidence-field"><dt>Allowed action</dt><dd>Assume role</dd></div>
        <div className="evidence-field"><dt>Required condition</dt><dd>External ID must equal the value shown above.</dd></div>
      </dl>
      <button type="button" className="button" onClick={() => {
        void navigator.clipboard.writeText(trust).catch(() => {
          const url = URL.createObjectURL(new Blob([trust], { type: "application/json" }));
          const link = document.createElement("a");
          link.href = url;
          link.download = "hacktricks-cspm-role-trust-policy.json";
          link.click();
          URL.revokeObjectURL(url);
        });
      }}>Copy or download trust policy</button>
    </section>
    <p>Deploy the template in each target account. It attaches the collector's scoped inventory and configuration read policies, plus the explicitly authorized IAM credential-report generation action. Review those policies and acknowledge named IAM resources before deployment.</p>
    {quickCreate ? <a className="button" href={quickCreate} target="_blank" rel="noreferrer">Create role with CloudFormation</a>
      : <p className="muted small">Quick create becomes available after the public S3 template is enabled. Download the template and create the stack in CloudFormation meanwhile.</p>}
    <a className="button" href={template} download="customer-role.json">Download CloudFormation template</a>
    <CopyValue label="AWS CLI fallback" value={cli} />
    <p className="muted small">For several AWS accounts, deploy the same template through StackSets and use this connector’s ExternalID parameter. Add each resulting role ARN to the target list.</p>
  </div>;
}
function GcpOnboarding({ details }: { details: NonNullable<Connector["gcp_onboarding"]> }) {
  const grantCommand = [
    "PROJECT_ID='REPLACE_WITH_CUSTOMER_PROJECT_ID'",
    "SA_EMAIL='" + details.service_account_email + "'",
    "for ROLE in " + gcpRoles.join(" ") + "; do",
    '  gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$SA_EMAIL" --role="$ROLE" --quiet',
    "done",
    'gcloud alpha projects update "$PROJECT_ID" --update-labels="' + details.project_label_key + "=" + details.project_label_value + '"',
  ].join("\n");
  return <div className="form">
    <p>In each customer project, grant the HackTricks CSPM service account read access and add this connector’s project label. The label authorizes this connector to scan that project, including when you select “Discover all approved customer projects.”</p>
    <CopyValue label="Service account email" value={details.service_account_email} />
    <CopyValue label="Project label key" value={details.project_label_key} />
    <CopyValue label="Project label value" value={details.project_label_value} />
    <CopyValue label="gcloud CLI: grant roles and label this project" value={grantCommand} />
    <ol>
      <li>Run the command above for each customer project after replacing PROJECT_ID. It grants {gcpRoles.join(", ")} to this service account.</li>
      <li>On each project’s Labels page, add the label key and value above. You need permission to edit project labels to do this.</li>
      <li>Enter the project IDs in this connector, or select “Discover all approved customer projects” to include every accessible project carrying this connector’s label. Run a scan after the grants and label are visible.</li>
    </ol>
    <p className="muted small">The HackTricks CSPM service account’s own project is always excluded. A missing label or read permission prevents that project from being scanned. Scan coverage records remaining permission gaps.</p>
  </div>;
}
function ConnectorForm({
  connector,
  demo,
  onClose,
}: {
  connector: Connector | null;
  demo: boolean;
  onClose: () => void;
}) {
  const health = useApi<{ auth_mode: string }>("/health", demo);
  const me = useApi<Me>("/me", demo);
  const hosted =
    me.data?.runtime_mode === "hosted" || health.data?.auth_mode === "cognito";
  const client = useQueryClient();
  const [provider, setProvider] = useState<Provider>(
    connector?.provider || "aws",
  );
  const [mode, setMode] = useState(
    String(
      connector?.auth_mode ||
        connector?.auth?.mode ||
        authModes[provider][0].id,
    ),
  );
  const [name, setName] = useState(connector?.name || "");
  const [scopes, setScopes] = useState(connector?.scopes?.join(", ") || "");
  const [auth, setAuth] = useState<Record<string, string>>({});
  const [prepared, setPrepared] = useState<PreparedSetup | null>(null);
  const [prepareError, setPrepareError] = useState("");
  const [credentialExpiresAt, setCredentialExpiresAt] = useState("");
  const [accessResult, setAccessResult] = useState<AccessCheck | null>(null);
  const [checkedPayload, setCheckedPayload] = useState("");
  const [checkPending, setCheckPending] = useState(false);
  const [nextCheckAt, setNextCheckAt] = useState(0);
  const [clockNow, setClockNow] = useState(Date.now());
  useEffect(() => {
    if (!nextCheckAt) return;
    const timer = window.setInterval(() => setClockNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [nextCheckAt]);
  useEffect(() => {
    let cancelled = false;
    const needsPreparation = !connector && hosted && ((provider === "aws" && mode === "assume_role") ||
      (provider === "gcp" && mode === "platform-service-account"));
    setPrepared(null);
    setPrepareError("");
    if (needsPreparation && !demo) {
      void request<PreparedSetup>("/connectors/prepare", json({ provider, method: mode }, "POST"), demo)
        .then((value) => { if (!cancelled) setPrepared(value); })
        .catch((cause) => { if (!cancelled) setPrepareError(humanError(cause)); });
    }
    return () => { cancelled = true; };
  }, [connector, demo, hosted, provider, mode]);
  const [awsRoles, setAwsRoles] = useState("");
  const [includeSourceAccount, setIncludeSourceAccount] = useState(connector?.options?.include_source_account !== false);
  const [allProjects, setAllProjects] = useState(
    !!connector?.options?.all_projects,
  );
  const [regions, setRegions] = useState(
    Array.isArray(connector?.options?.regions)
      ? connector.options.regions.join(", ")
      : "",
  );
  const savedBackupPolicy = savedBackupPlanPolicy(connector);
  const savedBackupScopes = savedBackupPolicy?.applies_to;
  const [backupPolicyEnabled, setBackupPolicyEnabled] = useState(savedBackupPolicy !== null);
  const [backupFrequencyHours, setBackupFrequencyHours] = useState(
    typeof savedBackupPolicy?.required_frequency_hours === "number"
      ? String(savedBackupPolicy.required_frequency_hours) : "",
  );
  const [backupPolicyScopes, setBackupPolicyScopes] = useState(
    Array.isArray(savedBackupScopes)
      ? savedBackupScopes.filter((scope): scope is string => typeof scope === "string").join(", ") : "",
  );
  const savedK8sPolicy = savedK8sNamespacePolicy(connector);
  const savedSystemNamespaces = savedK8sPolicy?.system_namespaces;
  const [k8sPolicyEnabled, setK8sPolicyEnabled] = useState(savedK8sPolicy !== null);
  const [k8sClusterId, setK8sClusterId] = useState(
    typeof savedK8sPolicy?.cluster_id === "string" ? savedK8sPolicy.cluster_id : "",
  );
  const [k8sObservedAt, setK8sObservedAt] = useState(
    typeof savedK8sPolicy?.observed_at === "string" ? savedK8sPolicy.observed_at : "",
  );
  const [k8sMaxAge, setK8sMaxAge] = useState(
    typeof savedK8sPolicy?.max_age_seconds === "number" ? String(savedK8sPolicy.max_age_seconds) : "",
  );
  const [k8sMaxItems, setK8sMaxItems] = useState(
    typeof savedK8sPolicy?.max_policy_items === "number" ? String(savedK8sPolicy.max_policy_items) : "",
  );
  const [k8sSystemNamespaces, setK8sSystemNamespaces] = useState(
    Array.isArray(savedSystemNamespaces)
      ? savedSystemNamespaces.filter((name): name is string => typeof name === "string").join(", ") : "",
  );
  const savedGcpAudit = savedGcpAuditPolicy(connector);
  const [gcpAuditEnabled, setGcpAuditEnabled] = useState(savedGcpAudit !== null);
  const [gcpAuditRecords, setGcpAuditRecords] = useState<GcpAuditRecord[]>(
    savedGcpAudit === null ? [emptyGcpAuditRecord()] : savedGcpAudit,
  );
  const rawPsc = connector?.options?.gcp_psc_dns_policy;
  const savedPsc = rawPsc && typeof rawPsc === "object" && !Array.isArray(rawPsc)
    ? rawPsc as Record<string, unknown> : null;
  const [pscEnabled, setPscEnabled] = useState(savedPsc !== null);
  const [pscProject, setPscProject] = useState(typeof savedPsc?.scope === "string" ? savedPsc.scope : "");
  const [pscNetworks, setPscNetworks] = useState(Array.isArray(savedPsc?.required_vpcs) ? savedPsc.required_vpcs.join(", ") : "");
  const [pscDnsNames, setPscDnsNames] = useState(Array.isArray(savedPsc?.required_google_api_hostnames) ? savedPsc.required_google_api_hostnames.join(", ") : "*.googleapis.com");
  const [pscReference, setPscReference] = useState(typeof savedPsc?.source_ref === "string" ? savedPsc.source_ref : "");
  const [pscDate, setPscDate] = useState(typeof savedPsc?.observed_at === "string" ? savedPsc.observed_at : new Date().toISOString());
  const [pscAgeDays, setPscAgeDays] = useState(typeof savedPsc?.max_age_seconds === "number" ? String(savedPsc.max_age_seconds / 86400) : "30");
  const updateGcpAuditRecord = (index: number, field: keyof GcpAuditRecord, value: string) =>
    setGcpAuditRecords((records) => records.map((row, position) =>
      position === index ? { ...row, [field]: value } : row));
  const [advancedAuth, setAdvancedAuth] = useState("");
  async function readCredentialFile(file: File | undefined, save: (value: string) => void) {
    if (!file) return;
    if (file.size > 1_000_000) { setError("Credential document exceeds the 1 MB input limit."); return; }
    try {
      const content = await file.text();
      const parsed: unknown = JSON.parse(content);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
      save(content);
      setError("");
    } catch {
      setError("Choose a valid JSON credential document.");
    }
  }
  const [advancedOptions, setAdvancedOptions] = useState("");
  const [sourceMethod, setSourceMethod] = useState("adc");
  const [error, setError] = useState("");
  const [replace, setReplace] = useState(!connector);
  const capabilities = me.data?.connector_auth_methods as
    | Record<string, string[]>
    | undefined;
  const capability = (m: Mode) =>
    m.id === "assume_role"
      ? "assume_role"
      : provider === "k8s"
        ? m.id === "kubeconfig-inline"
          ? "inline"
          : m.id.includes("certificate")
            ? "client-cert"
            : m.id === "in_cluster"
              ? "in-cluster"
              : m.id
        : provider === "azure" && m.id === "default"
          ? "auto"
          : m.method || m.id;
  const allowedModes = authModes[provider].filter(
    (m) =>
      (!hosted || !m.localOnly) &&
      (!capabilities?.[provider] ||
        capabilities[provider].includes(capability(m))),
  );
  const selected = allowedModes.find((m) => m.id === mode) || allowedModes[0];
  const mutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) => {
      const init = json(payload, connector ? "PATCH" : "POST");
      delete payload.auth;
      delete payload.options;
      return request(
        connector
          ? `/connectors/${encodeURIComponent(connector.id)}`
          : "/connectors",
        init,
        demo,
      );
    },
    onSuccess: () => {
      void client.invalidateQueries({
        queryKey: [demo ? "demo" : "live"],
      });
      onClose();
    },
  });
  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (!name.trim()) return setError("Enter a connector name.");
    if (replace) {
      for (const f of selected.fields.filter(
        (f) =>
          (!hosted || !["profile", "external_id", "role_session_name"].includes(f.key)) &&
          !(hosted && selected.id === "assume_role" && f.key === "role_arn"),
      )) {
        if (f.required && !auth[f.key]?.trim())
          return setError(`${f.label} is required.`);
      }
      if (auth.server && !auth.server.startsWith("https://"))
        return setError("The Kubernetes API server must use HTTPS.");
      if (auth.sa_json) {
        try {
          const data = JSON.parse(auth.sa_json);
          if (
            data.type !== "service_account" ||
            !data.client_email ||
            !data.private_key
          )
            throw new Error();
        } catch {
          return setError("Enter a valid service account JSON document.");
        }
      }
    }
    let extraAuth: Record<string, unknown> = {};
    let extraOptions: Record<string, unknown> = {};
    try {
      for (const [text, set] of [
        [advancedAuth, (v: Record<string, unknown>) => (extraAuth = v)],
        [advancedOptions, (v: Record<string, unknown>) => (extraOptions = v)],
      ] as const) {
        if (text.trim()) {
          const parsed = JSON.parse(text);
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
            throw new Error();
          set(parsed);
        }
      }
    } catch {
      return setError("Advanced configuration must be a JSON object.");
    }
    if (Object.prototype.hasOwnProperty.call(extraOptions, "compliance_policy"))
      return setError("Use the provider policy fields instead of advanced options JSON.");
    if (Object.prototype.hasOwnProperty.call(extraOptions, "gcp_data_access_required_principals"))
      return setError("Use the GCP Data Access policy fields instead of advanced options JSON.");
    if (Object.prototype.hasOwnProperty.call(extraOptions, "gcp_psc_dns_policy"))
      return setError("Use the Private Service Connect policy fields instead of advanced options JSON.");
    let backupPolicy: Record<string, unknown> | null = null;
    if (provider === "aws" && backupPolicyEnabled) {
      const hours = Number(backupFrequencyHours);
      const appliesTo = backupPolicyScopes.split(/[,\n]/).map((scope) => scope.trim()).filter(Boolean);
      if (!backupFrequencyHours.trim() || !Number.isFinite(hours) || hours <= 0 || hours > 744)
        return setError("Required backup frequency must be greater than 0 and at most 744 hours.");
      if (!appliesTo.length || appliesTo.length > 1000 ||
          appliesTo.some((scope) => !BACKUP_POLICY_SCOPE.test(scope)) || new Set(appliesTo).size !== appliesTo.length)
        return setError("Enter 1–1000 unique account/Region scopes such as 123456789012/us-east-1.");
      backupPolicy = { aws_backup_plan: { applies_to: appliesTo, required_frequency_hours: hours } };
    }
    let k8sPolicy: Record<string, unknown> | null = null;
    if (provider === "k8s" && k8sPolicyEnabled) {
      const cluster = k8sClusterId.trim();
      const age = Number(k8sMaxAge);
      const budget = Number(k8sMaxItems);
      const names = k8sSystemNamespaces.split(/[,\n]/).map((value) => value.trim()).filter(Boolean);
      if (!cluster || cluster.length > 512 || /[\x00-\x1f]/.test(cluster))
        return setError("Enter the exact Kubernetes cluster ID (1–512 characters).");
      const hasFreshness = !!(k8sObservedAt.trim() || k8sMaxAge.trim());
      if (hasFreshness && (!k8sObservedAt.trim() || !k8sMaxAge.trim()))
        return setError("Enter both declaration time and maximum age, or leave both empty.");
      if (hasFreshness && (!K8S_OBSERVED_UTC.test(k8sObservedAt) || k8sObservedAt.length > 64 ||
          Number.isNaN(Date.parse(k8sObservedAt))))
        return setError("Enter the declaration time in UTC, for example 2026-10-13T10:00:00Z.");
      if (hasFreshness && (!Number.isSafeInteger(age) || age <= 0 || age > 31536000))
        return setError("Enter a policy maximum age from 1 to 31536000 seconds.");
      if (!k8sMaxItems.trim() || !Number.isSafeInteger(budget) || budget <= 0 || budget > 10000)
        return setError("Enter a policy item limit from 1 to 10000.");
      if (!names.length || names.length > budget ||
          names.some((value) => value.length > 63 || !K8S_NAMESPACE.test(value)) ||
          new Set(names).size !== names.length)
        return setError("Enter unique Kubernetes system namespaces within the policy item limit.");
      k8sPolicy = { cluster_id: cluster, max_policy_items: budget, system_namespaces: names,
        ...(hasFreshness ? { observed_at: k8sObservedAt, max_age_seconds: age } : {}) };
    }
    if (provider === "gcp" && !allProjects && !scopes.trim())
      return setError("Enter project IDs or select all accessible projects.");
    let gcpAuditPolicy: Record<string, unknown>[] | null = null;
    if (provider === "gcp" && gcpAuditEnabled) {
      if (gcpAuditRecords.length > 100)
        return setError("Enter at most 100 approved project/service records.");
      const selectedScopes = scopes.split(",").map((value) => value.trim()).filter(Boolean)
        .map((value) => value.includes("/") ? value : `projects/${value}`);
      if (selectedScopes.some((value) => !GCP_POLICY_PROJECT.test(value)) ||
          new Set(selectedScopes).size !== selectedScopes.length)
        return setError("Enter unique, valid selected project scopes for the policy.");
      const selectedProjects = new Set(selectedScopes.filter((value) => GCP_POLICY_PROJECT.test(value)));
      const seen = new Set<string>();
      gcpAuditPolicy = [];
      for (const row of gcpAuditRecords) {
        const project = row.scope.trim();
        const sourceRef = row.sourceRef.trim();
        const principals = row.principals.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
        if (!GCP_POLICY_PROJECT.test(project) || !selectedProjects.has(project))
          return setError("Each policy project must match an explicitly selected project scope.");
        if (!GCP_AUDIT_SERVICES.some((service) => service === row.service))
          return setError("Select Spanner or Pub/Sub for each approved policy record.");
        if (!sourceRef || sourceRef.length > 512)
          return setError("Enter a bounded approval source reference for each policy record.");
        if (!principals.length || principals.length > 500 ||
            principals.some((principal) => principal.length > 512) ||
            new Set(principals).size !== principals.length)
          return setError("Enter 1–500 distinct required principals, one per line.");
        if (principals.some(malformedGcpDirectPrincipal))
          return setError("A direct user or service account principal needs one complete email address after its prefix.");
        const key = `${project}\0${row.service}`;
        if (seen.has(key))
          return setError("Enter each approved project and service pair only once.");
        seen.add(key);
        gcpAuditPolicy.push({ status: "approved", scope: project, service: row.service,
          source_ref: sourceRef, principals });
      }
    }
    let pscPolicy: Record<string, unknown> | null = null;
    if (provider === "gcp" && pscEnabled) {
      const scope = pscProject.trim().startsWith("projects/") ? pscProject.trim() : `projects/${pscProject.trim()}`;
      const selectedScopes = scopes.split(",").map((s) => s.trim()).filter(Boolean).map((s) => s.startsWith("projects/") ? s : `projects/${s}`);
      const networks = pscNetworks.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
      const names = pscDnsNames.split(/[,\n]/).map((s) => s.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean);
      const age = Number(pscAgeDays) * 86400;
      if (!GCP_POLICY_PROJECT.test(scope) || (!allProjects && !selectedScopes.includes(scope)))
        return setError("Choose a selected project for the PSC requirement.");
      if (!networks.length || networks.length > 100 || new Set(networks).size !== networks.length ||
          networks.some((s) => !s.startsWith("https://") && !/^[a-z][a-z0-9-]{0,62}$/.test(s)))
        return setError("Enter 1–100 distinct VPC names or native network URLs.");
      if (!names.length || names.length > 100 || new Set(names).size !== names.length ||
          names.some((s) => !/^(\*\.)?([a-z0-9][a-z0-9-]*\.)*googleapis\.com$/.test(s)))
        return setError("Enter distinct Google API DNS record names, such as *.googleapis.com.");
      if (!pscReference.trim() || pscReference.trim().length > 512 ||
          !Number.isInteger(age) || age <= 0 || age > 31536000 || !Number.isFinite(Date.parse(pscDate)))
        return setError("Enter an approval reference, declaration date and an expiry of at most 365 days.");
      pscPolicy = { status: "approved", scope, source_ref: pscReference.trim(), observed_at: pscDate,
        max_age_seconds: age, required_vpcs: networks.map((s) => s.startsWith("https://") ? s :
          `https://www.googleapis.com/compute/v1/${scope}/global/networks/${s}`), required_google_api_hostnames: names };
    }
    let awsTargets: ReturnType<typeof roleTargets> = [];
    if (replace && provider === "aws" && (selected.id === "access_keys" || (hosted && selected.id === "assume_role"))) {
      try { awsTargets = roleTargets(awsRoles, hosted && selected.id === "assume_role"); }
      catch (cause) { return setError((cause as Error).message); }
      if (hosted && selected.id === "assume_role" && !awsTargets.length)
        return setError("Enter at least one target role ARN.");
    }
    const options: Record<string, unknown> = {
      ...connector?.options,
      ...extraOptions,
      ...(provider === "aws" && regions
        ? { regions: regions.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
      ...(provider === "aws" && selected.id === "access_keys"
        ? { include_source_account: includeSourceAccount } : {}),
      ...(provider === "gcp" ? { all_projects: allProjects } : {}),
    };
    if (provider === "aws" && !regions.trim()) delete options.regions;
    if (provider === "aws") {
      if (backupPolicy) options.compliance_policy = backupPolicy;
      else delete options.compliance_policy;
    } else if (provider === "k8s") {
      if (k8sPolicy) options.compliance_policy = k8sPolicy;
      else delete options.compliance_policy;
    } else if (provider === "gcp") {
      if (gcpAuditPolicy) options.gcp_data_access_required_principals = gcpAuditPolicy;
      else delete options.gcp_data_access_required_principals;
      if (pscPolicy) options.gcp_psc_dns_policy = pscPolicy;
      else delete options.gcp_psc_dns_policy;
    }
    const body: Record<string, unknown> = {
      name: name.trim(),
      ...(!connector ? { provider } : {}),
      scopes:
        provider === "gcp" && allProjects && !scopes.trim()
          ? ["*"]
          : scopes
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
      options,
    };
    if (prepared?.prepared_id) body.prepared_id = prepared.prepared_id;
    if (
      connector &&
      JSON.stringify(body.options) === JSON.stringify(connector.options || {})
    )
      delete body.options;
    if (replace)
      body.auth = {
        method:
          selected.id === "assume_role"
            ? hosted
              ? "assume_role"
              : auth.aws_access_key_id
                ? "access_keys"
                : "default"
            : selected.method || selected.id,
        ...(provider === "k8s" && selected.id === "in_cluster"
          ? { in_cluster: true }
          : {}),
        ...auth,
        ...(auth.delegates
          ? {
              delegates: auth.delegates
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
            }
          : {}),
        ...(provider === "gcp" && selected.id === "impersonation"
          ? { source_auth: { method: sourceMethod } }
          : {}),
        ...extraAuth,
        ...(provider === "k8s" && k8sPolicy ? { cluster_id: k8sPolicy.cluster_id } : {}),
        ...(provider === "aws" && (selected.id === "access_keys" || (hosted && selected.id === "assume_role"))
          ? { assume_roles: awsTargets } : {}),
      };
    const fingerprint = JSON.stringify(body);
    if (checkedPayload === fingerprint && accessResult?.status !== "blocked") {
      if (accessResult?.check_token) body.check_token = accessResult.check_token;
      setAuth({});
      setAdvancedAuth("");
      setAdvancedOptions("");
      mutation.mutate(body);
      return;
    }
    if (Date.now() < nextCheckAt) return setError(`Wait ${Math.ceil((nextCheckAt - Date.now()) / 1000)} seconds before checking access again.`);
    if (hosted && ((provider === "aws" && selected.id === "assume_role") ||
      (provider === "gcp" && selected.id === "platform-service-account")) && !prepared?.prepared_id)
      return setError(prepareError || "Preparing this connector's trust details. Try again shortly.");
    setCheckPending(true);
    setAccessResult(null);
    setCheckedPayload("");
    try {
      const result = await request<AccessCheck>("/connectors/check-access", json({
        ...body, provider, auth: body.auth || {},
        options: body.options || connector?.options || {},
        ...(connector ? { connector_id: connector.id } : {}),
        ...(credentialExpiresAt ? { credential_expires_at: new Date(credentialExpiresAt).toISOString() } : {}),
      }, "POST"), demo);
      setAccessResult(result);
      setCheckedPayload(fingerprint);
      setNextCheckAt(Date.now() + 10_000);
      setClockNow(Date.now());
    } catch (cause) {
      setError(humanError(cause));
    } finally {
      setCheckPending(false);
    }
  }
  return (
    <Inspector
      title={connector ? "Edit connector" : "Add cloud connector"}
      onClose={onClose}
    >
      <form onSubmit={(event) => { void submit(event); }} onChange={() => setCheckedPayload("")} className="form">
        <label>
          Connector name
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={120}
            placeholder="Production cloud"
            required
            autoComplete="off"
          />
        </label>
        <div className="form-columns">
          <label>
            Cloud provider
            <select
              aria-label="Cloud provider"
              value={provider}
              disabled={!!connector}
              onChange={(e) => {
                const p = e.target.value as Provider;
                setProvider(p);
                setMode(authModes[p][0].id);
                setAuth({});
                setAwsRoles("");
                setIncludeSourceAccount(true);
                setAdvancedAuth("");
                setBackupPolicyEnabled(false);
                setBackupFrequencyHours("");
                setBackupPolicyScopes("");
                setGcpAuditEnabled(false);
                setGcpAuditRecords([emptyGcpAuditRecord()]);
                setK8sPolicyEnabled(false);
                setK8sClusterId("");
                setK8sObservedAt("");
                setK8sMaxAge("");
                setK8sMaxItems("");
                setK8sSystemNamespaces("");
              }}
            >
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Authentication
            <select
              aria-label="Authentication"
              value={selected.id}
              onChange={(e) => {
                setMode(e.target.value);
                setAuth({});
                setAwsRoles("");
                setIncludeSourceAccount(true);
                setAdvancedAuth("");
                setReplace(true);
              }}
            >
              {allowedModes.map((m) => (
                <option key={m.id} value={m.id}>
                  {hosted && provider === "aws" && m.id === "assume_role" ? "HackTricks CSPM IAM role" : m.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <AuthSetupGuide key={`${provider}-${selected.id}`} provider={provider} method={selected.id}
          label={hosted && provider === "aws" && selected.id === "assume_role" ? "HackTricks CSPM IAM role" : selected.label} hosted={hosted} prepared={prepared} />
        {prepareError && <p className="form-error" role="alert">Could not prepare setup details: {prepareError}</p>}
        {connector && (
          <label className="checkbox">
            <input
              type="checkbox"
              checked={replace}
              onChange={(e) => setReplace(e.target.checked)}
            />
            Replace authentication credentials
          </label>
        )}
        {replace &&
          selected.fields
            .filter(
              (f) =>
                (!hosted || !["profile", "external_id", "role_session_name"].includes(f.key)) &&
                !(hosted && selected.id === "assume_role" && f.key === "role_arn"),
            )
            .map((f) => (
              <label key={f.key}>
                {f.label}
                {f.key === "sa_json" ? (
                  <>
                    <input type="file" accept=".json,application/json" required={f.required && !auth.sa_json}
                      onChange={(e) => { setAuth((current) => ({ ...current, sa_json: "" })); void readCredentialFile(e.target.files?.[0], (value) => setAuth((current) => ({ ...current, sa_json: value }))); }} />
                    <small>{auth.sa_json ? "Service account document loaded; contents are hidden." : "Select a service account credential document. Its contents will not be previewed."}</small>
                    {auth.sa_json && <button type="button" className="text-button" onClick={() => setAuth((current) => ({ ...current, sa_json: "" }))}>Clear credential document</button>}
                  </>
                ) : f.multiline ? (
                  <textarea
                    value={auth[f.key] || ""}
                    required={f.required}
                    spellCheck={false}
                    autoComplete="off"
                    rows={4}
                    onChange={(e) =>
                      setAuth({ ...auth, [f.key]: e.target.value })
                    }
                  />
                ) : (
                  <input
                    type={f.secret ? "password" : "text"}
                    value={auth[f.key] || ""}
                    required={f.required}
                    autoComplete="off"
                    onChange={(e) =>
                      setAuth({ ...auth, [f.key]: e.target.value })
                    }
                  />
                )}
              </label>
            ))}
        {replace && ((provider === "aws" && !!auth.aws_session_token) ||
          (provider === "gcp" && ["token", "external-account"].includes(selected.id)) ||
          (provider === "azure" && ["token", "workload-identity-inline", "workload-identity"].includes(selected.id)) ||
          (provider === "k8s" && ["token", "kubeconfig-inline", "kubeconfig"].includes(selected.id))) &&
          <label>Temporary credential expiration (UTC, if the token has no readable expiry)
            <input type="datetime-local" value={credentialExpiresAt} onChange={(event) => setCredentialExpiresAt(event.target.value)} />
            <small>The checker blocks credentials with less than one hour remaining. AWS STS session tokens and opaque OAuth tokens need this timestamp because their expiration cannot be read from the token.</small>
          </label>}
        {replace && provider === "aws" && (selected.id === "access_keys" || (hosted && selected.id === "assume_role")) && (
          <label>
            {hosted && selected.id === "assume_role" ? "Target role ARNs (one per line)" : "Optional target roles (one ARN per line; External ID after |)"}
            <textarea value={awsRoles} rows={5} spellCheck={false} autoComplete="off"
              placeholder={hosted && selected.id === "assume_role" ? "arn:aws:iam::123456789012:role/ReadOnly" : "arn:aws:iam::123456789012:role/ReadOnly | optional-external-id"}
              onChange={(e) => setAwsRoles(e.target.value)} />
            <small>One role per AWS account; additional roles for the same account are skipped.</small>
          </label>
        )}
        {provider === "aws" && selected.id === "access_keys" && (
          <label className="checkbox"><input type="checkbox" checked={includeSourceAccount}
            onChange={(e) => setIncludeSourceAccount(e.target.checked)} />Include source account in scan</label>
        )}
        {provider === "gcp" && selected.id === "impersonation" && replace && (
          <label>
            Source authentication
            <select
              value={sourceMethod}
              onChange={(e) => setSourceMethod(e.target.value)}
            >
              <option value="adc">Application default credentials</option>
              <option value="metadata">
                Attached workload service account
              </option>
            </select>
          </label>
        )}
        {hosted && provider === "gcp" && selected.id === "platform-service-account" && (
          <p className="notice">Grant <strong>{String(me.data?.gcp_platform_service_account_email || "the HackTricks CSPM service account")}</strong> read access to each customer project. Save this connector to get its unique project label, then add that label to each project before scanning. The platform service account’s own project is excluded.</p>
        )}
        <label>
          {provider === "gcp"
            ? "Project IDs"
            : provider === "azure"
              ? "Subscription IDs"
              : provider === "k8s"
                ? "Namespaces"
                : "AWS account IDs"}{" "}
          (comma separated)
          <input
            value={scopes}
            onChange={(e) => setScopes(e.target.value)}
            placeholder={provider === "aws" ? "123456789012, 210987654321" : provider === "gcp" ? "my-project, another-project" : "Leave empty for the default accessible scope"}
          />
          {provider === "aws" && <small>Choose which AWS accounts to scan. Leave empty to scan {hosted && selected.id === "assume_role" ? "all configured target roles you can access" : "the source account and any configured target roles you can access"}.</small>}
          {provider === "gcp" && <small>{hosted && selected.id === "platform-service-account"
            ? "Enter customer project IDs, or select discovery below. This connector scans only projects with its onboarding label; the platform project is always excluded."
            : "Enter the projects to scan, or select “Discover all accessible projects” below. The service account’s home project is not selected automatically."}</small>}
        </label>
        {provider === "aws" && (
          <label>
            Regions (comma separated)
            <input
              value={regions}
              onChange={(e) => setRegions(e.target.value)}
              placeholder="us-east-1, eu-west-1"
            />
            <small>Choose which AWS Regions to scan. Leave empty to discover accessible Regions for each selected account.</small>
          </label>
        )}
        {provider === "k8s" && (
          <fieldset>
            <legend>Namespace policy declaration</legend>
            <label className="checkbox">
              <input type="checkbox" checked={k8sPolicyEnabled}
                onChange={(e) => setK8sPolicyEnabled(e.target.checked)} />
              Declare system namespaces for this cluster
            </label>
            {k8sPolicyEnabled && (
              <div className="form">
                <label>Exact cluster ID
                  <input value={k8sClusterId} onChange={(e) => setK8sClusterId(e.target.value)}
                    placeholder="cluster-a" />
                </label>
                <label>Declaration observed at (UTC, optional)
                  <input value={k8sObservedAt} onChange={(e) => setK8sObservedAt(e.target.value)}
                    placeholder="2026-10-13T10:00:00Z" />
                </label>
                <label>Maximum declaration age (seconds, optional)
                  <input type="number" min="1" max="31536000" step="1" value={k8sMaxAge}
                    onChange={(e) => setK8sMaxAge(e.target.value)} />
                </label>
                <label>Maximum policy items
                  <input type="number" min="1" max="10000" step="1" value={k8sMaxItems}
                    onChange={(e) => setK8sMaxItems(e.target.value)} />
                </label>
                <label>System namespaces (comma separated)
                  <textarea value={k8sSystemNamespaces} rows={2}
                    onChange={(e) => setK8sSystemNamespaces(e.target.value)}
                    placeholder="kube-system, kube-public" />
                </label>
                <small>This is an explicit declaration for the named cluster. Set both freshness fields to bound its age; an expired declaration yields an unknown check result. A NetworkPolicy declaration does not prove CNI enforcement.</small>
              </div>
            )}
          </fieldset>
        )}
        {provider === "gcp" && (
          <label className="checkbox">
            <input
              type="checkbox"
              checked={allProjects}
              onChange={(e) => setAllProjects(e.target.checked)}
            />
            {hosted && selected.id === "platform-service-account" ? "Discover all approved customer projects" : "Discover all accessible projects"}
          </label>
        )}
        <details>
          <summary>Advanced configuration</summary>
          <div className="form" style={{ marginTop: 16 }}>
            {provider === "aws" && (
              <fieldset>
                <legend>AWS Backup plan policy</legend>
                <p className="muted small">Set your required backup schedule for specific AWS account and Region pairs. The interval is the longest allowed time between scheduled runs: 24 hours means at least once per day. The scan compares AWS Backup plan rules with this declared requirement. One check evaluates every rule’s schedule; another checks whether at least one rule meets both the interval and a 35-day retention period.</p>
                <label className="checkbox">
                  <input
                    type="checkbox"
                    checked={backupPolicyEnabled}
                    onChange={(e) => setBackupPolicyEnabled(e.target.checked)}
                  />
                  Declare a required backup interval
                </label>
                {backupPolicyEnabled && (
                  <div className="form">
                    <label>
                      Maximum interval between scheduled backups (hours)
                      <input
                        type="number"
                        min="0.01"
                        max="744"
                        step="any"
                        value={backupFrequencyHours}
                        onChange={(e) => setBackupFrequencyHours(e.target.value)}
                      />
                    </label>
                    <label>
                      Applies to account/Region scopes (comma separated)
                      <textarea
                        value={backupPolicyScopes}
                        onChange={(e) => setBackupPolicyScopes(e.target.value)}
                        placeholder="123456789012/us-east-1"
                        rows={2}
                      />
                    </label>
                    <small>Enter exact account ID/Region pairs, such as 123456789012/us-east-1. This is a policy threshold, not an AWS setting: it does not change backup schedules or prove that backup jobs ran successfully. Without a declared interval for a scope, checks that require it report unknown.</small>
                  </div>
                )}
              </fieldset>
            )}
            {provider === "gcp" && (
              <fieldset>
                <legend>Data Access required principals</legend>
                <p className="muted small">Use this only if your organization requires specific users or service accounts to be covered by Spanner or Pub/Sub Data Access audit logs. For each selected project and service, enter the principals and an approval reference. The scan checks project and inherited audit settings for DATA_READ and DATA_WRITE coverage and exemptions. It cannot enable logging or prove that logs were delivered.</p>
                <label className="checkbox">
                  <input type="checkbox" checked={gcpAuditEnabled}
                    onChange={(e) => setGcpAuditEnabled(e.target.checked)} />
                  Declare approved project and service requirements
                </label>
                {gcpAuditEnabled && (
                  <div className="form">
                    {gcpAuditRecords.map((row, index) => (
                      <fieldset key={index}>
                        <legend>Approved requirement {index + 1}</legend>
                        <div className="form">
                          <label>Project scope {index + 1}
                            <input value={row.scope} placeholder="projects/my-project"
                              onChange={(e) => updateGcpAuditRecord(index, "scope", e.target.value)} />
                          </label>
                          <label>Service {index + 1}
                            <select value={row.service}
                              onChange={(e) => updateGcpAuditRecord(index, "service", e.target.value)}>
                              <option value="">Select service</option>
                              <option value="spanner.googleapis.com">Spanner</option>
                              <option value="pubsub.googleapis.com">Pub/Sub</option>
                            </select>
                          </label>
                          <label>Approval source reference {index + 1}
                            <input value={row.sourceRef} maxLength={512}
                              onChange={(e) => updateGcpAuditRecord(index, "sourceRef", e.target.value)} />
                          </label>
                          <label>Required principals {index + 1} (one per line)
                            <textarea value={row.principals} rows={3}
                              onChange={(e) => updateGcpAuditRecord(index, "principals", e.target.value)} />
                          </label>
                          <button type="button" className="text-button"
                            onClick={() => setGcpAuditRecords((records) => records.filter((_, position) => position !== index))}>
                            Remove requirement {index + 1}
                          </button>
                        </div>
                      </fieldset>
                    ))}
                    <button type="button" className="text-button"
                      onClick={() => setGcpAuditRecords((records) => [...records, emptyGcpAuditRecord()])}>
                      Add approved requirement
                    </button>
                    <small>Enter each project and service once. Use exact user: or serviceAccount: email identities where possible; group and domain exemptions can make the result unknown without membership evidence. Leave this declaration off if you have no approved list of principals.</small>
                  </div>
                )}
              </fieldset>
            )}
            {provider === "gcp" && (
              <fieldset>
                <legend>Private Service Connect requirements</legend>
                <p className="muted small">Use this only if your network policy requires Google APIs to be reached through Private Service Connect in specific VPCs. Enter the project, required VPCs and googleapis.com hostnames, the policy reference, and how long that declaration stays valid. The scan checks for matching Google APIs forwarding rules and private DNS A records. It cannot create endpoints or confirm actual DNS resolution, routing, or firewall behavior.</p>
                <label className="checkbox">
                  <input type="checkbox" checked={pscEnabled} onChange={(e) => setPscEnabled(e.target.checked)} />
                  Declare required private Google API endpoints
                </label>
                {pscEnabled && <div className="form">
                  <label>PSC project ID<input value={pscProject} placeholder="my-project" onChange={(e) => setPscProject(e.target.value)} /></label>
                  <label>Required VPC names or URLs<textarea value={pscNetworks} rows={2} placeholder="production-vpc" onChange={(e) => setPscNetworks(e.target.value)} /></label>
                  <label>Required Google API DNS records<textarea value={pscDnsNames} rows={2} onChange={(e) => setPscDnsNames(e.target.value)} /></label>
                  <label>PSC approval reference<input value={pscReference} maxLength={512} placeholder="Policy or change request" onChange={(e) => setPscReference(e.target.value)} /></label>
                  <label>PSC declaration date (UTC)<input value={pscDate} onChange={(e) => setPscDate(e.target.value)} /></label>
                  <label>PSC declaration expiry (days)<input type="number" min="1" max="365" value={pscAgeDays} onChange={(e) => setPscAgeDays(e.target.value)} /></label>
                  <small>The declaration must cover a selected project and be current when the scan runs. Without it, the policy-specific check cannot determine whether your chosen VPCs and DNS names meet the requirement.</small>
                </div>}
              </fieldset>
            )}
            {replace && (
              <label>
                Additional auth document (optional)
                <input type="file" accept=".json,application/json"
                  onChange={(e) => { setAdvancedAuth(""); void readCredentialFile(e.target.files?.[0], setAdvancedAuth); }} />
                <small>{advancedAuth ? "Additional auth document loaded; contents are hidden." : "Select a JSON file only when this connector requires extra credentials."}</small>
                {advancedAuth && <button type="button" className="text-button" onClick={() => setAdvancedAuth("")}>Clear additional auth document</button>}
              </label>
            )}
            <label>
                Additional collector options JSON (no credentials)
              <textarea
                value={advancedOptions}
                onChange={(e) => setAdvancedOptions(e.target.value)}
                spellCheck={false}
                placeholder='For example: {"max_pages": 10, "max_resources": 10000}'
                rows={3}
              />
            </label>
          </div>
        </details>
        {hosted && (
          <p className="notice">
            Hosted mode accepts portable inline credentials. Server paths, CLI
            sessions and ambient identity modes are available only on a local
            server.
          </p>
        )}
        <p className="muted small">
          Server identity modes use credentials already available to the HackTricks CSPM
          server. Web federation uses the server SDK environment. Advanced JSON
          supports native role chains, impersonation source credentials and
          collector limits.
        </p>
        {hosted && selected.id === "assume_role" && (
          <p className="notice">
            The HackTricks CSPM IAM collector role accesses each target role independently.
            Use the External ID in the setup guide, then check access before saving.
          </p>
        )}
        <p className="muted small">
          Use a read-only identity. Access and supported collectors determine
          actual coverage; permission denials appear in scan coverage.
        </p>
        {(error || mutation.error) && (
          <p className="form-error" role="alert">
            {error || (mutation.error && humanError(mutation.error))}
          </p>
        )}
        {accessResult && <div className={`access-check-result access-check-${accessResult.status}`} role="status">
          <strong>{accessResult.status === "pass" ? "Access verified" : accessResult.status === "warning" ? "Access works with recommendations" : "Access check blocked saving"}</strong>
          {accessResult.principals.length > 0 && <ul>{accessResult.principals.map((item) =>
            <li key={`${item.scope}-${item.principal}`}>{item.scope}: {item.principal}</li>)}</ul>}
          {accessResult.issues.length > 0 && <ul>{accessResult.issues.map((item, index) =>
            <li key={`${item.scope}-${index}`}><b>{item.severity === "critical" ? "Required" : "Recommended"}</b> · {item.scope}: {item.message}</li>)}</ul>}
          {accessResult.status === "warning" && <p>Recommended access can be added now. You may save this connector and recheck access after the grants propagate.</p>}
          {accessResult.status === "blocked" && <p>Resolve the required access or credential expiration, then run the check again.</p>}
        </div>}
        <button
          className="button primary"
          type="submit"
          disabled={mutation.isPending || checkPending || (checkedPayload === "" && clockNow < nextCheckAt)}
        >
          {mutation.isPending ? (
            "Saving…"
          ) : checkPending ? (
            "Checking access…"
          ) : checkedPayload && accessResult?.status !== "blocked" ? (
            <><Check size={16} />Save connector</>
          ) : (
            <>
              <Check size={16} />
              {clockNow < nextCheckAt ? `Check access again in ${Math.ceil((nextCheckAt - clockNow) / 1000)}s` : "Check access"}
            </>
          )}
        </button>
      </form>
    </Inspector>
  );
}
