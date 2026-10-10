import { useState } from "react";
import type { FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2, KeyRound, Check } from "lucide-react";
import { items, json, request, useApi } from "./api";
import { providers } from "./types";
import type { Connector, Me, Provider } from "./types";
import { Badge, Evidence, Inspector, Panel, ProviderIcon, State } from "./ui";
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
export function Connectors({ demo }: { demo: boolean }) {
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
        queryKey: [demo ? "demo" : "live", "/connectors"],
      });
    },
  });
  return (
    <>
      <div className="section-top">
        <p>Give PEASO a read-only view of your environments.</p>
        <button
          className="button primary"
          disabled={demo}
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
            disabled={demo}
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
                {c.onboarding && (
                  <button className="button" onClick={() => setOnboarding(c)}>
                    Onboarding
                  </button>
                )}
                <button
                  className="icon-button"
                  aria-label={`Edit ${c.name}`}
                  disabled={demo}
                  onClick={() => setEdit(c)}
                >
                  <Pencil size={17} />
                </button>
                <button
                  className="icon-button danger"
                  aria-label={`Delete ${c.name}`}
                  disabled={demo}
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
          profiles run on the server hosting PEASO.
        </p>
      </div>
      {onboarding && (
        <Inspector
          title="Hosted role onboarding"
          onClose={() => setOnboarding(undefined)}
        >
          <p>
            Use this server-generated ExternalID with your approved role trust
            configuration. Only the approved role is available to this
            workspace.
          </p>
          <Evidence data={onboarding.onboarding} />
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
          {del.error && <p role="alert">{del.error.message}</p>}
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
  const [allProjects, setAllProjects] = useState(
    !!connector?.options?.all_projects,
  );
  const [regions, setRegions] = useState(
    Array.isArray(connector?.options?.regions)
      ? connector.options.regions.join(", ")
      : "",
  );
  const [advancedAuth, setAdvancedAuth] = useState("");
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
        queryKey: [demo ? "demo" : "live", "/connectors"],
      });
      onClose();
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (!name.trim()) return setError("Enter a connector name.");
    if (replace) {
      for (const f of selected.fields.filter(
        (f) =>
          !hosted ||
          !["profile", "external_id", "role_session_name"].includes(f.key),
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
    if (provider === "gcp" && !allProjects && !scopes.trim())
      return setError("Enter project IDs or select all accessible projects.");
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
      options: {
        ...connector?.options,
        ...extraOptions,
        ...(provider === "aws" && regions
          ? {
              regions: regions
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
            }
          : {}),
        ...(provider === "gcp" ? { all_projects: allProjects } : {}),
      },
    };
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
      };
    setAuth({});
    setAdvancedAuth("");
    setAdvancedOptions("");
    mutation.mutate(body);
  }
  return (
    <Inspector
      title={connector ? "Edit connector" : "Add cloud connector"}
      onClose={onClose}
    >
      <form onSubmit={submit} className="form">
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
                setAdvancedAuth("");
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
                setAdvancedAuth("");
                setReplace(true);
              }}
            >
              {allowedModes.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
          </label>
        </div>
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
                !hosted ||
                !["profile", "external_id", "role_session_name"].includes(
                  f.key,
                ),
            )
            .map((f) => (
              <label key={f.key}>
                {f.label}
                {f.multiline ? (
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
        <label>
          {provider === "gcp"
            ? "Project IDs"
            : provider === "azure"
              ? "Subscription IDs"
              : provider === "k8s"
                ? "Namespaces"
                : "Account scopes"}{" "}
          (comma separated)
          <input
            value={scopes}
            onChange={(e) => setScopes(e.target.value)}
            placeholder="Leave empty for the default accessible scope"
          />
        </label>
        {provider === "aws" && (
          <label>
            Regions (comma separated)
            <input
              value={regions}
              onChange={(e) => setRegions(e.target.value)}
              placeholder="us-east-1, eu-west-1"
            />
          </label>
        )}
        {provider === "gcp" && (
          <label className="checkbox">
            <input
              type="checkbox"
              checked={allProjects}
              onChange={(e) => setAllProjects(e.target.checked)}
            />
            Discover all accessible projects
          </label>
        )}
        <details>
          <summary>Advanced native configuration</summary>
          <div className="form" style={{ marginTop: 16 }}>
            {replace && (
              <label>
                Additional auth JSON (secrets are cleared on submit)
                <textarea
                  value={advancedAuth}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(e) => setAdvancedAuth(e.target.value)}
                  placeholder='For example: {"role_chain": [{"role_arn": "arn:aws:iam::123456789012:role/ReadOnly"}]}'
                  rows={4}
                />
              </label>
            )}
            <label>
              Additional collector options JSON
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
          Server identity modes use credentials already available to the PEASO
          server. Web federation uses the server SDK environment. Advanced JSON
          supports native role chains, impersonation source credentials and
          collector limits.
        </p>
        {hosted && selected.id === "assume_role" && (
          <p className="notice">
            Hosted role access requires approved onboarding. The server
            generates your ExternalID; retrieve it from the saved connector and
            configure the reviewed trust relationship.
          </p>
        )}
        <p className="muted small">
          Use a read-only identity. Access and supported collectors determine
          actual coverage; permission denials appear in scan coverage.
        </p>
        {(error || mutation.error) && (
          <p className="form-error" role="alert">
            {error || mutation.error?.message}
          </p>
        )}
        <button
          className="button primary"
          type="submit"
          disabled={mutation.isPending}
        >
          {mutation.isPending ? (
            "Saving…"
          ) : (
            <>
              <Check size={16} />
              Save connector
            </>
          )}
        </button>
      </form>
    </Inspector>
  );
}
