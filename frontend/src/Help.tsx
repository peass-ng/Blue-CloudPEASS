import { Panel, ProviderIcon } from "./ui";

export function Help({ onNavigate }: { onNavigate: (page: string) => void }) {
  return <div className="help-grid">
    <Panel title="Get started" kicker="ASSESS YOUR ENVIRONMENT">
      <ol className="help-steps">
        <li>Sign in, then open <button className="text-button" onClick={() => onNavigate("Connectors")}>Connectors</button> and choose your cloud and access method.</li>
        <li>Open the setup guide beside that method. It includes the required identity, permissions and copyable commands.</li>
        <li>Enter the accounts or projects to assess and select your checks. Use <strong>Check access</strong> before saving.</li>
        <li>Open <button className="text-button" onClick={() => onNavigate("Scans")}>Scans</button> to start an assessment. Choose the completed assessment at the top of a findings page to view its results.</li>
      </ol>
    </Panel>
    <Panel title="AWS role access" kicker="CUSTOMER ACCOUNTS">
      <p>For a hosted AWS connector, create a role in each customer account that trusts the collector role shown in Connectors and requires the unique External ID shown in Connectors.</p>
      <button className="button" onClick={() => onNavigate("Connectors")}>Open AWS setup guide</button>
    </Panel>
    <Panel title="Read the results" kicker="EVIDENCE AND COVERAGE">
      <p>Open a finding to see what was detected and how to fix it. If the scan could not check something, you will see it marked as incomplete.</p>
      <p>Use the scan selector to review previous results.</p>
      <button className="button" onClick={() => onNavigate("Hardening Findings")}>Open findings</button>
    </Panel>
    <Panel title="Cloud documentation" kicker="SETUP REFERENCES">
      <ul className="help-links">
        <li><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html" target="_blank" rel="noopener noreferrer"><ProviderIcon provider="aws" size={20} />AWS cross-account roles and External IDs ↗</a></li>
        <li><a href="https://docs.cloud.google.com/iam/docs/granting-changing-revoking-access" target="_blank" rel="noopener noreferrer"><ProviderIcon provider="gcp" size={20} />Google Cloud project IAM grants ↗</a></li>
        <li><a href="https://learn.microsoft.com/azure/role-based-access-control/role-assignments-portal" target="_blank" rel="noopener noreferrer"><ProviderIcon provider="azure" size={20} />Azure role assignments ↗</a></li>
        <li><a href="https://kubernetes.io/docs/reference/access-authn-authz/rbac/" target="_blank" rel="noopener noreferrer"><ProviderIcon provider="k8s" size={20} />Kubernetes RBAC ↗</a></li>
      </ul>
    </Panel>
  </div>;
}
