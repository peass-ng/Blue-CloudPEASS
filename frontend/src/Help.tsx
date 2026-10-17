import { Panel } from "./ui";

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
      <p>For a hosted AWS connector, create a role in each customer account that trusts <code>arn:aws:iam::202533532952:role/HackTricks-CSPM</code> and requires the unique External ID shown in Connectors.</p>
      <p>The HackTricks role can assume customer roles but cannot read platform resources or assume roles in HackTricks accounts. The customer role supplies the read permissions for its own account.</p>
      <button className="button" onClick={() => onNavigate("Connectors")}>Open AWS setup guide</button>
    </Panel>
    <Panel title="Read the results" kicker="EVIDENCE AND COVERAGE">
      <p>Findings show the observed configuration, the check result and suggested remediation. A check with missing permissions or unavailable evidence is marked as incomplete; it is not treated as a pass.</p>
      <p>Use the assessment selector to compare completed scans. Fixture demo data is illustrative and never reads your cloud account.</p>
      <button className="button" onClick={() => onNavigate("Hardening Findings")}>Open findings</button>
    </Panel>
    <Panel title="Cloud documentation" kicker="SETUP REFERENCES">
      <ul className="help-links">
        <li><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html" target="_blank" rel="noopener noreferrer">AWS cross-account roles and External IDs ↗</a></li>
        <li><a href="https://docs.cloud.google.com/iam/docs/granting-changing-revoking-access" target="_blank" rel="noopener noreferrer">Google Cloud project IAM grants ↗</a></li>
        <li><a href="https://learn.microsoft.com/azure/role-based-access-control/role-assignments-portal" target="_blank" rel="noopener noreferrer">Azure role assignments ↗</a></li>
        <li><a href="https://kubernetes.io/docs/reference/access-authn-authz/rbac/" target="_blank" rel="noopener noreferrer">Kubernetes RBAC ↗</a></li>
      </ul>
    </Panel>
  </div>;
}
