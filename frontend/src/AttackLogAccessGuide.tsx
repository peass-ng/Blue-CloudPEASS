import type { ReactNode } from "react";

type Props = {
  provider: string;
  kind: string;
  authMode?: string;
  command: string;
  missingDetails: string;
  s3Policy: string;
  roleArn: string;
};

export function AttackLogAccessGuide({ provider, kind, authMode, command, missingDetails, s3Policy, roleArn }: Props) {
  let title: string;
  let steps: ReactNode[];
  let docs: string;
  let bucketPolicy = "";
  if (provider === "aws" && kind === "aws_event_history") {
    title = "Allow this connector to read CloudTrail Event History";
    docs = "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCloudTrail_ReadOnlyAccess.html";
    steps = [
      <>In the AWS account you want to analyze, open <strong>IAM → Roles</strong> and select the account role used by this connector. If the connector uses an IAM user's keys directly, select that user under <strong>IAM → Users</strong> instead.</>,
      <>Open <strong>Permissions → Add permissions → Attach policies</strong>. Find <strong>AWSCloudTrail_ReadOnlyAccess</strong>, select it and save. The hosted CSPM role template already includes the required access, so check existing permissions first.</>,
      <>For an assumed-role session, update the role being assumed. Temporary access keys cannot have policies attached to them. A session policy or permissions boundary can still limit what the role can read.</>,
      <>Return here, choose the same account role and AWS Region, then click <strong>Check log access</strong>. No S3 bucket is needed. This source reads management events from the last 90 days in the selected Region.</>,
    ];
  } else if (provider === "aws") {
    title = "Allow this connector to read the CloudTrail files in S3";
    docs = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-receive-logs-from-multiple-accounts.html";
    steps = [
      <>Open <strong>CloudTrail → Trails → your trail</strong> and follow its S3 bucket link. Find the folder for the account you want to analyze. Enter the bucket name and the folder path ending in <strong>CloudTrail/</strong> above; the Region and log day are added automatically. For an organization trail, keep the organization folder in that path.</>,
      <>In <strong>IAM → Roles</strong>, open the account role selected above. Go to <strong>Permissions → Add permissions → Create inline policy → JSON</strong> and paste the generated S3 policy. It allows listing only that folder and reading its log files. If you use an IAM user directly, add the policy to that user instead. For temporary assumed-role keys, update the role being assumed.</>,
      <>If the bucket is in a separate logging account, ask that account's administrator to open <strong>S3 → your bucket → Permissions → Bucket policy</strong> and add the statement below. Use the connector's IAM role or user ARN as the principal, not an STS session ARN. Keep the bucket's existing statements; do not replace its CloudTrail delivery permissions.</>,
      <>If the files use a customer-managed KMS key, enter its ARN above before copying the IAM policy. Ask the key administrator to allow that same role or user to use <strong>kms:Decrypt</strong> in the key policy, or through its IAM-delegation settings. The generated command updates IAM only; it does not change the bucket or key policy. AWS-managed KMS keys cannot be shared across accounts.</>,
      <>Choose a day when the trail wrote logs, then click <strong>Check log access</strong>. If access is blocked, check permissions in the connector account, the bucket account and, for encrypted files, the KMS key account.</>,
    ];
    if (s3Policy) {
      const identity = /^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]+$/.test(roleArn) ? roleArn : "REPLACE_WITH_CONNECTOR_IAM_ROLE_OR_USER_ARN";
      const policy = JSON.parse(s3Policy) as { Statement: { Sid: string; Action: string; [key: string]: unknown }[] };
      bucketPolicy = JSON.stringify({ Version: "2012-10-17", Statement: policy.Statement.filter(statement => statement.Action !== "kms:Decrypt").map(statement => ({ ...statement, Principal: { AWS: identity } })) }, null, 2);
    }
  } else if (provider === "gcp") {
    title = kind === "gke_audit" ? "Allow this connector to read GKE audit logs" : "Allow this connector to read Google Cloud audit logs";
    docs = "https://docs.cloud.google.com/logging/docs/access-control";
    steps = [
      <>Find the identity used by this GCP connector in its setup: usually a service account email, or your signed-in user's email. If the connector impersonates a service account, grant access to the target service account.</>,
      <>In Google Cloud Console, select the project entered above and open <strong>IAM & Admin → IAM → Grant access</strong>. Enter that identity's email under <strong>New principals</strong>.</>,
      <>Choose <strong>Logging → Private Logs Viewer</strong> and save. This includes Logs Viewer access and also allows reading Data Access audit logs. Logs Viewer alone is sufficient if you only need non-private logs such as Admin Activity.</>,
      ...(kind === "gke_audit" ? [<>Use the project that owns the GKE cluster and enter the cluster name above. These logs come from <strong>Cloud Logging</strong>; Kubernetes RBAC permissions or a kubeconfig do not grant access to them.</>] : []),
      <>Open <strong>Logging → Logs Explorer</strong> in that project to confirm the required audit logs exist. Granting read access does not enable missing Data Access logs or recover past events. If your logs exist only in another project's custom log bucket or view, this project-based source does not read that destination.</>,
      <>Return here and click <strong>Check log access</strong>. For the optional command below, replace the member placeholder with <strong>serviceAccount:EMAIL</strong> or <strong>user:EMAIL</strong>, matching the connector identity.</>,
    ];
  } else if (kind === "entra_directory_audit") {
    title = "Allow this connector to read Microsoft Entra directory audits";
    docs = "https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0";
    const userSession = authMode === "az-cli";
    const managedIdentity = authMode === "managed-identity";
    steps = userSession ? [
      <>In the connector's tenant, ask an Entra administrator to assign <strong>Reports Reader</strong> to the user signed in through Azure CLI.</>,
      <>The sign-in application also needs the delegated Microsoft Graph permission <strong>AuditLog.Read.All</strong> with tenant admin consent. A subscription role alone does not grant directory audit access.</>,
      <>Refresh the Azure CLI sign-in on the CSPM server after access is granted, then click <strong>Check log access</strong>.</>,
    ] : managedIdentity ? [
      <>Open the Azure resource running CSPM and copy the managed identity's <strong>Object (principal) ID</strong> from its Identity page.</>,
      <>Ask your Entra administrator to assign the Microsoft Graph application role <strong>AuditLog.Read.All</strong> to that managed identity's service principal. This is a Microsoft Graph app-role assignment, not an Azure subscription role assignment.</>,
      <>After the assignment, let the connector obtain a fresh token and click <strong>Check log access</strong>.</>,
    ] : [
      <>In the connector's tenant, open <strong>Microsoft Entra ID → App registrations</strong>. Find the application whose <strong>Application (client) ID</strong> matches your connector.</>,
      <>Open <strong>API permissions → Add a permission → Microsoft Graph → Application permissions</strong>. Select <strong>AuditLog.Read.All</strong> and add it.</>,
      <>Ask a tenant administrator authorized to grant Microsoft Graph application permissions to click <strong>Grant admin consent</strong>. Confirm the permission shows as granted for your tenant. Assigning Reader or Monitoring Reader on a subscription does not complete this step.</>,
      <>Let the connector obtain a fresh Microsoft Graph token, then click <strong>Check log access</strong>. If you pasted a token manually, replace it after the grant; an Azure Resource Manager token cannot read Graph audits. For a user token, the app needs delegated AuditLog.Read.All consent and the user needs a supported Entra role such as Reports Reader.</>,
    ];
  } else {
    title = "Allow this connector to read Azure Activity Log";
    docs = "https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/roles-permissions-security";
    steps = [
      <>Open <strong>Azure portal → Subscriptions</strong> and select the subscription entered above. Open <strong>Access control (IAM) → Add → Add role assignment</strong>. Use an administrator who can assign roles at this subscription.</>,
      <>Select <strong>Monitoring Reader</strong>. Under Members, select the app, managed identity or signed-in user used by this connector, then choose <strong>Review + assign</strong>. If it already has Reader or equivalent access at the subscription, an additional assignment may not be needed.</>,
      <>For an application, find its identity in <strong>Microsoft Entra ID → Enterprise applications</strong> by the connector's client ID, then copy its <strong>Object ID</strong>. For a managed identity, use its <strong>Object (principal) ID</strong>. For a user connector, use that user's object ID. Put this ID in the optional command below; it is not the app's client ID.</>,
      <>Allow time for the assignment to take effect, then click <strong>Check log access</strong>. This source reads subscription Activity Log, not Entra directory audits or exported Log Analytics records.</>,
    ];
  }
  return <details className="attack-permissions">
    <summary>How to grant log access</summary>
    <div className="attack-permission-guide">
      <h3>{title}</h3>
      <p>Make these changes using a cloud administrator account. Give read access to the identity used by this connector, so CSPM can read the logs on your behalf.</p>
      <ol>{steps.map((step, index) => <li key={index}>{step}</li>)}</ol>
      {kind !== "entra_directory_audit" && (command ? <div className="attack-permission-command"><h4>Optional: grant access from your terminal</h4><p>Use an administrator session in the account, project or subscription described above. Replace any REPLACE_WITH placeholders before running this command.</p><pre>{command}</pre><button className="button" type="button" onClick={() => void navigator.clipboard.writeText(command)}>Copy CLI</button></div> : <p className="attack-permission-hint">{missingDetails}</p>)}
      {s3Policy && provider === "aws" && kind === "aws_cloudtrail_s3" && !command && <div><h4>IAM policy for the selected log files</h4><p>Paste this into the inline policy for the connector's role or IAM user.</p><pre>{s3Policy}</pre><button className="button" type="button" onClick={() => void navigator.clipboard.writeText(s3Policy)}>Copy IAM policy</button></div>}
      {bucketPolicy && <details className="attack-bucket-policy"><summary>Bucket policy for a separate logging account</summary><p>Add these statements to the existing bucket policy. Replace the identity ARN placeholder if one is shown. This grants read access only; keep the existing log-delivery statements.</p><pre>{bucketPolicy}</pre><button className="button" type="button" onClick={() => void navigator.clipboard.writeText(bucketPolicy)}>Copy bucket policy</button></details>}
      <a className="attack-permission-docs" href={docs} target="_blank" rel="noopener noreferrer">Read the provider's access documentation ↗</a>
    </div>
  </details>;
}
