import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';

async function setup(page: Page, connector: Record<string, unknown>) {
  await page.route('**/api/**', route => route.fulfill({ json: { items: [] } }));
  await page.route('**/api/me', route => route.fulfill({ json: { tenant_id: 'fixture', auth_kind: 'user' } }));
  await page.route('**/api/health', route => route.fulfill({ json: { auth_mode: 'local' } }));
  await page.route('**/api/connectors', route => route.fulfill({ json: { items: [{ id: 'logs', name: 'Log reader', input_mode: 'live', scopes: [], ...connector }] } }));
  await page.goto('/#Attack%20Analysis');
  await page.getByText('How to grant log access', { exact: true }).click();
}

test('S3 access steps use consistent type and generate separate identity and bucket policies', async ({ page }) => {
  await setup(page, { provider: 'aws', onboarding: { target_role_arns: ['arn:aws:iam::123456789012:role/LogReader'] } });
  await expect(page.getByRole('combobox', { name: 'Detection rules', exact: true })).toHaveValue('latest');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Beta');
  await expect(page.getByRole('button', { name: 'Attack Detection', exact: true })).toContainText('Beta');
  await page.getByRole('combobox', { name: 'Audit source', exact: true }).selectOption('aws_cloudtrail_s3');
  const guide = page.locator('.attack-permissions');
  await expect(guide.getByRole('listitem')).toHaveCount(5);
  await expect(guide).toContainText('bucket is in a separate logging account');
  await expect(guide.locator('.attack-permission-hint')).toContainText('Choose the account role above');
  const typography = await guide.evaluate(element => {
    const prose = element.querySelector('.attack-permission-guide > p')!;
    const step = element.querySelector('li')!;
    const hint = element.querySelector('.attack-permission-hint')!;
    return [prose, step, hint].map(item => ({ family: getComputedStyle(item).fontFamily, size: getComputedStyle(item).fontSize }));
  });
  expect(typography[0]).toEqual(typography[1]);
  expect(typography[0]).toEqual(typography[2]);
  await page.getByRole('combobox', { name: 'Account role', exact: true }).selectOption('arn:aws:iam::123456789012:role/LogReader');
  await expect(guide.locator('.attack-permission-hint')).toContainText('Enter the S3 bucket name');
  await page.getByLabel('S3 bucket', { exact: true }).fill('central-audit');
  await page.getByLabel('CloudTrail base prefix', { exact: true }).fill('AWSLogs/123456789012/CloudTrail/');
  await page.getByLabel('KMS key ARN, if encrypted', { exact: true }).fill('arn:aws:kms:us-east-1:123456789012:key/example-key');
  await expect(guide.locator('.attack-permission-command pre')).toContainText('aws iam put-role-policy');
  await expect(guide.locator('.attack-permission-command pre')).toContainText('kms:Decrypt');
  await guide.getByText('Bucket policy for a separate logging account', { exact: true }).click();
  const bucketPolicy = JSON.parse(await guide.locator('.attack-bucket-policy pre').innerText());
  expect(bucketPolicy.Statement).toHaveLength(2);
  expect(bucketPolicy.Statement.every((row: { Principal: { AWS: string } }) => row.Principal.AWS === 'arn:aws:iam::123456789012:role/LogReader')).toBe(true);
  await page.screenshot({ path: '/tmp/cspm-attack-log-access.png', fullPage: true });
});

test('GCP and GKE explain project access and use the known service account', async ({ page }) => {
  await setup(page, { provider: 'gcp', scopes: ['projects/audit-project'], gcp_onboarding: { service_account_email: 'reader@identity-project.iam.gserviceaccount.com' } });
  await expect(page.getByRole('combobox', { name: 'Audit source', exact: true })).toHaveValue('gcp_audit');
  const guide = page.locator('.attack-permissions');
  await expect(guide).toContainText('IAM & Admin → IAM → Grant access');
  await expect(guide).toContainText('Private Logs Viewer');
  await expect(guide.locator('pre')).toContainText('--member=\'serviceAccount:reader@identity-project.iam.gserviceaccount.com\'');
  await page.getByRole('combobox', { name: 'Audit source', exact: true }).selectOption('gke_audit');
  await expect(guide).toContainText('Kubernetes RBAC permissions or a kubeconfig do not grant access');
});

test('Azure distinguishes subscription roles from Entra app permissions and consent', async ({ page }) => {
  await setup(page, { provider: 'azure', auth_mode: 'client-secret', scopes: ['/subscriptions/12345678-1234-1234-1234-123456789012'] });
  const guide = page.locator('.attack-permissions');
  await expect(page.getByRole('combobox', { name: 'Audit source', exact: true })).toHaveValue('azure_activity_log');
  await expect(guide).toContainText('Monitoring Reader');
  await expect(guide).toContainText('Enterprise applications');
  await expect(guide.locator('pre')).toContainText('/subscriptions/12345678-1234-1234-1234-123456789012');
  await page.getByRole('combobox', { name: 'Audit source', exact: true }).selectOption('entra_directory_audit');
  await expect(guide).toContainText('Microsoft Graph → Application permissions');
  await expect(guide).toContainText('AuditLog.Read.All');
  await expect(guide).toContainText('Grant admin consent');
  await expect(guide.getByRole('button', { name: 'Copy CLI' })).toHaveCount(0);
});

test('temporary AWS keys do not generate an IAM-user grant command', async ({ page }) => {
  await setup(page, { provider: 'aws', auth: { fields: ['aws_access_key_id', 'aws_secret_access_key', 'aws_session_token'] } });
  const guide = page.locator('.attack-permissions');
  await expect(guide).toContainText('update the role being assumed');
  await expect(guide.getByRole('button', { name: 'Copy CLI' })).toHaveCount(0);
  await expect(guide).not.toContainText('attach-user-policy');
});
