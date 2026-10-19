import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { explainAzureNativeEvidenceObservation } from '../src/azureNativeEvidenceObservation';
import rules from '../../peaso/checks/azure_native_evidence_observations.json' with { type: 'json' };

type Case = { status: string; evidence: Record<string, unknown> };
const cases = JSON.parse(gunzipSync(readFileSync(new URL('../../tests/fixtures/azure_evidence_review.json.gz', import.meta.url))).toString()) as Record<string, Case[]>;

test('all 477 native Azure interpreters cover every replayed conclusive witness', () => {
  expect(Object.keys(rules)).toHaveLength(477);
  for (const checkId of Object.keys(rules)) {
    for (const row of cases[checkId]) {
      const observation = explainAzureNativeEvidenceObservation(checkId, row.evidence, row.status);
      if (['PASS', 'FAIL'].includes(row.status)) {
        expect(observation, `${checkId} ${row.status}`).toBeTruthy();
        expect(observation).not.toContain('{');
        expect(observation).not.toContain('\n');
      } else expect(observation).toBeUndefined();
    }
  }
});

test('every native interpreter rejects unrelated witnesses and uncertain statuses', () => {
  for (const checkId of Object.keys(rules)) {
    for (const status of ['PASS', 'FAIL', 'UNKNOWN', 'MANUAL', 'NOT_APPLICABLE', 'DENIED', 'EMPTY']) {
      expect(explainAzureNativeEvidenceObservation(checkId, {}, status)).toBeUndefined();
      expect(explainAzureNativeEvidenceObservation(checkId, { unrelated: true }, status)).toBeUndefined();
    }
  }
});

test('counts retain missing deciding details without inventing settings', () => {
  expect(explainAzureNativeEvidenceObservation('azure.gap.asset_inventory_required_metadata', { evaluated: 7 }, 'PASS'))
    .toBe('The check assessed 7 resources; individual inventory tags were not retained.');
});

test('bulk-native observations render actual RSA bits and SSH key counts', () => {
  const rsaId = 'azure_vault_3_7_1_2_532ecd2';
  const rsa = structuredClone(cases[rsaId].find(row => row.status === 'FAIL')!);
  expect(explainAzureNativeEvidenceObservation(rsaId, rsa.evidence, 'FAIL')).toContain('1024-bit RSA');
  for (const item of rsa.evidence.outcomes as Record<string, unknown>[]) {
    if (item.status === 'FAIL') item.measured_rsa_modulus_bits = 4096;
  }
  expect(explainAzureNativeEvidenceObservation(rsaId, rsa.evidence, 'FAIL')).toBeUndefined();
  const sshId = 'azure_vm_8_2_1_1_712e1ad';
  const ssh = structuredClone(cases[sshId].find(row => row.status === 'FAIL')!);
  ssh.evidence.configured_bootstrap_ssh_public_key_count = 19;
  expect(explainAzureNativeEvidenceObservation(sshId, ssh.evidence, 'FAIL'))
    .toBe('The Linux VM launch settings declare 19 bootstrap SSH keys.');
});

test('native Azure observations explain settings without raw flag or policy-code dumps', () => {
  for (const checkId of Object.keys(rules)) {
    for (const row of cases[checkId]) {
      if (!['PASS', 'FAIL'].includes(row.status)) continue;
      const observed = explainAzureNativeEvidenceObservation(checkId, row.evidence, row.status)!;
      expect(observed, checkId).not.toMatch(/\b\w+_\w+\b|\b(?:True|False|NonCompliant|Compliant)\b/);
      expect(observed, checkId).not.toMatch(/\b(?:present|enabled|configured|password|mfa)\s*:\s*[01]\b/i);
      expect(observed, checkId).not.toMatch(/\([^)]*:\s*(?:\d+|enabled|disabled)\)/);
    }
  }
});

test('boolean settings are written as sentences and numeric stand-ins stay unclaimed', () => {
  const checkId = 'azure.claude.keyvault_audit_and_alllogs_groups';
  expect(explainAzureNativeEvidenceObservation(checkId, { all_logs_group: 0, audit_group: 0 }, 'FAIL')).toBeUndefined();
  expect(explainAzureNativeEvidenceObservation(checkId, { all_logs_group: false, audit_group: false }, 'FAIL'))
    .toBe('The vault disables both the required audit-log and complete-log category groups.');
});
