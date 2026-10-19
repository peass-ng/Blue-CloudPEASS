import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { explainAzureNativeEvidenceObservation } from '../src/azureNativeEvidenceObservation';
import rules from '../../peaso/checks/azure_native_evidence_observations.json' with { type: 'json' };

type Case = { status: string; evidence: Record<string, unknown> };
const cases = JSON.parse(gunzipSync(readFileSync(new URL('../../tests/fixtures/azure_evidence_review.json.gz', import.meta.url))).toString()) as Record<string, Case[]>;

test('all 325 native Azure interpreters cover every replayed conclusive witness', () => {
  expect(Object.keys(rules)).toHaveLength(325);
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
    .toBe('The result records 7 assessed resources; individual inventory tags were not stored.');
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
    .toBe('Bootstrap SSH public keys declared by the Linux VM: 19.');
});
