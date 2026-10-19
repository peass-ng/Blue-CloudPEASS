/** Exact native Azure witness interpreters shared with the Python projection.
 * Legacy titles never choose semantics; unknown shapes remain unclaimed.
 */
import nativeRules from '../../peaso/checks/azure_native_evidence_observations.json' with { type: 'json' };

type ObjectValue = Record<string, unknown>;
type Shape = Record<string, unknown>;
type Rule = {
  status: string;
  evidence: Shape;
  observation: string;
  values?: Record<string, string>;
  list_counts?: Record<string, string>;
  formatter?: string;
  detail?: { field: string; kind: string; label: string };
};
const rules = nativeRules as unknown as Record<string, Rule[]>;
const object = (v: unknown): v is ObjectValue => v !== null && typeof v === 'object' && !Array.isArray(v);

function matches(value: unknown, shape: Shape): boolean {
  if ('null' in shape) return value === null;
  if ('boolean' in shape) return typeof value === 'boolean' && value === shape.boolean;
  if ('integer' in shape) return typeof value === 'number' && Number.isInteger(value)
    && (value === 0 ? 'zero' : value > 0 ? 'positive' : 'negative') === shape.integer;
  if ('number' in shape) return typeof value === 'number' && Number.isFinite(value);
  if ('literal' in shape) return typeof value === 'string' && value === shape.literal;
  if ('string' in shape) return typeof value === 'string';
  if ('object' in shape) {
    const fields = shape.object as Record<string, Shape>;
    return object(value) && Object.keys(value).length === Object.keys(fields).length
      && Object.entries(fields).every(([key, child]) => Object.hasOwn(value, key) && matches(value[key], child));
  }
  if ('list' in shape) {
    const variants = shape.list as Shape[];
    return Array.isArray(value) && (value.length === 0) === shape.empty
      && value.every(item => variants.some(child => matches(item, child)));
  }
  return false;
}

export function explainAzureNativeEvidenceObservation(checkId: string, evidence: unknown, status: string): string | undefined {
  if (!['PASS', 'FAIL'].includes(status) || !object(evidence)) return undefined;
  for (const rule of rules[checkId] || []) {
    if (rule.status !== status || !matches(evidence, rule.evidence)) continue;
    let observation = rule.observation;
    for (const [name, field] of Object.entries(rule.values || {})) {
      observation = observation.replaceAll(`{${name}}`, String(evidence[field]));
    }
    for (const [name, field] of Object.entries(rule.list_counts || {})) {
      observation = observation.replaceAll(`{${name}}`, String((evidence[field] as unknown[]).length));
    }
    if (rule.formatter === 'rsa_bits') {
      const outcomes = evidence.outcomes;
      const failed = Array.isArray(outcomes) ? outcomes.find(item => object(item) && item.status === 'FAIL'
        && typeof item.measured_rsa_modulus_bits === 'number' && Number.isInteger(item.measured_rsa_modulus_bits)
        && item.measured_rsa_modulus_bits > 0 && item.measured_rsa_modulus_bits < 2048) : undefined;
      if (!failed) continue;
      observation = observation.replaceAll('{bits}', String((failed as ObjectValue).measured_rsa_modulus_bits));
    }
    const detail = rule.detail;
    if (detail) {
      const value = evidence[detail.field];
      let phrase: string;
      if (detail.kind === 'count') phrase = `${(value as unknown[]).length} ${detail.label}`;
      else if (detail.kind === 'strings') {
        const values = value as string[];
        if (values.some(v => typeof v !== 'string' || v.length > 80 || /[\u0000-\u001f]/.test(v))) return undefined;
        phrase = `${detail.label}: ${values.slice(0, 3).join(', ')}${values.length > 3 ? ` and ${values.length - 3} more` : ''}`;
      } else if (detail.kind === 'version') phrase = `${detail.label}: ${(value as number[]).join('.')}`;
      else phrase = `${detail.label}: ${typeof value === 'boolean' ? value ? 'enabled' : 'disabled' : value}`;
      observation = `${observation.replace(/\.+$/, '')} (${phrase}).`;
    }
    return observation;
  }
  return undefined;
}
