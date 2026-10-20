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
  plural_words?: Record<string, { count: string; one: string; many: string }>;
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
    const values: Record<string, unknown> = {};
    for (const [name, field] of Object.entries(rule.values || {})) {
      values[name] = evidence[field];
    }
    for (const [name, field] of Object.entries(rule.list_counts || {})) {
      values[name] = (evidence[field] as unknown[]).length;
    }
    if (rule.formatter === 'rsa_bits') {
      const outcomes = evidence.outcomes;
      const failed = Array.isArray(outcomes) ? outcomes.find(item => object(item) && item.status === 'FAIL'
        && typeof item.measured_rsa_modulus_bits === 'number' && Number.isInteger(item.measured_rsa_modulus_bits)
        && item.measured_rsa_modulus_bits > 0 && item.measured_rsa_modulus_bits < 2048) : undefined;
      if (!failed) continue;
      values.bits = (failed as ObjectValue).measured_rsa_modulus_bits;
    }
    for (const [name, words] of Object.entries(rule.plural_words || {})) {
      values[name] = values[words.count] === 1 ? words.one : words.many;
    }
    for (const [name, value] of Object.entries(values)) {
      observation = observation.replaceAll(`{${name}}`, String(value));
    }
    return observation;
  }
  return undefined;
}
