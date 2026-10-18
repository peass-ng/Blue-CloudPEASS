# Current secret metadata without reading values

The rotation evaluator has an additive, explicit `arm/secrets/get` provenance alternative. The original unversioned data-plane `secrets/get` reviewed-input path is retained unchanged. The new collector never calls data-plane GetSecret, reads values, guesses current state from creation times or invents old-version access outcomes.

ARM Secrets_Get 2023-07-01 returns native `secretUri` and `secretUriWithVersion` metadata. The ARM model documents that its value field is never returned. Two uncached reads must retain the same exact resource identity, version pointer and attributes around a complete data-plane ListVersions 2025-07-01 observation. Current attributes come from the exact listed version, with all supplied ARM attributes agreeing. Only declared lifecycle metadata is retained. A malformed, contradictory, denied, partial, stale, foreign or changing observation stays UNKNOWN. Both read receipts and their endpoint/version/time/source binding are independently rechecked by the pure evaluator.

The native rotation path evaluates current creation age against approved `maxDaysSinceRotation`; a newer disabled version does not substitute for the actual ARM-selected version. Disabled current versions remain NOT_APPLICABLE. The other secret checks still need their original audit-history/access-denial evidence, and no closure of those controls is claimed.

`azure_sw15_policy.normalize(options, scopes=None)` supplies a common normative policy for firewall, Function and secret families. It accepts only status/scope, allowAzureServices, Function thresholds/caller keys/observation window, and maxDaysSinceRotation/unusedForDays/approvedRotationDays. Missing namespace returns None; explicit null, malformed input, unknown observation flags, empty policy and foreign scope are rejected. Function owner_policy returns the entire normalized union, not only Function fields. The final Azure metadata projection preserves the union.

Primary API schema: https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/keyvault/resource-manager/Microsoft.KeyVault/KeyVault/stable/2023-07-01/secrets.json

Metadata model: https://learn.microsoft.com/en-us/javascript/api/%40azure/arm-keyvault/secretproperties?view=azure-node-latest

Data-plane versions: https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret-versions/get-secret-versions?view=rest-keyvault-secrets-2025-07-01

The proposed bulk source-module digest update is private and requires independent integration review. It does not change signed requirement IDs/spec hashes or other modules. SDK-shaped fixtures exercise collector-to-engine PASS, FAIL and UNKNOWN, old DP fixtures and mixed firewall/Function/rotation policy. No live cloud result is claimed by these fixtures.
