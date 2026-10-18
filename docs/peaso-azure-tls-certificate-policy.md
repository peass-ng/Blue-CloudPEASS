# Azure TLS certificate review criteria

A connector may provide explicit owner review criteria for the signed 90-day and
180-day certificate rotation checks under
`options.compliance_parameters.azure_tls_certificates`:

```json
{
  "compliance_parameters": {
    "azure_tls_certificates": {
      "status": "collected",
      "scope": "/subscriptions/11111111-1111-1111-1111-111111111111",
      "observed_at": "2026-10-16T09:00:00+00:00",
      "max_age_seconds": 86400,
      "parameters": {
        "approvedTlsServiceInventory": ["applicationGateway", "appService"],
        "tlsObservationMaxAgeSeconds": 3600
      }
    }
  }
}
```

This example is a schema illustration, not a default approval or a complete
service inventory. The operator supplies the exact subscription, original review
time, expiry duration, approved service names and required observation freshness.
No external verification of that operator's approval identity is claimed. Service
names are explicit evaluator identifiers, not ARM resource-type URLs. A service
name must begin with an ASCII letter and contain at most 64 letters, digits,
underscores or hyphens. The list has 1–64 members; case-insensitive aliases are
rejected. Use the exact identifiers emitted by the separately reviewed native
endpoint collector; accepting a name does not imply that a collector exists for it.

The namespace accepts exactly the five illustrated root fields and exactly the
two parameter fields. Both durations must be integers from 1 to 31,536,000;
booleans, floats and nulls are rejected. `observed_at` must be a timezone-aware
ISO8601 timestamp, which is preserved verbatim. Stale or future approvals are
retained as supplied and cause the signed evaluation to return UNKNOWN; collection
does not refresh approval time. A scope must be a subscription ARM scope with a
UUID. Collection binds it to the actual selected subscription before constructing
an authentication transport when scopes are explicitly selected. Subscription
discovery necessarily precedes binding when scopes are discovered dynamically.

Local and Cognito connector intake validate the same namespace, reject it for
non-Azure providers, and reject additional fields containing observations,
certificate payloads, snapshots or native evidence. The criteria are copied into
snapshot `metadata.compliance_policy`, preserving unrelated namespaces and
parameters. Existing flat approval authority must match the supplied status,
scope, timestamp and expiry exactly; conflicting authority or TLS parameters are
rejected without mutating existing metadata. Deep copies prevent later option or
metadata edits from changing the original declaration.

This namespace is also mutually exclusive with a raw
`options.compliance_policy` containing any flat `status`, `scope`, `observed_at`,
`max_age_seconds` or `parameters` field, even if its value matches. Raw flat
reviews can be shallowly combined by later bulk-evidence enrichment, so accepting
a competing review could replace its authority or parameters after validation.
Use separate connectors for competing flat approvals. Namespace-only policies,
such as `sw03` and `sw33`, can coexist without replacing their contents or the TLS
review authority. This input restriction is distinct from the defensive internal
metadata merge, which still rejects contradictory existing authority.

The legacy `azure_arm_metadata.approvedPredefinedSslPolicyName` option cannot be
combined with this namespace, even for the same subscription. That legacy bridge
has no operator-supplied approval clock, so sharing its flat authority could attach
legacy criteria to a different approval time. Use separate connectors for those
criteria. Other ARM metadata fields remain independent.

## Native evidence and limits

These criteria add no native TLS endpoint, binding, certificate, observed port,
serial/thumbprint or coverage evidence. The companion public-X.509 projection can
supply issuance facts from already collected public Key Vault certificates, but
cannot prove which certificate a public endpoint currently serves. It does not
prove complete TLS service coverage or certificate rotation history.

A rotation verdict still requires actual active endpoint observations, exact
certificate serial/thumbprint joins, freshness and complete coverage of the
explicit approved service universe. Missing native evidence remains UNKNOWN;
saving valid criteria alone closes neither rotation control. Existing complete
signed fixtures retain their PASS/FAIL outcomes, while stale/future review times
remain UNKNOWN. Empty inventory requirements produce no API requests and preserve
the supplied criteria exactly; they do not manufacture native coverage.

The focused portable tests exercise this namespace in local and Cognito intake,
strict malformed-input rejection, immutable merges, selected-scope rejection
before transport creation, a real collector dispatch with an inert transport,
and both signed rotation predicates through the existing fixture library. No
existing fixture tests are collected or executed by importing that library; its
registrations are temporarily sandboxed and restored. These are offline tests,
not live cloud observations or a global product-completion claim.
