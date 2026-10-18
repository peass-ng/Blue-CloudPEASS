# Native GCP super-admin separation

The existing control resolves Google Workspace Directory super-admin role assignments and compares their users against the selected project and its actual ancestor IAM policies. It derives project, optional folders and organization from native Resource Manager ancestry and current parent reads. The v3 organization directoryCustomerId binds the Workspace customer; IAM organization administrator and Workspace super-admin are separate identities.

Read-only collection obtains unique full IAM roots with original scopes and request provenance, then exposes a bounded origin-preserving projection to the registered evaluator. Collection and catalog declare the same dependencies. No engine registry replacement, unscoped global index or company-supplied hierarchy assertion is used.

The native path supports default or broader plans for one selected project, with or without folders. Complete matching direct administrative grants fail; complete evidence without conflicts can pass. Missing, denied, foreign, stale, duplicate or malformed evidence cannot pass. Conditional grants and unresolved indirect group/domain/principal-set grants remain UNKNOWN. Multiple selected projects remain UNKNOWN until Directory evidence can be partitioned safely per project and customer.

The original source criterion and provenance are retained. Legacy positive fixtures now use native evidence produced by the real collector with API fakes; expected PASS, FAIL and UNKNOWN outcomes remain unchanged. Directed tests do not certify a live tenant or project.
