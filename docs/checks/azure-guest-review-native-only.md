# Native Azure guest access reviews

The monthly and regular guest review controls can use complete Microsoft Graph users, review definitions, instances and decision metadata without a company-authored policy. The native path evaluates the complete guest universe, with tenant, scope, capture time and request provenance binding. No new Graph operations or cloud writes are introduced.

A complete supported review schedule and completed decisions within a conservative 28-day window provide a sufficient monthly witness. Deny decisions count as completed reviews; NotReviewed does not. The regular review control accepts this stronger witness too. A complete empty guest inventory is not applicable.

Missing decisions, unsupported scopes, incomplete enumeration, foreign evidence and future timestamps remain UNKNOWN or DENIED. A valid calendar-month schedule outside the stronger 28-day witness also remains UNKNOWN. Absence of this sufficient witness does not establish a monthly violation, so this policy-free path never fabricates FAIL from an overdue weekly instance. Explicit historical policy input retains its existing validation and cannot silently fall back when malformed.

The role-specific access review controls require separate effective role and PIM evidence; this implementation does not claim to resolve them. Tests use the real collector and engine with synthetic API responses, not a live tenant validation.
