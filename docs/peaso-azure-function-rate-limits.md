# Native Function/APIM rate-limit evidence

The `azure.other.function_invoke_rate_limit` collector has a narrow configuration-only path. It can report FAIL when complete ARM inventories join every active HTTP Function/method to literal online APIM operations and an explicit operation policy has no rate limit. The original signed evaluator is unchanged. This is partial native evidence, not full control closure.

A configured limiter remains UNKNOWN without the existing contract's authorized same-caller threshold-plus-one probe and rate-policy 429 receipt. The collector never invokes a Function, reads Function keys, contacts a downstream application, or manufactures probe results.

The supported configuration requires a native Function App GET; complete Functions and empty slots inventory; complete APIM service/online API revision/operation inventories; empty workspace inventory; exact HTTPS backend and invoke routes without query, parameters or rewriting; and an operation policy with all four explicit sections and no inherited `base`. Arbitrary policies, expressions, fragments, routes, slots, workspaces, missing metadata, denied reads, pagination limits and duplicate or foreign identities remain UNKNOWN. Only a tiny XML grammar is projected; unrelated config, files, test data and arbitrary policy strings are omitted. All reads use the existing ARM credential and shared budgets.

Owner policy uses `options.compliance_policy.sw15` with exactly `status: collected`, subscription `scope`, UTC `observationStart`/`observationEnd`, positive integer `maxCalls`/`maxRenewalPeriodSeconds`, and nonempty unique `stableCounterKeys`. These are normative limits and an approved observation window, not observations. Missing or malformed approval stays UNKNOWN. No behavior flag is accepted from the caller.

Example policy (replace bounds and window with owner-approved values):

```json
{"status":"collected","scope":"/subscriptions/OWNER-SUBSCRIPTION","observationStart":"2026-10-01T00:00:00Z","observationEnd":"2026-11-01T00:00:00Z","maxCalls":100,"maxRenewalPeriodSeconds":60,"stableCounterKeys":["approved-caller-key"]}
```

API references:

- https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-functions?view=rest-appservice-2025-03-01
- https://learn.microsoft.com/en-us/rest/api/apimanagement/api-operation/list-by-api?view=rest-apimanagement-2024-05-01
- https://learn.microsoft.com/en-us/rest/api/apimanagement/api-operation-policy/get?view=rest-apimanagement-2024-05-01
- https://learn.microsoft.com/en-us/azure/api-management/set-edit-policies (removing `base` prevents parent inheritance)

No live cloud run is claimed. SDK-shaped REST transport fixtures exercise the complete collector-to-engine path.
