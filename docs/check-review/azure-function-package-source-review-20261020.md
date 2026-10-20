# Azure configured deployment package source — local proposal review

New producer: `peaso/collectors/azure_function_package_source_20261020.py`. New pure consumer: `peaso/checks/azure_function_package_source_20261020.py`. Neither imports an install hook nor joins the shared registry. The producer validates an exact selected native site and Blob, makes nine direct native requests, brackets the setting and Blob version/ETag, and sends captured regular ZIP text members through the existing bounded parser and both offline scanners.

The verdict concerns **selected configured stored source only**. Runtime bytes and continuous immutability are explicitly `unknown`. Azure documents restarting the app after replacing a package at an unchanged URL; therefore a current ARM pointer plus Blob bytes does not establish the package mounted by a running instance. This limitation follows from [Functions deployment](https://learn.microsoft.com/en-us/azure/azure-functions/deployment-zip-push) and [App Service run from package](https://learn.microsoft.com/en-us/azure/app-service/deploy-run-package), verified using primary Microsoft documentation during this run.

The native record comprises same-subscription ARM subscription/account ownership, a fixed account primary Blob endpoint, the selected native appsettings value, captured Blob metadata and bytes, and matching observations after the capture. Only recognized SAS fields are discarded; no SAS grant reaches a request. Canonical URL host/path and optional `versionid` must equal the explicit selection. Unrelated settings, raw values, URLs, query parameters, response headers and native error bodies are ephemeral. Output retains HMAC locators, bounded redacted scanner observations and receipt metadata. No selected content enters the generic transport/cache.

The existing storage `_read`, `_properties`, `_bound_subscription`, `_bound_account`, `_inspect` and real scanner adapters are reused without edits. Blob receipts and scanner part paths keep the original selected storage identity; package Web receipts keep the package identity. The new consumer checks this relation and the nine-operation order. A process-local seal binds the complete projection to its receipts; trusted expected selection, capture, tenant, customer and credential context must also match. This is same-process evidence, not a portable snapshot admission mechanism or cryptographic Azure attestation.

Bounds: two targets, nine requests per target, eighteen calls, a 120-second shared collection deadline, 512 KiB per ARM response, 4 MiB per ZIP, 12 MiB total wire data, 1 MiB per member, 8 MiB expanded and 128 members per archive, 16 MiB/256 members across the run. The reused scanner path caps findings at 128 merged leaks and 512 locations and keeps bounded transient redactions. Native logs on the collection thread are suppressed. All HTTP resources close even on failure.

A clean result needs complete association, supported archive coverage and both engines. Bound positives can fail with incomplete coverage after an unsupported member or missing engine; an incomplete negative stays UNKNOWN. Failed association cannot produce a secret-content failure for this site, even if a separately selected object would contain a secret.

Counterexamples and intentionally unsupported cases:

- `WEBSITE_RUN_FROM_PACKAGE=1` identifies a local SitePackages deployment. ARM appsettings do not identify its bytes; no Kudu, publishing credentials or filesystem access is attempted.
- A Key Vault reference hides the URL. It remains UNKNOWN without secret-store dereference.
- A SAS URL can authorize a foreign/public object. Matching a URL alone is insufficient; the account must have the exact selected same-subscription native ARM identity and primary Blob endpoint, and capture uses independent caller OAuth.
- A current Blob can change at any time. ETag-conditional GET and matching observations establish the captured representation, not a lasting immutability policy. ABA changes of the setting between observations cannot be excluded; no atomic global snapshot or uninterrupted reference claim is made.
- An app may keep using an earlier package at an unchanged URL, fail to restart, or fail to fetch its configured URL. Even a versioned Blob capture does not prove mounted/executed bytes.
- Flex deployment configuration, slots, custom containers, Linux App Service sites, missing full hosting declarations, sovereign/custom endpoints, noncanonical paths and unsupported ZIP members remain UNKNOWN or invalid selections. No fallback uses arbitrary URLs, account keys, SAS grants, secret stores, execution or credential validation.

The setup document records the exact default-off selection, trusted shared-service-account rejection, native API versions and scoped permissions: [setup](azure-function-package-source-setup-20261020.md). Existing shared hosted rules were read only. The new option remains absent from their allowlist, and existing GCP shared-platform restrictions are unchanged.

Integration still required: independently review and admit this proposal; wire credential-free preflight before auth; add exact hosted option/check selection and preserve trusted shared-account rejection; schedule capture under the existing Azure request budgets; bind normal scan contexts and portable receipt admission if persistence is needed; add the package ledger to the existing final union redactor before any mixed metadata export; add final public engine and hosted validation tests. The standalone reader rejects mixed inventory state because it has no authority to alter existing finalizers. No shared hooks, admission receipts or registrations were changed; no cloud/auth, full suite, commit, push or deployment was performed.

Validation performed on 2026-10-20:

| Execution | Actual result | Limit |
| --- | --- | --- |
| Initial directed native fake-transport tests with both real offline scanners | 60 passed in 28.53 s | Earlier revision; required positive/clean/denied/change/reference/cross-scope/partial cases passed |
| Expanded directed run | 72 passed, 1 failed in 30.79 s | A test wrongly expected a later hit after the missing second engine aborted inspection on the first clean member |
| Corrected final directed run | Blocked before collection, pytest exit 4 | Existing global GCP source/receipt guard fails, latest error `metadata network router map changed` |
| Regular Azure collector import | Blocked by the same guard | An isolated native test would require bypassing a production import boundary; no such bypass was used |
| Standalone real scanner check, clean/hit with both engines and clean/hit with second engine unavailable | Four cases passed | Tests scanner behavior only, not final native producer/consumer admission |
| Final source parsing and whitespace | Passed for new files | Syntax validation only |

The failing expanded test was corrected to put the actual hit in its first and only archive member; this preserves early-abort semantics and does not manufacture a positive from an uninspected later member. The final producer/consumer additionally expose runtime bytes and continuous immutability as UNKNOWN. These final edits have not received a successful native test rerun because of the unrelated shared import blocker. The blocker was reported to the coordinator; no guard, receipt, existing file or registry was edited to work around it. No all-pass final/native integration claim is made.

Machine-readable evidence and SHA-256 hashes of the new source/test/setup files are in `azure-function-package-source-evidence-20261020.json`.
