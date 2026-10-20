# Historical GCP login contract disposition

`gcp_logging_detect_t1110` is archived as an unsupported exact contract. Its historical registration and signed source remain available for provenance; production collection/evaluation and public catalog selection reject it. This is not a new login detector.

The old project-scoped contract requires `authenticationEvent`, synthetic completeness/classification flags and failed `status.code` events. The project adapter emits none of those classification flags and selects unrelated RPCs. Google Workspace login events instead have organization scope and native `login.googleapis.com` / `google.login.LoginService.loginFailure` semantics. Relabelling a code-7 permission denial as failed authentication would be incorrect.

Final directed acceptance: **623 passed**, including public selection exclusion, explicit rejection, signed-source preservation and the native permission-denial regression. No live account or resource writes. A future organization login observer is a separate capability and is not claimed by this closure. [Exact source hashes and receipt](authentication-contract-review.json).

Primary documentation: [Login event samples](https://docs.cloud.google.com/logging/docs/audit/gsuite-login-samples), [organization log access](https://docs.cloud.google.com/logging/docs/audit/configure-gsuite-audit-logs), [organization-level troubleshooting](https://docs.cloud.google.com/logging/docs/audit/troubleshooting-faq-gsuite).
