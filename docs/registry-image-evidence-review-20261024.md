# Registry image evidence review

Native registry qualification identified two boundaries that must preserve valid scanner results.

Artifact Registry can return one relative blob redirect to its own registry origin and selected project/repository download path. The streaming reader follows only that bounded shape, counts both HTTP requests, verifies the final descriptor digest and size, and records the validated redirect. Manifests, cross-origin destinations, authentication challenges, repeated redirects and unproven two-attempt receipts remain rejected. The native CVE verifier accepts the explicit successful blob-redirect proof while rechecking the retained content and unchanged metadata.

The engine seals snapshot dictionaries and lists before evaluation. Azure ACR and GCP registry CVE evaluators now copy only exact JSON primitives and the engine's own sealed container types at their input boundary. Existing image identity, source receipt, selection and vulnerability validation still runs. Arbitrary container subclasses remain invalid. A complete clean scan can pass; observed HIGH/CRITICAL vulnerabilities fail even when the rest of the scan is incomplete. An unsupported OS, stale database or incomplete scan cannot become a clean result.

Regression coverage includes public reader methods, redirected native CVE capture, malformed or tampered receipts, full engine evaluation of sealed positive/negative/missing evidence, and rejection of unrelated container subclasses. Native live captures and offline pinned-scanner tests are kept separate: a local scanner result alone does not qualify the full collector or engine path.
