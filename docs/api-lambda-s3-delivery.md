# API Lambda package delivery

The API and scheduler Lambda functions use the same `infra/aws/build/api.zip` bytes. Terraform uploads that ZIP to `runtime-packages/api.zip` in the dedicated private artifacts bucket and passes the resulting **object version ID** to both functions. The object uses SSE-KMS with the existing connector key. Bucket versioning is enabled before upload, and the function references make the object upload finish before either code update begins.

`api_zip` remains a local build path so `filebase64sha256` binds the package, the release manifest, and the saved plan to the exact reviewed bytes. The existing zipped and expanded size limits still apply. The deployment review checks the dedicated bucket/key, source hash, SHA-256 metadata, KMS key, enabled versioning, and matching object versions for both functions. Resolved review must still compare each Lambda's `CodeSha256` and active state with the reviewed ZIP.

This is an additive source successor. Historical Terraform source hashes remain pinned; the deploy guard reconstructs the exact pre-change `api.tf` and `storage.tf` bytes before accepting this successor. Any production plan that changes the two existing Lambda resources and adds bucket versioning and the package object needs its own explicit action approval; existing historical update contracts do not authorize these new actions.
