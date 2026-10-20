# Hosted AWS architecture and releases

The hosted application is **https://cspm.hacktricks.wiki**. Its dedicated Terraform root is `infra/aws`; it shares the HackTricks login and billing integration without taking over the wiki infrastructure state.

## Architecture

The Fargate collector and analyzer worker image includes `aws` (CLI v2), `kubectl`, `gcloud` and `az`, installed through the same vendor installer used by every local Compose runtime. CLI Python dependencies are separate from the application SDK constraints. Builds verify all four executables as UID 10001.

- CloudFront serves a private S3 frontend and forwards `/api/*` to API Gateway and a FastAPI Lambda adapter.
- DynamoDB stores tenant-owned workspaces, connectors, jobs, schedules and quotas. Reports and sealed snapshots reside in private S3.
- Secrets Manager and KMS protect connector credentials. The API and collector receive only their required access; the analyzer cannot decrypt source connector credentials. Optional AI review uses captured sessions protected by a separate AI envelope key.
- Step Functions runs a collector and then an analyzer as separate, temporary ECS tasks. Deterministic evaluation uses the saved snapshot; optional post-scan Chack agents also use network access for Codex and cloud verification. The analyzer still needs platform S3/DynamoDB access to persist results.
- Conditional leases, deadlines, cancellation handling and bounded inventories control scan execution. Cloud permissions, collection limits and missing evidence are reported explicitly.

Infrastructure defaults and exact role permissions are defined in Terraform, not in historical sizing reports. Fargate, storage, requests, logs, public IPv4 and encryption incur charges. Budget notifications are alerts rather than spending cutoffs.

## Identity and tenant access

Hosted sign-in uses the existing [HackTricks Tools login](https://tools.hacktricks.wiki/login.html). The API verifies the identity, user state and tenant ownership. Cookie-authenticated mutations validate their origin. A client field or mutable user `custom:plan` attribute does not establish paid entitlement; the server verifies the existing Stripe subscription independently. Missing billing verification grants the free tier.

Artifacts require authenticated ownership checks before the API issues a short-lived private download URL. Do not publish raw reports, connector credentials, Terraform state or signed download links in Git or workflow logs.

## Production release

Production publication is owned by the operator-controlled release workflow in the private infrastructure repository. Do not run a competing local apply.

1. Merge the reviewed source and record its exact commit. Run the affected Python tests, compliance materialization check and frontend build/UI tests; resolve actual regressions before deployment.
2. Dispatch the workflow with `phase=plan` and that exact `source_sha`. Its pinned source produces the worker image, API/frontend artifacts, corresponding-source archive and immutable private release bundle.
3. Review the saved plan, source manifest and bundle digests. Verify the target account, state backend, expected resource identities and every change, including drift. Reject unexpected deletes, unrelated resources or permission expansion. A new source commit requires a new plan.
4. Dispatch `phase=apply` using the exact accepted `plan_run_id`, `plan_sha256`, `drift_sha256` and `bundle_sha256`. The apply uses that saved release rather than rebuilding another checkout.
5. Verify HTTPS health, the returned source version, HTML/assets, authenticated tenant access and the affected application flows. Compare the corresponding-source archive with the accepted commit. Retain the compact receipt and remove superseded local build artifacts.

Use the workflow's current input schema for dispatch:

```sh
gh workflow view "$RELEASE_WORKFLOW" --repo "$PRIVATE_INFRA_REPOSITORY" --yaml
gh workflow run "$RELEASE_WORKFLOW" --repo "$PRIVATE_INFRA_REPOSITORY" \
  -f phase=plan -f source_sha=EXACT_REVIEWED_COMMIT
```

A successful plan does not deploy. An old plan, a passing health endpoint or an earlier test receipt does not prove acceptance of later source.

## State and credentials

Deployment account, identity, billing and backend values come from private operator configuration. Set `PEASO_DEPLOY_CONFIG` to that JSON file and initialize Terraform with a private `-backend-config` file. Verify the configured account and isolated state key for every reviewed plan. GitHub Actions uses its scoped OIDC deployment role; a local read-only profile is insufficient for publication.

The private deployment JSON supplies `account_id`, `cognito_pool_id`, `cognito_client_id`, `stripe_secret_arn`, `stripe_price_id`, `budget_email` and `backend` (bucket/key/region/encrypt/use_lockfile). Optional fields are `codex_token_secret_arn`, `codex_token_kms_key_arn`, `gcp_platform_project`, `gcp_platform_email` and `platform_account_ids`. Token and billing secret **values** never belong in this file. The build helper writes these inputs to ignored Terraform variables. Keep the JSON and backend configuration outside this repository. An upgrade must also supply `archived_customer_role_templates`, mapping the existing template SHA256 keys to private archive paths. Preserve those keys to retain existing S3 objects; historical templates are no longer bundled in public source. `private_identifiers_file` points to an external JSON array of internal identifiers: the release freezer checks every selected source file, including compressed content, against that list before producing public artifacts. Relative private paths resolve from the configuration file location. Runtime token lookup uses only `CODEX_TOKEN_SECRET_ARN`; the operator manages token publication and refresh.


Terraform 1.14.3 or later is required by the current backend configuration. For maintenance:

```sh
terraform -chdir=infra/aws fmt -check
terraform -chdir=infra/aws init -backend=false
terraform -chdir=infra/aws validate
```

Build outputs, raw state, binary plans, private overrides and deployment variables remain ignored/private. Never remove the current production bundle or image while cleaning discarded plans.

## Customer permissions

`infra/aws/customer-role.json` is the generated customer-controlled AWS role template. Pass the collector role ARN and workspace External ID shown in connector setup as its `CollectorRoleArn` and `ExternalId` parameters. Platform role assumptions require the explicit permitted role ARN and tenant binding; customer credentials do not borrow platform authority. Use the connector's generated instructions and the provider [collection guide](peaso-aws-collector.md) for the current permission contract.

Native collection reads configuration and reports. When Access Analyzer evidence is requested, it reuses existing account analyzers in scanned Regions and attempts to create missing external analyzers per scanned Region and one unused analyzer per account and partition (90-day inactivity window). Unused analyzers incur AWS charges. Scan-created analyzers wait at least 180 seconds, then are polled for ACTIVE status for up to ten additional minutes before findings are collected. Initial analysis may take longer; temporary evidence is marked partial and empty results do not prove an absence of findings. The scan deletes only analyzers it successfully created, including on failure or cancellation; cleanup failures and analyzer ARNs are recorded in snapshot metadata under `access_analyzer_lifecycle`. Existing analyzers are retained. `IAMAccessAnalyzerFullAccess` supplies creation, deletion, and service-linked-role permissions; denied creation remains visible as incomplete evidence. Collection does not apply remediation, enable APIs or retrieve secret values. The original AWS IAM CLI reads existing Access Analyzers only.

Azure ARM Reader does not imply Microsoft Graph access. Device-registration policy evidence, for example, needs a suitable Graph read permission such as `Policy.Read.DeviceConfiguration`; denied Graph reads must remain unassessed. GCP and Kubernetes similarly require the documented service/resource read permissions. See the README's provider guide links.


Hosted AWS role setup allocates a persistent External ID for each personal/shared workspace using 48 cryptographically random bytes (384 bits). All new hosted role connectors in that workspace use the same ID; another workspace receives a different ID. Allocation is atomic in SQLite and DynamoDB. Prepared setup and access-check receipts are bound to the selected workspace, and clients cannot provide a hosted External ID. The customer role must require the exact value with `StringEquals` on `sts:ExternalId`.

Existing connectors retain their previously generated, workspace-owned bindings so deployment does not invalidate customer trust policies. Replacing their authentication uses the workspace ID and requires updating the role trust accordingly. Customer-supplied source credentials keep their explicitly configured role-chain External IDs; they do not use the platform's role-assumption authority.
