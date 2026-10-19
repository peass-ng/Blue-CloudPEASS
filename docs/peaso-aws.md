# Hosted AWS architecture and releases

The hosted application is **https://cspm.hacktricks.wiki**. Its dedicated Terraform root is `infra/aws`; it shares the HackTricks login and billing integration without taking over the wiki infrastructure state.

## Architecture

- CloudFront serves a private S3 frontend and forwards `/api/*` to API Gateway and a FastAPI Lambda adapter.
- DynamoDB stores tenant-owned workspaces, connectors, jobs, schedules and quotas. Reports and sealed snapshots reside in private S3.
- Secrets Manager and KMS protect connector credentials. The API and collector receive only their required access; the analyzer does not receive customer credentials.
- Step Functions runs a collector and then an offline analyzer as separate, temporary ECS tasks. The analyzer still needs platform S3/DynamoDB access to persist results.
- Conditional leases, deadlines, cancellation handling and bounded inventories control scan execution. Cloud permissions, collection limits and missing evidence are reported explicitly.

Infrastructure defaults and exact role permissions are defined in Terraform, not in historical sizing reports. Fargate, storage, requests, logs, public IPv4 and encryption incur charges. Budget notifications are alerts rather than spending cutoffs.

## Identity and tenant access

Hosted sign-in uses the existing [HackTricks Tools login](https://tools.hacktricks.wiki/login.html). The API verifies the identity, user state and tenant ownership. Cookie-authenticated mutations validate their origin. A client field or mutable user `custom:plan` attribute does not establish paid entitlement; the server verifies the existing Stripe subscription independently. Missing billing verification grants the free tier.

Artifacts require authenticated ownership checks before the API issues a short-lived private download URL. Do not publish raw reports, connector credentials, Terraform state or signed download links in Git or workflow logs.

## Production release

Production publication is owned by the **`cspm-release.yml` GitHub Actions workflow in [HackTricks-Training/wiki-infrastructure](https://github.com/HackTricks-Training/wiki-infrastructure)**. Do not run a competing local apply.

1. Merge the reviewed source and record its exact commit. Run the affected Python tests, compliance materialization check and frontend build/UI tests; resolve actual regressions before deployment.
2. Dispatch the workflow with `phase=plan` and that exact `source_sha`. Its pinned source produces the worker image, API/frontend artifacts, corresponding-source archive and immutable private release bundle.
3. Review the saved plan, source manifest and bundle digests. Verify the target account, state backend, expected resource identities and every change, including drift. Reject unexpected deletes, unrelated resources or permission expansion. A new source commit requires a new plan.
4. Dispatch `phase=apply` using the exact accepted `plan_run_id`, `plan_sha256`, `drift_sha256` and `bundle_sha256`. The apply uses that saved release rather than rebuilding another checkout.
5. Verify HTTPS health, the returned source version, HTML/assets, authenticated tenant access and the affected application flows. Compare the corresponding-source archive with the accepted commit. Retain the compact receipt and remove superseded local build artifacts.

Use the workflow's current input schema for dispatch:

```sh
gh workflow view cspm-release.yml --repo HackTricks-Training/wiki-infrastructure --yaml
gh workflow run cspm-release.yml --repo HackTricks-Training/wiki-infrastructure \
  -f phase=plan -f source_sha=EXACT_REVIEWED_COMMIT
```

A successful plan does not deploy. An old plan, a passing health endpoint or an earlier test receipt does not prove acceptance of later source.

## State and credentials

The production CSPM stack uses AWS account `202533532952`, region `us-east-1`, backend bucket `terraform-state-hacktricks-wiki`, key `cspm/terraform.tfstate`. The wiki stack uses a separate state key. Verify these identities for every reviewed plan. GitHub Actions uses its scoped OIDC deployment role; a local read-only profile is insufficient for publication.

Terraform 1.14.3 or later is required by the current backend configuration. For maintenance:

```sh
terraform -chdir=infra/aws fmt -check
terraform -chdir=infra/aws init -backend=false
terraform -chdir=infra/aws validate
```

Build outputs, raw state, binary plans, private overrides and deployment variables remain ignored/private. Never remove the current production bundle or image while cleaning discarded plans.

## Customer permissions

`infra/aws/customer-role.json` is the generated customer-controlled AWS role template. It specifies the collector principal and a workspace-specific external ID. Platform role assumptions require the explicit permitted role ARN and tenant binding; customer credentials do not borrow platform authority. Use the connector's generated instructions and the provider [collection guide](peaso-aws-collector.md) for the current permission contract.

Native collection reads configuration and existing reports. It does not apply remediation, create Access Analyzers, generate IAM credential reports, enable APIs or retrieve secret values. Missing permissions remain visible as denied/unknown evidence. The original AWS IAM CLI has optional Access Analyzer creation; pass `--no-access-analyzer` for that separate read-only invocation.

Azure ARM Reader does not imply Microsoft Graph access. Device-registration policy evidence, for example, needs a suitable Graph read permission such as `Policy.Read.DeviceConfiguration`; denied Graph reads must remain unassessed. GCP and Kubernetes similarly require the documented service/resource read permissions. See the README's provider guide links.


Hosted AWS role setup allocates a persistent External ID for each personal/shared workspace using 48 cryptographically random bytes (384 bits). All new hosted role connectors in that workspace use the same ID; another workspace receives a different ID. Allocation is atomic in SQLite and DynamoDB. Prepared setup and access-check receipts are bound to the selected workspace, and clients cannot provide a hosted External ID. The customer role must require the exact value with `StringEquals` on `sts:ExternalId`.

Existing connectors retain their previously generated, workspace-owned bindings so deployment does not invalidate customer trust policies. Replacing their authentication uses the workspace ID and requires updating the role trust accordingly. Customer-supplied source credentials keep their explicitly configured role-chain External IDs; they do not use the platform's role-assumption authority.
