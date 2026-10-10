# CSPM deployment in the existing wiki AWS account

Target: `https://cspm.hacktricks.wiki`, AWS account `202533532952`, region `us-east-1`. This deployment uses a dedicated Terraform root in `infra/aws` and the existing encrypted backend bucket `terraform-state-hacktricks-wiki` under **`cspm/terraform.tfstate`**. The existing wiki state key `wiki/terraform.tfstate`, authentication, billing, resources, and providers are not changed. Do not use `naxusai-admin` for deployment: it is the separate test account `947247140022`.

## Existing identity and authoritative entitlement

Live inspection on 2026-10-10 confirmed the existing user pool `us-east-1_7rbhezdKX`, issuer `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_7rbhezdKX`, and public app client `3g2u5ilb7kbte92lra40ji2ht0`. The pool contains one app client. These identifiers are public configuration, not credentials.

Use the existing pages:

- Login: `https://tools.hacktricks.wiki/login.html`
- Register: `https://tools.hacktricks.wiki/register.html`
- Password reset: `https://tools.hacktricks.wiki/forgot-password.html`

The existing login sends `POST /api/auth/login` with JSON `{email,password,turnstile_token}` and returns `{ok:true}`. Registration sends `POST /api/auth/register` with `{email,password,training_news_opt_in}`; email confirmation uses `POST /api/auth/confirm` with `{email,code}`. Login sets an HttpOnly `__Secure-ht_refresh` cookie with `Domain=hacktricks.wiki`, `Secure`, `SameSite=Strict`, and `Path=/`. It does not return a browser JWT. CSPM uses the same cookie on its own same-origin `/api/*`; the server refreshes through Cognito and validates the resulting identity JWT and live user identity. Cookie-authenticated writes must validate the requesting origin.

**Do not authorize paid quotas from `custom:plan`.** Existing Terraform says `write_attributes=[]`, but the live `DescribeUserPoolClient` response omitted `WriteAttributes`. AWS documents that an omitted list represents default write access to standard and custom attributes, so the inspection does not prove that customers cannot self-upgrade. Existing wiki billing reads `custom:plan` with `AdminGetUser` and writes it through its signed Stripe webhook. We preserve that behavior without relying on this mutable attribute for CSPM. See [AWS attribute permissions](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html) and [the live API response semantics](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserPoolClientType.html).

CSPM must verify the authenticated subject, enabled user, and verified email with `AdminGetUser`, then independently verify the existing Stripe customer/subscription server-side. The customer must belong to that verified email and have `metadata.source=hacktricks-tools`; the subscription must match that source, an accepted active billing status, and the exact price `price_1TLm63Io7pPswHK23F4vZFvW`. `custom:stripe_customer_id` is only a lookup hint and cannot establish ownership. The API alone can read the existing Stripe API secret by ARN; neither collector nor analyzer can access billing credentials. Missing or unverifiable billing information grants the free quota. No Stripe secret is copied into Terraform variables, images, logs, or this document.

Weekly quotas are 1 for free users and 10 for server-verified paid users. Manual and scheduled submissions must reserve quota through the same atomic DynamoDB transaction. Client tier fields, stale token claims, and local identity never grant paid entitlement.

## Dedicated architecture and limits

CloudFront uses the existing issued wildcard wiki certificate and its own `cspm` DNS records. The static frontend bucket is private and accessible only through this distribution's origin access control. `/api/*` forwards cookies, Authorization and Origin to an HTTP API Gateway/Lambda FastAPI adapter with caching disabled. Artifact downloads go through tenant-authenticated API ownership checks and private S3 reads; there is no unauthenticated artifact CDN path.

The API stores metadata and weekly quota in a dedicated on-demand DynamoDB table with `PK/SK`, encryption, point-in-time recovery, and `expires_at` TTL. Connector secrets use a new Secrets Manager Fernet key encrypted under a dedicated rotating KMS key. API and collector can retrieve the connector key; the analyzer has explicit denial for Secrets Manager, KMS decryption, and `sts:AssumeRole`.

Step Functions runs a collector followed by a separate analyzer task with distinct IAM roles. A DynamoDB conditional lease limits global hosted concurrency to one scan. JSONata computes fresh acquisition/expiration times for retries; the lease owner is the workflow execution ARN and deletion is conditional on ownership. Lease TTL is 35 minutes, workflow timeout is 30 minutes, each ECS stage timeout is 15 minutes, and workers must check their persisted job deadline/cancellation state before starting and throughout execution. Timeout/abort cancellation uses the ECS `.sync` integration and narrowly scoped StopTask permissions; see [AWS ECS integration](https://docs.aws.amazon.com/step-functions/latest/dg/connect-ecs.html).

Fargate tasks use 0.25 vCPU, 512 MiB RAM, no inbound ports, read-only roots, non-root UID, and temporary scratch storage. There are no permanent ECS services, database servers, load balancers, or NAT gateways. A public IPv4 address exists only during task execution. Free S3 and DynamoDB gateway endpoints handle storage traffic. Logs expire after 7 days; artifacts after 30 days; credential-input objects after 1 day; incomplete multipart uploads after 1 day; ECR retains 3 immutable image releases. Lambda reserved concurrency is 3 for API and 1 for scheduling, API Gateway limits traffic to 5 requests/second with burst 10, and schedules tick every 15 minutes.

The hosted analyzer needs S3/DynamoDB network access for persisted snapshots and reports. Its evaluator runs without customer credentials or provider clients; this is distinct from a fully disconnected local evaluation process. The worker image includes only the native `peaso` package and its SDK dependencies, with no Turbot, Steampipe, Powerpipe, Prowler, PostgreSQL, or legacy executor.

The monthly CSPM budget defaults to USD 25, with email notifications at 80% actual and 100% forecast. The `Application=hacktricks-cspm` cost allocation tag must be active in billing for the tag-filtered budget to capture costs. The authorized wiki session received `AccessDeniedException: Linked account doesn't have access to cost allocation tags` on `ListCostAllocationTags`; activation must therefore be verified by the payer/management account. A budget alert is a notification, not an automatic spending cutoff. Storage, requests, KMS, Secrets Manager, Fargate runtime/public IP, and egress still incur usage charges.

## Deployment and review

Terraform 1.14.3+ is required for the S3 lockfile backend. Authenticate through the existing legitimate wiki deployment session, then verify account identity before every mutation. A read-only `wiki-infrastructure` profile is sufficient for reconnaissance but cannot deploy. On this machine the authorized command is `assume wiki --exec 'COMMAND'`; it must wrap Terraform and AWS publishing processes without printing credentials.

1. Run `terraform -chdir=infra/aws init`, `fmt -check`, and `validate`.
2. Build the Linux x86_64 API ZIP with `python3 scripts/peaso_deploy.py package-api` and the native worker with `build-worker --tag RELEASE`.
3. Generate `plan --bootstrap-ecr`, review its exact two-resource create-only ECR plan with the coordinator, then apply only that reviewed binary plan/digest.
4. Run `push-worker --tag RELEASE` to publish the immutable digest and write private deployment variables. Add only explicitly approved customer role ARNs to `deployment.auto.tfvars.json`.
5. Rebuild the API ZIP and worker after all runtime owners have completed integration. Generate the full `plan` and review the complete saved plan, account, state key, resource IDs and action counts before apply. Never apply unrelated changes or deletes.
6. Apply using `apply --plan PATH --reviewed-sha256 SHA256`. The script verifies the binary digest, rejects destructive/unrelated named changes and uses only the saved plan. All commands must retain the authorized wiki credentials.
7. Publish the finished frontend with `publish-frontend`, run `verify-host` for HTTPS health and unauthenticated tenant endpoints, then test authenticated endpoints, the same existing users, atomic manual/scheduled quota, a hosted fixture scan, and an explicitly authorized read-only cloud scan.

Example wrapper: `PEASO_TERRAFORM=/path/to/terraform assume wiki --exec 'python3 /Users/carlospolop/git/Blue-CloudPEASS/scripts/peaso_deploy.py plan'`. Build outputs, binary plans, raw Terraform state and deployment variables remain ignored/private. Terraform state can contain the new connector key and must remain encrypted and access controlled; sanitized `.review.json` files contain addresses/action counts/digests only.

## Customer AWS roles

`infra/aws/customer-role.json` is a customer-controlled CloudFormation template with the exact CSPM collector principal and a unique server-generated connector external ID. It grants only listed configuration/inventory reads, no secret values or mutation APIs. The permanent collector also needs the exact customer role ARN in the deployment allow-list; an empty list permits no role assumptions. The backend must enforce that allow-list and the tenant-owned external ID, and must reject hosted filesystem/exec-based credential directives. Additional services outside the template return explicit denied/unknown coverage rather than fabricated success.

Temporary acceptance identities/resources are tracked by the dedicated test worker and must be removed after testing. Their role ARNs must then be removed from the permanent collector allow-list through a separately reviewed dedicated plan.

## Evidence and deployment status

Reconnaissance proved account identity, access to the existing wiki state, the existing issued wildcard certificate, public Cognito identifiers, live app-client write-permission ambiguity, and the current Stripe source/price using sanitized reads. The initial read-only profile denied creation of IAM, VPC, Lambda, Step Functions, S3, ECR and DNS resources; an authorized `assume wiki` session subsequently resolved the credential blocker.

Terraform formatting/validation and initial worker/API builds have passed. The ECR-only bootstrap plan is available at `infra/aws/build/bootstrap.tfplan` with its sanitized review summary alongside it. Full deployment, hosted resources/IDs, HTTPS authentication/quota checks, fixture/cloud scans and cleanup are pending until the reviewed full apply and runtime integration finish; do not treat this preparation as a deployed service.
