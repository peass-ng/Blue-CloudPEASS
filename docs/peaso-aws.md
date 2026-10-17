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

CloudFront uses the existing issued wildcard wiki certificate and its own `cspm` DNS records. The static frontend bucket is private and accessible only through this distribution's origin access control. `/api/*` forwards cookies, Authorization and Origin to an HTTP API Gateway/Lambda FastAPI adapter with caching disabled. Artifact downloads require tenant-authenticated API ownership checks before receiving a short-lived private S3 signed URL. Exact-origin S3 CORS permits browser GET/HEAD downloads; signed-URL requests omit cookies. Large reports use bounded summary/findings/detail/graph pages. There is no unauthenticated artifact CDN path.

The API stores metadata and weekly quota in a dedicated on-demand DynamoDB table with `PK/SK`, encryption, point-in-time recovery, and `expires_at` TTL. Connector secrets use a new Secrets Manager Fernet key encrypted under a dedicated rotating KMS key. API and collector can retrieve the connector key; the analyzer has explicit denial for Secrets Manager, KMS decryption, and `sts:AssumeRole`.

Step Functions runs a collector followed by a separate analyzer task with distinct IAM roles. A DynamoDB conditional lease limits global hosted concurrency to one scan. JSONata computes fresh acquisition/expiration times for retries; the lease owner is the workflow execution ARN and deletion is conditional on ownership. Lease TTL defaults to 65 minutes, whole-job/workflow timeout to 60 minutes, and each ECS stage timeout to 30 minutes, and workers must check their persisted job deadline/cancellation state before starting and throughout execution. Timeout/abort cancellation uses the ECS `.sync` integration and narrowly scoped StopTask permissions; see [AWS ECS integration](https://docs.aws.amazon.com/step-functions/latest/dg/connect-ecs.html).

Prospective Fargate tasks default to 1 vCPU/6 GiB RAM for collection and 0.5 vCPU/4 GiB RAM for analysis, through configurable `worker_resources`. These are starting sizes for the reported measurements, with no claim that every estate fits. Tasks have no inbound ports, read-only roots, non-root UID, and temporary scratch storage. There are no permanent ECS services, database servers, load balancers, or NAT gateways. A public IPv4 address exists only during task execution. Free S3 and DynamoDB gateway endpoints handle storage traffic. Logs expire after 7 days; artifacts after 30 days; credential-input objects after 1 day; incomplete multipart uploads after 1 day; ECR retains 3 immutable image releases. Lambda reserved concurrency is 3 for API and 1 for scheduling, API Gateway limits traffic to 5 requests/second with burst 10, and schedules tick every 15 minutes.

Using the previously recorded US East Linux/x86 example rates of USD 0.000011244/vCPU-second and USD 0.000001235/GiB-second, [Fargate pricing](https://aws.amazon.com/fargate/pricing/) and [public IPv4 rate](https://aws.amazon.com/vpc/pricing/), a run with 15 minutes in each configured task estimates USD 0.0288 for compute and IPv4, before image pull time, storage, API requests, logging, encryption and egress. Runtime cost telemetry derives both stage sizes from the deployment settings, applies a 60-second minimum per observed attempt, and excludes IPv4 and other service costs. These rates were not revalidated during this offline sizing task; telemetry is an estimate rather than a bill.

The hosted analyzer needs S3/DynamoDB network access for persisted snapshots and reports. Its evaluator runs without customer credentials or provider clients; this is distinct from a fully disconnected local evaluation process. The frozen source/archive, API package and worker image include the full `peaso` package, including the read-only `peaso/privesc` attack-path analyzer and its catalog. The worker image includes the native `peaso` package, explicitly selected read-only Kubernetes transports and offline permission classifiers, and SDK dependencies, with no Turbot, Steampipe, Powerpipe, Prowler, PostgreSQL, or legacy executor.

The monthly CSPM budget defaults to USD 25, with email notifications at 80% actual and 100% forecast. The `Application=hacktricks-cspm` cost allocation tag must be active in billing for the tag-filtered budget to capture costs. The authorized wiki session received `AccessDeniedException: Linked account doesn't have access to cost allocation tags` on `ListCostAllocationTags`; activation must therefore be verified by the payer/management account. A budget alert is a notification, not an automatic spending cutoff. Storage, requests, KMS, Secrets Manager, Fargate runtime/public IP, and egress still incur usage charges.

## Deployment and review

Terraform 1.14.3+ is required for the S3 lockfile backend. Authenticate through the existing legitimate wiki deployment session, then verify account identity before every mutation. A read-only `wiki-infrastructure` profile is sufficient for reconnaissance but cannot deploy. On this machine the authorized command is `assume wiki --exec 'COMMAND'`; it must wrap Terraform and AWS publishing processes without printing credentials.

1. Run `terraform -chdir=infra/aws init`, `fmt -check`, and `validate`.
2. Wait for a new supervisor SOURCE STABLE event after the independent 40-technique semantic review; the earlier stable event is revoked and the current local release must not ship. After that event, the coordinator grants the heavy build slot and the API/worker owners settle their source, run `python3 scripts/peaso_deploy.py freeze-release` from the complete current working source, including uncommitted supervisor additions and all of `peaso/privesc`. Build sequentially from that exact manifest: `package-api`, `verify-package`, `build-frontend`, then `build-worker --tag RELEASE`. Preserve every supplied report/UI section. Do not use an isolated export, omit modules, or reuse the old source snapshot. The release digest identifies the complete source used by API, frontend and worker.
3. Inspect the dedicated state before planning. The ECR repository and lifecycle policy already exist in `cspm/terraform.tfstate`; do not replay the applied bootstrap plan. For a genuinely new environment only, review a fresh `plan --bootstrap-ecr` with the coordinator before applying its exact digest.
4. Run `push-worker --tag RELEASE` to publish the immutable digest and write private deployment variables. Add only explicitly approved customer role ARNs to `deployment.auto.tfvars.json`.
5. Rebuild the API ZIP and worker after all runtime owners have completed integration. Generate the full `plan` and review the complete saved plan, account, state key, resource IDs and action counts before apply. Require zero updates and zero deletes on every existing resource, including CSPM bootstrap resources. Send sanitized action counts and the saved-plan SHA256 to the coordinator before apply.
6. Apply using `apply --plan PATH --reviewed-sha256 SHA256`. The script verifies the binary digest, rejects every update, delete, replacement, unrelated named change, or backend mismatch and uses only the saved plan. All commands must retain the authorized wiki credentials.
7. Publish the finished frontend with `publish-frontend`, run `verify-host` for HTTPS health and unauthenticated tenant endpoints, then test authenticated endpoints, the same existing users, atomic manual/scheduled quota, a hosted fixture scan, and an explicitly authorized read-only cloud scan.

Example wrapper: `PEASO_TERRAFORM=/path/to/terraform assume wiki --exec 'python3 /Users/carlospolop/git/Blue-CloudPEASS/scripts/peaso_deploy.py plan'`. Build outputs, binary plans, raw Terraform state and deployment variables remain ignored/private. Terraform state can contain the new connector key and must remain encrypted and access controlled; sanitized `.review.json` files contain addresses/action counts/digests only.

## Customer AWS roles

`infra/aws/customer-role.json` is a customer-controlled CloudFormation template with the exact CSPM collector principal and a unique server-generated connector external ID. It grants listed configuration/inventory reads and the explicitly authorized `iam:GenerateCredentialReport` evidence operation when the report is missing, with no secret-value reads or IAM configuration writes. Region discovery uses `ec2:DescribeRegions` so default AWS collection can visit all enabled regions. For platform task-role authentication, the permanent collector needs the exact customer role ARN in the deployment allow-list; an empty list disables platform-source assumptions. The backend enforces that allow-list and a server-generated tenant connector external ID. Explicit customer credentials may use the customer’s own authorized role chains and existing external IDs without borrowing platform authority. Hosted filesystem/exec-based credential directives remain rejected. Additional services outside the template return explicit denied/unknown coverage rather than fabricated success.

IAM access-report evidence (`ServicesLastAccessed`) is collected for every IAM user and role with `iam:GenerateServiceLastAccessedDetails` (Granularity `SERVICE_LEVEL` only, enforced by the collector gate) followed by paginated `iam:GetServiceLastAccessedDetails`. Generation creates only a report job; it changes no IAM principal, policy or credential. Both actions are granted by the AWS managed `SecurityAudit` policy (v94: explicit `iam:GenerateServiceLastAccessedDetails`, `iam:Get*`) and `ReadOnlyAccess` (v190: `iam:Generate*`, `iam:Get*`), verified read-only on 2026-10-11, and they are in the generated customer template. The read is bounded by `service_last_accessed_concurrency` (default 4) and `service_last_accessed_wait_seconds` (default 120) with 1 to 5 s poll backoff. A principal whose job fails, is denied or misses the deadline gets no `ServicesLastAccessed` list, so only its checks are UNKNOWN; `ServicesLastAccessedStatus` records the reason.

Temporary acceptance identities/resources are tracked by the dedicated test worker and must be removed after testing. Their role ARNs must then be removed from the permanent collector allow-list through a separately reviewed dedicated plan.

## Evidence and deployment status

Reconnaissance proved account identity, access to the existing wiki state, the existing issued wildcard certificate, public Cognito identifiers, live app-client write-permission ambiguity, and the current Stripe source/price using sanitized reads. The initial read-only profile denied creation of IAM, VPC, Lambda, Step Functions, S3, ECR and DNS resources; an authorized `assume wiki` session subsequently resolved the credential blocker.

Terraform formatting/validation, AWS state-machine-definition validation (zero diagnostics), CloudFormation customer-template validation, release-archive privacy/determinism checks, and initial worker/API builds have passed. The coordinator reviewed and approved the exact ECR bootstrap plan, which applied with 2 additions, 0 changes, and 0 deletions. The deployed repository is `arn:aws:ecr:us-east-1:202533532952:repository/hacktricks-cspm-worker`, with immutable tags, scanning, and three-release retention. The updated full scaffold plan contains 61 creates and no changes/deletes, and remains ineligible to apply until actual frozen artifacts replace the placeholder image. Full deployment, hosted resources/IDs, HTTPS authentication/quota checks, fixture/cloud scans and cleanup are pending until the reviewed full apply and runtime integration finish; do not treat this preparation as a deployed service.

The historical source snapshot `e077fee1a881254cada54614d175d9588bf51ec5683cd7ab1963ebd568873368` is obsolete and must not ship. The 2026-10-11 light preflight found 189 archived files and no `peaso/privesc`, a placeholder image in private deployment variables, an empty ECR repository, and no CSPM Lambda/distribution. Current source must be frozen afresh after the coordinator grants the heavy slot; full package verification, new reviewed additive plan/apply, HTTPS publication, shared-login acceptance, free/paid quotas and a real bounded hosted scan remain pending. Current evidence and resource/fixture cleanup ownership are recorded in `docs/handoff/gate-hosted.md`; past documentation-only restrictions and isolated-export recommendations are superseded by this dispatched deployment task.

Cleanup evidence: the exact temporary test role `peaso-test-622b8d3c82d54e02` in account `947247140022` returned `NoSuchEntity` on the final read-only check, and its expired ARN was removed from private deployment variables. Platform customer-role allow-list is empty until a newly approved test/customer lifecycle is supplied. No collector role or cross-account grant has been created by this worker. The customer template now covers 151 declared metadata actions, API Gateway GET restricted to configuration paths, and the separately authorized credential-report generation operation; its AWS template validation passed.


## Azure connector device-registration policy

Azure ARM Reader does not grant Microsoft Graph permissions. For tenant device-registration policy evidence (`GET /v1.0/policies/deviceRegistrationPolicy`), the connector application or delegated token requires Microsoft Graph `Policy.Read.DeviceConfiguration` with tenant admin consent where applicable. Microsoft lists that permission as the least-privileged read permission; an already-consented `Policy.Read.All` also permits the read. A missing Graph token/consent or denied request must remain unavailable/UNKNOWN coverage and must never be reported as a passing device policy. See [Microsoft Graph deviceRegistrationPolicy permissions](https://learn.microsoft.com/en-us/graph/api/deviceregistrationpolicy-get?view=graph-rest-1.0).


## Full-scan sizing checkpoint

Supervisor-reported split analysis peaks are AWS 0.50 GB/4.9 seconds,
Azure 1.47 GB/8.4 seconds, GCP (81 projects) 1.99 GB/23.2 seconds and large
Azure 2.96 GB/26.4 seconds; collector peaks are AWS 2.8 GB and GCP 3.1 GB.
These are supplied measurements, not fresh scans or Fargate measurements.
Prospective defaults are collector 1 vCPU/6 GiB and analyzer 0.5 vCPU/4 GiB;
validation accepts supported 0.5/1 vCPU combinations, with collector at least
6 GiB and analyzer at least 4 GiB, up to 8 GiB. API/worker environment values
and runtime cost telemetry use the same configured stage sizes.
[Fargate CPU/memory matrix](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html).
Coordinator-approved `scan_runtime_limits` remain workflow/job 3,600 seconds,
stage 1,800 seconds and owned global lease 3,900 seconds. Single hosted scan
concurrency and separate sequential stages are capacity assumptions. Process
RSS excludes some task overhead and does not predict larger estates or related
snapshot joins. A small fixture proves lifecycle, not full-estate capacity.
No default inventory cap or check removal is used to fit memory. See the
[memory and failure gate](handoff/gate-memory-oom.md) for exact evidence and limits.


The maximum illustrative two 30-minute-task compute/memory/IPv4 estimate at the
new prospective defaults is approximately USD0.0576, before image pull and other
service charges. Local ASL compilation verified bounds, owner-conditional lock
release, conditional expired-lease reacquisition and ECS `.sync` cancellation.
AWS ASL validation is pending legitimate wiki SSO browser renewal at this
checkpoint; this is not a cloud-validation pass. Mocked ECS OOM/SIGKILL failures
persist `worker_task_failed` with the failing stage and clear job ownership;
owned child SIGKILL persists `worker_interrupted`, without claiming OOM.
Lock deletion remains owner-conditional; a deletion error still reaches job
failure reconciliation, and an undeleted owned global lock expires after its
bounded lease. Whole-workflow timeout/dependency outages still require deadline
expiry/reconciliation; no live OOM or hosted failure acceptance is claimed.
