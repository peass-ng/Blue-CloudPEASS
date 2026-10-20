# PEASO local API and durable workers

PEASO collects declared read-only cloud configuration, seals a sanitized snapshot, and evaluates it offline. Findings and graphs describe captured configuration and declared relationships; collection gaps remain visible. This runtime uses the repository's native engine and contains no Steampipe, Powerpipe, Turbot or PostgreSQL runtime.

## Start the three-container application

Docker Engine and Docker Compose v2 are required. From the repository root:

```sh
cp .env.example .env
chmod 600 .env
docker compose up --build -d --wait
docker compose exec api cat /var/lib/peaso/identity/local.token
```

Open `http://127.0.0.1:8000`, select Settings, and enter the token. Leave `PEASO_LOCAL_TOKEN` blank to generate a persistent private token; if you explicitly set it in `.env`, enter that configured value instead. The API publishes its port only on loopback. The generated token has no unauthenticated HTTP discovery endpoint. API origins are restricted to the configured local UI origins; update `PEASO_ALLOWED_ORIGINS` when using a different local port.

The API initializes named volumes and drops root to UID/GID 10001 before serving requests. The collector receives the private identity volume read-only and can decrypt saved connector credentials. The analyzer receives state/evidence and the separate AI-key volume. It can decrypt captured scan sessions for optional AI verification, but does not receive the source connector-key volume. It has network access for Codex and those scoped verification calls. Containers use read-only root filesystems, restricted capabilities, temporary private working space, and `no-new-privileges`. Both workers wait for API readiness.

Connectors support portable explicit credentials. Local native SDK profiles require access inside the collector, not inside the analyzer. Mount only the particular credential/config files read-only into the collector using a local Compose override; host filesystem paths are not automatically available inside a container. The API, collector and analyzer images include AWS CLI v2 (`aws`), Kubernetes CLI (`kubectl`), Google Cloud CLI (`gcloud`) and Azure CLI (`az`) alongside the Python provider SDKs. The AWS hosted worker uses the same installer. Google and Azure CLI config directories default to `/tmp/peaso-gcloud` and `/tmp/peaso-azure` so commands can run as UID 10001 with a read-only root filesystem; override `CLOUDSDK_CONFIG` or `AZURE_CONFIG_DIR` when mounting existing CLI profiles. `AWS_CLI_VERSION` and `KUBECTL_VERSION` Docker build arguments select the pinned client versions; choose a kubectl version compatible with your clusters. Kubernetes kubeconfigs must contain embedded tokens or certificates. Exec helpers, auth-provider plugins, proxies, YAML aliases and references to external credential files are rejected, including in locally loaded files. Credential YAML is limited to 2 MB, 20,000 nodes and 64 nesting levels. The native Python setup below can reuse host profiles and data-only kubeconfigs.

```sh
docker compose ps
docker compose logs --tail=50
docker compose stop
docker compose up -d --wait
```

Stopping or recreating containers preserves named volumes, saved connectors, quotas, schedules and completed reports. Back up both the state and identity volumes together: losing the encryption key makes saved credentials unreadable. `docker compose down` also preserves volumes; `down -v` deliberately deletes them. Keep `.env`, `.peaso/`, keys, tokens, reports and credential files outside Git and deployment source archives.

## Native Python startup

Use an existing isolated environment or create one, then install the package:

```sh
python3 -m venv /tmp/peaso-venv
/tmp/peaso-venv/bin/pip install -e '.[cloud,hosted]'
/tmp/peaso-venv/bin/python -m peaso.server
```

In two additional terminals, with the same environment/configuration:

```sh
/tmp/peaso-venv/bin/python -m peaso.worker collector
/tmp/peaso-venv/bin/python -m peaso.worker analyzer
```

For optional AI review, also install `.[ai]`, install the Codex CLI, and sign in through Settings or configure an explicit token source. Without AI, the base native installation and standalone CLI do not need Codex.

Native startup defaults to `127.0.0.1:8000` and `.peaso/state` plus `.peaso/identity`. Read `.peaso/identity/local.token` once and enter it in Settings. Override `PEASO_STATE_DIR`, `PEASO_IDENTITY_DIR`, `PEASO_PORT` and `PEASO_ALLOWED_ORIGINS` for isolated validation runs. The deterministic evaluator makes no cloud calls. Optional AI review uses network access and captured sessions; its read-only instruction does not reduce the supplied sessions’ IAM permissions. Install the Codex CLI and configure a token only if using AI. Standalone [CLI checks](peaso-cli.md) need neither.

## API contracts

OpenAPI is available at `/docs`. Protected endpoints require `Authorization: Bearer <local-token>` locally. Connector credentials and inline configuration are Fernet-encrypted before persistence, and credential values are absent from connector responses, worker errors and sanitized evidence. Validation errors omit rejected input. Worker child stdout/stderr and HTTP access logging do not expose provider exceptions or request bodies. Typed job failure codes and stages explain failures without serializing credentials.

| Operation | Contract |
| --- | --- |
| `/api/health` | Unauthenticated health plus optional source URL/version; no token disclosure. |
| `/api/me` | Tenant, verified plan, weekly limit/usage, runtime mode and supported authentication methods. |
| `/api/connectors` GET/POST | Collection `{items}`; create `{name,provider,auth,scopes,options}`. |
| `/api/connectors/{id}` GET/PATCH/DELETE | Owned connector only; response `auth:{configured,fields}` contains field names, never values. |
| `/api/scans` GET/POST | Create `{connector_id,categories,checks,frameworks}`; optional `Idempotency-Key` header. |
| `/api/scans/{id}` GET | State, immutable connector reference, timestamps, timeline, input mode, typed failure and runtime estimate. |
| `/api/scans/{id}/cancel` POST | Cancel queued or active work; terminal states remain terminal. |
| `/api/scans/{id}/report?format=json\|markdown` | Complete local download; hosted returns `{download_url,expires_in:300,format}` for an owned private object. |
| `/api/scans/{id}/summary` GET | Report metadata, statistics, category counts and coverage summary, without large evidence arrays. |
| `/api/scans/{id}/findings` GET | Bounded summary pages with `offset`, `limit` (1–500), `total`, `has_more`, `next_offset`, category-global facets. |
| `/api/scans/{id}/findings/{finding_id}` GET | Complete evidence for one owned finding; oversized hosted detail uses the signed download envelope. |
| `/api/scans/{id}/coverage` GET | Bounded coverage pages with the same pagination fields. |
| `/api/scans/{id}/graphs/{network\|iam}` GET | Complete graph; optional `max_nodes` projection. Hosted supports precomputed `max_nodes=500` or complete signed graph downloads. |
| `/api/scans/{id}/reachability` POST | One selected TCP/UDP configuration query over the owned immutable network sidecar, with no cloud calls or probes. |
| `/api/schedules` GET/POST | Create scan selectors plus `rules` (1–20 calendar rules), IANA `timezone`, `enabled`, optional timezone-aware `next_run_at`. Legacy `interval_hours` remains supported. |
| `/api/schedules/{id}` PATCH/DELETE | Owned schedule updates/removal. |
| `/api/catalog` GET | Engine catalog dictionary: providers, categories, checks, framework families/versions and coverage limitations. |

Findings filters are `categories` (comma-separated), `framework`, `severity`, `service`, `status`, and `search`. Search covers summary metadata: title, check, service, resource, scope, framework and remediation; detailed evidence is retrieved separately. `group_by=service|check_id|resource_id` provides stable grouping before pagination. Evidence summaries explicitly mark any shortened large metadata; complete values remain in detail and downloads. Fetch pages until `has_more` is false; the first page is not the complete result set.

Reachability accepts `{source_resource_id,destination_resource_id,protocol:"tcp"|"udp",destination_port,source_port?,address_family:"ipv4"|"ipv6"}` using globally scoped report resource IDs and integer ports 1–65535. It returns modeled `allowed`, `blocked` or `unknown` with native references and unresolved dependencies. It does not establish application listening or observed connectivity. Existing reports created before sidecar support require a new scan. Supported provider cases and limitations are maintained in `docs/peaso-reachability.md`.

When Codex is unavailable, the web form disables AI automatically. API callers should include `ai_enabled: false` when creating scans or schedules without Codex access; requests that explicitly or implicitly enable AI require a usable token.

Local `options.snapshot` imports a schema-1.0 snapshot; `options.demo` explicitly selects fixture input. Jobs/reports label these `offline_snapshot` or `demo`, and both consume the same weekly quota as live runs. Hosted connectors reject these options. Default scans request all accessible supported inventory and pagination; explicit selections/caps remain available through engine options. The API does not inject `max_resources`, `max_calls` or `max_pages` limits. The hosted enqueue deadline is disclosed in `/api/me.scan_timeout_seconds` and each job's `deadline_at`; reaching it produces an explicit terminal timeout. Coverage never turns missing/denied/time-limited data into a pass. IAM credential-report generation is a specifically authorized metadata-generation exception when the native AWS collector needs it; it changes neither IAM policy nor cloud resource configuration.

## Durability, quota and scheduling

SQLite uses WAL, full synchronization, a busy timeout and `BEGIN IMMEDIATE` for mutations. Tenant, connector validation, weekly quota reservation, job creation and idempotency are one transaction. Replaying the same key/body returns the same job without charging twice; reusing the key for a different request returns 409. Free users have one scan per UTC Monday-based week and verified paid users have ten, shared across manual and scheduled runs. Local identities always remain free. Cancellation/failure does not refund reservations.

States are `queued → collecting → collected → analyzing → completed`, with `failed`, `cancelled`, and `timed_out` terminal alternatives. Thirty-second leases are heartbeated and fenced with fresh owner tokens. Expired leases can be reclaimed; stale owners cannot publish a terminal transition. The absolute deadline begins at enqueue, including queue wait (default 900 seconds). Workers poll cancellation, terminate their child process on cancellation/deadline/shutdown, and publish artifacts before making the completed transition. Report/evidence artifacts have generated tenant-hashed paths, never paths supplied by HTTP clients.

In **Scans → Add schedule**, choose a time zone and one or more daily, weekly or monthly rules. Daily rules select a time; weekly rules select weekdays and a time; monthly rules select a day number and a time. Shorter months use their last day. Daylight saving gaps shift the occurrence forward by the gap; repeated wall-clock times run once. Coincident rules start one scan. Existing interval schedules continue to run until explicitly converted in the editor.

The local collector checks schedules every 30 seconds in a separate thread, including while collection is busy. The AWS EventBridge rule invokes the scheduler Lambda every minute. These are due-time checks, not exact-second execution promises; queue capacity and quota still apply. Each occurrence advances atomically with job creation and shares manual quota. Concurrent schedulers cannot reserve an occurrence twice. Quota/access rejection records `last_error` and advances to the next calendar occurrence without a partial charge. Offline downtime coalesces missed occurrences into one due run. Connector deletion retires its schedules while existing jobs retain their immutable encrypted input.

Calendar payload example: `{"connector_id":"…","timezone":"Europe/Madrid","rules":[{"frequency":"weekly","weekdays":[0,2,4],"time":"09:00"},{"frequency":"monthly","day_of_month":1,"time":"18:30"}]}`. Weekdays use Monday=0 through Sunday=6. SQLite and DynamoDB use the same recurrence calculation. Time-zone data is included in both the local runtime dependency set and the AWS Lambda package.

## Optional hosted adapters and identity

`PEASO_STORAGE=dynamodb` selects the tenant-keyed DynamoDB repository and private S3 artifacts. See `.env.example` and `infra/aws` for exact environment names. Lambda entrypoints are `peaso.server.lambda_handler.handler` and `peaso.server.scheduler_handler.handler`; targeted task commands are `python -m peaso.worker collector|analyzer --once --tenant-id <sub> --scan-id <id>`. Step Functions dispatch contains job/tenant identifiers and timing only. A scheduled dispatcher recovers queued jobs if API dispatch temporarily fails.

The API reuses the existing HackTricks Cognito pool/client. It verifies RS256 JWT signature, issuer, ID-token audience, `exp`, `iat`, subject and token use. The existing `__Secure-ht_refresh` cookie can be refreshed server-side; cookie-authenticated writes require a configured Origin. No new identity provider or self-declared paid flag is used. Paid entitlement resolves the enabled Cognito subject and verified email, then independently validates the linked Stripe customer email/metadata, `hacktricks-tools` source, active/trialing subscription and configured exact price. `custom:plan` alone cannot grant entitlement. Successful paid verification is cached server-side for one hour; free results for one minute; billing uncertainty fails closed to free.

Hosted auth rejects arbitrary file paths, executable helpers, ambient customer scans and endpoint overrides. Portable customer keys, tokens, inline service-account/WIF JSON, Azure inline PEM/assertions and safe inline Kubernetes configurations are supported. Hosted Kubernetes repeats public-address validation at collection and pins the transport address while preserving TLS verification; private cluster endpoints require a local/customer runner. Explicit customer AWS credentials retain their authorized, strictly validated role chains and existing ExternalIDs, without any platform-identity fallback. Hosted platform AWS role assumption accepts up to 50 explicit customer role ARNs with a server-generated connector ExternalID; platform-owned account targets are rejected. Each target is checked with an ExternalID-free AssumeRole attempt and refused if that attempt succeeds. The owned connector's onboarding information supplies the collector ARN, trust JSON, and a private-bucket CloudFront template download. Optional public S3 hosting enables CloudFormation quick-create only after account-level public-access review; the download and CLI path remain usable without it. A failed target is recorded in coverage while the remaining targets continue. One role is selected per AWS account. After the first successful context, later roles for that account are skipped before STS and appear as `duplicate_account_target` / `not_collected` credential-target coverage. Uncheck the source-account checkbox to audit that account through an assumed role.

Hosted quota/job/idempotency creation uses DynamoDB transactions with connector revision checks. Scheduled occurrence advancement participates in the same transaction. Job/idempotency metadata expires after 30 days and weekly quota metadata after 14 days; expired jobs are hidden even before delayed DynamoDB TTL deletion. Active connectors and schedules remain durable. S3 lifecycle and public-access blocks remain infrastructure responsibilities. Object keys are `artifacts/<sha256(tenant)>/<scan-id>/<generated-file>`; each download authorization checks the owned job before issuing a five-minute signed GET URL. The browser fetches that URL with credentials omitted, no bearer header and no referrer. Bucket CORS must permit only the configured application origin.

The hosted analyzer needs DynamoDB/S3 transport and therefore is not an OS-level `network_mode: none` container. Its evaluator makes no provider calls and its separate cloud role denies access to connector credential secrets and identity-assumption capabilities. Local Compose isolates the source connector key in a separate volume; its analyzer retains network access for optional AI review. Hosted collector/analyzer sizing and egress policies are defined in infrastructure and must be verified with real deployment tests.

Runtime cost telemetry is an estimate from observed stage durations and configured task sizes, with a 60-second minimum per task attempt. It excludes image pull/provisioning, Lambda, Step Functions, storage, logs, transfer and public IPv4 costs; it is not an AWS bill. Defaults are the published US East Linux/x86 example rates and can be overridden per deployment. [AWS Fargate pricing](https://aws.amazon.com/fargate/pricing/) defines the duration, minimum charge and additional costs.

## Verification recorded on 2026-10-10

The API package was installed in a fresh isolated Python 3.13 environment. API, JWT/billing, worker/scheduler, tenant-escape, atomic quota/idempotency, redaction, large-report and independent lifecycle/fact-preservation checks passed (64 checks at the recorded checkpoint). These include disabled identity rejection before cached entitlement. The official `amazon/dynamodb-local` emulator passed nine hosted repository checks, including concurrent free/paid reservations and duplicate-key single charging. Moto verifies S3 encryption/reference handling and hosted transaction behavior; emulator tests independently cover DynamoDB concurrency.

```sh
python -m pytest tests/test_peaso_api*.py tests/e2e/test_api_lifecycle.py tests/e2e/test_credential_fact_preservation.py -q
```

For hosted adapter tests install `moto[dynamodb,s3]` in the test environment. To use the official DynamoDB Local emulator, point `PEASO_TEST_DYNAMODB_ENDPOINT` at its loopback endpoint and run `tests/test_peaso_api_hosted.py`; these tests create/delete uniquely named test tables and use synthetic local credentials.

The actual QA Azure report of 46,720,109 bytes, 8,614 findings and 9,153 resources was published without dropping evidence. A hosted-style transport harness measured 226/230-byte JSON/Markdown URL envelopes, a 1,660-byte summary, a 132,194-byte 200-row findings response and a 19,121-byte coverage response; detailed evidence matched the original. This payload test uses validated local artifact references and simulated signed URL envelopes, not a deployed S3 browser request. S3 signing/CORS and the actual cloud workflow require separate hosted acceptance. Peak process memory during full publication/projection was about 700 MB, supporting larger analyzer sizing instead of loading the report in Lambda.

An independent cold API process serving the same complete Azure bundle plus the catalog peaked at 98,238,464 bytes of process memory. Findings pages were approximately 132 KB, with metadata indexes cached independently of evidence; no complete report or IAM graph was loaded for the signed download descriptors. This measurement uses local storage with hosted-style URL envelopes and does not substitute for Lambda/S3 latency or CORS acceptance.

The actual three-image Compose build and health-gated startup passed. A supplied AWS snapshot completed through the durable collector/analyzer pipeline and preserved the IMDSv2 `optional` fact as a FAIL. JSON (3,555 bytes) and Markdown (3,023 bytes) downloaded successfully. Replaying the same idempotency key returned the same job and retained quota usage one; an additional manual run returned 429. Restarting all three containers preserved the completed report, snapshot identity and quota. That historical analyzer inspection confirmed its then-offline configuration and an offline `iam:PassRole` critical severity classification from bundled risk data. A sentinel credential was absent from downloads and container logs. One initial build captured a concurrently rewritten invalid source manifest; rebuilding valid source fixed it, and image builds now validate JSON integrity before installation.

Live hosted acceptance and provider coverage are recorded separately in `docs/peaso-validation.md` and `docs/peaso-aws.md`. This component verification does not claim paid live billing, public registration, successful cloud deployment or provider coverage beyond independently recorded acceptance results.
