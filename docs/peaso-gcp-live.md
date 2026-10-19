# GCP/GKE live acceptance

This acceptance belongs to task `task_5e05a82b0109`, dispatch `ctx_d12c7cfe9bea`, under the coordinator's amended live-only scope. Collector source changes belong to the source owner. The acceptance scripts call native collectors and explicitly select `hardening`, `exposure`, `least_privilege`, `iam_graph`, and `network`; they do not run a privilege-chain evaluator or use default all-category execution.

## Authentication and discovery evidence

On 2026-10-10 the selected gcloud account `auditor@example.com` successfully authenticated. Impersonation is explicitly disabled, including any configured CLI default. A fresh, unrestricted-pagination gcloud project/organization listing observed **78 active accessible projects and two organizations**. The list completed in 18.609 seconds and is recorded privately; visibility is limited to the selected identity and the observation time.

| Private evidence | SHA256 of normalized JSON |
| --- | --- |
| `accessible-projects.json` | `2c986f0b527c735731855e29a76c99b5ae64817b3f11a8dd9d7bc90a29b0268f` |
| `accessible-organizations.json` | `694d0d5e773d9371eb30346d766f43582153dd6387c7555c40ab489691e6614d` |

Evidence directory: `/private/tmp/peaso-gke-task_5e05a82b0109-ctx_d12c7cfe9bea` (0700); files are 0600. `gcp-discovery-summary.json` distinguishes discovery from service inventory completeness. Earlier `.cache/peaso-qa/task_02a312b5ac1f/gcp-cli*/snapshot.json` artifacts contain authentication-denied reads and do not establish successful current cloud coverage. The supervisor's current broad immutable inventory must be reconciled separately; no complete all-project service inventory is claimed at this checkpoint.

`tests/e2e/test_gcp_auth_acceptance_transport.py` uses the actual installed Google credential classes and offline OAuth, STS, IAM Credentials and metadata transports. It covers ADC authorized-user refresh, locally generated ephemeral RSA signing for explicit service-account auth, portable external-account subject suppliers, ordered delegated impersonation, metadata account selection, selected-source failures/redaction, and gcloud account/impersonation pinning. No cloud service-account key is created. These are SDK protocol fixtures, not live authorization tests for alternate identities.

The actual SDK fixtures exposed a Google Auth 2.45 compatibility defect: `identity_pool.Credentials.from_info` replaced the supplier keyword argument with the supplier from the configuration mapping. The source owner corrected the validated supplier handoff; the acceptance passed against the actual installed SDK. Together with ownership, pagination, API-error, generated-name and evidence-preservation guards, **24 tests passed in 2.73 seconds**.

## Collector-only coverage across all discovered scopes

With no current supervisor artifact available and Orca messaging disconnected, the worker ran `gcp_live_inventory.py` directly against all 78 projects and two organizations. It selected only CAI assets, IAM policies/roles/denies, VPCs/subnets and Shared VPC. No feature evaluator ran. Pagination had no call/page/resource/scope caps, and all 80 discovered scopes were attempted. The immutable snapshot completed in 258.180 seconds:

- Snapshot ID: `sha256:05bfc14a107ca60a112a5f6a6c23ed6a73d9fe810a6b69640d23abd5abf1bfb7`.
- File SHA256: `5e2bfcc1b48e3b3a5cb246a6467290c7854e8df84f4e7786b0f05b37d36945f8`.
- 46,009 fact rows: 39,744 CAI assets, 1,007 IAM policies, 2,077 role definitions, 73 VPCs and 3,108 subnets. Rows can describe the same native asset at multiple authoritative scopes; this is not a unique-asset count.
- 563 collection envelopes: 380 collected, 42 empty, five denied, 128 unavailable, six unsupported and two partial. Wire `unknown` encodes unavailable/unsupported separately in `coverage_status`.
- 1,092 source request records and 1,138 recorded attempts across Compute, CAI, IAM and Resource Manager.

The source hashes remained unchanged during collection: GCP `2f5c6aa5cca950544de082609ff4981a9263acfb19ac6cbb905213d13af26d6d`, Kubernetes `fdfb626def2495cc2995314d12c3d2b4503b4495000e4ed55875a79db58077e9`. `gcp-native-summary.json` records exact scope/service status, request IDs and safe API error evidence. Eighteen collections have `SERVICE_DISABLED`; no API was enabled. Two role collections retain partial metadata after referenced-role 404s.

A sequential paced retry of only 38 IAM-deny quota gaps completed in 95.876 seconds, returning 24 empty collections and 14 remaining `RATE_LIMIT_EXCEEDED` gaps. The separate immutable retry snapshot ID is `sha256:31ea1a155d5a616189dde75f5043055d182b60ec8cb7ba3ab27de13ee2930071`; it does not replace the original evidence.

All 72 HTTP 400 collection errors are Shared VPC reads, not IAM-deny attachment errors. A narrow read-only probe observed `getXpnHost` HTTP 204 and `getXpnResources` HTTP 400/`invalidResourceUsage` for a project that is not a Shared VPC host. The current collector encodes this negative applicability as unavailable; source-owner follow-up is needed. Complete universal visibility, all-service hydration and effective IAM access are not claimed.

## Disposable GKE lifecycle

The only approved cluster name is `peaso-qa-a95372b98e2b`, project `example-audit-project` (number `882210141464`), zone `us-central1-a`. The private ledger was written and the plan sent to the coordinator before writes. The cleanup deadline is **2026-10-10 20:31:41 UTC**.

The fixture plan uses a single e2-medium node, a 20 GB standard boot disk, DNS-only control-plane access, Workload Identity configuration and NetworkPolicy support. An owned VPC/subnet with explicit pod/service secondary ranges keeps existing default network configuration untouched. The node service account receives only `roles/container.defaultNodeServiceAccount` on this project; the separate workload service account receives no cloud roles. A Kubernetes annotation establishes declared identity metadata without a token issuance or effective-access claim. Two pause-only pods, a private ClusterIP service, deny-all NetworkPolicy, and a get/list-only namespace Role/RoleBinding produce inert PASS/FAIL/UNKNOWN review evidence. No public workload, payload, probe, or escalation is planned.

`gke_session_guard.py` verifies the pinned project/account before mutations, records each planned resource and exact etag/member addition before creating/granting, and removes only exact owned identities. Policy cleanup reads the latest etag and preserves unrelated concurrent policy changes and conditions. A detached watchdog enforces the deadline, while the runner uses `finally` cleanup. Private kubeconfig and namespace selection leave the user's default contexts untouched.

IAM get on a deleted service-account email can return 403 with “or it may not exist.” Cleanup therefore verifies service-account absence using a successful fully paginated project list; a denied get is never treated as proof of absence. The precluster interruption created two prerequisite SAs, then removed both with successful project-list absence verification. No cluster or IAM grant was created during that attempt; its identities and cleanup remain in ledger history.

The session records generated VM/disk/firewall/route/group/template identities and verifies exact resource GET 404 after cluster deletion. Owned network/subnet and SAs are then deleted and verified absent, the exact node-role membership is removed with fresh etag protection, and private kubeconfig is removed. A failed cleanup remains a blocker, rather than a successful acceptance result.

## Reproducibility and validation

`gcp_live_acceptance.py` validates immutable snapshots and summarizes scope/status/API-error evidence without reevaluating features in its summary mode. GKE mode runs the real native CLI with `--provider k8s` and explicit defensive categories, compares JSON against offline reevaluation, writes Markdown, checks expected fixture findings, and records exact node `spec.providerID` to GCP instance and KSA annotation to GCP service-account joins. These joins do not establish network reachability or effective workload permissions.

```sh
python3 -m pytest tests/e2e/test_gcp_auth_acceptance_transport.py tests/e2e/test_gcp_live_fixture_guards.py -q
python3 -m scripts.peaso_test_resources.gcp_live_acceptance /absolute/immutable/gcp-snapshot.json --output /private/evidence/gcp-summary.json
```

The fixture runner is deliberately pinned to this dispatch and project; it is not a general cloud cleanup tool. The first create request was rejected with HTTP 400 because a release-channel opt-out is no longer available for this customer; all prerequisites and the grant were removed and verified absent before the same-name retry. The retry used the Regular channel, consistent with [Google's release-channel documentation](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/release-channels#no_channel).

Exactly one actual GKE cluster was created. It reached RUNNING and all eight inert Kubernetes objects were created. The initial real CLI scan observed 15 Kubernetes records in 11 collected inventories, including two pods and one node, and emitted 801 evaluated-check progress events. Subsequent verification failed with a `TypeError`. A diagnostic rerun during teardown replaced the initial snapshot/report before they had been preserved; its 412/UNKNOWN evidence cannot establish the original fixture findings or joins. This is a worker evidence-preservation failure, not an established collector defect. The helper now refuses a diagnostic live rerun when capture files exist, with a regression test; verification must use the original capture offline.

The GKE acceptance outcome is **failed**: expected PASS/FAIL/UNKNOWN findings, offline identity, and real cross-provider joins were not durably verified. No second actual cluster was created. The provisioning GCP snapshot remains valid (`sha256:6294e6b620dd2e2e64fca28a8c7ca657d82a340b6ebeb6c439c0159f5bca67c2`, 55 facts, five collected inventories), while later GKE artifacts are marked as teardown evidence.

Primary cleanup completed at **2026-10-10T20:28:48.917583Z**, before the accepted 20:31:41 UTC deadline. The exact cluster, both SAs, owned VPC/subnet and node-role membership were removed and verified absent. `gcp_live_cleanup_verify.py` repeats read-only absence checks for captured VM/disk/managed-group/group/routes, including GKE's truncated node names, verifies no owned instance templates remain, and checks the user's default kubeconfig digest. Final supplementary evidence is `gke-cleanup-verification.json`. Orca runtime remained starting/disconnected during this checkpoint, preventing several coordinator status messages from being delivered.
