# PEASO claude_gcp_k8s partition coverage

Partition `claude_gcp_k8s` in `peaso/rulepacks/port_partitions_claude.json`: 326 GCP and Kubernetes upstream rows
(steampipe gcp-compliance, gcp-perimeter, kubernetes-compliance, Prowler gcp and kubernetes; services cloudstorage..vpc).

## Artifacts

- Predicates: `peaso/checks/claude_gcp_k8s_common.py` (helpers, fixtures, empty-resource guard),
  `claude_gcp_k8s_compute.py` (64), `claude_gcp_k8s_iam.py` (68), `claude_gcp_k8s_k8s.py` (76), loader `claude_gcp_k8s.py`.
  208 unique predicates, ids `gcp.claude.*` and `k8s.claude.*`.
- Reviews: `peaso/rulepacks/reviewed_claude_gcp_k8s.json` (325 rows) and `reviewed_claude_gcp_k8s_manual.json` (1 row).
  Both must be added to `active_reviews.json` by the lead (not done here; that file is Codex-owned).
- Tests: `tests/test_peaso_checks_claude_gcp_k8s.py` (shard integrity, in-memory manifest validation) and
  `tests/test_peaso_checks_claude_gcp_k8s_behavior.py` (PASS/FAIL/MANUAL/NOT_APPLICABLE/UNKNOWN per predicate, uncollected
  dependency, firewall/RBAC/probe semantics).

## Counts

| Disposition | Rows |
|---|---|
| ported (at least one claude predicate) | 221 |
| merged (existing reviewed Codex/core native) | 69 |
| rejected (official-doc evidence; 29 invalid_predicate with replacement checks) | 35 |
| manual (question kept) | 1 |

Rows mirroring a registered Codex decision for the same upstream query were merged or rejected with the same
natives/replacements and reason. 9 rows were `pending` in other active shards and carry `supersedes`.

## Notable corrections versus upstream

- Target HTTPS proxy TLS: an empty sslPolicy (Google default, TLS 1.0) fails instead of passing.
- Log sink and metric alerts: same-project scope; aggregated org/folder sinks give MANUAL, not FAIL.
- Audit logs (project `auditConfigs`): absent gives MANUAL, because org/folder configs are inherited.
- RBAC secret access: the predicate checks `secrets` (upstream has the typo `secret`) against each role's own rules.
- Bind: the predicate checks the bind verb on roles/clusterroles (upstream checked bindings).
- Kubernetes Dashboard: the image is matched by path (upstream used exact string equality).
- hostPort: Prowler always fails; the native checks the declared hostPort.
- Probes and resources look only at regular containers. Init and ephemeral containers cannot declare probes.

## Rejections

- **Inverted predicates:**
  - `auto_create_subnetwork_enabled`
  - `client_certificate_authentication_enabled`
  - `kubernetes_alpha_enabled`
  - `pod_service_account_token_enabled`
- **Logic flaws:**
  - `etcd_peer_tls_config`: passes when only one flag is set.
  - `pod_service_account_token_disabled`: reads only the last-applied annotation.
  - kms/sa separation of duties.
- **Non-security or not discriminating:**
  - `custom_metadata`: a metadata object is always present.
  - QUIC.
  - Label presence (×2).
  - Small-pool auto-upgrade.
- **Third-party API:** Shodan.

Manual: Prowler `kubelet_event_record_qps`. CIS allows 0, Prowler fails 0, and Prowler reads the wrong field.

## COLLECTOR FACTS NEEDED (predicates return UNKNOWN until collected)

**GCP**
- compute `images.list` + `images.getIamPolicy`, `snapshots.list`, `instanceTemplates.list` (`properties.canIpForward`), `instanceGroupManagers.aggregatedList`
- service_usage state for `containerscanning.googleapis.com` and `generativelanguage.googleapis.com`
- accesscontextmanager `servicePerimeters` (status.resources, restrictedServices), joined to the project number
- pubsub topics / subscriptions / snapshots + getIamPolicy
- Policy Analyzer serviceAccountLastAuthentication / serviceAccountKeyLastAuthentication, projected as `_activity` (lastAuthenticatedTime, observationEndTime)
- `iamPolicy` hydration for disk, instance, subnetwork, nodeGroup, nodeTemplate, resourcePolicy and kms keyRing (perimeter shared-access rows)
- the `compute.requireOsLogin` org policy (project OS Login only reads project metadata)

**Kubernetes**
- `--trusted-ca-file` in the etcd CONFIG_FLAGS allow-list (`pod.etcd_unique_ca`)
- complete ingress and PodSecurityPolicy annotations, plus `provenance.annotations_complete` (nginx snippet rows, PSP seccomp/AppArmor rows)
- PodSecurityPolicy `_provenance.kubernetes_version` (NOT_APPLICABLE on 1.25+)

## Overlap / false-positive notes

- `gcp.claude.sql_instance.second_gen_no_public_ip` overlaps core `gcp.sql.no_public_ip`. It is kept for the SECOND_GEN applicability of the CIS row.
- `gcp.claude.firewall.*` overlaps Codex RDP/SSH natives on `all`-protocol rules. Codex's unregistered
  `gcp_ports_metadata`/`gcp_ports_logging` replacement ids were not referenced.
- Codex `k8s.ports.*` workload predicates include init/ephemeral containers. Do not merge probe/resource rows onto them,
  because init and ephemeral containers would produce false positives.
- Optional-default fields would PASS on an empty resource. The common decorator therefore raises UNKNOWN for resources without collected fields.
