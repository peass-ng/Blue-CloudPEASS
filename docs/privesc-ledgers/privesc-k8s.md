# Kubernetes privilege-escalation catalog ledger (HackTricks Cloud 329aec912e90)

The row classification below started at historical revision `329aec912e90`. At HackTricks Cloud [PR #481](https://github.com/HackTricks-wiki/hacktricks-cloud/pull/481) head `4202559da3`, its rows cover **422 of 422 headings across 50 scoped Kubernetes and OpenShift pages**. The 2026-10-16 strict catalog review now has **72 active techniques and 221 exclusions**. Four exact reviewed-evidence variants activate Argo CD remote credentials, static Google keys, GKE RBAC self-grants, and Kiam/Kube2IAM role credentials; metadata-only guesses remain excluded. The Kubernetes HackTricks change moves secret-copy, admission-bypass, generic API operations, host-file reads, controller/status side effects, and OpenShift label discovery out of the privilege-escalation section; their exclusion links below follow the destination pages. The [PR #479 interim snapshot](privesc-k8s-pr479-head.md) is historical and should not be read as the final PR #481 heading count.

This ledger lists every heading in the Kubernetes and OpenShift pages of HackTricks Cloud at revision `4202559da31f53bb101052ab4622a636d243c4a5`. Each heading maps to one of these:

- catalog ids in `peaso/privesc/catalog/k8s/*.yaml`
- an exclusion in `peaso/privesc/catalog/k8s/_excluded.yaml`
- a structural or out-of-scope reason

The ledger is generated from the checkout, the catalog and the manual rows. `tests/test_peaso_privesc_coverage_k8s.py` checks that every id and exclusion named here exists. When the checkout is at 4202559da31f53bb101052ab4622a636d243c4a5, it also checks that every in-scope heading has a row.

**Pages in scope** (relative to `src/pentesting-cloud/`):

- `kubernetes-security/kubernetes-privilege-escalation/**`
- `kubernetes-security/kubernetes-post-exploitation/**`
- `kubernetes-security/kubernetes-basic-information/api-object-operations.md`
- `kubernetes-security/kubernetes-basic-information/kyverno.md`
- `kubernetes-security/kubernetes-basic-information/opa-gatekeeper.md`
- `kubernetes-security/kubernetes-unauthenticated-access/**`
- `kubernetes-security/kubernetes-persistence/**`
- `kubernetes-security/spiffe-spire-workload-identity-spoofing.md`
- `openshift-pentesting/**`

## Summary

- **Current strict catalog:** 72 k8s entries and 221 k8s exclusions. The legacy ServiceAccount token and four newly activated paths require fresh reviewed proof of the exact source action, accepted target and permission gain; Secret metadata alone creates no edge. The reviewed Helm values-to-RBAC grant is active only with typed evidence of the exact source ServiceAccount and newly granted Secret permissions.
- **Current ledger row counts:** covered: 70, excluded: 124, out-of-scope: 37, structural: 216 (total rows: 447).
- **Catalog before this pass:** 67 k8s entries and 115 k8s exclusions.
- **Catalog after this pass:** 71 k8s entries and 132 k8s exclusions. `load_catalog(strict=True)` passes.
- **Catalog after round 2 (schema extensions, NEEDS SCHEMA items 1-9):** 82 k8s entries and 126 k8s exclusions. `scripts/peaso_validate_privesc_catalog.py` reports 0 errors.

### Added entries (4, historical; two GitOps rows are now excluded)

| Id | Upstream source |
|---|---|
| `k8s-cloud-eks-irsa-wildcard-trust-existing-sa` | kubernetes-pivoting-to-clouds#iam-role-for-k8s-service-accounts-via-oidc (IRSA wildcard trust). Needs only create pods or create serviceaccounts/token in a namespace that a `system:serviceaccount:<ns>:*` trust matches. No ServiceAccount write is needed. |
| `k8s-workloads-flux-kustomization-patch-controller-identity` | controllers-and-admission#other-gitops-and-platform-controller-source-changes. Uses patch or update on a Flux Kustomization `spec.path`. |
| `k8s-workloads-crossplane-provider-kubernetes-identity` | Same section. Covers create, patch or update on Crossplane provider-kubernetes `Object`s (namespaced `kubernetes.m.crossplane.io` or cluster `kubernetes.crossplane.io`). |
| `k8s-rbac-escalate-aggregating-clusterrole` | kubernetes-persistence/identities-and-rbac#bindings-and-aggregated-clusterroles. Uses create plus escalate on clusterroles. |

The strict re-audit excludes seven previously active controller/configuration rows whose source-to-target joins were only stated in conditions. Their exact reasons are in `_excluded.yaml`; they remain documented candidate techniques.

### Fixed entries

| Id | Fix |
|---|---|
| `k8s-rbac-constrained-impersonation-user` | The identity half now accepts `authentication.k8s.io` users (the group upstream reproduces) as well as the core group. Confidence changed to conditional, and the verb_prefix limitation is documented. |
| `k8s-rbac-constrained-impersonation-serviceaccount`, `-node` | Confidence changed to conditional. The action half only matches wildcard rules (see NEEDS SCHEMA 1). |
| `k8s-nodes-replacement-pod-to-controlled-node` | Changes: <ul><li>Placement now also accepts patch or update on `nodes` (label, taint, cordon), as documented in dosing-other-nodes#taints-cordon-and-eviction and node-permissions-and-status.</li><li>Replacement now also accepts `pods/eviction`.</li><li>Added the condition `every_competing_node_excluded`.</li><li>Confidence changed to conditional.</li></ul> |

### Round 2: NEEDS SCHEMA items implemented (11 entries added, 6 exclusions removed)

| NEEDS SCHEMA item | Catalog change |
|---|---|
| 1 verb_prefix | `k8s-rbac-constrained-impersonation-user`, `-serviceaccount`, `-node`: action half is now `{verb_prefix: "impersonate-on:<mode>:", resource_match: any}`; `-node` is arbitrary-node mode only. |
| 9 k8s_node_hosting_pod_of_source | Added `k8s-rbac-constrained-impersonation-associated-node`. |
| 2 source_reaches_kind | `k8s-nodes-replacement-pod-to-controlled-node` now has `source_selector: {source_reaches_kind: k8s_node}`. |
| 3 k8s_sa_used_by_pending_pod | Added `k8s-nodes-pods-binding-pending-pod-to-controlled-node` (pods/binding or bindings create). |
| 4 k8s_secret_holds_cloud_credential | Added `k8s-cloud-pivot-secret-static-gcp-sa-key` (covers both GCP-key headings). |
| 5 k8s_secret_holds_remote_cluster_credential | Added `k8s-rbac-secrets-read-argocd-cluster-credential`. |
| 6 blocker removal | Added `k8s-admission-validating-policy-weaken`, `k8s-admission-webhook-configuration-weaken`, `k8s-admission-namespace-label-exit`, `k8s-admission-fail-open-webhook-backend` and `k8s-admission-policy-engine-excluded-namespace` (`admission_control.yaml`). |
| 7 k8s_sa_namespace_absent / k8s_sa_named_in_scc_users | Added `k8s-rbac-serviceaccount-in-absent-namespace` and `k8s-openshift-scc-users-missing-serviceaccount`. |
| 8 source_bound_to_aggregated_clusterrole | `k8s-rbac-escalate-aggregating-clusterrole` now has `source_selector: {source_bound_to_aggregated_clusterrole: cluster}`, requiring a cluster-wide binding to the aggregated ClusterRole. |
| SCC users[] collected | `k8s-openshift-scc-via-namespace-sa`: removed the `scc_direct_users_groups` condition (the collector and hook now evaluate SCC users[]/groups[]); `k8s-openshift-scc-use-host-scc` keeps it, reworded, because its RBAC `use` requirement does not read SCC users[]. |

Exclusions removed: tested-admission-control-mutations, disrupting-a-fail-open-webhook-backend, abusing-kyverno-and-gatekeeper-vwc, mounting-gcp-sa-keys-as-secret, static-google-service-account-key-mounted-as-a-secret, argo-cd-managed-cluster-credentials. Exclusions narrowed: nodes-and-pods-status (pods/binding part now mapped), controllers-and-admission VWC (now "create" only; patch/update/delete mapped).

Later exact-evidence review archived metadata-only static Google-key and Argo CD credential guesses because Secret metadata cannot prove usable content and an exact target principal. Four narrow variants now require unique, fresh, reviewed source/action/object/target and permission-delta evidence; the generic guesses remain excluded below.

### Admission blockers wired (schema section 13)

The K8s model now evaluates `pod_security_admission` / `pivot_namespace_psa_enforce_baseline_or_restricted` (definitive `blocked` on an enforce baseline/restricted namespace label) and `admission_policy`, `admission_webhook`, `kyverno_policy`, `gatekeeper_constraint` (`possibly_blocked`, edge kept as conditional). 23 entries got new or extended `blockers`; 24 k8s entries now carry blockers in total (with `k8s-rbac-serviceaccount-in-absent-namespace`). 5 entries carry `removes_blockers`.

| Blockers | Entries |
|---|---|
| PSA + the four engine blockers (privileged or host-level pod) | `k8s-nodes-privileged-pod-create`, `k8s-nodes-privileged-controller-create`, `k8s-nodes-privileged-ephemeral-container`, `k8s-cloud-hostnetwork-pod-node-identity` (pivot alias); `k8s-openshift-scc-use-host-scc`, `k8s-openshift-scc-via-namespace-sa`, `k8s-openshift-privileged-default-projects`, `k8s-openshift-scc-users-missing-serviceaccount` (`pod_security_admission`) |
| Engine blockers only, no PSA (plain pod spec, or the entry itself controls the namespace labels) | `k8s-workloads-pods-create`, `-controllers-create`, `-controllers-modify`, `-pods-modify-running`, `-pods-ephemeralcontainers`; `k8s-cloud-pod-imds-node-identity`; `k8s-nodes-hostpath-persistentvolume` (PVC volumes are allowed by restricted); `k8s-nodes-namespace-psa-relabel`, `k8s-nodes-namespace-create-privileged-pod`, `k8s-openshift-run-level-label-existing-namespace`, `-run-level-label-new-namespace`, (Tekton SCC annotation path is excluded until its controller and SCC joins are verified); `k8s-nodes-replacement-pod-to-controlled-node`, `k8s-nodes-pods-binding-pending-pod-to-controlled-node` (pod spec unchanged, so no PSA) |
| Not given blockers (a non-workload alternative in the same entry would be wrongly downgraded) | `k8s-cloud-eks-irsa-create-matching-sa`, `k8s-cloud-eks-irsa-wildcard-trust-existing-sa`, `k8s-rbac-dangling-serviceaccount-reference` (serviceaccounts/token or Secret paths), `k8s-cloud-pivot-secret-static-gcp-sa-key` (Secret read) |

| `removes_blockers` | Entry |
|---|---|
| admission_policy | `k8s-admission-validating-policy-weaken` |
| admission_webhook, kyverno_policy, gatekeeper_constraint | `k8s-admission-webhook-configuration-weaken`, `k8s-admission-fail-open-webhook-backend`, `k8s-admission-policy-engine-excluded-namespace` |
| pod_security_admission, admission_policy, admission_webhook | `k8s-admission-namespace-label-exit` (PSA alias covers the pivot blocker) |

Fixture tests in `tests/test_peaso_privesc_coverage_k8s.py` run the real entries: a privileged pod blocked by PSA restricted, a plain pod not blocked, and the PSA block lifted by `k8s-admission-namespace-label-exit` (restored as conditional, the chain's weakest confidence).

### Verified, source_revision bumped to 171e422

- All 6 entries in `openshift.yaml`:
  - `k8s-openshift-scc-use-host-scc`
  - `k8s-openshift-scc-via-namespace-sa`
  - `k8s-openshift-privileged-default-projects`
  - `k8s-openshift-run-level-label-existing-namespace`
  - `k8s-openshift-run-level-label-new-namespace`
- `k8s-rbac-dangling-serviceaccount-reference`.
- The `rbac.yaml`, `workloads.yaml`, `nodes.yaml` and `cloud_pivot.yaml` headers now cite re-verification against 171e422.

### Exclusions added (17)

| Page | Excluded headings |
|---|---|
| dosing-other-nodes | resource-pressure / node health |
| etcd | locate the datastore; create a workload through etcd |
| helm-release | release records; runner / chart supply chain |
| unauthenticated-access README | <ul><li>Helm 2 Tiller</li><li>NodePort / ingress</li><li>Dashboard skip-login</li><li>Argo CD anonymous</li><li>Argo Workflows</li><li>Prometheus</li><li>Envoy admin</li><li>Weave Scope</li><li>container registries</li></ul> |
| kubelet authentication | authentication; webhook cache / permission revocation |
| spiffe | cgroup selector spoofing |

Two older exclusions cite pages outside the scope above (`kubernetes-basic-information/access-and-common-concepts.md#rbac-roles-subjects-and-bindings` and `kubernetes-hardening/kubernetes-securitycontext-s.md`). They are kept as-is.

The new exclusions are not RBAC-reachable principals, or they are unauthenticated network exposures that cluster RBAC cannot express.

## Ledger

### kubernetes-security/kubernetes-privilege-escalation/README.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/README.md#k8s---privilege-escalation` | K8s - Privilege Escalation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-privilege-escalation/README.md#permission-risk-map` | &nbsp;&nbsp;Permission risk map | - | structural | Index of the two risk tables below; every linked technique has its own row on its page. |
| `kubernetes-security/kubernetes-privilege-escalation/README.md#critical-permissions` | &nbsp;&nbsp;&nbsp;&nbsp;Critical permissions | get secrets; list secrets; watch secrets; * * (cluster); create serviceaccounts/token; create nodes/proxy (cluster); +10 alternatives | covered | `k8s-rbac-secrets-read-legacy-sa-token`<br>`k8s-rbac-serviceaccounts-token-create`<br>`k8s-nodes-nodes-proxy-pod-sas`<br>`k8s-rbac-impersonate-users`<br>`k8s-rbac-impersonate-serviceaccounts`<br>`k8s-rbac-bind-clusterrolebinding-cluster-admin`<br>`k8s-rbac-escalate-bound-clusterrole`<br>excluded: "Critical permission summary table"<br>Table rows are covered by the linked technique sections (the catalog also keeps the summary exclusion). |
| `kubernetes-security/kubernetes-privilege-escalation/README.md#high-permissions` | &nbsp;&nbsp;&nbsp;&nbsp;High permissions | patch pods; update pods | covered | `k8s-workloads-pods-modify-running`<br>Other table rows map to their linked sections (pods/binding, status writes, admission, traffic objects, ClusterTrustBundle, debug URLs are excluded there; constrained impersonation, CSR, PV create, controllers are covered there). |
| `kubernetes-security/kubernetes-privilege-escalation/README.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-basic-information/api-object-operations.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-basic-information/api-object-operations.md#k8s---api-object-operations-without-kubectl` | K8s - API Object Operations Without kubectl | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-basic-information/api-object-operations.md#create-and-remove-a-pod` | &nbsp;&nbsp;Create and remove a Pod | - | excluded | excluded: "Pod create/delete lab procedure" |
| `kubernetes-security/kubernetes-basic-information/api-object-operations.md#create-and-remove-serviceaccounts-roles-and-bindings` | &nbsp;&nbsp;Create and remove ServiceAccounts, Roles, and bindings | - | excluded | excluded: "ServiceAccount/Role/binding create-delete lab procedure" |
| `kubernetes-security/kubernetes-basic-information/api-object-operations.md#manually-created-serviceaccount-token-secret` | &nbsp;&nbsp;Manually created ServiceAccount token Secret | - | excluded | excluded: "Manually created ServiceAccount token Secret" |
| `kubernetes-security/kubernetes-basic-information/api-object-operations.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#k8s---controller-and-admission-escalation` | K8s - Controller and Admission Escalation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#operator-custom-resource-confused-deputy` | &nbsp;&nbsp;Operator custom-resource confused deputy | - | excluded | excluded: "Operator custom-resource confused deputy" |
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#cross-namespace-reference-through-an-operator` | &nbsp;&nbsp;&nbsp;&nbsp;Cross-namespace reference through an operator | - | excluded | excluded: "Operator reading cross-namespace Secrets on behalf of a CR author" |
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#gitops-and-platform-controller-deputies` | &nbsp;&nbsp;GitOps and platform-controller deputies | create helmreleases.helm.toolkit.fluxcd.io; create helmrepositories.source.toolkit.fluxcd.io; create gitrepositories.source.toolkit.fluxcd.io; create ocirepositories.source.toolkit.fluxcd.io | excluded | excluded: "k8s-workloads-flux-helmrelease-controller-identity" |
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#flux-kustomization-without-a-tenant-serviceaccount` | &nbsp;&nbsp;&nbsp;&nbsp;Flux Kustomization without a tenant ServiceAccount | create kustomizations.kustomize.toolkit.fluxcd.io; create gitrepositories.source.toolkit.fluxcd.io; create ocirepositories.source.toolkit.fluxcd.io; create buckets.source.toolkit.fluxcd.io | excluded | excluded: "k8s-workloads-flux-kustomization-controller-identity" |
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#other-gitops-and-platform-controller-source-changes` | &nbsp;&nbsp;&nbsp;&nbsp;Other GitOps and platform-controller source changes | patch kustomizations.kustomize.toolkit.fluxcd.io; update kustomizations.kustomize.toolkit.fluxcd.io; create objects.kubernetes.m.crossplane.io; patch objects.kubernetes.m.crossplane.io; update objects.kubernetes.m.crossplane.io; create objects.kubernetes.crossplane.io (cluster); +5 alternatives | excluded | excluded: "k8s-workloads-flux-kustomization-patch-controller-identity"<br>excluded: "k8s-workloads-crossplane-provider-kubernetes-identity"<br>excluded: "k8s-workloads-argocd-application-controller-identity" |
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#validatingwebhookconfigurations-or-mutatingwebhookconfigurations` | &nbsp;&nbsp;ValidatingWebhookConfigurations or MutatingWebhookConfigurations | create mutatingwebhookconfigurations.admissionregistration.k8s.io (cluster); patch mutatingwebhookconfigurations.admissionregistration.k8s.io (cluster); update mutatingwebhookconfigurations.admissionregistration.k8s.io (cluster) | covered | `k8s-workloads-mutating-webhook-injection`<br>excluded: "k8s-admission-webhook-configuration-weaken"<br>excluded: "ValidatingWebhookConfiguration create" |
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#malicious-admission-controller` | &nbsp;&nbsp;Malicious Admission Controller | - | excluded | excluded: "Malicious mutating admission controller deployment" |
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#opa-gatekeeper-bypass` | &nbsp;&nbsp;OPA Gatekeeper bypass | - | excluded | excluded: "OPA Gatekeeper bypass" |
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md#k8s---external-secrets-operator` | K8s - External Secrets Operator | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md#disclaimer` | &nbsp;&nbsp;Disclaimer | - | excluded | excluded: "ESO prerequisites disclaimer" |
| `kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md#prerequisites` | &nbsp;&nbsp;Prerequisites | - | structural | Prerequisite list for the ESO walkthrough (excluded at |
| `kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md#gathering-information-about-existing-clustersecretstore` | &nbsp;&nbsp;&nbsp;&nbsp;Gathering information about existing ClusterSecretStore | - | excluded | excluded: "ClusterSecretStore enumeration" |
| `kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md#externalsecret-enumeration` | &nbsp;&nbsp;&nbsp;&nbsp;ExternalSecret enumeration | - | excluded | excluded: "ExternalSecret enumeration" |
| `kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md#assembling-the-pieces` | &nbsp;&nbsp;&nbsp;&nbsp;Assembling the pieces | - | excluded | excluded: "External Secrets Operator ExternalSecret creation against a ClusterSecretStore" |
| `kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-privilege-escalation/helm-template-injection.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/helm-template-injection.md#k8s---helm-privilege-escalation` | K8s - Helm Privilege Escalation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-privilege-escalation/helm-template-injection.md#values-to-rbac-through-a-privileged-reconciler` | &nbsp;&nbsp;Values-to-RBAC through a privileged reconciler | patch configmaps/prod-values in krte-sc-source | covered | `k8s-helm-values-rbac-privileged-reconciler`; exact reviewed applier, RoleBinding, source subject and permission differential required. |
| `kubernetes-security/kubernetes-privilege-escalation/helm-template-injection.md#helm-values-yaml-injection` | &nbsp;&nbsp;Helm `.Values` YAML injection | - | structural | Parent of |
| `kubernetes-security/kubernetes-privilege-escalation/helm-template-injection.md#exploitation-ideas` | &nbsp;&nbsp;&nbsp;&nbsp;Exploitation ideas | - | excluded | excluded: "Helm .Values YAML injection" |
| `kubernetes-security/kubernetes-privilege-escalation/helm-template-injection.md#helm-v3-vs-helm-v4` | &nbsp;&nbsp;&nbsp;&nbsp;Helm v3 vs Helm v4 | - | excluded | excluded: "Helm 3 vs Helm 4 apply behaviour" |
| `kubernetes-security/kubernetes-privilege-escalation/helm-template-injection.md#other-helm-escalation-inputs` | &nbsp;&nbsp;Other Helm escalation inputs | - | excluded | excluded: "Helm chart, dependency, hook, tpl/lookup and post-renderer inputs" |
| `kubernetes-security/kubernetes-privilege-escalation/helm-template-injection.md#defensive-patterns` | &nbsp;&nbsp;&nbsp;&nbsp;Defensive patterns | - | structural | Mitigation. |
| `kubernetes-security/kubernetes-privilege-escalation/helm-template-injection.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-basic-information/kyverno.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-basic-information/kyverno.md#k8s---kyverno` | K8s - Kyverno | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-basic-information/kyverno.md#definition` | &nbsp;&nbsp;Definition | - | excluded | excluded: "Kyverno definition" |
| `kubernetes-security/kubernetes-basic-information/kyverno.md#use-cases` | &nbsp;&nbsp;Use cases | - | excluded | excluded: "Kyverno use cases" |
| `kubernetes-security/kubernetes-basic-information/kyverno.md#example-clusterpolicy-and-policy` | &nbsp;&nbsp;Example: ClusterPolicy and Policy | - | excluded | excluded: "Kyverno policy example" |
| `kubernetes-security/kubernetes-basic-information/kyverno.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/kyverno-bypass.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/kyverno-bypass.md#k8s---kyverno-bypass` | K8s - Kyverno Bypass | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/kyverno-bypass.md#abusing-policies-misconfiguration` | &nbsp;&nbsp;Abusing policies misconfiguration | - | excluded | excluded: "Kyverno policy misconfiguration / exclusions" |
| `kubernetes-security/kubernetes-post-exploitation/kyverno-bypass.md#enumerate-rules` | &nbsp;&nbsp;&nbsp;&nbsp;Enumerate rules | - | structural | Enumeration step of the excluded Kyverno exclusion bypass (admission bypass, NEEDS SCHEMA blocker_removal). |
| `kubernetes-security/kubernetes-post-exploitation/kyverno-bypass.md#enumerate-excluded` | &nbsp;&nbsp;&nbsp;&nbsp;Enumerate Excluded | - | structural | Enumeration step of the excluded Kyverno exclusion bypass. |
| `kubernetes-security/kubernetes-post-exploitation/kyverno-bypass.md#example` | &nbsp;&nbsp;Example | - | structural | Example of the excluded Kyverno exclusion bypass (namespace-exempt policy). |
| `kubernetes-security/kubernetes-post-exploitation/kyverno-bypass.md#abusing-validatingwebhookconfiguration` | &nbsp;&nbsp;Abusing ValidatingWebhookConfiguration | - | excluded | excluded: "Kyverno webhook configuration bypass" |
| `kubernetes-security/kubernetes-post-exploitation/kyverno-bypass.md#more-info` | &nbsp;&nbsp;More info | - | structural | Link. |
| `kubernetes-security/kubernetes-post-exploitation/kyverno-bypass.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md#k8s---node-permissions-and-status-writes` | K8s - Node Permissions and Status Writes | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md#nodes-proxy` | &nbsp;&nbsp;Nodes proxy | create nodes/proxy (cluster); get nodes/proxy (cluster) | covered | `k8s-nodes-nodes-proxy-pod-sas`<br>`k8s-nodes-nodes-proxy-host-mount-node` |
| `kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md#nodesproxy-get---kubelet-exec-via-websocket-verb-confusion` | &nbsp;&nbsp;&nbsp;&nbsp;nodes/proxy GET -> Kubelet /exec via WebSocket verb confusion | create nodes/proxy (cluster); get nodes/proxy (cluster) | covered | `k8s-nodes-nodes-proxy-node` |
| `kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md#delete-pods--unschedulable-nodes` | &nbsp;&nbsp;Delete pods + unschedulable nodes | delete pods; patch nodes/status (cluster); update nodes/status (cluster); patch nodes (cluster); update nodes (cluster); create pods/eviction | covered | `k8s-nodes-replacement-pod-to-controlled-node` |
| `kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md#nodes-and-pods-status` | &nbsp;&nbsp;Nodes and Pods status | create pods/binding; create bindings | covered | `k8s-nodes-pods-binding-pending-pod-to-controlled-node`<br>`k8s-nodes-attract-pending-pod-to-controlled-node` |
| `kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md#legacy-status-metadata-and-controller-deputies` | &nbsp;&nbsp;Legacy status metadata and controller deputies | - | structural | Retained pointer to terminal controller effects in post exploitation; exact pending-Pod identity paths remain under Nodes and Pods status. |
| `kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md#policy-and-scheduling-control-objects` | &nbsp;&nbsp;Policy and scheduling control objects | delete pods; patch nodes/status (cluster); update nodes/status (cluster); patch nodes (cluster); update nodes (cluster); create pods/eviction | covered | `k8s-nodes-replacement-pod-to-controlled-node`<br>Node update/patch (label/taint/cordon) is now an alternative of the replacement-pod entry; NetworkPolicy and ClusterTrustBundle writes stay excluded. |
| `kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-basic-information/opa-gatekeeper.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-basic-information/opa-gatekeeper.md#k8s---opa-gatekeeper` | K8s - OPA Gatekeeper | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-basic-information/opa-gatekeeper.md#definition` | &nbsp;&nbsp;Definition | - | excluded | excluded: "Gatekeeper definition" |
| `kubernetes-security/kubernetes-basic-information/opa-gatekeeper.md#apply-constraint` | &nbsp;&nbsp;Apply Constraint | - | excluded | excluded: "Gatekeeper constraint example" |
| `kubernetes-security/kubernetes-basic-information/opa-gatekeeper.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md#k8s---opa-gatekeeper-bypass` | K8s - OPA Gatekeeper Bypass | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md#abusing-misconfiguration` | &nbsp;&nbsp;Abusing misconfiguration | - | excluded | excluded: "Gatekeeper excluded namespaces" |
| `kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md#enumerate-rules` | &nbsp;&nbsp;&nbsp;&nbsp;Enumerate rules | - | structural | Enumeration step of the excluded Gatekeeper excluded-namespace bypass. |
| `kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md#with-the-cli` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;With the CLI | - | structural | Enumeration (CLI). |
| `kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md#with-the-gui` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;With the GUI | - | structural | Enumeration (GUI). |
| `kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md#excluded-namespaces` | &nbsp;&nbsp;&nbsp;&nbsp;Excluded namespaces | - | structural | Sub-step of the excluded Gatekeeper excluded-namespace bypass (pods create in an exempt namespace is already modelled by k8s-nodes-privileged-pod-create; Gatekeeper is listed as a condition there). |
| `kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md#bypass` | &nbsp;&nbsp;&nbsp;&nbsp;Bypass | - | structural | Sub-step of the excluded Gatekeeper excluded-namespace bypass. |
| `kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md#abusing-validatingwebhookconfiguration` | &nbsp;&nbsp;Abusing ValidatingWebhookConfiguration | - | excluded | excluded: "Gatekeeper webhook configuration bypass" |
| `kubernetes-security/kubernetes-post-exploitation/opa-gatekeeper-bypass.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#k8s---rbac-and-identity-escalation` | K8s - RBAC and Identity Escalation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-basic-information/access-and-common-concepts.md#access-any-resource-or-verb-wildcard` | &nbsp;&nbsp;Access Any Resource or Verb (Wildcard) | * * (cluster) | excluded | excluded: "Wildcard RBAC rights already held by the source" |
| `kubernetes-security/kubernetes-basic-information/access-and-common-concepts.md#access-any-resource-with-a-specific-verb` | &nbsp;&nbsp;Access Any Resource with a specific verb | - | excluded | excluded: "Single verb on all resources (e.g. get * or create *)" |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#impersonating-privileged-accounts` | &nbsp;&nbsp;Impersonating privileged accounts | impersonate serviceaccounts; impersonate users (cluster); impersonate groups (cluster); impersonate groups (cluster) name=system:masters; impersonate groups (cluster) name=system:nodes | covered | `k8s-rbac-impersonate-serviceaccounts`<br>`k8s-rbac-impersonate-users`<br>`k8s-rbac-impersonate-groups`<br>`k8s-rbac-impersonate-system-masters`<br>`k8s-rbac-impersonate-node` |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#constrained-impersonation` | &nbsp;&nbsp;Constrained impersonation | impersonate:user-info users.authentication.k8s.io (cluster); impersonate:user-info users (cluster); impersonate:serviceaccount serviceaccounts; impersonate:arbitrary-node nodes (cluster); impersonate:associated-node nodes (cluster); verb_prefix impersonate-on:&lt;mode&gt;: on any resource (cluster) | covered | `k8s-rbac-constrained-impersonation-user`<br>`k8s-rbac-constrained-impersonation-serviceaccount`<br>`k8s-rbac-constrained-impersonation-node`<br>`k8s-rbac-constrained-impersonation-associated-node`<br>Action half uses verb_prefix impersonate-on:&lt;mode&gt;: with resource_match any. |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#certificate-signing-requests` | &nbsp;&nbsp;Certificate Signing Requests | create certificatesigningrequests.certificates.k8s.io (cluster); get certificatesigningrequests.certificates.k8s.io (cluster); update certificatesigningrequests/approval.certificates.k8s.io (cluster); approve signers.certificates.k8s.io (cluster) name=kubernetes.io/kube-apiserver-client-kubelet; create certificatesigningrequests/nodeclient.certificates.k8s.io (cluster); approve signers.certificates.k8s.io (cluster) name=kubernetes.io/kube-apiserver-client | covered | `k8s-nodes-csr-kubelet-client-signer`<br>`k8s-nodes-csr-nodeclient-autoapprove`<br>`k8s-rbac-csr-kube-apiserver-client-user`<br>`k8s-rbac-csr-kube-apiserver-client-group` |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#create-serviceaccounts-token` | &nbsp;&nbsp;Create serviceaccounts token | create serviceaccounts/token | covered | `k8s-rbac-serviceaccounts-token-create` |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#bind` | &nbsp;&nbsp;Bind | bind exact cluster-admin ClusterRole plus create RoleBinding; cluster-wide admin-equivalent ClusterRoleBinding alternatives | covered | `k8s-rbac-bind-clusterrolebinding-cluster-admin`<br>`k8s-rbac-bind-rolebinding-namespace`<br>excluded: "Bind an arbitrary Role or ClusterRole through an existing or new binding"; only exact cluster-admin RoleBinding create remains active. |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#escalate` | &nbsp;&nbsp;Escalate | escalate clusterroles.rbac.authorization.k8s.io (cluster); update clusterroles.rbac.authorization.k8s.io (cluster); patch clusterroles.rbac.authorization.k8s.io (cluster); escalate roles.rbac.authorization.k8s.io; update roles.rbac.authorization.k8s.io; patch roles.rbac.authorization.k8s.io | covered | `k8s-rbac-escalate-bound-clusterrole`<br>`k8s-rbac-escalate-bound-role-namespace`<br>`k8s-rbac-escalate-rolebound-clusterrole-namespace` |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#sensitive-non-resource-urls` | &nbsp;&nbsp;Sensitive non-resource URLs | - | structural | Pointer to diagnostic non-resource URL enumeration. |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#built-in-privileged-escalation-prevention` | &nbsp;&nbsp;Built-in Privileged Escalation Prevention | - | structural | Pointer to RBAC enforcement basics. |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#create-or-patch-rolebindingsclusterrolebindings` | &nbsp;&nbsp;Create or patch RoleBindings/ClusterRoleBindings | - | structural | Pointer to binding-write behavior without bind in RBAC basics. |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#k8s---secrets-configmaps-and-cloud-identity` | K8s - Secrets, ConfigMaps and Cloud Identity | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#consumed-configuration-as-code` | &nbsp;&nbsp;Consumed configuration as code | patch configmaps; update configmaps | excluded | excluded: "k8s-workloads-configmap-executed-by-workload" |
| `kubernetes-security/kubernetes-post-exploitation/secrets-and-configmaps.md#secret-listing-and-data-inspection` | &nbsp;&nbsp;Listing Secrets | get secrets; list secrets; watch secrets | excluded | excluded: "Generic Secret listing without a verified identity" |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#listing-secrets` | &nbsp;&nbsp;Listing Secrets | - | structural | Pointer to the full example at `kubernetes-security/kubernetes-post-exploitation/secrets-and-configmaps.md#secret-listing-and-data-inspection`. |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#verified-legacy-serviceaccount-token-secret` | &nbsp;&nbsp;Verified legacy ServiceAccount token Secret | get secrets; list secrets; watch secrets plus fresh reviewed usable-token evidence | covered | `k8s-rbac-secrets-read-legacy-sa-token` |
| `kubernetes-security/kubernetes-post-exploitation/secrets-and-configmaps.md#argo-cd-stored-cluster-credentials` | &nbsp;&nbsp;Argo CD stored cluster credentials | - | structural | Pointer to the verified credential path on the privilege-escalation page. |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#argo-cd-managed-cluster-credentials` | &nbsp;&nbsp;Argo CD managed-cluster credentials | get/list/watch exact Secret; reviewed usable remote credential and newly allowed action | covered | `k8s-rbac-secrets-read-argocd-cluster-credential`; label-only guess excluded: "Argo CD remote-cluster credential inferred from Secret label". |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#creating-and-reading-secrets` | &nbsp;&nbsp;Creating and Reading Secrets | create secrets; get secrets; list secrets; watch secrets | covered | `k8s-rbac-secrets-create-sa-token-secret` |
| `kubernetes-security/kubernetes-post-exploitation/secrets-and-configmaps.md#legacy-token-secret-name-guessing` | &nbsp;&nbsp;Reading a secret – brute-forcing token IDs | - | excluded | excluded: "Brute-forcing legacy token Secret names with get" |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#reading-a-secret--brute-forcing-token-ids` | &nbsp;&nbsp;Reading a secret – brute-forcing token IDs | - | structural | Pointer to the full example at `kubernetes-security/kubernetes-post-exploitation/secrets-and-configmaps.md#legacy-token-secret-name-guessing`. |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#encryption-configuration-found-on-a-control-plane-node` | &nbsp;&nbsp;Encryption configuration found on a control-plane node | - | excluded | excluded: "EncryptionConfiguration keys on control-plane hosts" |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#aws-eks-aws-auth-configmaps` | &nbsp;&nbsp;AWS EKS aws-auth configmaps | update configmaps [kube-system] name=aws-auth; patch configmaps [kube-system] name=aws-auth; create configmaps [kube-system] | excluded | excluded: "k8s-cloud-eks-aws-auth-configmap" |
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#configmap-name-squatting-and-live-update` | &nbsp;&nbsp;ConfigMap name squatting and live update | exact reviewed executable-path and target join | excluded | excluded: "k8s-v3-33-missing-configmap-name-squatting" (conditional; missing facts unresolved) |
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#coredns-config-map` | &nbsp;&nbsp;CoreDNS config map | - | excluded | excluded: "CoreDNS ConfigMap modification" |
| `kubernetes-security/kubernetes-post-exploitation/secrets-and-configmaps.md#gke-rbac-binding-example` | &nbsp;&nbsp;GKE RBAC binding example | - | structural | Pointer to the full self-grant example at `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#escalating-in-gke`. |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#escalating-in-gke` | &nbsp;&nbsp;Escalating in GKE | create/patch/update RoleBindings; bind ClusterRole view; reviewed same authenticated subject and new get-pods permission | covered | `k8s-gke-authenticated-user-rolebinding-self-grant`; unverified grants excluded: "GKE RoleBinding self-grant without exact authenticated subject and permission proof". |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md#k8s---storage-and-networking-permissions` | K8s - Storage and Networking Permissions | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md#hosts-writable-varlog-escape` | &nbsp;&nbsp;Hosts Writable /var/log/ Escape | - | structural | Retained pointer to post-exploitation host-file reads; hostPath permission paths remain documented separately. |
| `kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md#bypassing-hostpath-readonly-protection` | &nbsp;&nbsp;&nbsp;&nbsp;Bypassing hostPath readOnly protection | - | excluded | excluded: "Bypassing hostPath readOnly" |
| `kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md#storage-control-objects` | &nbsp;&nbsp;Storage control objects | create persistentvolumes (cluster); create persistentvolumeclaims; create pods | covered | `k8s-nodes-hostpath-persistentvolume` |
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#copy-a-pvc-through-volumesnapshot` | &nbsp;&nbsp;Copy a PVC through VolumeSnapshot | - | excluded | excluded: "Copy a PVC through VolumeSnapshot" |
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#services-status-cve-2020-8554` | &nbsp;&nbsp;Services status (CVE-2020-8554) | - | excluded | excluded: "services/status LoadBalancer IP spoofing (CVE-2020-8554)" |
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#dra-admin-device-claims` | &nbsp;&nbsp;DRA admin device claims | - | excluded | excluded: "DRA adminAccess ResourceClaims" |
| `kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md

| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#definition` | &nbsp;&nbsp;Definition | - | structural | Pointer to `kubernetes-basic-information/admission-policy-objects.md#definition`. |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#purpose` | &nbsp;&nbsp;Purpose | - | structural | Pointer to `kubernetes-basic-information/admission-policy-objects.md#purpose`. |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#native-cel-admission-policies` | &nbsp;&nbsp;&nbsp;&nbsp;Native CEL admission policies | - | structural | Pointer to `kubernetes-basic-information/admission-policy-objects.md#native-cel-admission-policies`. |

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#k8s---validating-admission-policies` | K8s - Validating Admission Policies | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-basic-information/admission-policy-objects.md#definition` | &nbsp;&nbsp;Definition | - | excluded | excluded: "ValidatingWebhookConfiguration definition" |
| `kubernetes-security/kubernetes-basic-information/admission-policy-objects.md#purpose` | &nbsp;&nbsp;Purpose | - | excluded | excluded: "Admission webhook purpose" |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#enumeration` | &nbsp;&nbsp;Enumeration | - | structural | Enumeration of webhooks/VAPs. |
| `kubernetes-security/kubernetes-basic-information/admission-policy-objects.md#native-cel-admission-policies` | &nbsp;&nbsp;&nbsp;&nbsp;Native CEL admission policies | - | excluded | excluded: "Native CEL admission policies" |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#pod-creation-policy-gaps` | &nbsp;&nbsp;&nbsp;&nbsp;Pod-creation policy gaps | - | covered | Parent of three excluded policy-gap sub-sections (admission bypasses with the same pods-create requirement).<br>`k8s-workloads-pods-mount-argocd-cluster-credential` — exact admitted Secret mount and reviewed remote credential proof; UID/resourceVersion, audience, subject, expiry and remote rights are required. |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#explicit-serviceaccount-token-projection` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Explicit ServiceAccount token projection | - | excluded | excluded: "Explicit projected ServiceAccount token despite automount false" |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#init-container-envfrom-omission` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Init-container `envFrom` omission | - | excluded | excluded: "Init-container envFrom policy gap" |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#scoped-resourcequota-gap` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Scoped ResourceQuota gap | - | excluded | excluded: "Scoped ResourceQuota gap" |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#tested-admission-control-mutations` | &nbsp;&nbsp;&nbsp;&nbsp;Tested admission-control mutations | patch/update/delete validatingadmissionpolicies, validatingadmissionpolicybindings, validatingwebhookconfigurations, mutatingwebhookconfigurations (cluster); patch/update namespaces, namespaces/status; update namespaces/finalize (cluster) | excluded | excluded: "k8s-admission-validating-policy-weaken"<br>excluded: "k8s-admission-webhook-configuration-weaken"<br>excluded: "k8s-admission-namespace-label-exit"<br>Blocker removal (target k8s_admission_control, removes_blockers). |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#authorizer-match-condition-grants` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Authorizer match-condition grants | - | excluded | excluded: "Custom verbs used by authorizer match conditions" |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#validatingadmissionpolicy-parameter-object-writes` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ValidatingAdmissionPolicy parameter-object writes | - | excluded | excluded: "ValidatingAdmissionPolicy parameter object writes" |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#disrupting-a-fail-open-webhook-backend` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Disrupting a fail-open webhook backend | delete services; get + patch/update deployments/scale; delete deployments; patch pods/status (cluster) | excluded | excluded: "k8s-admission-fail-open-webhook-backend" |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#mutatingadmissionpolicy-code-injection` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;MutatingAdmissionPolicy code injection | create mutatingadmissionpolicies.admissionregistration.k8s.io (cluster); create mutatingadmissionpolicybindings.admissionregistration.k8s.io (cluster); patch mutatingadmissionpolicies.admissionregistration.k8s.io (cluster); update mutatingadmissionpolicies.admissionregistration.k8s.io (cluster); patch mutatingadmissionpolicybindings.admissionregistration.k8s.io (cluster); update mutatingadmissionpolicybindings.admissionregistration.k8s.io (cluster) | covered | `k8s-workloads-mutating-admission-policy-injection`<br>excluded: "k8s-workloads-mutating-admission-policy-half-pair" |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#abusing-kyverno-and-gatekeeper-vwc` | &nbsp;&nbsp;&nbsp;&nbsp;Abusing Kyverno and Gatekeeper VWC | create namespaces (cluster) | excluded | excluded: "k8s-admission-policy-engine-excluded-namespace"<br>objectSelector opt-out labels and broad policy exceptions are not modelled.<br>excluded: "k8s-admission-policy-engine-validating-webhook-weaken"<br>excluded: "k8s-admission-kyverno-policy-weaken"<br>excluded: "k8s-admission-gatekeeper-constraint-weaken" |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#use-case` | &nbsp;&nbsp;&nbsp;&nbsp;Use Case | - | excluded | excluded: "Webhook use case" |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#k8s---workload-and-pod-privilege-escalation` | K8s - Workload and Pod Privilege Escalation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#pod-create---steal-token` | &nbsp;&nbsp;Pod Create - Steal Token | create pods | covered | `k8s-workloads-pods-create` |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#pod-create--escape` | &nbsp;&nbsp;Pod Create & Escape | create pods | covered | `k8s-nodes-privileged-pod-create` |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#stealth` | &nbsp;&nbsp;&nbsp;&nbsp;Stealth | - | structural | Pointer to Pod security-mode basics. |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#pod-create---move-to-cloud` | &nbsp;&nbsp;Pod Create - Move to cloud | create pods | covered | `k8s-cloud-hostnetwork-pod-node-identity` |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#createpatch-deployment-daemonsets-statefulsets-replicationcontrollers-replicasets-jobs-and-cronjobs` | &nbsp;&nbsp;Create/Patch Deployment, Daemonsets, Statefulsets, Replicationcontrollers, Replicasets, Jobs and Cronjobs | create deployments.apps; create daemonsets.apps; create statefulsets.apps; create replicasets.apps; create replicationcontrollers; create jobs.batch; +13 alternatives | covered | `k8s-nodes-privileged-controller-create`<br>`k8s-workloads-controllers-create`<br>`k8s-workloads-controllers-modify` |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#pod-interactive-subresources` | &nbsp;&nbsp;Pod interactive subresources | get pods/exec; create pods/attach | covered | `k8s-workloads-pods-exec-get-websocket`<br>`k8s-workloads-pods-attach`<br>excluded: "pods/proxy and services/proxy" |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#pods-exec` | &nbsp;&nbsp;Pods Exec | create pods/exec | covered | `k8s-workloads-pods-exec` |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#port-forward` | &nbsp;&nbsp;port-forward | - | structural | Pointer to post-exploitation network access. |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#ephemeralcontainers` | &nbsp;&nbsp;ephemeralcontainers | patch pods/ephemeralcontainers; update pods/ephemeralcontainers | covered | `k8s-nodes-privileged-ephemeral-container`<br>`k8s-workloads-pods-ephemeralcontainers` |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#sidecar-template-changes` | &nbsp;&nbsp;Sidecar template changes | - | excluded | excluded: "Sidecar proxy app" |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#privileged-pod-and-hostpid-escape` | &nbsp;&nbsp;Privileged Pod and hostPID escape | create pods/exec | covered | `k8s-nodes-exec-into-host-privileged-pod` |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#podcertificate-signer-identity-confusion` | &nbsp;&nbsp;PodCertificate signer identity confusion | - | excluded | excluded: "PodCertificate custom signer trusting userAnnotations" |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/README.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/README.md#k8s---post-exploitation` | K8s - Post Exploitation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/README.md#sections` | &nbsp;&nbsp;Sections | - | structural | Index. |
| `kubernetes-security/kubernetes-post-exploitation/README.md#build-an-evidence-map` | &nbsp;&nbsp;Build an evidence map | - | structural | Methodology. |
| `kubernetes-security/kubernetes-post-exploitation/README.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#k8s---post-exploitation-from-inside-a-pod` | K8s - Post Exploitation from inside a Pod | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#starting-from-an-existing-pod-foothold` | &nbsp;&nbsp;Starting from an existing Pod foothold | - | excluded | excluded: "Pod foothold boundary review" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#pod-breakout` | &nbsp;&nbsp;Pod Breakout | - | structural | Parent of the escape sub-sections below. |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#escaping-from-the-pod` | &nbsp;&nbsp;&nbsp;&nbsp;Escaping from the pod | - | excluded | excluded: "Generic Linux container escape references" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#establish-an-actual-host-escape-path` | &nbsp;&nbsp;&nbsp;&nbsp;Establish an actual host escape path | - | excluded | excluded: "Host escape surface table (mounts, host namespaces, capabilities, runtime)" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#host-namespace-capability-and-device-paths` | &nbsp;&nbsp;&nbsp;&nbsp;Host namespace, capability, and device paths | - | excluded | excluded: "SYS_ADMIN / SYS_PTRACE+hostPID / DAC_READ_SEARCH / SYS_MODULE / MKNOD / NET_ADMIN capability paths" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#creating-an-escape-capable-pod-through-the-api` | &nbsp;&nbsp;&nbsp;&nbsp;Creating an escape-capable Pod through the API | create pods | covered | `k8s-nodes-privileged-pod-create`<br>excluded: "Escape-capable pod creation (nodeName, kubectl debug node)" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#runtime-sockets-and-kernel-helper-paths` | &nbsp;&nbsp;&nbsp;&nbsp;Runtime sockets and kernel helper paths | create pods/exec | covered | `k8s-nodes-exec-into-host-mount-pod` |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#abusing-writable-hostpathbind-mounts-container---host-root-via-suid-planting` | &nbsp;&nbsp;&nbsp;&nbsp;Abusing writable hostPath/bind mounts (container -> host root via SUID planting) | - | excluded | excluded: "SUID planting through writable hostPath mounts" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#abusing-kubernetes-privileges` | &nbsp;&nbsp;&nbsp;&nbsp;Abusing Kubernetes Privileges | - | excluded | excluded: "Using the pod ServiceAccount's RBAC"<br>The pod ServiceAccount is the source principal; its RBAC is evaluated by every entry. |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#abusing-cloud-privileges` | &nbsp;&nbsp;&nbsp;&nbsp;Abusing Cloud Privileges | - | excluded | excluded: "Using the pod's cloud identity" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#search-vulnerable-network-services` | &nbsp;&nbsp;Search vulnerable network services | - | excluded | excluded: "Scanning/sniffing in-cluster services" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#services` | &nbsp;&nbsp;&nbsp;&nbsp;Services | - | structural | Sub-step of the excluded network scanning. |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#scanning` | &nbsp;&nbsp;&nbsp;&nbsp;Scanning | - | structural | Sub-step of the excluded network scanning. |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#sniffing` | &nbsp;&nbsp;&nbsp;&nbsp;Sniffing | - | structural | Sub-step of the excluded network scanning. |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#network-spoofing` | &nbsp;&nbsp;Network Spoofing | - | excluded | excluded: "In-cluster network spoofing" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#automatic-tools` | &nbsp;&nbsp;Automatic Tools | - | excluded | excluded: "Automated tooling" |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md#k8s---dosing-other-nodes` | K8s - DoSing other nodes | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md#establish-the-replacement-and-placement-paths` | &nbsp;&nbsp;Establish the replacement and placement paths | delete pods; patch nodes/status (cluster); update nodes/status (cluster); patch nodes (cluster); update nodes (cluster); create pods/eviction | covered | `k8s-nodes-replacement-pod-to-controlled-node`<br>Requirement table for the composite path (source must already control a node - NEEDS SCHEMA source_reaches_kind). |
| `kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md#cause-a-replacement-pod` | &nbsp;&nbsp;Cause a replacement Pod | delete pods; patch nodes/status (cluster); update nodes/status (cluster); patch nodes (cluster); update nodes (cluster); create pods/eviction; +12 alternatives | covered | `k8s-nodes-replacement-pod-to-controlled-node`<br>`k8s-workloads-controllers-modify`<br>delete pods / create pods/eviction are modelled; scale, rollout restart, Job parallelism and selector-label tricks only re-create pods under the controller's existing template (no extra principal beyond controllers-modify). |
| `kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md#deny-competing-nodes` | &nbsp;&nbsp;Deny competing nodes | delete pods; patch nodes/status (cluster); update nodes/status (cluster); patch nodes (cluster); update nodes (cluster); create pods/eviction | covered | `k8s-nodes-replacement-pod-to-controlled-node` |
| `kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md#resource-pressure-or-loss-of-node-health` | &nbsp;&nbsp;&nbsp;&nbsp;Resource pressure or loss of node health | - | excluded | excluded: "Resource pressure or stopping kubelet on competing nodes" |
| `kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md#taints-cordon-and-eviction` | &nbsp;&nbsp;&nbsp;&nbsp;Taints, cordon and eviction | delete pods; patch nodes/status (cluster); update nodes/status (cluster); patch nodes (cluster); update nodes (cluster); create pods/eviction | covered | `k8s-nodes-replacement-pod-to-controlled-node`<br>patch/update nodes (taint, cordon) and nodes/status (allocatable pods 0) alternatives. |
| `kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md#choose-the-compromised-node` | &nbsp;&nbsp;Choose the compromised node | create pods | covered | `k8s-workloads-pods-create`<br>`k8s-nodes-privileged-pod-create`<br>spec.nodeName on a new pod only chooses placement of the attacker's own pod (same requirement as pods create). |
| `kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md#confirm-impact-and-restore-the-lab` | &nbsp;&nbsp;Confirm impact and restore the lab | - | structural | Lab cleanup. |
| `kubernetes-security/kubernetes-post-exploitation/dosing-other-nodes.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/etcd-post-exploitation.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/etcd-post-exploitation.md#k8s---etcd-post-exploitation` | K8s - etcd Post-Exploitation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/etcd-post-exploitation.md#locate-and-read-the-active-datastore` | &nbsp;&nbsp;Locate and read the active datastore | - | excluded | excluded: "Reading Kubernetes objects directly from etcd" |
| `kubernetes-security/kubernetes-post-exploitation/etcd-post-exploitation.md#create-a-new-workload-through-etcd` | &nbsp;&nbsp;Create a new workload through etcd | - | excluded | excluded: "Writing a Pod object directly into etcd" |
| `kubernetes-security/kubernetes-post-exploitation/etcd-post-exploitation.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/helm-release-and-runner-evidence.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/helm-release-and-runner-evidence.md#k8s---helm-release-and-runner-evidence` | K8s - Helm Release and Runner Evidence | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/helm-release-and-runner-evidence.md#release-records-and-sensitive-history` | &nbsp;&nbsp;Release records and sensitive history | - | excluded | excluded: "Reading Helm release Secrets (sh.helm.release.v1.*) for values history" |
| `kubernetes-security/kubernetes-post-exploitation/helm-release-and-runner-evidence.md#deployment-runner-and-chart-supply-chain` | &nbsp;&nbsp;Deployment runner and chart supply chain | - | excluded | excluded: "Compromising the Helm deployment runner or chart supply chain" |
| `kubernetes-security/kubernetes-post-exploitation/helm-release-and-runner-evidence.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#k8s---internal-network-attacks` | K8s - Internal Network Attacks | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#trust-boundaries-and-prerequisites` | &nbsp;&nbsp;Trust boundaries and prerequisites | - | out-of-scope | Network-layer attacks yield traffic access, not a Kubernetes or cloud principal. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#dns-and-proxy-policy-review` | &nbsp;&nbsp;&nbsp;&nbsp;DNS and proxy policy review | - | out-of-scope | Network-layer review. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#introduction` | &nbsp;&nbsp;Introduction | - | structural | Background. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#basic-kubernetes-networking` | &nbsp;&nbsp;Basic Kubernetes Networking | - | structural | Background. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#arp` | &nbsp;&nbsp;&nbsp;&nbsp;ARP | - | structural | Background for the excluded ARP spoofing. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#networkpolicy-and-admin-policy-layers` | &nbsp;&nbsp;&nbsp;&nbsp;NetworkPolicy and admin policy layers | - | out-of-scope | NetworkPolicy writes reopen traffic; excluded at node-permissions-and-status.md#policy-and-scheduling-control-objects. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#pivot-through-an-allowed-application` | &nbsp;&nbsp;&nbsp;&nbsp;Pivot through an allowed application | - | out-of-scope | Application-level pivot; no principal edge. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#kubernetes-traffic-object-writes` | &nbsp;&nbsp;&nbsp;&nbsp;Kubernetes traffic-object writes | - | excluded | excluded: "Service/Endpoints/EndpointSlice/ExternalName redirection, pod-label hijack, create-only name squatting" |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#service-externalname-redirect` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Service ExternalName redirect | - | out-of-scope | Part of the excluded traffic-object writes. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#pod-label-traffic-hijack` | &nbsp;&nbsp;&nbsp;&nbsp;Pod-label traffic hijack | - | out-of-scope | Part of the excluded traffic-object writes (traffic redirection only). |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#create-only-name-squatting` | &nbsp;&nbsp;&nbsp;&nbsp;Create-only name squatting | - | out-of-scope | Part of the excluded traffic-object writes. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#ingress-creation-and-route-replacement` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Ingress creation and route replacement | - | excluded | excluded: "Ingress and Gateway API HTTPRoute exposure/replacement/mirroring" |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#gateway-api-httproute-exposure-replacement-and-mirroring` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Gateway API HTTPRoute exposure, replacement, and mirroring | - | out-of-scope | Part of the excluded Ingress/HTTPRoute exposure. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#service-externalips-interception-cve-2020-8554-class` | &nbsp;&nbsp;&nbsp;&nbsp;Service `externalIPs` interception (CVE-2020-8554 class) | - | out-of-scope | Traffic interception (same class as the excluded services/status CVE-2020-8554 row). |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#status-based-traffic-interception` | &nbsp;&nbsp;&nbsp;&nbsp;Status-based traffic interception | - | excluded | excluded: "Status-based traffic interception" |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#dns` | &nbsp;&nbsp;&nbsp;&nbsp;DNS | - | structural | Background. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#arp-spoofing-in-pods-in-the-same-node` | &nbsp;&nbsp;ARP Spoofing in pods in the same Node | - | excluded | excluded: "ARP / DNS spoofing between pods" |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#scapy` | &nbsp;&nbsp;&nbsp;&nbsp;Scapy | - | structural | Tooling for the excluded ARP spoofing. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#arpspoof` | &nbsp;&nbsp;&nbsp;&nbsp;ARPSpoof | - | structural | Tooling for the excluded ARP spoofing. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#dns-spoofing` | &nbsp;&nbsp;DNS Spoofing | - | out-of-scope | Covered by the excluded ARP / DNS spoofing row. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#cross-node-resolver-side-dns-interception` | &nbsp;&nbsp;&nbsp;&nbsp;Cross-node resolver-side DNS interception | - | out-of-scope | Network interception. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#dns-spoofing-via-coredns-configmap` | &nbsp;&nbsp;DNS Spoofing via coreDNS configmap | - | excluded | excluded: "DNS spoofing via CoreDNS ConfigMap" |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#abusing-exposed-kubernetes-management-services` | &nbsp;&nbsp;Abusing exposed kubernetes management services | - | out-of-scope | Link to unauthenticated access (rows there). |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#enumerating-kubernetes-network-policies` | &nbsp;&nbsp;Enumerating kubernetes network policies | - | structural | Enumeration. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#capturing-traffic` | &nbsp;&nbsp;Capturing Traffic | - | out-of-scope | Network capture. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#workload-scoped-name-redirection` | &nbsp;&nbsp;Workload-scoped name redirection | - | out-of-scope | DNS/name redirection. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#stable-pod-dns-names-are-routing-hints-not-identity` | &nbsp;&nbsp;&nbsp;&nbsp;Stable Pod DNS names are routing hints, not identity | - | out-of-scope | Background on DNS identity. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#mesh-and-direct-path-validation` | &nbsp;&nbsp;Mesh and direct-path validation | - | out-of-scope | Service-mesh validation. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#mesh-identity-confused-deputy-through-ssrf` | &nbsp;&nbsp;&nbsp;&nbsp;Mesh identity confused deputy through SSRF | - | out-of-scope | Application SSRF using the mesh identity of a reachable workload; mesh authorization policies are not collected. |
| `kubernetes-security/kubernetes-post-exploitation/internal-network-attacks.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/kubernetes-namespace-escalation.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-namespace-escalation.md#k8s---namespace-escalation` | K8s - Namespace Escalation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-namespace-escalation.md#abuse-k8s-privileges` | &nbsp;&nbsp;&nbsp;&nbsp;Abuse K8s privileges | - | excluded | excluded: "Cross-namespace RBAC abuse" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-namespace-escalation.md#escape-to-the-node` | &nbsp;&nbsp;&nbsp;&nbsp;Escape to the node | create pods; patch namespaces (cluster); update namespaces (cluster); patch namespaces/status (cluster); update namespaces/status (cluster); update namespaces/finalize (cluster); +2 alternatives | covered | `k8s-nodes-namespace-psa-relabel`<br>`k8s-nodes-namespace-create-privileged-pod` |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-namespace-escalation.md#cross-namespace-identity-review` | &nbsp;&nbsp;Cross-namespace identity review | - | excluded | excluded: "Cross-namespace binding review" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-namespace-escalation.md#node-compromise-and-namespace-isolation` | &nbsp;&nbsp;Node compromise and namespace isolation | - | excluded | excluded: "Node compromise crossing namespaces" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-namespace-escalation.md#cloud-to-cluster-trust-paths` | &nbsp;&nbsp;Cloud-to-cluster trust paths | - | excluded | excluded: "Cloud principal mapped into the cluster" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-namespace-escalation.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#k8s---pivoting-to-clouds` | K8s - Pivoting to Clouds | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#kubernetes-and-cloud-identity-boundaries` | &nbsp;&nbsp;Kubernetes and cloud identity boundaries | - | structural | Parent of the two excluded verification rows. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#verify-the-cloud-to-kubernetes-bridge` | &nbsp;&nbsp;&nbsp;&nbsp;Verify the cloud-to-Kubernetes bridge | - | excluded | excluded: "Verifying cloud-to-cluster kubeconfig access" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#cloud-controllers-as-an-indirect-privilege-path` | &nbsp;&nbsp;&nbsp;&nbsp;Cloud controllers as an indirect privilege path | - | excluded | excluded: "Cloud controllers acting on Kubernetes objects (LoadBalancer, snapshots, DNS, external secrets)" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#gcp` | &nbsp;&nbsp;GCP | - | structural | Provider heading. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#mounting-gcp-sa-keys-as-secret` | &nbsp;&nbsp;&nbsp;&nbsp;Mounting GCP-SA keys as secret | get/list/watch secrets; create pods | excluded | excluded: "k8s-cloud-pivot-secret-static-gcp-sa-key" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#static-google-service-account-key-mounted-as-a-secret` | &nbsp;&nbsp;&nbsp;&nbsp;Static Google service-account key mounted as a Secret | - | structural | Pointer to the verified Secret-to-Google-principal path on the privilege-escalation page. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#workload-identity-federation-for-gke` | &nbsp;&nbsp;&nbsp;&nbsp;Workload Identity Federation for GKE | intrinsic: source is k8s_service_account | structural | Pointer to `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#workload-identity-federation-for-gke`. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#direct-gke-workload-principals-and-node-boundaries` | &nbsp;&nbsp;&nbsp;&nbsp;Direct GKE workload principals and node boundaries | - | excluded | excluded: "Direct IAM grants to GKE workload principals" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#gke-iam-permissions-node-pools-and-autopilot-exceptions` | &nbsp;&nbsp;&nbsp;&nbsp;GKE IAM permissions, node pools and Autopilot exceptions | - | excluded | excluded: "GKE IAM container.* permissions and Autopilot allowlists" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#aws` | &nbsp;&nbsp;AWS | - | structural | Provider heading. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#kiam--kube2iam-iam-role-for-pods` | &nbsp;&nbsp;&nbsp;&nbsp;Kiam & Kube2IAM (IAM role for Pods) | - | structural | Pointer to the exact Pod-to-IAM-role path on the privilege-escalation page. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#iam-role-for-k8s-service-accounts-via-oidc` | &nbsp;&nbsp;&nbsp;&nbsp;IAM Role for K8s Service Accounts via OIDC | intrinsic: source is k8s_service_account; create serviceaccounts; create pods; create serviceaccounts/token | structural | Pointer to `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#iam-role-for-k8s-service-accounts-via-oidc`. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#eks-pod-identity` | &nbsp;&nbsp;&nbsp;&nbsp;EKS Pod Identity | intrinsic: source is k8s_service_account | structural | Pointer to `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#eks-pod-identity`. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#eks-governance-guardrails` | &nbsp;&nbsp;&nbsp;&nbsp;EKS governance guardrails | - | excluded | excluded: "EKS governance condition keys / SCPs" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#eks-auto-mode-node-configuration` | &nbsp;&nbsp;&nbsp;&nbsp;EKS Auto Mode node configuration | - | excluded | excluded: "EKS Auto Mode NodePool/NodeClass writes selecting a node IAM role" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#find-pods-a-sas-with-iam-roles-in-the-cluster` | &nbsp;&nbsp;&nbsp;&nbsp;Find Pods a SAs with IAM Roles in the Cluster | - | excluded | excluded: "Finding ServiceAccounts with IAM roles" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#node-iam-role-to-cluster-admin` | &nbsp;&nbsp;&nbsp;&nbsp;Node IAM Role to cluster-admin | intrinsic: source is k8s_node; create pods | structural | Pointer to `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#node-iam-role-to-cluster-admin`. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#steal-iam-role-token` | &nbsp;&nbsp;&nbsp;&nbsp;Steal IAM Role Token | create pods; intrinsic: source is k8s_node | excluded | excluded: "Reading node IAM role credentials from IMDS" |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#privesc-to-cluster-admin` | &nbsp;&nbsp;&nbsp;&nbsp;Privesc to cluster-admin | intrinsic: source is cloud_identity; intrinsic: source is k8s_node | structural | Pointer to `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#privesc-to-cluster-admin`. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#azure--aks` | &nbsp;&nbsp;Azure / AKS | intrinsic: source is k8s_service_account; use-managed-identity {target.client_id}.cid.wi.aks.azure.com (cluster) | structural | Pointer to `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#azure--aks`. |
| `kubernetes-security/kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#k8s---node-post-exploitation` | K8s - Node Post-Exploitation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#node-boundary-and-evidence` | &nbsp;&nbsp;Node boundary and evidence | - | structural | Methodology. |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#disruption-and-unexpected-workload-movement` | &nbsp;&nbsp;&nbsp;&nbsp;Disruption and unexpected workload movement | delete pods; patch nodes/status (cluster); update nodes/status (cluster); patch nodes (cluster); update nodes (cluster); create pods/eviction | covered | `k8s-nodes-replacement-pod-to-controlled-node` |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#confirm-the-host-and-active-components` | &nbsp;&nbsp;&nbsp;&nbsp;Confirm the host and active components | - | structural | Host evidence collection. |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#node-post-exploitation` | &nbsp;&nbsp;Node Post-Exploitation | - | structural | Parent of the node sub-sections. |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#spiffespire-workload-identity-spoofing` | &nbsp;&nbsp;&nbsp;&nbsp;SPIFFE/SPIRE workload identity spoofing | - | out-of-scope | Excluded on the dedicated SPIFFE page (#cgroup-based-selector-spoofing). |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#kubelet-credentials-and-local-api` | &nbsp;&nbsp;&nbsp;&nbsp;Kubelet credentials and local API | intrinsic: source is k8s_node | covered | `k8s-nodes-node-mint-pod-sa-tokens`<br>The kubelet credential is the k8s_node principal; its Node-authorizer-limited reach is the node-mint entry. |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#cri-runtime-containers-and-filesystems` | &nbsp;&nbsp;&nbsp;&nbsp;CRI runtime, containers, and filesystems | intrinsic: source is k8s_node | covered | `k8s-nodes-node-mint-pod-sa-tokens`<br>Reading local pod volumes/tokens from the runtime yields the same ServiceAccounts as the node entry. |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#node-network-and-local-services` | &nbsp;&nbsp;&nbsp;&nbsp;Node network and local services | - | out-of-scope | Network-level host access. |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#control-plane-node-artifacts` | &nbsp;&nbsp;&nbsp;&nbsp;Control-plane node artifacts | intrinsic: source is k8s_node | covered | `k8s-nodes-control-plane-node` |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#image-pull-and-registry-credentials` | &nbsp;&nbsp;&nbsp;&nbsp;Image Pull and Registry Credentials | - | excluded | excluded: "Image pull / registry credentials on nodes" |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#find-node-kubeconfig` | &nbsp;&nbsp;&nbsp;&nbsp;Find node kubeconfig | intrinsic: source is k8s_node | covered | `k8s-nodes-node-mint-pod-sa-tokens`<br>Locating the kubelet kubeconfig is how the k8s_node principal is used. |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#steal-secrets` | &nbsp;&nbsp;&nbsp;&nbsp;Steal Secrets | intrinsic: source is k8s_node | covered | `k8s-nodes-node-mint-pod-sa-tokens`<br>excluded: "Stealing pod tokens from the node filesystem" |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#privileged-daemonsets` | &nbsp;&nbsp;&nbsp;&nbsp;Privileged DaemonSets | intrinsic: source is k8s_node | covered | `k8s-nodes-node-mint-pod-sa-tokens`<br>excluded: "Privileged DaemonSets on the node" |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#pivot-to-cloud` | &nbsp;&nbsp;&nbsp;&nbsp;Pivot to Cloud | intrinsic: source is k8s_node | covered | `k8s-cloud-node-cloud-identity` |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#etcd-post-exploitation` | &nbsp;&nbsp;&nbsp;&nbsp;etcd post-exploitation | - | excluded | excluded: "Reading Secrets from etcd" |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#staticmirrored-pods-persistence` | &nbsp;&nbsp;&nbsp;&nbsp;Static/Mirrored Pods Persistence | - | excluded | excluded: "Static/mirror pods" |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#dosing-other-nodes` | &nbsp;&nbsp;&nbsp;&nbsp;DoSing other nodes | - | excluded | excluded: "Node DoS" |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-unauthenticated-access/README.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#k8s---unauthenticated-access` | K8s - Unauthenticated Access | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#finding-exposed-kubernetes-assets-with-osint` | &nbsp;&nbsp;Finding exposed Kubernetes assets with OSINT | - | out-of-scope | Discovery. |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#finding-exposed-pods-via-port-scanning` | &nbsp;&nbsp;Finding Exposed pods via port scanning | - | out-of-scope | Discovery (parent of the exposed-service rows). |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#kube-apiserver-anonymous-resource-apis` | &nbsp;&nbsp;&nbsp;&nbsp;kube-apiserver: anonymous resource APIs | - | excluded | excluded: "Anonymous API server access" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#kubelet-https-api-and-legacy-read-only-port` | &nbsp;&nbsp;&nbsp;&nbsp;Kubelet HTTPS API and legacy read-only port | - | excluded | excluded: "Unauthenticated kubelet API (anonymous auth, AlwaysAllow)" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#etcd-anonymous-cluster-state-access` | &nbsp;&nbsp;&nbsp;&nbsp;etcd: anonymous cluster-state access | - | excluded | excluded: "Anonymous etcd access" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#helm-2-tiller-release-operations-without-client-tls` | &nbsp;&nbsp;&nbsp;&nbsp;Helm 2 Tiller: release operations without client TLS | - | excluded | excluded: "Helm 2 Tiller without client TLS" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#nodeport-ingress-gateway-and-exposed-application-backends` | &nbsp;&nbsp;&nbsp;&nbsp;NodePort, Ingress, Gateway, and exposed application backends | - | excluded | excluded: "Exposed NodePort/Ingress/Gateway application backends" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#kubernetes-dashboard-legacy-skip-login` | &nbsp;&nbsp;&nbsp;&nbsp;Kubernetes Dashboard: legacy Skip login | - | excluded | excluded: "Kubernetes Dashboard skip login" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#argo-cd-anonymous-gitops-permissions` | &nbsp;&nbsp;&nbsp;&nbsp;Argo CD: anonymous GitOps permissions | - | excluded | excluded: "Argo CD anonymous access" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#argo-workflows-server-mode-workflow-submission` | &nbsp;&nbsp;&nbsp;&nbsp;Argo Workflows: server-mode workflow submission | - | excluded | excluded: "Argo Workflows server-mode submission" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#prometheus-alertmanager-grafana-and-metrics-endpoints` | &nbsp;&nbsp;&nbsp;&nbsp;Prometheus, Alertmanager, Grafana, and metrics endpoints | - | excluded | excluded: "Exposed Prometheus, Alertmanager, Grafana and metrics endpoints" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#envoy-and-service-mesh-admin-interfaces` | &nbsp;&nbsp;&nbsp;&nbsp;Envoy and service-mesh admin interfaces | - | excluded | excluded: "Exposed Envoy and mesh admin interfaces" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#weave-scope-exposed-container-controls` | &nbsp;&nbsp;&nbsp;&nbsp;Weave Scope: exposed container controls | - | excluded | excluded: "Weave Scope exposed container controls" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#container-registries-anonymous-images-and-layers` | &nbsp;&nbsp;&nbsp;&nbsp;Container registries: anonymous images and layers | - | excluded | excluded: "Anonymous container registry access" |
| `kubernetes-security/kubernetes-unauthenticated-access/README.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-unauthenticated-access/kubelet-authentication-and-authorization.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-unauthenticated-access/kubelet-authentication-and-authorization.md#kubelet-authentication--authorization` | Kubelet Authentication & Authorization | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-unauthenticated-access/kubelet-authentication-and-authorization.md#kubelet-authentication` | &nbsp;&nbsp;Kubelet Authentication | - | excluded | excluded: "Kubelet anonymous / webhook authentication" |
| `kubernetes-security/kubernetes-unauthenticated-access/kubelet-authentication-and-authorization.md#kubelet-authorization` | &nbsp;&nbsp;Kubelet Authorization | - | excluded | excluded: "nodes/checkpoint and other kubelet subresources" |
| `kubernetes-security/kubernetes-unauthenticated-access/kubelet-authentication-and-authorization.md#webhook-cache-and-permission-revocation` | &nbsp;&nbsp;&nbsp;&nbsp;Webhook cache and permission revocation | - | excluded | excluded: "Kubelet authorization cache after RBAC revocation" |
| `kubernetes-security/kubernetes-unauthenticated-access/kubelet-authentication-and-authorization.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-persistence/README.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-persistence/README.md#k8s---persistence` | K8s - Persistence | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-persistence/README.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-persistence/controllers-and-admission.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-persistence/controllers-and-admission.md#k8s---controller-admission-and-api-persistence` | K8s - Controller, Admission and API Persistence | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-persistence/controllers-and-admission.md#mutating-admission-webhook` | &nbsp;&nbsp;Mutating admission webhook | create mutatingwebhookconfigurations.admissionregistration.k8s.io (cluster); patch mutatingwebhookconfigurations.admissionregistration.k8s.io (cluster); update mutatingwebhookconfigurations.admissionregistration.k8s.io (cluster) | covered | `k8s-workloads-mutating-webhook-injection` |
| `kubernetes-security/kubernetes-persistence/controllers-and-admission.md#operator-custom-resources` | &nbsp;&nbsp;Operator custom resources | - | out-of-scope | Persistence via operator CRs; the escalation form is excluded at controllers-and-admission.md#operator-custom-resource-confused-deputy. |
| `kubernetes-security/kubernetes-persistence/controllers-and-admission.md#aggregated-api-backend` | &nbsp;&nbsp;Aggregated API backend | - | out-of-scope | APIService registration confers no authorization by itself (HackTricks states this explicitly). |
| `kubernetes-security/kubernetes-persistence/controllers-and-admission.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-persistence/identities-and-rbac.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-persistence/identities-and-rbac.md#k8s---identity-and-rbac-persistence` | K8s - Identity and RBAC Persistence | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-persistence/identities-and-rbac.md#manually-created-serviceaccount-token-secret` | &nbsp;&nbsp;Manually created ServiceAccount token Secret | create secrets; get secrets; list secrets; watch secrets | covered | `k8s-rbac-secrets-create-sa-token-secret` |
| `kubernetes-security/kubernetes-persistence/identities-and-rbac.md#bindings-and-aggregated-clusterroles` | &nbsp;&nbsp;Bindings and aggregated ClusterRoles | create clusterroles.rbac.authorization.k8s.io (cluster); escalate clusterroles.rbac.authorization.k8s.io (cluster) | covered | `k8s-rbac-escalate-aggregating-clusterrole` |
| `kubernetes-security/kubernetes-persistence/identities-and-rbac.md#client-certificates-and-cloud-side-identities` | &nbsp;&nbsp;Client certificates and cloud-side identities | create certificatesigningrequests.certificates.k8s.io (cluster); get certificatesigningrequests.certificates.k8s.io (cluster); update certificatesigningrequests/approval.certificates.k8s.io (cluster); approve signers.certificates.k8s.io (cluster) name=kubernetes.io/kube-apiserver-client; update configmaps [kube-system] name=aws-auth; patch configmaps [kube-system] name=aws-auth; +1 alternatives | covered | `k8s-rbac-csr-kube-apiserver-client-user`<br>aws-auth mapping excluded in current strict review (missing source IAM subject and auth-mode join)<br>EKS access entries are AWS-side and belong to the AWS catalog. |
| `kubernetes-security/kubernetes-persistence/identities-and-rbac.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-persistence/nodes-and-static-pods.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-persistence/nodes-and-static-pods.md#k8s---node-and-static-pod-persistence` | K8s - Node and Static-Pod Persistence | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-persistence/nodes-and-static-pods.md#host-process-and-startup-service` | &nbsp;&nbsp;Host process and startup service | - | out-of-scope | Node-root persistence. |
| `kubernetes-security/kubernetes-persistence/nodes-and-static-pods.md#static-pod-manifest` | &nbsp;&nbsp;Static Pod manifest | - | out-of-scope | Node-root persistence (static pods cannot reference ServiceAccounts). |
| `kubernetes-security/kubernetes-persistence/nodes-and-static-pods.md#cni-plugin-trigger` | &nbsp;&nbsp;CNI plugin trigger | - | out-of-scope | Node-root persistence. |
| `kubernetes-security/kubernetes-persistence/nodes-and-static-pods.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/kubernetes-persistence/workloads-and-gitops.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-persistence/workloads-and-gitops.md#k8s---workload-image-and-gitops-persistence` | K8s - Workload, Image and GitOps Persistence | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/kubernetes-persistence/workloads-and-gitops.md#detached-process-in-an-existing-pod` | &nbsp;&nbsp;Detached process in an existing Pod | - | out-of-scope | Persistence inside an already controlled pod. |
| `kubernetes-security/kubernetes-persistence/workloads-and-gitops.md#deployment-and-statefulset-templates` | &nbsp;&nbsp;Deployment and StatefulSet templates | patch deployments.apps; update deployments.apps; patch daemonsets.apps; update daemonsets.apps; patch statefulsets.apps; update statefulsets.apps; +6 alternatives | covered | `k8s-workloads-controllers-modify` |
| `kubernetes-security/kubernetes-persistence/workloads-and-gitops.md#cronjob-and-daemonset-return-paths` | &nbsp;&nbsp;CronJob and DaemonSet return paths | create deployments.apps; create daemonsets.apps; create statefulsets.apps; create replicasets.apps; create replicationcontrollers; create jobs.batch; +13 alternatives | covered | `k8s-workloads-controllers-create`<br>`k8s-nodes-privileged-controller-create` |
| `kubernetes-security/kubernetes-persistence/workloads-and-gitops.md#gitops-helm-operators-and-mutable-images` | &nbsp;&nbsp;GitOps, Helm, operators and mutable images | create applications.argoproj.io [argocd]; patch applications.argoproj.io [argocd]; update applications.argoproj.io [argocd]; create kustomizations.kustomize.toolkit.fluxcd.io; create gitrepositories.source.toolkit.fluxcd.io; create ocirepositories.source.toolkit.fluxcd.io; +3 alternatives | out-of-scope | Persistence discussion; Flux and Argo controller-identity paths are excluded until exact reconciliation and target-identity evidence exists. |
| `kubernetes-security/kubernetes-persistence/workloads-and-gitops.md#helm-release-source-as-a-return-path` | &nbsp;&nbsp;&nbsp;&nbsp;Helm release source as a return path | create helmreleases.helm.toolkit.fluxcd.io; create helmrepositories.source.toolkit.fluxcd.io; create gitrepositories.source.toolkit.fluxcd.io; create ocirepositories.source.toolkit.fluxcd.io | out-of-scope | Persistence discussion; Helm controller-identity path is excluded until exact reconciliation and target-identity evidence exists. |
| `kubernetes-security/kubernetes-persistence/workloads-and-gitops.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### kubernetes-security/spiffe-spire-workload-identity-spoofing.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/spiffe-spire-workload-identity-spoofing.md#spiffespire-workload-identity-spoofing` | SPIFFE/SPIRE Workload Identity Spoofing | - | structural | Page title/introduction; techniques are the sub-headings. |
| `kubernetes-security/spiffe-spire-workload-identity-spoofing.md#what-is-spire` | &nbsp;&nbsp;What is SPIRE? | - | structural | Background. |
| `kubernetes-security/spiffe-spire-workload-identity-spoofing.md#how-it-works` | &nbsp;&nbsp;How it works | - | structural | Background. |
| `kubernetes-security/spiffe-spire-workload-identity-spoofing.md#threat-model` | &nbsp;&nbsp;Threat model | - | structural | Prerequisite is node root (already a k8s_node edge). |
| `kubernetes-security/spiffe-spire-workload-identity-spoofing.md#cgroup-based-selector-spoofing` | &nbsp;&nbsp;Cgroup-based selector spoofing | - | excluded | excluded: "SPIRE cgroup selector spoofing from node root" |
| `kubernetes-security/spiffe-spire-workload-identity-spoofing.md#manual-validation` | &nbsp;&nbsp;&nbsp;&nbsp;Manual validation | - | structural | Procedure of the excluded cgroup spoofing. |
| `kubernetes-security/spiffe-spire-workload-identity-spoofing.md#automated-assessment-with-spooffe` | &nbsp;&nbsp;Automated assessment with Spooffe | - | structural | Tooling. |
| `kubernetes-security/spiffe-spire-workload-identity-spoofing.md#scope-and-hardening-implications` | &nbsp;&nbsp;Scope and hardening implications | - | structural | Mitigation. |
| `kubernetes-security/spiffe-spire-workload-identity-spoofing.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### openshift-pentesting/README.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/README.md#openshift-pentesting` | OpenShift Pentesting | - | structural | Page title/introduction; techniques are the sub-headings. |
| `openshift-pentesting/README.md#basic-information` | &nbsp;&nbsp;Basic Information | - | structural | Index. |
| `openshift-pentesting/README.md#security-context-constraints` | &nbsp;&nbsp;Security Context Constraints | - | structural | Index. |
| `openshift-pentesting/README.md#privilege-escalation` | &nbsp;&nbsp;Privilege Escalation | - | structural | Index. |
| `openshift-pentesting/README.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### openshift-pentesting/openshift-basic-information.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-basic-information.md#openshift---basic-information` | OpenShift - Basic information | - | structural | Page title/introduction; techniques are the sub-headings. |
| `openshift-pentesting/openshift-basic-information.md#kubernetes-prior-basic-knowledge` | &nbsp;&nbsp;Kubernetes prior basic knowledge | - | structural | Background. |
| `openshift-pentesting/openshift-basic-information.md#openshift---basic-information-1` | &nbsp;&nbsp;OpenShift - Basic Information | - | structural | Background. |
| `openshift-pentesting/openshift-basic-information.md#introduction` | &nbsp;&nbsp;&nbsp;&nbsp;Introduction | - | structural | Background. |
| `openshift-pentesting/openshift-basic-information.md#cli` | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;CLI | - | structural | Background. |
| `openshift-pentesting/openshift-basic-information.md#openshift---security-context-constraints` | &nbsp;&nbsp;&nbsp;&nbsp;OpenShift - Security Context Constraints | - | structural | Background. |
| `openshift-pentesting/openshift-basic-information.md#custom-labels-and-automation` | &nbsp;&nbsp;Custom labels and automation | - | excluded | excluded: "Custom labels consumed by automation or admission"; no exact permission gain is established. |
| `openshift-pentesting/openshift-basic-information.md#list-namespaces-with-the-run-level-label` | &nbsp;&nbsp;List namespaces with the run-level label | - | excluded | excluded: "Listing run-level namespaces"; enumeration only. |
| `openshift-pentesting/openshift-basic-information.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### openshift-pentesting/openshift-jenkins/README.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-jenkins/README.md#openshift---jenkins` | OpenShift - Jenkins | - | structural | Page title/introduction; techniques are the sub-headings. |
| `openshift-pentesting/openshift-jenkins/README.md#disclaimer` | &nbsp;&nbsp;Disclaimer | - | structural | Background. |
| `openshift-pentesting/openshift-jenkins/README.md#prerequisites` | &nbsp;&nbsp;Prerequisites | - | structural | Background. |
| `openshift-pentesting/openshift-jenkins/README.md#how-it-works` | &nbsp;&nbsp;How it works | - | structural | Background. |
| `openshift-pentesting/openshift-jenkins/README.md#builds` | &nbsp;&nbsp;&nbsp;&nbsp;Builds | - | structural | Background. |
| `openshift-pentesting/openshift-jenkins/README.md#triggering-a-build` | &nbsp;&nbsp;&nbsp;&nbsp;Triggering a build | - | structural | Background for the excluded Jenkins build trigger (Jenkins auth, not Kubernetes RBAC). |
| `openshift-pentesting/openshift-jenkins/README.md#jenkins-build-pod-yaml-override` | &nbsp;&nbsp;Jenkins Build Pod YAML override | - | excluded | excluded: "Triggering Jenkins builds in OpenShift" |
| `openshift-pentesting/openshift-jenkins/README.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### openshift-pentesting/openshift-jenkins/openshift-jenkins-build-overrides.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-jenkins/openshift-jenkins-build-overrides.md#jenkins-in-openshift---build-pod-overrides` | Jenkins in OpenShift - build pod overrides | - | structural | Page title/introduction; techniques are the sub-headings. |
| `openshift-pentesting/openshift-jenkins/openshift-jenkins-build-overrides.md#kubernetes-plugin-for-jenkins` | &nbsp;&nbsp;Kubernetes plugin for Jenkins | - | structural | Background. |
| `openshift-pentesting/openshift-jenkins/openshift-jenkins-build-overrides.md#core-functionality` | &nbsp;&nbsp;Core functionality | - | structural | Background. |
| `openshift-pentesting/openshift-jenkins/openshift-jenkins-build-overrides.md#some-abuses-leveraging-pod-yaml-override` | &nbsp;&nbsp;Some abuses leveraging pod yaml override | - | structural | Examples of the excluded build-pod YAML override (Jenkins job config, not Kubernetes RBAC; the resulting pod runs as the Jenkins agent ServiceAccount). |
| `openshift-pentesting/openshift-jenkins/openshift-jenkins-build-overrides.md#going-further` | &nbsp;&nbsp;Going further | - | structural | Parent of the excluded privesc scenarios. |
| `openshift-pentesting/openshift-jenkins/openshift-jenkins-build-overrides.md#possible-privescpivoting-scenarios` | &nbsp;&nbsp;&nbsp;&nbsp;Possible privesc/pivoting scenarios | - | excluded | excluded: "Jenkins Kubernetes plugin build pod YAML overrides" |
| `openshift-pentesting/openshift-jenkins/openshift-jenkins-build-overrides.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### openshift-pentesting/openshift-privilege-escalation/README.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-privilege-escalation/README.md#openshift---privilege-escalation` | OpenShift - Privilege Escalation | - | structural | Page title/introduction; techniques are the sub-headings. |
| `openshift-pentesting/openshift-privilege-escalation/README.md#missing-service-account` | &nbsp;&nbsp;Missing Service Account | - | excluded | excluded: "Missing ServiceAccount (index)" |
| `openshift-pentesting/openshift-privilege-escalation/README.md#tekton` | &nbsp;&nbsp;Tekton | - | excluded | excluded: "Tekton (index)" |
| `openshift-pentesting/openshift-privilege-escalation/README.md#scc-bypass` | &nbsp;&nbsp;SCC Bypass | - | excluded | excluded: "SCC bypass (index)" |
| `openshift-pentesting/openshift-privilege-escalation/README.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### openshift-pentesting/openshift-privilege-escalation/openshift-missing-service-account.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-privilege-escalation/openshift-missing-service-account.md#openshift---missing-service-account` | OpenShift - Missing Service Account | - | structural | Page title/introduction; techniques are the sub-headings. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-missing-service-account.md#missing-service-account` | &nbsp;&nbsp;Missing Service Account | create serviceaccounts; create pods; create serviceaccounts/token; create secrets; get secrets; create namespaces (cluster); create projectrequests.project.openshift.io (cluster) | covered | `k8s-rbac-dangling-serviceaccount-reference`<br>`k8s-rbac-serviceaccount-in-absent-namespace`<br>`k8s-openshift-scc-users-missing-serviceaccount` |
| `openshift-pentesting/openshift-privilege-escalation/openshift-missing-service-account.md#tools` | &nbsp;&nbsp;Tools | - | structural | Tooling. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-missing-service-account.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### openshift-pentesting/openshift-privilege-escalation/openshift-scc-bypass.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc-bypass.md#openshift---scc-bypass` | Openshift - SCC bypass | - | structural | Page title/introduction; techniques are the sub-headings. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc-bypass.md#privileged-namespaces` | &nbsp;&nbsp;Privileged Namespaces | create pods [default]; create pods [kube-system]; create pods [kube-public]; create pods [openshift-node]; create pods [openshift-infra]; create pods [openshift] | covered | `k8s-openshift-privileged-default-projects` |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc-bypass.md#namespace-label` | &nbsp;&nbsp;Namespace Label | create pods; patch namespaces (cluster); update namespaces (cluster); create namespaces (cluster); create pods (cluster) | covered | `k8s-openshift-run-level-label-existing-namespace`<br>`k8s-openshift-run-level-label-new-namespace` |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc-bypass.md#add-label` | &nbsp;&nbsp;Add Label | create pods; patch namespaces (cluster); update namespaces (cluster) | covered | `k8s-openshift-run-level-label-existing-namespace`<br>Procedure of the run-level label technique. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc-bypass.md#custom-labels` | &nbsp;&nbsp;&nbsp;&nbsp;Custom labels | - | structural | Retained pointer to basic-information label context. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc-bypass.md#list-namespaces-with-the-run-level-label` | &nbsp;&nbsp;List namespaces with the run-level label | - | structural | Retained pointer to basic-information enumeration. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc-bypass.md#mitigation` | &nbsp;&nbsp;Mitigation | - | structural | Mitigation. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc-bypass.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### openshift-pentesting/openshift-privilege-escalation/openshift-tekton.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-privilege-escalation/openshift-tekton.md#openshift---tekton` | OpenShift - Tekton | - | structural | Page title/introduction; techniques are the sub-headings. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-tekton.md#what-is-tekton` | &nbsp;&nbsp;&nbsp;&nbsp;What is Tekton | - | excluded | excluded: "Tekton background" |
| `openshift-pentesting/openshift-privilege-escalation/openshift-tekton.md#the-pipeline-service-account-capabilities` | &nbsp;&nbsp;&nbsp;&nbsp;The `pipeline` service account capabilities | - | excluded | excluded: "pipeline ServiceAccount with pipelines-scc" |
| `openshift-pentesting/openshift-privilege-escalation/openshift-tekton.md#the-misconfiguration` | &nbsp;&nbsp;&nbsp;&nbsp;The misconfiguration | patch namespaces (cluster); create taskruns.tekton.dev; update namespaces (cluster); create pipelineruns.tekton.dev; create namespaces (cluster); create taskruns.tekton.dev (cluster); +1 alternatives | excluded | excluded: "k8s-openshift-tekton-namespace-scc-annotation" |
| `openshift-pentesting/openshift-privilege-escalation/openshift-tekton.md#the-fix` | &nbsp;&nbsp;&nbsp;&nbsp;The fix | - | excluded | excluded: "Tekton maxAllowed fix" |
| `openshift-pentesting/openshift-privilege-escalation/openshift-tekton.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

### openshift-pentesting/openshift-scc.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-scc.md#openshift---scc` | Openshift - SCC | - | structural | Page title/introduction; techniques are the sub-headings. |
| `openshift-pentesting/openshift-scc.md#definition` | &nbsp;&nbsp;Definition | - | structural | Background. |
| `openshift-pentesting/openshift-scc.md#list-scc` | &nbsp;&nbsp;List SCC | - | structural | Enumeration. |
| `openshift-pentesting/openshift-scc.md#use-scc` | &nbsp;&nbsp;Use SCC | create pods; use securitycontextconstraints.security.openshift.io name=privileged; use securitycontextconstraints.security.openshift.io name=hostaccess; use securitycontextconstraints.security.openshift.io name=hostmount-anyuid; use securitycontextconstraints.security.openshift.io name=node-exporter; use securitycontextconstraints.security.openshift.io; +6 alternatives | covered | `k8s-openshift-scc-use-host-scc`<br>`k8s-openshift-scc-via-namespace-sa` |
| `openshift-pentesting/openshift-scc.md#scc-bypass` | &nbsp;&nbsp;SCC Bypass | - | structural | Link to openshift-scc-bypass.md (rows there). |
| `openshift-pentesting/openshift-scc.md#references` | &nbsp;&nbsp;References | - | structural | Reference list. |

## Catalog-only entries

| Id | Note |
|---|---|
| `k8s-workloads-pods-exec-get-websocket` | Its upstream anchor, `pods/exec`, no longer documents the GET-over-WebSocket variant at 171e422. The entry is kept because the behaviour is real for API servers before v1.35, and the entry carries a condition for that version. It is not counted as upstream coverage. |

## NEEDS SCHEMA

Round 1 proposals. All nine were IMPLEMENTED by the schema owner and are now written in the catalog (see "Round 2" above); the proposals and IMPLEMENTED notes are kept for traceability. The evaluator and schema (`peaso/privesc/schema.py`, `evaluator.py`, effective-permissions) belong to the schema owner and were not changed here.

### 1. `verb_prefix` for constrained impersonation (KEP-5284)

- **Affected entries:** `k8s-rbac-constrained-impersonation-user`, `-serviceaccount`, `-node`, and the associated-node mode. The associated-node mode also needs item 9.
- **Problem:** The action half is `impersonate-on:<mode>:<verb>` on the impersonated request's resource. The evaluator matches verbs exactly, so the requirement only matches wildcard rules (`verbs: ["*"]` and `resources: ["*"]`).

Proposed requirement shape:

```yaml
requires:
  all_of:
    - verb_prefix: "impersonate-on:user-info:"   # or serviceaccount: / arbitrary-node: / associated-node:
      resource: "*"
      resource_match: any        # any resource the rule names satisfies the requirement
      namespace: "*"
    - {verb: "impersonate:user-info", api_group: authentication.k8s.io, resource: users, resource_name: "{target.name}", namespace: "*"}
```

IMPLEMENTED: requirement fields `verb_prefix` (instead of `verb`, no `*`) and `resource_match: any` (no `resource`/`subresource`/`resource_name`, or `resource: "*"`). Write the action half exactly as proposed, without `resource: "*"` being required:
`- {verb_prefix: "impersonate-on:user-info:", resource_match: any, namespace: "*"}` plus the `impersonate:<mode>` requirement unchanged. A rule matches when one of its verbs starts with the prefix (or is `*`) and it names any resource of the group (any group when `api_group` is omitted). Test: tests/test_peaso_privesc_schema_ext_k8s.py::test_verb_prefix_and_resource_match.

### 2. `source_selector: {source_reaches_kind: k8s_node}`

- **Affected:** composite node-control paths, which are `k8s-nodes-replacement-pod-to-controlled-node` and the excluded pods/binding placement.
- **Problem:** The source must already control a node through another path. Today this is only stated as a condition.

```yaml
source_selector:
  source_reaches_kind: k8s_node     # source has (any chain to) a k8s_node principal
```

IMPLEMENTED: `source_selector: {source_reaches_kind: k8s_node}` (any target kind; all providers). A source of that kind passes unchanged; otherwise the evaluator keeps the technique only if a chain of other edges in the same run reaches a node of that kind (fixpoint closure), downgraded to the chain's weakest confidence with condition `source_reaches_k8s_node_via_chain`. Write it exactly as proposed.

### 3. `k8s_sa_used_by_pending_pod`

- **Affected:** `create pods/binding` or `create bindings` (node-permissions-and-status#nodes-and-pods-status). The technique binds a pending pod that runs as a privileged SA to an attacker-controlled node.

```yaml
target:
  kind: k8s_service_account
  selector: {k8s_sa_used_by_pending_pod: true}
  scope: "{pivot.namespace}"
source_selector: {source_reaches_kind: k8s_node}
```

IMPLEMENTED: selector `k8s_sa_used_by_pending_pod: true` (collected pods with `status.phase: Pending` and no `spec.nodeName`; derived from the pod inventory). Note `{pivot.namespace}` is not needed: write
`requires: {all_of: [{verb: create, resource: pods, subresource: binding, namespace: "{target.namespace}"}]}` (or `{verb: create, resource: bindings, ...}` as an any_of alternative), `target: {kind: k8s_service_account, selector: {k8s_sa_used_by_pending_pod: true}, scope: cluster}`, `source_selector: {source_reaches_kind: k8s_node}`.

### 4. `k8s_secret_holds_cloud_credential`

- **Affected:** a static GCP service-account key (or AWS or Azure static keys) stored in a Kubernetes Secret, which leads to a cloud identity (secrets-and-configmaps, kubernetes-pivoting-to-clouds).

```yaml
target:
  kind: cloud_identity
  selector:
    k8s_secret_holds_cloud_credential: {namespace: "{pivot.namespace}", provider: gcp}
requires:
  all_of:
    - {verb: get, resource: secrets, namespace: "{pivot.namespace}"}
```

IMPLEMENTED (shape changed): selector value is the provider, not a mapping: `k8s_secret_holds_cloud_credential: gcp` (or `aws` | `azure` | `any` | `true` | a list). One `cloud_identity` node per matching Secret (scope `<cluster>/<namespace>`), recognised from Secret metadata only (name/labels/annotations/type, never data), always `conditional` (`secret_content_not_verified`); with incomplete secret metadata an unresolved placeholder per cluster. Write:
`requires: {all_of: [{verb: get, resource: secrets, namespace: "{target.namespace}", resource_name: "{target.name}"}]}`, `target: {kind: cloud_identity, selector: {k8s_secret_holds_cloud_credential: gcp}, scope: cluster}` (outcome defaults to `credentials`). Collector fact: secret_metadata (already collected when enabled).

### 5. `k8s_secret_holds_remote_cluster_credential`

- **Affected:** Argo CD managed-cluster Secrets (`argocd.argoproj.io/secret-type: cluster`) in secrets-and-configmaps#argo-cd-managed-cluster-credentials.

```yaml
target:
  kind: k8s_remote_cluster
  selector:
    k8s_secret_holds_remote_cluster_credential: {label: "argocd.argoproj.io/secret-type=cluster"}
requires:
  all_of:
    - {verb: get, resource: secrets, namespace: argocd}
```

IMPLEMENTED (shape changed): new target kind `k8s_remote_cluster` (principal) and selector `k8s_secret_holds_remote_cluster_credential: true` (known markers: `argocd.argoproj.io/secret-type=cluster`, `cluster.x-k8s.io/cluster-name` with a `*-kubeconfig` name) or a `'key=value'` / `'key'` string or list. Write:
`requires: {all_of: [{verb: get, resource: secrets, namespace: "{target.namespace}", resource_name: "{target.name}"}]}`, `target: {kind: k8s_remote_cluster, selector: {k8s_secret_holds_remote_cluster_credential: "argocd.argoproj.io/secret-type=cluster"}, scope: cluster}`. Derived from secret labels; outcome defaults to `credentials`.

### 6. `remove_blocker` effect for admission changes

- **Affected:** ValidatingAdmissionPolicy and binding writes, webhook configuration deletes or patches, fail-open webhooks, Kyverno or Gatekeeper exclusions, and Pod Security namespace label changes (validating-admission-policies, kyverno, opa-gatekeeper, controllers-and-admission).
- **Problem:** These do not reach a principal. They lift a blocker that gates other entries, such as privileged pod create.

```yaml
effect: remove_blocker
removes_blockers: [admission_policy]   # or pod_security_admission, kyverno_policy, gatekeeper_constraint
scope_namespace: "{pivot.namespace}"
requires:
  any_of:
    - - {verb: delete, api_group: admissionregistration.k8s.io, resource: validatingadmissionpolicybindings, namespace: "*"}
    - - {verb: patch, resource: namespaces, resource_name: "{pivot.namespace}", namespace: "*"}
```

IMPLEMENTED (shape changed): no `effect:` field. Use target kind `k8s_admission_control` (one entity per cluster) with mandatory `target.removes_blockers` (subset of `admission_policy`, `pod_security_admission`, `admission_webhook`, `kyverno_policy`, `gatekeeper_constraint`); outcome defaults to `blocker_removal`. Write:
`target: {kind: k8s_admission_control, selector: {any_principal_in_scope: true}, scope: cluster, removes_blockers: [admission_policy]}` with the requires as proposed but `namespace: "*"` instead of `{pivot.namespace}` for the namespace-label alternative (`{verb: patch, resource: namespaces, namespace: "*"}`). Limitation: the edge is reported as its own finding; other entries' blockers are not yet automatically marked as lifted.

### 7. `k8s_sa_namespace_absent` plus SCC `users[]` subjects

- **Affected:** `k8s-rbac-dangling-serviceaccount-reference`. Upstream also covers bindings to an SA in a namespace that does not exist yet (so the attacker creates the namespace) and direct SCC `users:` grants on OpenShift.

```yaml
target:
  kind: k8s_service_account
  selector:
    k8s_sa_absent_but_bound: true
    k8s_sa_namespace_absent: true          # requires create namespaces
    include_scc_user_subjects: true        # SCC users[] entries become virtual SA nodes
```

IMPLEMENTED (shape changed): two selectors instead of `include_scc_user_subjects`: `k8s_sa_namespace_absent: true` (SA referenced by a binding subject or SCC users[] whose namespace is absent from a complete namespace inventory; unknown if the namespace inventory is incomplete) and `k8s_sa_named_in_scc_users: true` (OpenShift; SCC users[] SAs become virtual SA nodes; non-OpenShift: no targets). `k8s_sa_absent_but_bound` now only matches SAs that are binding subjects. Write two entries:
(a) `requires: {all_of: [{verb: create, resource: namespaces, namespace: "*"}, {verb: create, resource: serviceaccounts, namespace: "*"}]}`, `target: {kind: k8s_service_account, selector: {k8s_sa_namespace_absent: true}, scope: cluster}`;
(b) `requires: {all_of: [{verb: create, resource: serviceaccounts, namespace: "{target.namespace}"}]}`, `target: {kind: k8s_service_account, selector: {k8s_sa_named_in_scc_users: true}, scope: cluster}`. Collector fact for (b): securitycontextconstraint {metadata.name, users} (OpenShift).

### 8. `source_bound_to_aggregated_clusterrole`

- **Affected:** `k8s-rbac-escalate-aggregating-clusterrole`. A new ClusterRole that carries an aggregation label only helps if the source is already bound to the aggregating ClusterRole.

```yaml
source_selector:
  source_bound_to_aggregated_clusterrole: true   # source binding refers to a ClusterRole with aggregationRule
```

IMPLEMENTED: `source_selector: {source_bound_to_aggregated_clusterrole: true}` (any binding to a ClusterRole with aggregationRule) or `cluster` (through a ClusterRoleBinding only, i.e. cluster-wide effect). Write exactly as proposed.

### 9. `k8s_node_hosting_pod_of_source`

- **Affected:** the constrained-impersonation `associated-node` mode, where the source may only impersonate the node that runs its own pod.

```yaml
target:
  kind: k8s_node
  selector: {k8s_node_hosting_pod_of_source: true}
```

IMPLEMENTED: selector `k8s_node_hosting_pod_of_source: true` (dynamic; k8s_node targets hosting a collected pod running as the source SA). Write `target: {kind: k8s_node, selector: {k8s_node_hosting_pod_of_source: true}, scope: cluster}`, with the action half as in item 1 (`verb_prefix: "impersonate-on:associated-node:"`, `resource_match: any`).

## Pages out of scope

These pages are not privilege-escalation technique pages, or another catalog owns them.

**Kubernetes pages that are not technique pages:**

- `kubernetes-security/README.md`: index.
- `kubernetes-security/kubernetes-basic-information/**`: concepts.
- `kubernetes-security/kubernetes-enumeration/**` and `kubernetes-security/kubernetes-enumeration.md`: enumeration only.
- `kubernetes-security/kubernetes-hardening/**`: defensive guidance.
- `kubernetes-security/kubernetes-permissions-for-a-pentest.md`: the permission set needed to audit a cluster.
- `kubernetes-security/permission-risk-categorizations.md`: categorisation notes. Its techniques are linked to the privesc pages that are mapped above.

**Cross-provider Kubernetes pages owned by other catalogs:**

- `azure-security/az-privilege-escalation/az-kubernetes-privesc.md` (azure catalog)
- `gcp-security/gcp-privilege-escalation/gcp-container-privesc.md` (gcp catalog)
- `aws-security/aws-privilege-escalation/aws-eks-privesc/**` (aws catalog)

The in-cluster halves of those paths (IRSA, Pod Identity, GKE Workload Identity, AKS workload identity and IMDS) are covered by `cloud_pivot.yaml` and mapped on `kubernetes-pivoting-to-clouds.md` above.

## EKS access entries / Pod Identity joined (facts follow-up)

- `k8s_nodes_mapped_to_cloud_identity` and `eks_access_entry_type` are now evaluated in `effective_permissions/k8s.py` from related AWS snapshots: the EKS cluster is matched by EKS ARN, eksctl context, `k8s-cluster:<sha256(origin)>` of the `eks_cluster` endpoint, or bare name. EKS node-role cloud identities (`cloud:eks_node:<role>`, from instance facts) are now sources of `k8s-cloud-eks-node-role-to-node`.
- Verdicts: an EC2_LINUX/EC2_WINDOWS access entry for the node role = derived edge to the nodes running with that role; entries collected but none for the role = conditional (`eks_node_mapping_via_aws_auth_not_collected`; dropped in API-only authentication mode); an entry of another type (e.g. STANDARD) drops the source; `eks_access_entry` not fully collected = selector not evaluated (coverage says which facts are needed).
- `eks_pod_identity_association` builds `cloud:eks_pod_identity:<role>` identities bound to the (namespace, serviceAccount); `targetRoleArn` wins over `roleArn`. The cross-snapshot join to the IAM role is unchanged.
- FACTS_NEEDED for both keys kept, with the text rewritten to name the exact collection: it is still the needs-facts message when the related AWS facts are missing.
- Fixture tests: `tests/test_peaso_privesc_facts_followups.py`.

### kubernetes-security/kubernetes-post-exploitation/secrets-and-configmaps.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements (verb resource/subresource, scope) | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/secrets-and-configmaps.md#k8s---secret-and-configmap-post-exploitation` | K8s - Secret and ConfigMap Post-Exploitation | - | structural | Page title and scope note. |
| `kubernetes-security/kubernetes-post-exploitation/secrets-and-configmaps.md#references` | References | - | structural | Numbered source citations retained after relocation. |

## Current HackTricks relocation heading reconciliation

These rows cover headings added or retained as inbound pointers by the current HackTricks relocation.

### kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#k8s---admission-control-bypass` | K8s - Admission Control Bypass | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#tested-admission-control-mutations` | Tested admission-control mutations | - | out-of-scope | Post-exploitation context or pointer; no separate verified principal or permission gain. |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#authorizer-match-condition-grants` | Authorizer match-condition grants | - | out-of-scope | Post-exploitation context or pointer; no separate verified principal or permission gain. |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#validatingadmissionpolicy-parameter-object-writes` | ValidatingAdmissionPolicy parameter-object writes | - | out-of-scope | Post-exploitation context or pointer; no separate verified principal or permission gain. |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#disrupting-a-fail-open-webhook-backend` | Disrupting a fail-open webhook backend | - | out-of-scope | Post-exploitation context or pointer; no separate verified principal or permission gain. |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#abusing-kyverno-and-gatekeeper-vwc` | Abusing Kyverno and Gatekeeper VWC | - | out-of-scope | Post-exploitation context or pointer; no separate verified principal or permission gain. |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#use-case` | Use Case | - | out-of-scope | Post-exploitation context or pointer; no separate verified principal or permission gain. |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#secret-and-quota-admission-gaps` | Secret and quota admission gaps | - | out-of-scope | Post-exploitation context or pointer; no separate verified principal or permission gain. |
| `kubernetes-security/kubernetes-post-exploitation/admission-control-bypass.md#references` | References | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#k8s---controller-data-and-network-effects` | K8s - Controller Data and Network Effects | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#legacy-status-metadata-and-controller-deputies` | Legacy status metadata and controller deputies | - | excluded | excluded: "Legacy status metadata writes and controller deputies (ownerReferences GC, quota, PDB, Job/CronJob status)"; identity-bearing node scheduling and namespace PSA cases remain active elsewhere. |
| `kubernetes-security/kubernetes-post-exploitation/controller-data-and-network-effects.md#references` | References | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/external-secrets-operator.md#k8s---external-secrets-operator-secret-access` | K8s - External Secrets Operator Secret Access | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#node-compromise-and-namespace-isolation` | Node compromise and namespace isolation | - | out-of-scope | Post-exploitation context or pointer; no separate verified principal or permission gain. |
| `kubernetes-security/kubernetes-post-exploitation/node-post-exploitation.md#host-log-symlink-file-reads` | Host log symlink file reads | - | excluded | excluded: "Writable /var/log hostPath symlink escape via kubelet logs"; a file read alone has no known principal target. |

### kubernetes-security/kubernetes-privilege-escalation/api-object-operations.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/api-object-operations.md#moved-api-object-operations` | Moved: API object operations | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#operator-custom-resource-confused-deputy` | Operator custom-resource confused deputy | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/controllers-and-admission.md#cross-namespace-reference-through-an-operator` | Cross-namespace reference through an operator | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/external-secrets-operator.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/external-secrets-operator.md#moved-external-secrets-operator-secret-access` | Moved: External Secrets Operator secret access | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/kubernetes-namespace-escalation.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-namespace-escalation.md#k8s---namespace-escalation` | K8s - Namespace Escalation | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-namespace-escalation.md#abuse-k8s-privileges` | Abuse K8s privileges | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-namespace-escalation.md#escape-to-the-node` | Escape to the node | See catalog prerequisites. | covered | `k8s-nodes-namespace-psa-relabel` `k8s-nodes-namespace-create-privileged-pod` |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-namespace-escalation.md#cross-namespace-identity-review` | Cross-namespace identity review | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-namespace-escalation.md#node-compromise-and-namespace-isolation` | Node compromise and namespace isolation | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-namespace-escalation.md#cloud-to-cluster-trust-paths` | Cloud-to-cluster trust paths | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-namespace-escalation.md#references` | References | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#k8s---pivoting-to-clouds` | K8s - Pivoting to Clouds | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#kubernetes-and-cloud-identity-boundaries` | Kubernetes and cloud identity boundaries | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#gcp` | GCP | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#mounting-gcp-sa-keys-as-secret` | Mounting GCP-SA keys as secret | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#static-google-service-account-key-mounted-as-a-secret` | Static Google service-account key mounted as a Secret | get/list/watch the exact Secret; reviewed active key, named Google service account and newly allowed IAM action | covered | `k8s-cloud-pivot-secret-static-gcp-sa-key`; unverified metadata or Pod mount excluded: "Static Google key Secret inferred from metadata or unverified Pod mount". |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#workload-identity-federation-for-gke` | Workload Identity Federation for GKE | See catalog prerequisites. | covered | `k8s-cloud-gke-workload-identity` |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#direct-gke-workload-principals-and-node-boundaries` | Direct GKE workload principals and node boundaries | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#gke-iam-permissions-node-pools-and-autopilot-exceptions` | GKE IAM permissions, node pools and Autopilot exceptions | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#aws` | AWS | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#kiam--kube2iam-iam-role-for-pods` | Kiam & Kube2IAM (IAM role for Pods) <a href="#workflow-of-iam-role-for-service-accounts" id="workflow-of-iam-role-for-service-accounts"></a> | create exact running Pod; reviewed namespace policy, proxy, trust, delivered IAM credentials and new action | covered | `k8s-cloud-kiam-kube2iam-annotation`; annotation-only guess excluded: "Kiam or Kube2IAM role inferred from namespace or Pod annotation". |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#create-pod-with-iam-role` | Create Pod with IAM Role | create pods | structural | Example under the excluded Kiam/Kube2IAM annotation path. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#iam-role-for-k8s-service-accounts-via-oidc` | IAM Role for K8s Service Accounts via OIDC <a href="#workflow-of-iam-role-for-service-accounts-1" id="workflow-of-iam-role-for-service-accounts-1"></a> | See catalog prerequisites. | covered | `k8s-cloud-eks-irsa` `k8s-cloud-eks-irsa-create-matching-sa` `k8s-cloud-eks-irsa-wildcard-trust-existing-sa` |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#eks-pod-identity` | EKS Pod Identity | See catalog prerequisites. | covered | `k8s-cloud-eks-pod-identity` |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#eks-governance-guardrails` | EKS governance guardrails | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#eks-auto-mode-node-configuration` | EKS Auto Mode node configuration | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#find-pods-a-sas-with-iam-roles-in-the-cluster` | Find Pods a SAs with IAM Roles in the Cluster | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#node-iam-role-to-cluster-admin` | Node IAM Role to cluster-admin | See catalog prerequisites. | covered | `k8s-cloud-node-cloud-identity` `k8s-cloud-pod-imds-node-identity` |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#steal-iam-role-token` | Steal IAM Role Token | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#privesc-to-cluster-admin` | Privesc to cluster-admin | See catalog prerequisites. | covered | `k8s-cloud-eks-node-role-to-node` `k8s-nodes-node-mint-pod-sa-tokens` |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#azure--aks` | Azure / AKS | See catalog prerequisites. | covered | `k8s-cloud-aks-workload-identity` |
| `kubernetes-security/kubernetes-privilege-escalation/kubernetes-pivoting-to-clouds.md#references` | References | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/kyverno/README.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/kyverno/README.md#moved-kyverno-basics` | Moved: Kyverno basics | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/kyverno/kubernetes-kyverno-bypass.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/kyverno/kubernetes-kyverno-bypass.md#moved-kyverno-bypass` | Moved: Kyverno bypass | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/node-permissions-and-status.md#control-plane-node-artifacts` | Control-plane node artifacts | See catalog prerequisites. | covered | `k8s-nodes-control-plane-node` |

### kubernetes-security/kubernetes-privilege-escalation/opa-gatekeeper/README.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/opa-gatekeeper/README.md#moved-opa-gatekeeper-basics` | Moved: OPA Gatekeeper basics | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/opa-gatekeeper/kubernetes-opa-gatekeeper-bypass.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/opa-gatekeeper/kubernetes-opa-gatekeeper-bypass.md#moved-opa-gatekeeper-bypass` | Moved: OPA Gatekeeper bypass | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#access-any-resource-or-verb-wildcard` | Access Any Resource or Verb (Wildcard) | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#access-any-resource-with-a-specific-verb` | Access Any Resource with a specific verb | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/rbac-and-identities.md#bindings-and-aggregated-clusterroles` | Bindings and aggregated ClusterRoles | See catalog prerequisites. | covered | `k8s-rbac-escalate-aggregating-clusterrole` requires a cluster-wide binding; excluded: "Aggregate into a ClusterRole bound only through a RoleBinding". |

### kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#configmap-name-squatting-and-live-update` | ConfigMap name squatting and live update | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/secrets-and-configmaps.md#coredns-config-map` | CoreDNS config map | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md#copy-a-pvc-through-volumesnapshot` | Copy a PVC through VolumeSnapshot | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md#services-status-cve-2020-8554` | Services status (CVE-2020-8554) | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/storage-and-networking.md#dra-admin-device-claims` | DRA admin device claims | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#init-container-envfrom-omission` | Init-container `envFrom` omission | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `kubernetes-security/kubernetes-privilege-escalation/validating-admission-policies.md#scoped-resourcequota-gap` | Scoped ResourceQuota gap | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#runtime-sockets-and-kernel-helper-paths` | Runtime sockets and kernel helper paths | See catalog prerequisites. | covered | `k8s-nodes-exec-into-host-mount-pod` |
| `kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.md#abusing-writable-hostpathbind-mounts-container---host-root-via-suid-planting` | Abusing writable hostPath/bind mounts (container -> host root via SUID planting) | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### openshift-pentesting/openshift-privilege-escalation/openshift-scc.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc.md#openshift-scc-privilege-escalation` | OpenShift SCC privilege escalation | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc.md#use-scc` | Use SCC | See catalog prerequisites. | covered | `k8s-openshift-scc-use-host-scc` `k8s-openshift-scc-via-namespace-sa` |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc.md#scc-bypass` | SCC Bypass | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |
| `openshift-pentesting/openshift-privilege-escalation/openshift-scc.md#references` | References | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

### openshift-pentesting/openshift-scc.md

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `openshift-pentesting/openshift-scc.md#openshift-security-context-constraints` | OpenShift Security Context Constraints | - | structural | Page context, grouping heading, or retained inbound pointer; no separate catalog edge. |

## Non-escalation content moved from Kubernetes privilege-escalation pages

| Source (page#anchor, relative to src/pentesting-cloud/) | Heading | Requirements | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `kubernetes-security/kubernetes-basic-information/access-and-common-concepts.md#pod-security-mode-effects` | Pod security mode effects | - | excluded | excluded: "Stealthy pod naming/placement"; Pod configuration context, not a distinct identity or permission gain. |
| `kubernetes-security/kubernetes-basic-information/access-and-common-concepts.md#built-in-privileged-escalation-prevention` | Built-in Privileged Escalation Prevention | - | excluded | excluded: "Role/ClusterRole creation without escalate"; documents the API's rejection behavior. |
| `kubernetes-security/kubernetes-basic-information/access-and-common-concepts.md#create-or-patch-rolebindingsclusterrolebindings` | Create or patch RoleBindings/ClusterRoleBindings | - | excluded | excluded: "RoleBinding/ClusterRoleBinding writes without bind"; delegation of already held permissions. |
| `kubernetes-security/kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md#podsportforward-network-access` | pods/portforward network access | - | excluded | excluded: "pods/portforward"; network access to a Pod listener. |
| `kubernetes-security/kubernetes-enumeration/rbac-objects.md#diagnostic-non-resource-urls` | Diagnostic non-resource URLs | - | excluded | excluded: "/debug/* and /metrics non-resource URLs"; diagnostic read only. |
