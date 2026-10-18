# Kubernetes network graph semantics

The network projection now connects workload selectors to collected matching pods,
attaches observed interfaces to their native owners, and exposes selector details
in both labels and cards. These are offline structural associations. Membership
and observed addresses do not establish internet-to-pod routed reachability.

## Selector semantics

- Service selectors are nonempty equality maps; every key/value must match,
  including case. An omitted selector has no automatic selection; an explicitly
  empty map retains a selector node with no matched-pod edges.
- NetworkPolicy `spec.podSelector` supports `matchLabels` and `matchExpressions`
  using AND semantics. `In`, `NotIn`, `Exists`, and `DoesNotExist` are supported;
  `NotIn` also matches a pod without that key. An empty policy selector selects
  all observed pods in its namespace. It never shares a node with an empty
  Service selector. Policy peer selectors are retained as native policy evidence,
  not interpreted as workload membership or routing.
- Matches require the exact collection scope, cluster identity, and namespace.
  Cluster identity comes from native `k8s://` IDs and collector provenance,
  with snapshot cluster metadata used when both item sources are absent.
  Conflicting or missing context stays unknown; namespace never defaults to
  `default`. Unmatched selectors have zero observed matches, not a reachability
  verdict. Partial/unavailable pod inventory and malformed labels retain reasons.
- Selector IDs include the selector kind, scope, cluster, namespace, and native
  selector. Labels include the kind, namespace, and deterministic selector JSON;
  cards and evidence retain the original selector. Identical Service selectors
  in the same context share one expansion; differing selectors remain distinct.
- `matches_pod` edges retain selector and pod-label sources, native label facts,
  and `reachability: unknown`. Readiness, endpoints, port mapping, additive
  policy evaluation, CNI enforcement, and external routing remain unresolved.

## Interface semantics

Each Kubernetes `network_interface` resolves `data.resource_id` against collected
pod/node native IDs in the exact collection scope and cluster, with namespace
checked when present. The owner points to the interface with `attached_interface`.
Names and IP equality are not owner resolution inputs. Missing, ambiguous,
uncollected, or conflicting owners leave an explicit unresolved attachment reason.

Cards and evidence retain every address entry, including overlapping host/pod
addresses, IPv4, IPv6, and hostnames. This collector observes `object.status`
addresses; it does not collect an authoritative CNI interface inventory.
Attachments retain `reachability: unknown` and the existing shared native-resource
reference, without copying entire workloads into graph nodes.

## Immutable native recheck

Only `k8sqa/k8s-snap.json` and `k8sqa/net.txt` were read as captured QA inputs.
No report/evaluator artifacts or privilege-analysis hooks were used.

| Input | SHA256 |
| --- | --- |
| Native snapshot bytes | `47fb2b55ceb6cd67199960a2b5fffb397d587b162f4a5b4520f5b801bf612783` |
| Captured `net.txt` bytes | `a5bb042cce40663a05b3c52170bce5329d16e2bf15f506e42e11222acd7d8db3` |

The snapshot content ID is
`sha256:08dfca945ebe357f30f8725857edf55e01026de7e327eb644a2be6c66ab9ebf7`.
Both input byte hashes remained unchanged after projection, and sealed snapshot
content remained unchanged. The recheck calls `build_network` and the existing
`annotate_network` directly inside `analysis_context`, without running an evaluator.

Captured baseline: 71 nodes, 61 edges, no selector-to-pod edges, and 20 disconnected
interfaces. Rechecked result: 71 nodes, 87 edges, 6 `matches_pod` edges, 20
`attached_interface` edges, and all 20 interface attachments resolved. Existing
edge counts remain 33 namespace containments, 18 scheduling associations,
7 declared selectors, 2 internet-exposure annotations, and 1 policy-rule candidate.

| Structural path node | Graph ID |
| --- | --- |
| Internet | `analysis:1bbc99bad72f666e1813ebb7` |
| `service:lb-open` | `analysis:826cb5ffb45c14348c3b9f22` |
| Service selector in `qa-net`, `{"app":"front"}` | `analysis:2104f627b0359f2b33e49db7` |
| `pod:app` | `analysis:b5c142afbeb65af6beeb31aa` |

The path uses the existing `internet_exposure` annotation, followed by
`declared_selector` and the new structural `matches_pod` association. Pod exposure
is not inherited from that path.

| Distinct selector label | Observed matched pods |
| --- | ---: |
| `networkpolicy selector in qa-clean: {}` | 1 |
| `networkpolicy selector in qa-net: {"matchLabels":{"app":"front"}}` | 1 |
| `service selector in kube-system: {"k8s-app":"kube-dns"}` | 2 |
| `service selector in qa-clean: {"app":"clean"}` | 1 |
| `service selector in qa-net: {"app":"front"}` | 1 |

The SHA256 of the complete rechecked network graph serialized with
`json.dumps(graph, sort_keys=True, separators=(',', ':'))` is
`60b9982780ff3f6f7afe1e9093da2094b82d6a6ad13b61ef4122f112739ef1c5`.

## Targeted verification

49 named network regressions passed, including the captured native recheck:

```sh
```

Without `K8S_NETWORK_QA_SNAPSHOT`, the captured recheck skips and the portable
regressions still run. The native test pins the expected snapshot byte hash.
Portable cases cover exact Service matches, all four NetworkPolicy expression
operators, conjunctions, empty-selector differences, unsupported selectors,
distinct cards/labels, shared expansion, unmatched/cross-namespace/cross-cluster/
cross-scope cases, partial/missing inventory, missing/conflicting context,
overlapping IPv4/IPv6/hostname addresses, and explicit unresolved owner reasons.
Cloud-only cases verify AWS attachments/policy candidates/remote scope references,
Azure case-insensitive references/containment, and GCP embedded interfaces/shared
networks/overlapping project scopes.

Four existing targeted graph tests also passed:

```sh
.venv/bin/python -m pytest -q tests/test_peaso_analysis.py::test_gcp_global_shared_vpc_and_overlapping_scope_ids tests/test_peaso_analysis.py::test_k8s_namespace_containment_and_selector_is_not_subnet tests/test_peaso_analysis.py::test_projected_network_preserves_three_vpc_roots_and_containment tests/test_peaso_analysis.py::test_gcp_embedded_interfaces_have_native_evidence_and_host_network_parent
```

No full feature suite or default all-category evaluator was run. No probes,
cloud writes, git operations, or resources were required. AWS/Azure/GCP projection
branches and supervisor common/index/projection performance edits were preserved;
Kubernetes pod/owner indexes are built once and shared selectors expand once.
