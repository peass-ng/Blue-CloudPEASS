# Network inventory guard diagnosis and current isolation proof

No existing file needs a metadata successor now. The network owner restored the 37-entry base inventory and isolated its 28 route additions in a separate router; a fresh normal registry import succeeds. This new-only diagnostic retains the transient four-file candidate as historical evidence and explicitly rejects its applicability to the current source state.

The original Workbench receipt's `network_resources` map reconstructs the exact 4,078 bytes of `k8s_network_extensions.json` using sorted two-space JSON and a final newline. SHA-256 is verified as `0f4edb682316e4f0c0059af146f14bb6ee819cb03a0677e09825a26c945e615d`; this matches the current file. Semantically equivalent but byte-different replacements are rejected.

The transient helper at SHA `719a2a917106244b03573296dada0d2bf074b5cd021899e51c437b746c1072b2` added exactly this line:

```python
RESOURCES.update(json.loads(Path(__file__).with_name('k8s_network_route_extensions.json').read_text()))
```

That line preserved the accepted `match` function body SHA `bfbfa6d3415a085afaecd004a0c7bdadafb4d3e0383fa77c40734ef41a044a85` but changed its runtime `RESOURCES`/`BY_ENDPOINT` metadata, so the old guard correctly rejected map equality. The line is now removed and the helper's SHA is `126598ead4e287b264c818eae59bc788c16c76ff3885dfb47aa549501e17aa46`. Its original accepted authority is the actual matcher body and original JSON/map contract; no historical whole-file hash is invented. The transient whole helper is reconstructable from this current helper plus that exact line and its previously observed SHA; the archive labels the inverse as a reconstruction rather than independent historical whole-file authority.

The 28-entry `k8s_network_route_extensions.json` remains exactly `ef83a169812ab23a043d23ea653cb27884b89ab05d8e60aba56840b98342f6bb`. Its separate `k8s_network_route_extensions.py` has its own map and matcher, used by `k8s_network_catalog.allowed_path/read`; `route.project` must be the original `network.project` object. This leaves the admitted base network matcher and map unchanged. The receipt binds the current actual route-helper/catalog source and exact API group alternatives, plurals and namespace flags.

The accepted base matcher and the new route matcher use full matches of `/apis/G/v1[/namespaces/N]/P`. Every supported metadata/literal kind is derived from the accepted metadata schema and current literal producer's `NATIVE_KINDS`: Pod, ConfigMap, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob, ReplicationController and PodTemplate. Core `/api/v1` paths cannot match this grammar; the grouped selected lists use `apps` or `batch`, whose exact group/plural pairs are disjoint from every old and new inventory endpoint. Named GET and `/log` suffixes also cannot match a list grammar. This structural argument covers arbitrary valid namespaces and names; counterexamples exercise every kind, namespace/name variations, and selected pod/log routes. The actual current catalog and both real executing matchers are checked, not a substitute matcher.

All 119 original Dataflow/Batch function rows retain their exact manifest/source hashes and compile without executing source. `validate_live` then uses a normal package import and calls the unchanged production `gcp_dataflow_batch_source_runtime_admission_20261020.reviewed_inputs` guard, which checks the real executing 119 functions, defaults/globals, original admission callable identities, all eighteen imported identity pairs, sealed grant/profile/source relationships, native cases and transitive Workbench/K8s prepared/runtime guards. No existing guard is copied, replaced or bypassed; no global Path or JSON read is intercepted.

The archive `peaso/checks/k8s_network_inventory_successor_20261020_candidates.json.gz` preserves exact original helper/receipt bytes and the concrete historical candidate. That candidate would have required only four existing-file edits: Workbench JSON `sources` add the transient helper and exact route JSON, `network_resources` add the 28 entries, and `network_map_contract` clarify scope; Workbench helper `RECEIPT_SHA256`; Dataflow shared JSON `accepted_receipt_sha256`; and Dataflow shared helper `RECEIPT_SHA256`. All function definitions, helper normalized-self hashes, original source pins, and 119 runtime rows remain unchanged; no registry or top Dataflow admission receipt edits were needed. Candidate tests reject any extra file, old-entry change, extra imported source, function edit, dropped manifest row or broken transitive digest. This candidate is **stale and must not be applied**: `candidate_applicable` rejects current network helper bytes because the merged map no longer exists.

Run the finite local proof:

```sh
PYTHONPATH=. .venv/bin/python peaso/checks/k8s_network_inventory_successor_20261020.py
.venv/bin/python -m pytest -q tests/test_k8s_network_inventory_successor_20261020.py
```

The companion JSON report records actual results. No cloud, authentication, full suite, build, commit, push or deploy is performed, and this worker edits only its new files. Remaining work is the network owner's own transport/inventory integration acceptance; this proof establishes guard compatibility and route disjointness, not deployed Kubernetes collection coverage. If any bound source or route map changes, the diagnostic rejects that change until reviewed again.
