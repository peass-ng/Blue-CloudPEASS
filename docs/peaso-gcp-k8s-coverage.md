# GCP and Kubernetes source review and native coverage

The exhaustive review starts with 725 pending GCP references and 870 pending
Kubernetes references assigned by `rulepacks/port_partitions.json`. A reference
is a source check/control plus its framework/checklist lineage, not necessarily
a distinct predicate. Source revisions and licenses are pinned in `sources.json`.
Native modules never import or execute upstream scanner or SQL runtimes.

## Review accounting

| Provider | Assigned references | Initial source identities | Semantic review status |
| --- | ---: | --- | --- |
| GCP | 725 | 197 shared SQL-query identities plus 119 direct/inline/Prowler identities | Exact query references are candidate groups; control parameters, applicability, joins and policy versions still require review. |
| Kubernetes | 870 | 773 SQL-query identities plus 88 direct/Prowler identities | Workload-prefix normalization yields 210 candidate names, not verified equivalents; Pod-level and container-level settings remain separate. |

The identity totals above intentionally differ from reference totals: one shared
query can appear in many framework controls, and several entity templates can
apply one predicate to different native resource paths. Equal hashes or similar
names do not establish semantic equivalence. Reviewing an expression also checks
the selected entity, optional field defaults, source joins, arguments, provider
versions and the security claim made by its title.

## Completed partitions

| Partition | References reviewed | Automated associations | Other outcomes |
| --- | ---: | ---: | --- |
| Kubernetes workload declarations | 177 | 159 | 18 invalid capability predicates, with concrete counterexamples and corrected replacement guidance. |
| GCP manual-only controls | 44 | 0 | 44 manual attestation requirements, preserved separately with their original questions, source revisions and complete framework/control/checklist lineage. |

The workload partition contains 21 reviewed expression families across actual
resource/template paths. Its implementation also provides two corrected
capability predicates. Pod-level RuntimeDefault seccomp and container-level
RuntimeDefault seccomp are different predicates. Resource limits/requests are
configuration declarations, not a claim about runtime enforcement or capacity.

Native template extraction uses `spec` for Pods, `spec.template.spec` for
Deployments, DaemonSets, StatefulSets, ReplicaSets, ReplicationControllers and
Jobs, `spec.jobTemplate.spec.template.spec` for CronJobs, and `template.spec` for
PodTemplates. Tests cover regular, init and ephemeral containers, strict native
types, denied details, malformed and missing objects, and input immutability.
Namespaces are administrative scope boundaries and are never modeled as subnets.

Two independently reviewed source defects account for the capability rejections.
The `CAP_SYS_ADMIN` membership query misses the native Kubernetes `SYS_ADMIN`
symbol. The capability-add existence query alarms on a valid empty list even
though no capabilities are added. The review shard retains exact source paths,
lines, revision and query hashes, official Pod Security Standards guidance, and
replacement check identifiers. Rejection does not discard the applicable
security requirement or silently claim that a corrected predicate is the same
upstream evaluator.

GCP `manual_control` emits constant INFO and “Manual verification required” for
projects. Every associated control was individually routed into the manual
requirements catalog with its own question and framework mappings. It has no
machine-evaluable security condition, so it is rejected as an automated check,
not reported as a supported PASS/FAIL check. Manual requirements must produce
MANUAL presentation when selected and remain separate from invalid predicates.

## Facts and coverage boundaries

Live GCP acceptance remains pending refresh of the selected gcloud identity.
Its expired login is preserved as denied evidence; the collector never falls
back to another identity or enables an API. The prior 294 targeted GCP tests
are rerun independently as changes proceed. New checks evaluate modeled
available facts and distinguish actual collection gaps from check implementation.

Kubernetes integration uses the private captured snapshot at
`.cache/peaso-qa/task_02a312b5ac1f/k8s-snapshot.json`. Collector extensions read
native metadata only, with no node execution, host file access, Secret values,
resource creation or cluster writes. Controller-template endpoint coverage now
includes ReplicationControllers and PodTemplates in addition to existing
controllers. Missing node/control-plane configuration remains an explicit gap;
container command names are not proof of cluster-wide configuration or node
runtime behavior.

Source partitions still under review include component arguments and their
version applicability, RBAC and namespace joins, complete-inventory absence
checks, legacy PSP requirements and their admission alternatives, GCP service
metadata, IAM inheritance/conditions/deny/PAB semantics, and temporal evidence.
They remain pending until a real evaluator and truth fixtures exist, or until
substantive source evidence justifies another disposition. Missing data alone
is never a rejection reason, and no always-UNKNOWN placeholder counts as a port.

## Verification

```sh
python3 -m pytest tests/test_peaso_checks_k8s_ports_workloads.py -q
```

The first workload partition passed 1,046 tests. Differential fixtures project
the reviewed CASE truth conditions independently of native evaluation; explicit
counterexamples document rejected predicates. A source reference is merged only
after its actual applicability and extraction paths are checked. Master imports,
manual requirement extraction and framework catalog regeneration belong to the
registry lead; review shards do not overwrite existing supported definitions.
