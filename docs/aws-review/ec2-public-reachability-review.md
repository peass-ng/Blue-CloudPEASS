# EC2 public reachability: exact contract disposition

Recommend explicit, root-reviewed archival/quarantine of **`aws_nist_ec2_instance_not_publicly_accessible` under its current signed contract**, preserving its historical lineage and requirement mapping. Keep the existing configuration-only alternatives active. No runtime, dependencies, signed source pins, exclusions, counters or final field ledger were changed by this review.

## What the historical contract actually asks

The signed specification `74cbf6b2b5fa1d4184ca17247291df3db48b9d8057eb8f5ad8b8ea2d0dba001c`, recorded in `docs/compliance-ledgers/new-checks-aws.json`, requires a route and security-group path **to a listening port**, considering associated public IPv4/IPv6 addresses and internet-facing load-balancer targets. Incomplete route, target or ingress inventory is UNKNOWN. The title, “EC2 instances should not have a public IP address,” understates this stronger predicate; it does not authorize substituting a simple address-assignment check.

The actual registered dispatch resolves to `_ec2_public` in [compliance_new_sw46.py](../../peaso/checks/compliance_new_sw46.py), starting at line 396. Its function SHA256 is `4392038a3c9834d48010a0335f4308db3808dad52bcbdee9978e9bf405fcc393`. It requires the synthetic `PublicReachability` envelope, four completeness booleans including `listener_inventory_complete`, and `ListeningPortVerified` for individual paths. The only declared dependency is `instance`.

Existing hand-built PASS/FAIL fixtures supply those assertions themselves. They are not evidence that a native API read produced listener verification or closed the public-path universe. A native DescribeInstances row has no such envelope; the installed SDK Instance shape includes public addresses and interfaces, but no `PublicReachability` or `ListeningPortVerified` member.

## What the existing readonly model proves

[aws_public_ingress.py](../../peaso/analysis/aws_public_ingress.py) implements `aws-public-config-witness-v1`. [aws_public_ingress_native.py](../../peaso/collectors/aws_public_ingress_native.py) collects its declared EC2 dependencies: instance, network interface, VPC, subnet, security group, network ACL, route table, internet gateway and VPC block-public-access options. It uses Describe operations and validates a supported direct IPv4 configuration path, including ENI/address agreement, routing, gateway attachment, SG ingress, NACL forward/return rules and relevant configuration states.

Every positive witness explicitly records:

- `application_listening: unknown`
- `network_probes: false`
- `all_paths_evaluated: false`

It excludes IPv6, load-balancer paths and several other configurations. Candidate sampling is bounded; no witness means UNKNOWN. The collector preserves these limits and does not emit a complete negative.

[compliance_new_sw37.py](../../peaso/checks/compliance_new_sw37.py) independently reconstructs this configured witness from the native dependency inventories before accepting the collector projection. It does not upgrade the witness into an observed guest listener or an exhaustive path analysis.

A guest with a listener and a guest without one can have exactly the same reviewed EC2/ENI/SG/NACL/route configuration. The model therefore cannot distinguish them. Reusing its configured-path witness as a FAIL for the old listening contract would change the predicate; interpreting absence of that witness as PASS would be unsound. The review establishes no general complete negative for the old contract, including stopped, IPv6-only or unsupported paths.

This conclusion concerns the reviewed model and exact historical contract. It is **not** a claim that all possible AWS readonly evidence is incapable of supporting any narrower listener-related conclusion. A separately specified provider-managed ELB listener and healthy-target proof could merit future investigation; this model has no such support, and equivalence to the old listening predicate was not established. No guest commands, packet probes, cloud writes or new broad graph implementation were attempted.

## Useful alternatives to preserve

| Active ID | Actual supported question |
|---|---|
| `aws.nist.ec2_instance_effective_public_reachability` | Independently validated configured direct IPv4 public-path counterexample; listener state and unexamined paths remain unknown. |
| `aws_fedramp_ec2_effective_public_exposure` | Same bounded configured-ingress proof, with its existing framework lineage. |
| `aws.claude_a.ec2.instance_no_public_ip` | Whether a public IPv4 address is declared. |
| `aws.claude_a.ec2.instance_no_public_ip_not_terminated` | The corresponding IPv4 assignment question for non-terminated instances. |
| `aws_g6_ec2_instance_no_public_ipv6` | Whether a globally routable IPv6 address is assigned to an instance interface. |

These are useful partial alternatives, not exact semantic replacements for the historical listening contract.

## Proposed disposition for root

The companion JSON contains a proposed exclusion entry, exact source hashes and the signed predicate. Its `mandatory_external_fields` is **empty**: the reason is an unsupported evidence/semantics contract, not missing customer approval and not an assertion that collector absence alone requires external input. The first native alternative is the configured-ingress ID above; the complete list and their distinct scopes are explicit.

If root instead elects to revise this ID, the signed predicate and base description must explicitly say **configured direct IPv4 allowance; application listening and packet delivery unverified**, declare all native model dependencies, allow FAIL only on an independently validated supported counterexample, and leave unsupported/no-witness cases UNKNOWN. No complete-negative PASS is implemented by the existing model. That revision would substantially duplicate the two active configured-ingress checks and requires explicit versioned requirement review rather than a silent handler substitution.

## Validation

**21 tests passed**, including two existing botocore-validating `collect_live` cases. New tests distinguish configured allowance from observed listening, verify that genuine configuration witnesses cannot be relabelled as the old projection, keep unsupported/no-witness and denied/partial/malformed cases from PASS, check explicit dependencies, and inspect native SDK response shapes.

Reproduce:

```sh
.venv/bin/python -m pytest -q \
  tests/test_aws_ec2_public_reachability_review.py \
  tests/test_peaso_aws_public_ingress_native.py::test_sdk_collect_live_projection_requests_exact_dependencies_and_checks \
  --junitxml=/tmp/peasso-aws-review-20261019/native/ec2-public-reachability-review.xml
```

The small JUnit receipt and log are under `/tmp/peasso-aws-review-20261019/native/`. No full suite or final field-ledger refresh was run.
