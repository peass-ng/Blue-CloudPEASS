#!/usr/bin/env python3
"""Write the honest reviewed-remediation coverage gate as readable Markdown."""
from collections import Counter
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from peaso.analysis import ANALYSIS_CHECKS  # noqa: E402
from peaso.checks import CHECKS  # noqa: E402
from peaso.remediation import rules, template  # noqa: E402

OUT = ROOT / "docs/handoff/gate-remediation-audit.md"
OFFICIAL = {"docs.aws.amazon.com", "cloud.google.com", "kubernetes.io", "etcd.io", "learn.microsoft.com"}
ANALYSIS_PROVIDERS = {"analysis.federated_trust": ("aws", "gcp", "azure")}
PROVENANCE_SUMMARY = re.compile(r"\b(evaluator|Prowler|Steampipe|upstream)\b", re.I)


def build():
    available = rules()
    native = Counter()
    pending = Counter()
    pending_modules = Counter()
    errors = []
    seen = Counter()
    provenance_summaries = []
    for check in CHECKS:
        value = template(check.id, check.provider)
        if value is None:
            pending[check.provider] += 1
            pending_modules[(check.provider, check.evaluate.__module__)] += 1
            continue
        native[check.provider] += 1
        seen[value.get("summary")] += 1
        if PROVENANCE_SUMMARY.search(value.get("summary") or ""):
            provenance_summaries.append(check.id)
        if not isinstance(value.get("summary"), str) or not value["summary"].strip():
            errors.append(f"{check.id}: summary missing")
        if not 1 <= len(value.get("steps") or []) <= 5:
            errors.append(f"{check.id}: steps outside 1–5")
        if not value.get("references"):
            errors.append(f"{check.id}: official reference missing")
        for row in value.get("references") or []:
            url = urlsplit(row.get("url", ""))
            if url.scheme != "https" or url.hostname not in OFFICIAL:
                errors.append(f"{check.id}: nonofficial reference {row.get('url')}")
        if not isinstance(value.get("cli"), list) or (not value["cli"] and not value.get("caveats")):
            errors.append(f"{check.id}: CLI list or omission caveat missing")
        binding = value.get("field_binding") or {}
        if binding.get("target") != check.target or binding.get("kind") != check.kind or not any(binding.get(key) for key in ("field", "fields", "path", "predicate", "label")):
            errors.append(f"{check.id}: evaluator target/kind/field binding missing or mismatched")
    analysis = [row["id"] for row in ANALYSIS_CHECKS]
    variants = [(cid, provider) for cid in analysis
                for provider in ANALYSIS_PROVIDERS.get(cid, ("aws", "gcp", "azure", "k8s"))]
    analysis_approved = [(cid, provider) for cid, provider in variants if template(cid, provider)]
    analysis_fully_approved = [cid for cid in analysis if all(template(cid, provider)
                               for provider in ANALYSIS_PROVIDERS.get(cid, ("aws", "gcp", "azure", "k8s")))]
    for cid, provider in analysis_approved:
        value = template(cid, provider)
        seen[value.get("summary")] += 1
        if PROVENANCE_SUMMARY.search(value.get("summary") or ""):
            provenance_summaries.append(f"{cid}@{provider}")
        if not value.get("summary") or not 1 <= len(value.get("steps") or []) <= 5:
            errors.append(f"{cid}@{provider}: missing summary or steps")
        if not value.get("references"):
            errors.append(f"{cid}@{provider}: official reference missing")
        for row in value.get("references") or []:
            url = urlsplit(row.get("url", ""))
            if url.scheme != "https" or url.hostname not in OFFICIAL:
                errors.append(f"{cid}@{provider}: nonofficial reference {row.get('url')}")
        if not isinstance(value.get("cli"), list) or (not value["cli"] and not value.get("caveats")):
            errors.append(f"{cid}@{provider}: CLI list or omission caveat missing")
        binding = value.get("field_binding") or {}
        if binding.get("target") != "projection" or not binding.get("kind") or not binding.get("field"):
            errors.append(f"{cid}@{provider}: projection kind/field binding missing")
    for summary, count in seen.items():
        if count > 3:
            errors.append(f"summary shared by {count} checks: {summary}")
    if provenance_summaries:
        errors.append(f"{len(provenance_summaries)} approved customer summaries expose evaluator/source provenance; first IDs: {', '.join(provenance_summaries[:10])}")
    bedrock = template("aws.c2b.bedrock.api_key_long_term_expired")
    if bedrock and "has expired" in bedrock["summary"].lower():
        errors.append("aws.c2b.bedrock.api_key_long_term_expired: approved summary describes PASS expired-key branch rather than failed unexpired-key branch")
    efs = template("aws.c2b.efs.access_points_posix_user")
    if efs and "without a PosixUser with" in (efs["summary"] + " " + " ".join(efs["steps"])):
        errors.append("aws.c2b.efs.access_points_posix_user: approved POSIX-user change is internally contradictory")
    appsync = template("aws.c2b.appsync.cache_at_rest_encryption")
    if appsync and len(appsync.get("cli", [])) <= 2 and not any("console" in step.lower() and "cache" in step.lower() for step in appsync["steps"]):
        errors.append("aws.c2b.appsync.cache_at_rest_encryption: approved cache recreation has inspect-only CLI and no console workflow")
    all_approved = sum(native.values()) + len(analysis_approved)
    lines = ["# Reviewed remediation coverage gate", "",
             "This audit counts entries tagged approved and checks their shape, target/kind binding, summary reuse and official reference host. It does not prove service-specific command semantics; sampled semantic review and focused tests are separate gates. Draft entries are unavailable to reports and the interface; legacy remediation strings remain readable.", "",
             "| Provider | Registered native checks | Approved structured details | Pending |",
             "| --- | ---: | ---: | ---: |"]
    for provider in ("aws", "gcp", "azure", "k8s"):
        total = sum(check.provider == provider for check in CHECKS)
        lines.append(f"| {provider.upper()} | {total} | {native[provider]} | {pending[provider]} |")
    lines.extend([f"| Native total | {len(CHECKS)} | {sum(native.values())} | {sum(pending.values())} |", "",
                  f"Analysis: **{len(analysis_fully_approved)} of {len(analysis)}** IDs approved across applicable providers; {len(analysis_approved)} of {len(variants)} applicable provider variants approved. Federated trust is emitted only for AWS, GCP and Azure.",
                  "", "## Reviewed evaluator families", "",
                  "- AWS: reviewed security-group, IAM and service-specific predicates; AWS shard counts are included only when their approved IDs do not collide with the central pack.",
                  "- GCP: firewall direction/source/port predicates, exact Cloud SQL flags and address declarations, Cloud DNSSEC, public IAM and dataset ACL checks, service enablement and reviewed scalar settings.",
                  "- Azure: `claude_azure_network.nsg_check` priority-aware `exposed_rules`, direct scalar settings, and reviewed Application Insights, Key Vault, Blob recovery/versioning and storage key reminder predicates.",
                  "- Kubernetes: `k8s_ports_components.evaluate_component` thirty-nine reviewed component flag tuples; `k8s_ports_workloads.evaluate_predicate` twenty-four explicit PodSpec predicates; `k8s_ports_cluster` quota, RBAC, Service and NetworkPolicy predicates; `k8s_extended` Pod-template, ServiceAccount and quota predicates; `claude_gcp_k8s_k8s` regular-container and literal-secret predicates; core Pod/RBAC checks and twelve defensive HackTricks RBAC/Service/token/anonymous-subject checks.",
                  "- Direct scalar predicates: `FIELD_SPECS` entries are approved only where the exact native path, compliant value, target and provider inspect/update operation were checked; immutable settings and deprecated APIs remain drafts.",
                  "- Analysis network candidates: `analysis.network_review` has provider-specific AWS SG, GCP firewall, Azure NSG and Kubernetes NetworkPolicy actions; rule IDs and approved CIDRs stay placeholders, and reachability remains unproven.",
                  "- Analysis federated trust: `analysis.federated_trust` has AWS role trust, GCP Workload Identity provider and Azure credential actions tied to the evaluator's actual issuer/subject/condition fields; no Kubernetes variant exists.",
                  "- Analysis coverage: `analysis.coverage` has provider-specific missing/denied inventory recovery tied to `evidence.gaps`, `reason` and collector status; identity inspection does not imply that inventory is complete.",
                  "- Analysis grant review: `analysis.grant_review` follows each native grant path and actual policy owner for AWS, GCP, Azure and Kubernetes; it has no universal CLI because the same ID covers multiple policy resource kinds.",
                  "- Analysis principal exposure: `analysis.principal_exposure` follows each declared principal source for all four providers and requires the policy owner to approve any replacement identity; the evaluator does not prove effective access.",
                  "- Analysis inactivity: `analysis.inactive_identity` validates the observation window and completeness before staging a reversible, owner-approved credential or binding change; `safe_to_remove` remains false.",
                  "- Analysis internet exposure: `analysis.internet_exposure` follows the reported public path, unresolved layers and asset type for all four providers; no traffic is sent and no universal deletion command is given.",
                  "", "## Acceptance gaps", "",
                  f"- **{sum(pending.values())} native checks** still lack reviewed structured guidance. All seven analysis IDs have applicable-provider guidance, but native 3,105-check coverage is incomplete and must not be advertised as complete.",
                  "- Unknown configuration ownership, approved CIDRs, SG/NSG rule IDs, replacement IAM policy documents and workload permissions are not inferred from evidence.",
                  "- Kubernetes projected component declarations do not establish the durable node or control-plane update route; those templates provide inspection and an IaC owner action, not an automatic mutation command.",
                  "- The earlier current-registry 10x same-snapshot benchmark is recorded below; it predates the growing AWS remediation shards and must be refreshed after source freeze before making a current-pack size claim.",
                  "", "## Largest pending evaluator families", "",
                  "These modules identify where per-check command and field review is still needed; pending checks retain legacy remediation strings.", "",
                  "| Provider | Evaluator module | Pending checks |", "| --- | --- | ---: |"])
    for (provider, module), count in pending_modules.most_common(20):
        lines.append(f"| {provider.upper()} | `{module}` | {count} |")
    lines.extend(["", "## Validation", "",
                  f"- Approved structured entries counted here: **{all_approved}** (native {sum(native.values())}, analysis provider variants {len(analysis_approved)}).",
                  f"- Shape/reference/summary audit errors: **{len(errors)}**; service-specific command semantics require separate review.",
                  f"- Approved summaries with evaluator/source provenance wording: **{len(provenance_summaries)}**.",
                  "- `tests/test_peaso_remediation.py` checks strict identity bindings, malformed identifiers, provider family metadata, once-per-check factoring, schema 1.0/1.1 Markdown rendering and legacy fallback.",
                  ""])
    benchmark_path = ROOT / ".cache/remediation-preflight/10x-size-comparison.json"
    if benchmark_path.is_file():
        benchmark = json.loads(benchmark_path.read_text())
        compact = benchmark["compact_11"]
        expanded = benchmark["expanded_10"]
        lines.extend(["## Earlier current-registry 10x size receipt", "",
                      f"- Synthetic 10x: {benchmark['resources']:,} resources, {benchmark['findings']:,} findings, {benchmark['selected_checks']:,} selected checks; same snapshot and registry for both serialization variants.",
                      f"- Compact schema 1.1: {compact['baseline_bytes']:,} → {compact['with_templates_bytes']:,} bytes (**+{compact['delta_percent']}%**).",
                      f"- Expanded schema 1.0: {expanded['baseline_bytes']:,} → {expanded['with_templates_bytes']:,} bytes (**+{expanded['delta_percent']}%**).",
                      f"- {benchmark['templates_in_report']} templates stored once; {benchmark['per_finding_structured_copies']} per-finding structured copies. Evaluation {benchmark['evaluation_seconds']} s, total benchmark {benchmark['total_seconds']} s, peak RSS {benchmark['peak_rss_mb']} MiB.",
                      "- Private sanitized machine receipt: `.cache/remediation-preflight/10x-size-comparison.json`.", ""])
    if errors:
        lines.extend(["## Audit errors", "", *["- " + error for error in errors], ""])
    OUT.write_text("\n".join(lines))
    print(f"Approved native {sum(native.values())}/{len(CHECKS)}, analysis variants {len(analysis_approved)}/{len(variants)}; {len(errors)} validation errors; wrote {OUT}")
    return not errors


if __name__ == "__main__":
    raise SystemExit(0 if build() else 1)
