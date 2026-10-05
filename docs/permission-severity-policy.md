# Permission severity policy

Both CloudPEASS and Blue-CloudPEASS use these levels for AWS, GCP, Azure and Kubernetes:

- **Critical:** direct or nearly self-sufficient privilege grants, identity takeover, credential minting or privileged execution. Examples include `iam:PassRole`, service-account token minting, administrator assignment and Kubernetes `bind`/`escalate`. A trivial lookup or target-dependent prerequisite can still exist; Critical does not promise that a call succeeds on every target.
- **High:** protected data, stored secrets or private-key disclosure; code/configuration poisoning, traffic interception and escalation paths that depend on additional grants or target configuration.
- **Medium:** availability/integrity disruption (DoS/Break), telemetry tampering and ordinary operational changes. A prerequisite without the complete permission chain stays at its standalone level.
- **Low:** discovery and ordinary metadata reads without protected content.

The audit uses HackTricks Cloud master **45bcf7a7381a496d6dfd5b5d533681fff85c608d**. `permission-severity-audit.csv` records exact provider decisions and source links. It is a documentation-based classification review; existing live validation records retain their original provenance.

Exact `severity_overrides` precede generic naming rules. `severity_caps` prevent legacy combination lists from raising pure disruption or discovery above its audited level. Other prerequisites can be raised when their complete documented combination is present. Both runtime reports and stored catalogs use the same engine. Bundled rules are authoritative; a stale network/cache copy cannot silently change a shipped audit.

Kubernetes classification includes the API group, resource, subresource, verb and available name/selector constraints. Reading Secrets is High; minting a ServiceAccount token is Critical. Legacy status mutations whose only demonstrated effect is deletion or failed rollout availability are Medium. Ordinary RBAC writes respect Kubernetes escalation checks.

## Keeping both repositories aligned

Update the four canonical files in [HackTricks Cloud](https://github.com/HackTricks-wiki/hacktricks-cloud/tree/master/src/permission-categorizations). Both repositories synchronize them weekly. See [the synchronization guide](permission-categorization-sync.md).

For classifier code updates, use a checkout of CloudPEASS main:

```bash
python scripts/sync_cloudpeass_risks.py --cloudpeass-root /path/to/CloudPEASS
python scripts/sync_hacktricks_permissions.py --book-root /path/to/hacktricks-cloud
python scripts/check_cloudpeass_risk_parity.py --cloudpeass-root /path/to/CloudPEASS
```

The code sync copies the provider engine, Kubernetes model/engine and audit evidence. The book sync copies canonical data and regenerates the permission catalogs. Both support `--check`. The parity script checks provider casing, wildcard identifiers, complete/incomplete combinations, and a Kubernetes grant matrix; it never contacts cloud APIs.

Confirmed identifier errors are recorded in `permission-identifier-corrections.csv`. Condition keys, API method names and SDK namespaces are excluded from permission catalogs and candidate actions. Missing reference entries are checked against API documentation rather than automatically discarded.

The recheck also uses the full documented source inventory in `hacktricks-permission-inventory.csv`. It is copied from CloudPEASS together with the identifier corrections and exact rules, and participates in the offline parity check. Kubernetes workload logs are High; pure WAF/filter disruption is Medium; stored Entra BitLocker/LAPS values and conditional ordinary-group membership are High. Existing complete permission combinations retain their prerequisites.
