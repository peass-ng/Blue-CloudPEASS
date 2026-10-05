# Permission categories

Permission categorizations for AWS, GCP, Azure, and Kubernetes are maintained in [HackTricks Cloud](https://github.com/HackTricks-wiki/hacktricks-cloud/tree/master/src/permission-categorizations), with one canonical YAML file per platform.

- **Critical**: direct or nearly independent privilege escalation, identity grants or minting, and privileged execution.
- **High**: protected information, stored secrets, and conditional privilege escalation.
- **Medium**: DoS/Break, operational disruption, and ordinary resource changes.
- **Low**: discovery and ordinary metadata.

See the [severity policy](docs/permission-severity-policy.md) for contextual limits and the [synchronization guide](docs/permission-categorization-sync.md) for updates. The bundled `risk_rules/{aws,gcp,azure,k8s}.yaml` files and categorized cloud catalogs are generated copies. Complete permission combinations can raise a rating only when every prerequisite is present; severity caps preserve audited exceptions. Kubernetes matches API group, resource, subresource, verb, and scope through ordered rules.
