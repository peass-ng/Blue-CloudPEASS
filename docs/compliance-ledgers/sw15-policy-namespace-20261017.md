# SW15 policy namespace selection

SW15 checks accept the approved subscription policy from either `context.metadata.sw15` or `context.metadata.compliance_policy.sw15`. When both are declared, the copies must agree exactly before any policy-derived verdict is made. An explicitly unreadable or malformed declared copy leaves the verdict UNKNOWN even if the other copy is readable. A modern `compliance_policy` root that contains no SW15 declaration does not override the legacy SW15 policy.

The change resolves policy authority only. `azure.other.build_private_network` still requires complete current endpoint, NIC, firewall, route, and authorized external-probe evidence; policy metadata alone cannot prove a private build network. The directed fixtures use synthetic captured observations and do not claim a live probe.
