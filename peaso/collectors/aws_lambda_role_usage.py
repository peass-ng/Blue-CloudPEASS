"""Pure, bounded account-wide Lambda role-use summary from cached inventory."""
from __future__ import annotations

import re


_CALLER = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):[^:]+:[^:]*:([0-9]{12}):.+$")
_FUNCTION = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):lambda:([a-z0-9-]+):([0-9]{12}):function:[^:]+$")
_ROLE = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):iam::([0-9]{12}):role/.+$")
_NONACTIVE = {"Pending", "Inactive", "Failed", "Deactivating", "Deactivated", "ActiveNonInvocable", "Deleting"}


def summarize_lambda_role_usage(collections, identities, region_discovery, *, explicit_regions):
    """Keep proven duplicate active roles; only complete accounts can pass uniqueness."""
    accounts = sorted({identity.get("Account") for identity in identities
                       if isinstance(identity, dict) and isinstance(identity.get("Account"), str)})
    rows = []
    for account in accounts:
        issues = set()
        partitions = set()
        matching = [x for x in identities if isinstance(x, dict) and x.get("Account") == account]
        for identity in matching:
            arn = identity.get("Arn")
            parsed = _CALLER.fullmatch(arn) if isinstance(arn, str) else None
            if parsed is None or parsed.group(2) != account:
                issues.add("caller_identity_unavailable")
            else:
                partitions.add(parsed.group(1))
        if len(partitions) != 1 or len(matching) != 1:
            issues.add("caller_identity_ambiguous")
        partition = next(iter(partitions)) if len(partitions) == 1 else None
        if explicit_regions:
            issues.add("explicit_region_selection")
        discovery = [x for x in (region_discovery or []) if isinstance(x, dict) and x.get("account_id") == account]
        enabled = []
        if len(discovery) != 1 or discovery[0].get("status") != "collected":
            issues.add("enabled_region_discovery_unavailable")
        else:
            regions = discovery[0].get("regions")
            if (not isinstance(regions, list) or not regions or
                    any(not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x) for x in regions) or
                    len(set(regions)) != len(regions)):
                issues.add("enabled_region_discovery_malformed")
            else:
                enabled = sorted(regions)
        envelopes = [x for x in collections if isinstance(x, dict) and x.get("type") == "lambda_function" and x.get("account_id") == account]
        observed = []
        seen_functions = set()
        roles = {}
        active_count = 0
        for envelope in envelopes:
            scope = envelope.get("scope")
            region = scope.split("/", 1)[1] if isinstance(scope, str) and scope.startswith(account + "/") else None
            if (region is None or not re.fullmatch(r"[a-z0-9-]+", region) or
                    envelope.get("global") is not False):
                issues.add("lambda_scope_malformed")
                continue
            observed.append(region)
            if envelope.get("status") not in {"collected", "empty"}:
                issues.add("lambda_inventory_incomplete")
            if envelope.get("error"):
                issues.add("lambda_inventory_incomplete")
            items = envelope.get("items")
            if not isinstance(items, list):
                issues.add("lambda_inventory_malformed")
                continue
            if envelope.get("status") == "empty" and items:
                issues.add("lambda_inventory_malformed")
            for item in items:
                if not isinstance(item, dict):
                    issues.add("lambda_function_malformed")
                    continue
                function_arn, role_arn = item.get("FunctionArn"), item.get("Role")
                fn = _FUNCTION.fullmatch(function_arn) if isinstance(function_arn, str) else None
                role = _ROLE.fullmatch(role_arn) if isinstance(role_arn, str) else None
                if (fn is None or role is None or partition is None or
                        fn.groups() != (partition, region, account) or role.groups() != (partition, account) or
                        item.get("AccountId") != account or item.get("Region") != region):
                    issues.add("lambda_identity_malformed")
                    continue
                if function_arn in seen_functions:
                    issues.add("lambda_function_duplicate")
                    continue
                seen_functions.add(function_arn)
                configuration = item.get("Configuration")
                if not isinstance(configuration, dict) or configuration.get("collection_status") != "collected":
                    issues.add("lambda_state_unavailable")
                    continue
                detail_arn, detail_role = configuration.get("FunctionArn"), configuration.get("Role")
                if ((detail_arn is not None and detail_arn != function_arn) or
                        (detail_role is not None and detail_role != role_arn)):
                    issues.add("lambda_detail_identity_mismatch")
                    continue
                state = configuration.get("State")
                if not isinstance(state, str):
                    issues.add("lambda_state_unavailable")
                elif state == "Active":
                    active_count += 1
                    roles.setdefault(role_arn, set()).add(function_arn)
                elif state not in _NONACTIVE:
                    issues.add("lambda_state_unavailable")
        if len(observed) != len(set(observed)):
            issues.add("lambda_region_duplicate")
        if not enabled or set(observed) != set(enabled):
            issues.add("lambda_region_coverage_incomplete")
        shared = [{"role_arn": role, "function_count": len(functions)}
                  for role, functions in sorted(roles.items()) if len(functions) > 1]
        rows.append({"account_id": account, "partition": partition,
                     "status": "collected" if not issues else "partial",
                     "enabled_regions": enabled, "observed_regions": sorted(set(observed)),
                     "active_function_count": active_count,
                     "shared_active_roles": shared, "issue_codes": sorted(issues)})
    return {"schema_version": 1,
            "source": "lambda:ListFunctions + lambda:GetFunctionConfiguration + ec2:DescribeRegions",
            "accounts": rows}
