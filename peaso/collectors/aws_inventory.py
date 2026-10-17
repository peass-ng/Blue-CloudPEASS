"""Account-wide derived configuration facts reuse complete regional inventories."""


def vpc_account_inventory(collections, account, regions, *, full_region_coverage):
    if not full_region_coverage:
        return [], "not_collected", {"code": "full_account_region_coverage_not_proven"}
    rows, incomplete = [], []
    for region in regions:
        scope = f"{account}/{region}"
        matches = [c for c in collections if c["type"] == "vpc" and c["scope"] == scope]
        if len(matches) != 1 or matches[0]["status"] not in {"collected", "empty"}:
            incomplete.append(region)
            continue
        for item in matches[0]["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("VpcId"), str):
                incomplete.append(region)
                continue
            if item.get("collection_status") not in (None, "collected", "empty"):
                incomplete.append(region)
                continue
            projected = {key: item[key] for key in ("VpcId", "IsDefault", "OwnerId") if key in item}
            if "_coverage" in item:
                projected["_coverage"] = item["_coverage"]
            rows.append({**projected, "id": f"{account}/{region}/{item['VpcId']}", "AccountId": account, "Region": region,
                         "_provenance": {"inventory": "vpc", "source_scope": scope, "native_id": item["VpcId"]}})
    if incomplete:
        return rows, "partial" if rows else "unknown", {"code": "account_vpc_inventory_incomplete", "regions": sorted(set(incomplete))}
    return rows, "collected" if rows else "empty", None
