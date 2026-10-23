"""Read IAP TCP tunnel policies for exact inventoried Compute instances."""

import re

from .gcp import ReadError


def collection_pages(collector, scope):
    inventory = collector.collections.get(("instance", scope))
    if not inventory or inventory["coverage_status"] not in ("collected", "empty"):
        raise ReadError("unavailable", "instance_inventory_incomplete")
    instances = {}
    zones = set()
    for vm in inventory["items"]:
        link = vm.get("selfLink")
        match = re.fullmatch(
            rf"https://(?:www|compute)\.googleapis\.com/compute/v1/{re.escape(scope)}"
            r"/zones/([a-z][a-z0-9-]*[0-9]-[a-z])/instances/([A-Za-z0-9_-]+)",
            link) if isinstance(link, str) else None
        if not match or vm.get("name") != match.group(2):
            raise ReadError("malformed", "iap_instance_identity_unbound")
        zone, name = match.groups()
        resource = f"{scope}/iap_tunnel/zones/{zone}/instances/{name}"
        if resource in instances:
            raise ReadError("malformed", "duplicate_iap_instance_identity")
        instances[resource] = vm
        zones.add(zone)
    if not instances:
        return
    root = scope + "/iap_tunnel"
    resources = [root, *(f"{root}/zones/{zone}" for zone in sorted(zones)), *sorted(instances)]
    for resource in resources:
        url = "https://iap.googleapis.com/v1/" + resource + ":getIamPolicy"
        row = collector.hydrate({"name": resource}, "iamPolicy", url, scope,
                                method="POST", body={"options": {"requestedPolicyVersion": 3}})
        refs = row.get("_coverage", {}).get("iamPolicy", {}).get("source_requests", [])
        yield [row], refs[0] if refs else "local:iap_policy_read_failed"
