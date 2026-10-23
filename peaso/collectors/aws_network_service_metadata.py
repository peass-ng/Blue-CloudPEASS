"""Read-only CloudFront VPC origins and MemoryDB subnet groups."""
SPECS = {"cloudfront_vpc_origin": ("cloudfront", "list_vpc_origins", "VpcOriginList.Items"),
         "memorydb_subnet_group": ("memorydb", "describe_subnet_groups", "SubnetGroups")}
NATIVE_IDS = {"cloudfront_vpc_origin": "Id", "memorydb_subnet_group": "Name"}
GLOBAL_TYPES = {"cloudfront_vpc_origin"}
READ_ACTIONS = {("cloudfront", "get_vpc_origin")}


def fetch(requests, session, region, account):
    # Botocore has no paginator for this API. Validate truncation before
    # treating omitted Items as an empty list; a missing next marker is a gap.
    # CloudFront omits IsTruncated on some complete zero-quantity responses.
    # Accept that exact empty shape while keeping ambiguous nonempty pages malformed.
    expression = ("((VpcOriginList.IsTruncated == `false`) || "
                  "(VpcOriginList.IsTruncated == `null` && VpcOriginList.Quantity == `0` && "
                  "VpcOriginList.NextMarker == `null` && (VpcOriginList.Items || `[]`) == `[]`) || "
                  "(VpcOriginList.IsTruncated == `true` && VpcOriginList.NextMarker)) && "
                  "(VpcOriginList.Items || `[]`)")
    return requests.pages(session, "cloudfront", region, "list_vpc_origins", expression,
                          _tokens=("Marker", "VpcOriginList.NextMarker"))


def enrich(requests, session, region, items):
    from .aws import _single
    for item in items:
        if not isinstance(item.get("Id"), str) or not item["Id"]:
            item["VpcOrigin"] = {"collection_status": "malformed"}
            continue
        result = _single(requests, session, region, "cloudfront", "get_vpc_origin", Id=item["Id"])
        if result.status == "collected" and len(result.items) == 1:
            item["VpcOrigin"] = result.items[0].get("VpcOrigin", {})
        else:
            item["VpcOrigin"] = {"collection_status": result.status, "error": result.error}
    return items


ENRICHERS = {"cloudfront_vpc_origin": enrich}
FETCHERS = {"cloudfront_vpc_origin": fetch}
