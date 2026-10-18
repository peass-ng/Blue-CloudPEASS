"""CloudFront configuration checks preserving default and every additional behavior."""
from . import result, unknown
from .facts import get, list_of_objects
from .aws_b_core import install, scalar, SOURCES


BASE = "Config.DistributionConfig."
DOC = "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_DistributionConfig.html"


def config(item):
    return get(item, "Config.DistributionConfig", dict)


def behavior_rows(data):
    default = get(data, "DefaultCacheBehavior", dict)
    extra = data.get("CacheBehaviors", {"Quantity": 0})
    if not isinstance(extra, dict):
        raise ValueError("malformed additional cache behaviors")
    quantity = extra.get("Quantity")
    if type(quantity) is not int or quantity < 0:
        raise ValueError("cache behavior quantity missing or malformed")
    items = list_of_objects(extra.get("Items", []))
    if quantity != len(items):
        raise ValueError("cache behavior inventory quantity mismatch")
    return [default] + items


def viewer_http(data):
    policies = [get(row, "ViewerProtocolPolicy", str) for row in behavior_rows(data)]
    if any(value not in ("allow-all", "https-only", "redirect-to-https") for value in policies):
        raise ValueError("unknown viewer protocol policy")
    return "allow-all" in policies, policies


@install("aws.b.cloudfront.viewer_encryption", "cloudfront_distribution", "CloudFront default and additional cache behaviors require encrypted viewer traffic", {"Config": {"DistributionConfig": {"DefaultCacheBehavior": {"ViewerProtocolPolicy": "redirect-to-https"}, "CacheBehaviors": {"Quantity": 0}}}}, {"Config": {"DistributionConfig": {"DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only"}, "CacheBehaviors": {"Quantity": 1, "Items": [{"ViewerProtocolPolicy": "allow-all"}]}}}}, query="cloudfront_distribution_encryption_in_transit_enabled")
def viewers(item, index):
    insecure, policies = viewer_http(config(item))
    return result(insecure, viewer_protocol_policies=policies, official_reference=DOC)


scalar("aws.b.cloudfront.access_logging", "cloudfront_distribution", BASE + "Logging.Enabled", True, False, "CloudFront distribution access logging is enabled", "cloudfront_distribution_logging_enabled")
scalar("aws.b.cloudfront.sni", "cloudfront_distribution", BASE + "ViewerCertificate.SSLSupportMethod", "sni-only", "vip", "CloudFront certificate uses SNI-only support", "cloudfront_distribution_sni_enabled", allowed={"sni-only", "vip", "static-ip"})


@install("aws.b.cloudfront.geo_restrictions", "cloudfront_distribution", "CloudFront distribution has an allow/block geographical restriction policy", {"Config": {"DistributionConfig": {"Restrictions": {"GeoRestriction": {"RestrictionType": "whitelist"}}}}}, {"Config": {"DistributionConfig": {"Restrictions": {"GeoRestriction": {"RestrictionType": "none"}}}}}, query="cloudfront_distribution_geo_restrictions_enabled")
def geo(item, index):
    value = get(item, BASE + "Restrictions.GeoRestriction.RestrictionType", str)
    if value not in ("none", "whitelist", "blacklist"):
        return unknown("unrecognized geographical restriction type")
    return result(value == "none", restriction_type=value, semantics="Declaration of geographical policy; business need and effectiveness are separate.")


for _field, _suffix, _query, _title in [
    ("WebACLId", "waf_reference", "cloudfront_distribution_waf_enabled", "CloudFront distribution references a WAF ACL"),
    ("DefaultRootObject", "default_root_object", "cloudfront_distribution_default_root_object_configured", "CloudFront distribution configures a default root object"),
    ("DefaultCacheBehavior.FieldLevelEncryptionId", "field_level_encryption", "cloudfront_distribution_field_level_encryption_enabled", "CloudFront default behavior configures field-level encryption"),
]:
    def _nonempty(field, suffix, query, title):
        cid = "aws.b.cloudfront." + suffix
        from .fixtures import nest
        @install(cid, "cloudfront_distribution", title, nest(BASE + field, "configured"), nest(BASE + field, ""), query=query)
        def evaluate(item, index):
            value = get(item, BASE + field, str)
            return result(value == "", field=field, configured=value, official_reference=DOC)
    _nonempty(_field, _suffix, _query, _title)


@install("aws.b.cloudfront.custom_acm_certificate", "cloudfront_distribution", "CloudFront certificate declares both ACM ARN and certificate reference", {"Config": {"DistributionConfig": {"ViewerCertificate": {"ACMCertificateArn": "arn:acm", "Certificate": "arn:acm"}}}}, {"Config": {"DistributionConfig": {"ViewerCertificate": {"CloudFrontDefaultCertificate": True}}}}, query="cloudfront_distribution_use_custom_ssl_certificate")
def custom_certificate(item, index):
    viewer = get(item, BASE + "ViewerCertificate", dict)
    for field in ("ACMCertificateArn", "Certificate"):
        if field in viewer and not isinstance(viewer[field], str):
            return unknown("malformed certificate reference", field=field)
    return result(not (viewer.get("ACMCertificateArn") is not None and viewer.get("Certificate") is not None), certificate_references={key: viewer.get(key) for key in ("ACMCertificateArn", "Certificate")}, semantics="Source metadata-presence policy; certificate validity and hosted default-certificate suitability are separate.")


@install("aws.b.cloudfront.origin_group_metadata", "cloudfront_distribution", "CloudFront distribution declares origin-group item metadata", {"Config": {"DistributionConfig": {"OriginGroups": {"Quantity": 1, "Items": [{"Id": "group"}]}}}}, {"Config": {"DistributionConfig": {"OriginGroups": {"Quantity": 0}}}}, query="cloudfront_distribution_configured_with_origin_failover")
def group_metadata(item, index):
    groups = get(item, BASE + "OriginGroups", dict)
    items = groups.get("Items")
    if items is not None:
        list_of_objects(items)
    return result(items is None, origin_groups=groups, semantics="Exact source item-metadata presence predicate; failover member count and functioning routing are not inferred.")


def origins(data):
    source = get(data, "Origins", dict)
    qty = get(source, "Quantity", int)
    rows = list_of_objects(get(source, "Items", list))
    if qty != len(rows) or qty < 0:
        raise ValueError("origin inventory quantity mismatch")
    return rows


for _forbidden, _suffix, _query in [({"SSLv3", "TLSv1"}, "origin_secure_protocols", "cloudfront_distribution_use_secure_cipher"), ({"SSLv3"}, "no_sslv3_origin", "cloudfront_distribution_no_deprecated_ssl_protocol")]:
    def _protocol_check(forbidden, suffix, query):
        good = {"Config": {"DistributionConfig": {"Origins": {"Quantity": 1, "Items": [{"Id": "origin", "CustomOriginConfig": {"OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]}}}]}}}}
        bad = {"Config": {"DistributionConfig": {"Origins": {"Quantity": 1, "Items": [{"Id": "origin", "CustomOriginConfig": {"OriginSslProtocols": {"Quantity": 1, "Items": ["SSLv3"]}}}]}}}}
        @install("aws.b.cloudfront." + suffix, "cloudfront_distribution", "CloudFront origins exclude " + ", ".join(sorted(forbidden)), good, bad, query=query)
        def evaluate(item, index):
            rejected = []
            for origin in origins(config(item)):
                custom = origin.get("CustomOriginConfig")
                if custom is None:
                    continue
                if not isinstance(custom, dict):
                    return unknown("malformed custom-origin configuration")
                selected = get(custom, "OriginSslProtocols", dict)
                protocol_items = get(selected, "Items", list)
                count = get(selected, "Quantity", int)
                if count != len(protocol_items) or any(not isinstance(p, str) for p in protocol_items):
                    return unknown("malformed origin protocol list")
                if forbidden.intersection(protocol_items):
                    rejected.append({"origin_id": origin.get("Id"), "ssl_protocols": protocol_items})
            return result(bool(rejected), rejected_origins=rejected, source_forbidden_protocols=sorted(forbidden), semantics="Configured origin protocols; no network connection was tested.")
    _protocol_check(_forbidden, _suffix, _query)


@install("aws.b.cloudfront.custom_origin_encryption", "cloudfront_distribution", "CloudFront custom origins avoid plaintext transport including match-viewer alternatives", {"Config": {"DistributionConfig": {"DefaultCacheBehavior": {"ViewerProtocolPolicy": "https-only"}, "CacheBehaviors": {"Quantity": 0}, "Origins": {"Quantity": 1, "Items": [{"CustomOriginConfig": {"OriginProtocolPolicy": "match-viewer"}}]}}}}, {"Config": {"DistributionConfig": {"DefaultCacheBehavior": {"ViewerProtocolPolicy": "allow-all"}, "CacheBehaviors": {"Quantity": 0}, "Origins": {"Quantity": 1, "Items": [{"CustomOriginConfig": {"OriginProtocolPolicy": "match-viewer"}}]}}}}, query="cloudfront_distribution_custom_origins_encryption_in_transit_enabled")
def custom_origin_https(item, index):
    data = config(item)
    viewer_insecure, policies = viewer_http(data)
    insecure = []
    for origin in origins(data):
        custom = origin.get("CustomOriginConfig")
        if custom is None:
            continue
        policy = get(custom, "OriginProtocolPolicy", str)
        if policy not in ("http-only", "https-only", "match-viewer"):
            return unknown("unknown origin protocol policy")
        if policy == "http-only" or (policy == "match-viewer" and viewer_insecure):
            insecure.append({"origin_id": origin.get("Id"), "origin_protocol_policy": policy})
    return result(bool(insecure), insecure_origins=insecure, viewer_protocol_policies=policies)
