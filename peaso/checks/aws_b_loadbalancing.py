"""ELB/ACM metadata predicates with explicit type applicability and snapshot clock."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from . import result, unknown
from .facts import get, list_of_objects, Unavailable
from .aws_b_core import install, scalar, IDS, SOURCES


def lb_attrs(item):
    rows = list_of_objects(get(item, "Attributes.Attributes", list))
    output = {}
    for row in rows:
        key, value = get(row, "Key", str), get(row, "Value", str)
        if key in output:
            raise Unavailable("duplicate load balancer attribute")
        output[key] = value
    return output


def lb_fixture(values, kind="application"):
    return {"Type": kind, "Attributes": {"Attributes": [{"Key": k, "Value": v} for k, v in values.items()]}}


for _key, _suffix, _query, _title in [
    ("access_logs.s3.enabled", "access_logs", "elb_application_classic_lb_logging_enabled", "ALB access logging is enabled"),
    ("deletion_protection.enabled", "deletion_protection", "elb_application_lb_deletion_protection_enabled", "ALB deletion protection is enabled"),
    ("routing.http.drop_invalid_header_fields.enabled", "invalid_header_dropping", "elb_application_lb_drop_http_headers", "ALB invalid HTTP header dropping is enabled"),
]:
    def _attribute(key, suffix, query, title):
        @install("aws.b.alb." + suffix, "load_balancer", title, lb_fixture({key: "true"}), lb_fixture({key: "false"}), query=query, extra={"not_applicable": {"Type": "network"}})
        def evaluate(item, index):
            kind = get(item, "Type", str)
            if kind not in ("application", "network", "gateway"):
                return unknown("unrecognized ELBv2 type")
            if kind != "application":
                return "NOT_APPLICABLE", {"type": kind}
            values = lb_attrs(item)
            if key not in values:
                return unknown("required ALB attribute not collected", attribute=key)
            if values[key] not in ("true", "false"):
                return unknown("malformed ALB attribute value", attribute=key)
            return result(values[key] != "true", attribute=key, configured=values[key])
    _attribute(_key, _suffix, _query, _title)
SOURCES["elb_application_lb_http_drop_invalid_header_enabled"] = ["aws.b.alb.invalid_header_dropping"]


@install("aws.b.alb.desync_mode", "load_balancer", "ALB uses defensive or strictest HTTP desync mitigation", lb_fixture({"routing.http.desync_mitigation_mode": "defensive"}), lb_fixture({"routing.http.desync_mitigation_mode": "monitor"}), query="elb_application_lb_desync_mitigation_mode", extra={"not_applicable": {"Type": "network"}})
def desync(item, index):
    kind = get(item, "Type", str)
    if kind != "application":
        return "NOT_APPLICABLE", {"type": kind}
    mode = lb_attrs(item).get("routing.http.desync_mitigation_mode")
    if mode not in ("defensive", "strictest", "monitor"):
        return unknown("desync mitigation value absent or unrecognized")
    return result(mode == "monitor", desync_mitigation_mode=mode, semantics="Pinned source requires mitigation mode; dropping headers alone is not its alternative passing branch.")


for _key, _suffix, _query in [("AccessLog.Enabled", "access_logs", "elb_application_classic_lb_logging_enabled"), ("CrossZoneLoadBalancing.Enabled", "cross_zone", "elb_classic_lb_cross_zone_load_balancing_enabled"), ("ConnectionDraining.Enabled", "connection_draining", "ec2_classic_lb_connection_draining_enabled")]:
    cid = "aws.b.classic_elb." + _suffix
    scalar(cid, "classic_load_balancer", "Attributes.LoadBalancerAttributes." + _key, True, False, "Classic ELB " + _suffix.replace("_", " ") + " is enabled", "_classic:" + _query)
    SOURCES.setdefault(_query, []).append(cid)
SOURCES["elb_application_classic_lb_logging_enabled"].insert(0, "aws.b.alb.access_logs")


@install("aws.b.classic_elb.multiple_az", "classic_load_balancer", "Classic ELB declares at least two availability zones", {"AvailabilityZones": ["us-east-1a", "us-east-1b"]}, {"AvailabilityZones": ["us-east-1a"]}, query="elb_classic_lb_multiple_az_configured")
def classic_zones(item, index):
    zones = get(item, "AvailabilityZones", list)
    if any(not isinstance(v, str) or not v for v in zones):
        return unknown("malformed classic ELB availability zones")
    # The pinned SQL counts list cardinality, not a silently different unique-set threshold.
    return result(len(zones) < 2, availability_zones=zones, minimum=2)


@install("aws.b.elbv2.multiple_az", "load_balancer", "Application/network/gateway ELB declares at least two availability zones", {"Type": "gateway", "AvailabilityZones": [{"ZoneName": "us-east-1a"}, {"ZoneName": "us-east-1b"}]}, {"Type": "application", "AvailabilityZones": [{"ZoneName": "us-east-1a"}]}, query="elb_application_gateway_network_lb_multiple_az_configured")
def v2_zones(item, index):
    kind = get(item, "Type", str)
    if kind not in ("application", "network", "gateway"):
        return unknown("unrecognized load balancer type")
    zones = list_of_objects(get(item, "AvailabilityZones", list))
    names = [get(row, "ZoneName", str) for row in zones]
    return result(len(zones) < 2, load_balancer_type=kind, availability_zones=names, minimum=2)


@install("aws.b.elbv2.listener_presence", "load_balancer", "Application/network load balancer has a listener", {"Type": "application", "Listeners": {"collection_status": "collected", "items": [{"ListenerArn": "arn:listener"}]}}, {"Type": "application", "Listeners": {"collection_status": "empty", "items": []}}, query="elb_application_network_lb_use_listeners", extra={"not_applicable": {"Type": "gateway"}})
def listeners(item, index):
    kind = get(item, "Type", str)
    if kind == "gateway":
        return "NOT_APPLICABLE", {"type": kind, "reason": "Source union includes only application/network load balancers."}
    if kind not in ("application", "network"):
        return unknown("unrecognized load balancer type")
    listing = get(item, "Listeners", dict)
    if listing.get("collection_status") not in ("collected", "empty"):
        return unknown("listener inventory incomplete")
    rows = list_of_objects(get(listing, "items", list))
    return result(not rows, listener_count=len(rows), load_balancer_type=kind)


@install("aws.b.classic_elb.encrypted_listeners", "classic_load_balancer", "Classic ELB listeners use HTTPS/SSL/TLS", {"ListenerDescriptions": [{"Listener": {"Protocol": "HTTPS"}}]}, {"ListenerDescriptions": [{"Listener": {"Protocol": "HTTP"}}]}, query="elb_classic_lb_use_tls_https_listeners", extra={"not_applicable": {"ListenerDescriptions": []}})
def classic_tls(item, index):
    rows = list_of_objects(get(item, "ListenerDescriptions", list))
    if not rows:
        return "NOT_APPLICABLE", {"reason": "No listener rows exist for the source's expanded listener relation."}
    protocols = [get(row, "Listener.Protocol", str) for row in rows]
    return result(any(p not in {"HTTPS", "SSL", "TLS"} for p in protocols), protocols=protocols)


@install("aws.b.classic_elb.desync_mode", "classic_load_balancer", "Classic ELB uses defensive or strictest desync mitigation", {"Attributes": {"LoadBalancerAttributes": {"AdditionalAttributes": [{"Key": "elb.http.desyncmitigationmode", "Value": "defensive"}]}}}, {"Attributes": {"LoadBalancerAttributes": {"AdditionalAttributes": [{"Key": "elb.http.desyncmitigationmode", "Value": "monitor"}]}}}, query="elb_classic_lb_desync_mitigation_mode")
def classic_desync(item, index):
    rows = list_of_objects(get(item, "Attributes.LoadBalancerAttributes.AdditionalAttributes", list))
    matches = [get(row, "Value", str) for row in rows if get(row, "Key", str) == "elb.http.desyncmitigationmode"]
    if len(matches) != 1 or matches[0] not in {"defensive", "strictest", "monitor"}:
        return unknown("desync mitigation absent, duplicate or unrecognized")
    return result(matches[0] == "monitor", desync_mitigation_mode=matches[0])


def certificate(item):
    return get(item, "Certificate.Certificate", dict)


def timestamp(value):
    if not isinstance(value, str):
        raise Unavailable("captured timestamp must be an ISO string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise Unavailable("captured timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


@install("aws.b.acm.expiry_thirty_days", "acm_certificate", "Renewal-eligible ACM certificate has at least 30 calendar days until expiry", {"Certificate": {"Certificate": {"RenewalEligibility": "ELIGIBLE", "NotAfter": "2026-11-09T00:00:00Z"}}}, {"Certificate": {"Certificate": {"RenewalEligibility": "ELIGIBLE", "NotAfter": "2026-11-08T23:59:59Z"}}}, query="acm_certificate_expires_30_days", extra={"index": {"context": {"created_at": "2026-10-10T20:00:00Z"}}, "not_applicable": {"Certificate": {"Certificate": {"RenewalEligibility": "INELIGIBLE"}}}})
def expiry(item, index):
    details = certificate(item)
    eligibility = get(details, "RenewalEligibility", str)
    if eligibility == "INELIGIBLE":
        return "NOT_APPLICABLE", {"renewal_eligibility": eligibility}
    if eligibility != "ELIGIBLE":
        return unknown("unrecognized renewal eligibility")
    expired = timestamp(get(details, "NotAfter", str))
    clock = timestamp(index.get("context", {}).get("created_at"))
    days = (expired.date() - clock.date()).days
    return result(days < 30, remaining_calendar_days=days, snapshot_clock=clock.isoformat(), not_after=expired.isoformat())


@install("aws.b.acm.transparency_logging", "acm_certificate", "Non-imported ACM certificate enables transparency logging", {"Certificate": {"Certificate": {"Type": "AMAZON_ISSUED", "Options": {"CertificateTransparencyLoggingPreference": "ENABLED"}}}}, {"Certificate": {"Certificate": {"Type": "AMAZON_ISSUED", "Options": {"CertificateTransparencyLoggingPreference": "DISABLED"}}}}, query="acm_certificate_transparency_logging_enabled", extra={"not_applicable": {"Certificate": {"Certificate": {"Type": "IMPORTED"}}}})
def transparency(item, index):
    details = certificate(item)
    kind = get(details, "Type", str)
    if kind == "IMPORTED":
        return "NOT_APPLICABLE", {"certificate_type": kind}
    if kind not in {"AMAZON_ISSUED", "PRIVATE"}:
        return unknown("unknown certificate type")
    preference = get(details, "Options.CertificateTransparencyLoggingPreference", str)
    if preference not in {"ENABLED", "DISABLED"}:
        return unknown("unknown transparency logging preference")
    return result(preference != "ENABLED", certificate_type=kind, transparency_logging=preference)


@install("aws.b.acm.no_wildcard_domain", "acm_certificate", "ACM primary domain does not start with wildcard", {"Certificate": {"Certificate": {"DomainName": "app.example.test"}}}, {"Certificate": {"Certificate": {"DomainName": "*.example.test"}}}, query="acm_certificate_no_wildcard_domain_name")
def wildcard(item, index):
    name = get(certificate(item), "DomainName", str)
    return result(name.startswith("*"), primary_domain=name, semantics="Pinned source checks the primary DomainName; SAN inventory has a separate scope.")


@install("aws.b.acm.no_failed_validation", "acm_certificate", "ACM certificate is not failed or validation-timed-out", {"Certificate": {"Certificate": {"Status": "ISSUED"}}}, {"Certificate": {"Certificate": {"Status": "FAILED"}}}, query="acm_certificate_no_failed_certificate")
def failed_certificate(item, index):
    status = get(certificate(item), "Status", str)
    if status not in {"PENDING_VALIDATION", "ISSUED", "INACTIVE", "EXPIRED", "VALIDATION_TIMED_OUT", "REVOKED", "FAILED"}:
        return unknown("unknown certificate status")
    return result(status in {"VALIDATION_TIMED_OUT", "FAILED"}, certificate_status=status)


@install("aws.b.acm.pending_validation_review", "acm_certificate", "Pending ACM validation requires review", {"Certificate": {"Certificate": {"Status": "ISSUED"}}}, {"Certificate": {"Certificate": {"Status": "EXPIRED"}}}, query="acm_certificate_no_pending_validation_certificate")
def pending_certificate(item, index):
    status = get(certificate(item), "Status", str)
    if status not in {"PENDING_VALIDATION", "ISSUED", "INACTIVE", "EXPIRED", "VALIDATION_TIMED_OUT", "REVOKED", "FAILED"}:
        return unknown("unknown certificate status")
    if status == "PENDING_VALIDATION":
        return "MANUAL", {"certificate_status": status, "reason": "Pinned source reports pending validation as info/manual."}
    return result(False, certificate_status=status)


@install("aws.b.acm.not_past_expiry_date", "acm_certificate", "Renewal-eligible ACM certificate is not past its calendar expiry date", {"Certificate": {"Certificate": {"RenewalEligibility": "ELIGIBLE", "NotAfter": "2026-10-10T01:00:00Z"}}}, {"Certificate": {"Certificate": {"RenewalEligibility": "ELIGIBLE", "NotAfter": "2026-10-09T23:59:59Z"}}}, query="acm_certificate_not_expired", extra={"index": {"context": {"created_at": "2026-10-10T20:00:00Z"}}, "not_applicable": {"Certificate": {"Certificate": {"RenewalEligibility": "INELIGIBLE"}}}})
def not_expired(item, index):
    details = certificate(item)
    eligibility = get(details, "RenewalEligibility", str)
    if eligibility == "INELIGIBLE":
        return "NOT_APPLICABLE", {"renewal_eligibility": eligibility}
    if eligibility != "ELIGIBLE":
        return unknown("unrecognized renewal eligibility")
    end = timestamp(get(details, "NotAfter", str))
    clock = timestamp(index.get("context", {}).get("created_at"))
    return result(end.date() < clock.date(), expiry_date=end.date().isoformat(), snapshot_date=clock.date().isoformat(), semantics="Exact calendar-date source predicate; not an assertion that the certificate remains valid at the current instant.")


@install("aws.b.acm.rsa_minimum_2048", "acm_certificate", "RSA ACM certificates use at least 2048-bit keys", {"Certificate": {"Certificate": {"KeyAlgorithm": "RSA_2048"}}}, {"Certificate": {"Certificate": {"KeyAlgorithm": "RSA_1024"}}}, query="_corrected:acm_certificate_rsa_key_length_2048_bits_or_greater", extra={"not_applicable": {"Certificate": {"Certificate": {"KeyAlgorithm": "EC_prime256v1"}}}})
def rsa(item, index):
    algorithm = get(certificate(item), "KeyAlgorithm", str)
    if algorithm in {"EC_prime256v1", "EC_secp384r1", "EC_secp521r1"}:
        return "NOT_APPLICABLE", {"key_algorithm": algorithm}
    # DescribeCertificate's official CLI example returns RSA-2048, while the
    # API enum reference uses RSA_2048. Preserve the raw fact and interpret only
    # the enumerated spellings; an arbitrary future algorithm stays unknown.
    bits = {"RSA" + separator + str(size): size
            for separator in ("_", "-") for size in (1024, 2048, 3072, 4096)}
    if algorithm not in bits:
        return unknown("unknown ACM key algorithm", key_algorithm=algorithm)
    return result(bits[algorithm] < 2048, key_algorithm=algorithm, rsa_bits=bits[algorithm],
                  official_reference="https://docs.aws.amazon.com/cli/latest/reference/acm/describe-certificate.html",
                  semantics="Corrected native rule; upstream SQL's RSA-% eligibility contradicts its RSA_1024 failing branch and is not equivalent.")


# A legitimate source with conditional manual status has no failing assessment.
from .fixtures import CASES
CASES["aws.b.acm.pending_validation_review"].pop("fail")
CASES["aws.b.acm.pending_validation_review"]["manual"] = {"Certificate": {"Certificate": {"Status": "PENDING_VALIDATION"}}}
SOURCES["elb_application_classic_lb_logging_enabled"] = ["aws.b.alb.access_logs", "aws.b.classic_elb.access_logs"]
