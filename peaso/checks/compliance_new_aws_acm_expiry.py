"""Signed ACM expiry predicates over one complete, cached regional inventory."""
from __future__ import annotations

from datetime import timedelta

from . import register, result
from .compliance_new_aws import _clock, _instant
from .facts import Unavailable, complete_items, get, memoized
from .fixtures import CASES


_STATUSES = {"PENDING_VALIDATION", "ISSUED", "INACTIVE", "EXPIRED",
             "VALIDATION_TIMED_OUT", "REVOKED", "FAILED"}


def _inventory(index, issued_only):
    rows = {}
    incomplete = False
    captured = _clock(index)
    for candidate in complete_items(index, "acm_certificate"):
        arn = get(candidate, "CertificateArn", str)
        if not arn or arn in rows:
            raise Unavailable("missing or duplicate certificate identity in scoped inventory")
        try:
            status = get(candidate, "Certificate.Certificate.Status", str)
            if status not in _STATUSES:
                raise Unavailable("unrecognized ACM certificate status")
            expiry = None if issued_only and status != "ISSUED" else _instant(
                get(candidate, "Certificate.Certificate.NotAfter"))
        except Unavailable:
            status, expiry = None, None
            incomplete = True
        rows[arn] = (candidate, status, expiry)
    return rows, incomplete, captured, captured + timedelta(days=30)


def _assess(item, index, *, issued_only, boundary):
    inventory, incomplete, captured, threshold = memoized(
        index, ("acm_expiry_inventory", issued_only), lambda: _inventory(index, issued_only))
    arn = get(item, "CertificateArn", str)
    own = inventory.get(arn)
    if own is None:
        raise Unavailable("certificate absent from scoped complete inventory")
    candidate, status, expiry = own
    if item != candidate:
        raise Unavailable("certificate differs from scoped inventory fact")
    if status is None:
        raise Unavailable("certificate status or expiry detail unavailable")
    if issued_only and status != "ISSUED":
        return "NOT_APPLICABLE", {"certificate_arn": arn, "status": status}
    if expiry is None:
        raise Unavailable("certificate expiry detail unavailable")
    if boundary == "closed_instant":
        fail = expiry <= threshold
    elif boundary == "strict_instant":
        fail = expiry < threshold
    elif boundary == "strict_date":
        fail = expiry.date() < (captured.date() + timedelta(days=30))
    else:
        raise AssertionError("unreviewed ACM expiry boundary")
    # A definite failure remains visible despite another unreadable detail;
    # a PASS requires every applicable peer to have valid detail.
    if not fail and incomplete:
        raise Unavailable("applicable certificate detail incomplete in scoped inventory")
    return result(fail, certificate_arn=arn, status=status, not_after=expiry.isoformat(),
                  threshold=threshold.isoformat(), boundary=boundary,
                  semantics="Expiry is evaluated independently of RenewalEligibility")


@register("aws_fedramp_acm_all_certificates_30_day_expiry", "aws", "hardening", "acm_certificate",
          "All ACM certificates expire later than 30 days from capture", "medium", "CM-6",
          "Review and renew or replace each applicable certificate before its 30-day threshold.",
          dependencies=["acm_certificate"])
def fedramp_all(item, index):
    return _assess(item, index, issued_only=False, boundary="closed_instant")


@register("aws.nist.acm_all_certificates_expiry_30_days", "aws", "hardening", "acm_certificate",
          "Issued ACM certificates expire later than 30 days from capture", "medium", "CM-6",
          "Review and renew or replace issued certificates before their 30-day threshold.",
          dependencies=["acm_certificate"])
def nist_issued_closed(item, index):
    return _assess(item, index, issued_only=True, boundary="closed_instant")


@register("aws_nist_acm_certificate_expires_30_days", "aws", "hardening", "acm_certificate",
          "Issued ACM certificates do not expire within 30 days", "medium", "CM-6",
          "Review and renew or replace issued certificates before they enter the 30-day window.",
          dependencies=["acm_certificate"])
def nist_issued_strict(item, index):
    return _assess(item, index, issued_only=True, boundary="strict_instant")


@register("aws_g6_acm_all_certificates_30_day_expiry", "aws", "hardening", "acm_certificate",
          "All ACM certificates have at least 30 calendar days to expiry", "medium", "CM-6",
          "Review and renew or replace certificates before their remaining calendar lifetime is below 30 days.",
          dependencies=["acm_certificate"])
def g6_all_calendar(item, index):
    return _assess(item, index, issued_only=False, boundary="strict_date")


def _expiry_case(expires):
    return {"CertificateArn": "arn:aws:acm:eu-west-1:123456789012:certificate/inert",
        "Certificate": {"collection_status": "collected", "Certificate": {
            "Status": "ISSUED", "NotAfter": expires, "RenewalEligibility": "ELIGIBLE"}}}


def _expiry_index(row):
    scope = "123456789012/eu-west-1"
    return {"context": {"created_at": "2026-10-12T00:00:00Z"},
        "collections": {"acm_certificate": [{"type": "acm_certificate", "scope": scope,
            "status": "collected", "items": [row]}]},
        "acm_certificate": [{"type": "acm_certificate", "scope": scope, "data": row}]}


for _check_id in (
    "aws_fedramp_acm_all_certificates_30_day_expiry",
    "aws.nist.acm_all_certificates_expiry_30_days",
    "aws_nist_acm_certificate_expires_30_days",
    "aws_g6_acm_all_certificates_30_day_expiry",
):
    _safe, _expiring = _expiry_case("2026-12-01T00:00:00Z"), _expiry_case("2026-10-20T00:00:00Z")
    CASES[_check_id] = {"pass": _safe, "pass_index": _expiry_index(_safe),
        "fail": _expiring, "fail_index": _expiry_index(_expiring),
        "unknown": {**_safe, "Certificate": {"collection_status": "denied"}},
        "unknown_index": _expiry_index({**_safe, "Certificate": {"collection_status": "denied"}}),
        "index": _expiry_index(_safe)}
