"""Signed GCP backend configuration predicates over cached full API resources."""
from __future__ import annotations

from . import register, result, unknown
from .facts import Unavailable, full_representation, get
from .fixtures import CASES


_COOKIE_MODES = {"GENERATED_COOKIE", "HTTP_COOKIE"}
_OTHER_MODES = {"NONE", "CLIENT_IP", "CLIENT_IP_NO_DESTINATION", "CLIENT_IP_PROTO",
                "CLIENT_IP_PORT_PROTO", "HEADER_FIELD", "STRONG_COOKIE_AFFINITY"}


@register("gcp_cloudcdn_cookie_ttl", "gcp", "network", "backend_service",
          "Backend cookie affinity TTL is at most 30 minutes", "medium", "SC-23",
          "Review cookie-affinity behavior and set the backend's affinityCookieTtlSec to at most 1800 seconds.")
def backend_cookie_affinity_ttl(item, index):
    name = get(item, "name", str)
    if not full_representation(item):
        raise Unavailable("backend service is not a full API projection")
    # The API documents NONE as a default, but this signed check requires an
    # observed affinity mode before declaring a non-cookie mode inapplicable.
    affinity = get(item, "sessionAffinity", str)
    if affinity in _OTHER_MODES:
        return "NOT_APPLICABLE", {"reason": "signed TTL predicate applies only to GENERATED_COOKIE or HTTP_COOKIE",
                                  "session_affinity": affinity}
    if affinity not in _COOKIE_MODES:
        return unknown("unrecognized backend session affinity", session_affinity=affinity)
    # The signed proposal explicitly requires UNKNOWN when TTL is absent.
    ttl = get(item, "affinityCookieTtlSec", int)
    if ttl < 0 or ttl > 1209600:
        return unknown("invalid backend affinity cookie lifetime", affinity_cookie_ttl_sec=ttl)
    return result(ttl > 1800, backend_service=name, session_affinity=affinity,
                  affinity_cookie_ttl_sec=ttl, maximum_seconds=1800,
                  semantics="Declared backend affinityCookieTtlSec; not inactivity expiry or an override in consistentHash.httpCookie.ttl")


_backend = {"name": "inert-backend", "_provenance": {"representation": "full"},
    "sessionAffinity": "HTTP_COOKIE", "affinityCookieTtlSec": 1800}
CASES["gcp_cloudcdn_cookie_ttl"] = {
    "pass": _backend, "fail": {**_backend, "affinityCookieTtlSec": 1801},
    "unknown": {**_backend, "affinityCookieTtlSec": "1800"},
}
