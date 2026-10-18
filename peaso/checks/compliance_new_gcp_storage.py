"""Signed GCP storage compliance predicates over complete cached bucket facts.

No provider request is made by an evaluator in this module.
"""
from __future__ import annotations

from . import register, result
from .facts import full_representation, get, omitted, Unavailable
from .fixtures import CASES


@register("gcp_bucket_logging_enabled_fb7cc594582a", "gcp", "hardening", "bucket",
          "Cloud Storage bucket names a usage-log destination", "medium", "AU-12",
          "Review the bucket's usage-log requirement and configure an owner-approved log destination bucket.")
def bucket_usage_log_destination(item, index):
    bucket_name = get(item, "name", str)
    if not full_representation(item):
        raise Unavailable("Cloud Storage bucket properties are not a full projection")
    # storage.buckets.list projection=full returns all bucket properties. The
    # logging object and its logBucket member are omitted when not configured.
    destination = omitted(item, "logging.logBucket", "", str)
    return result(not bool(destination.strip()), bucket_name=bucket_name,
                  log_bucket=destination or None,
                  semantics="Declared Cloud Storage usage/storage log destination only")


_bucket = {"name": "pci-inert-bucket", "_provenance": {"representation": "full"}}
CASES["gcp_bucket_logging_enabled_fb7cc594582a"] = {
    "pass": {**_bucket, "logging": {"logBucket": "pci-inert-log-bucket"}},
    "fail": _bucket,
    "unknown": {**_bucket, "_coverage": {"logging": {"status": "denied"}}},
}
