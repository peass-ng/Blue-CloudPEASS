"""Portable audit-event detections with explicit evidence and narrow claims."""

from .aws import normalize_aws_cloudtrail
from .gcp import normalize_gcp_audit
from .kubernetes import normalize_kubernetes_audit
from .rules import Detection, Rule, detect_aws_events, detect_azure_events, detect_gcp_events, detect_kubernetes_events, load_rules

__all__ = ["Detection", "Rule", "detect_aws_events", "detect_azure_events", "detect_gcp_events", "detect_kubernetes_events", "load_rules", "normalize_aws_cloudtrail", "normalize_gcp_audit", "normalize_kubernetes_audit"]
