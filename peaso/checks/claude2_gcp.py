"""claude2_gcp partition: native GCP predicates (see docs/peaso-claude2-gcp-coverage.md)."""
from . import claude2_gcp_logging, claude2_gcp_services  # noqa: F401
from .claude2_gcp_common import CHECK_IDS, PREFIX

__all__ = ["CHECK_IDS", "PREFIX"]
