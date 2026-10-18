"""Offline region criteria must reject an unused malformed approved-zone type."""
import pytest

from peaso.server.native_policy_validation import azure_sw31_review
from peaso.snapshot import make_snapshot
from test_peaso_azure_region_counterexample import snapshot, status


def test_unused_malformed_approved_zone_resource_type_is_unknown():
    capture = snapshot('westeurope', zones=['1'], evidence_status='collected')
    policy = capture['metadata']['compliance_policy']['sw31']
    policy['approvedZones']['not-an-arm-resource-type'] = []
    with pytest.raises(ValueError, match='approved zone resource types invalid'):
        azure_sw31_review(policy)
    resealed = make_snapshot('azure', capture['scopes'], capture['collections'],
                             metadata=capture['metadata'])
    assert status(resealed) == 'UNKNOWN'
