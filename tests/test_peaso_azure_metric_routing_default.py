"""Pinned metric defaults reach the public collector without owner observations."""
import pytest

from tests import test_peaso_azure_alert_routing_public_collect as public_flow


@pytest.mark.parametrize('groups,expected', [(True, 'PASS'), (False, 'FAIL'), (None, 'UNKNOWN')])
def test_native_metric_default_supports_public_routing_without_auto_mitigate(monkeypatch, groups, expected):
    original = public_flow.native
    def native_without_default(*args, **kwargs):
        row = original(*args, **kwargs)
        row['properties'].pop('autoMitigate', None)
        return row
    monkeypatch.setattr(public_flow, 'native', native_without_default)
    public_flow.test_public_native_collect_routes_without_owner_observations(monkeypatch, 'metric_alert', groups, expected)
