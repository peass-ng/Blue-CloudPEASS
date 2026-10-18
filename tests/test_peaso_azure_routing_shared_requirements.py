"""Requirements for another control do not make an optional routing ID mandatory."""
import pytest

from tests import test_peaso_azure_alert_routing_public_collect as public_flow
from tests.test_peaso_azure_gateway_requirements import review


@pytest.mark.parametrize('kind', public_flow.CONTRACTS)
def test_native_routing_coexists_with_other_valid_normal_requirements(monkeypatch, kind):
    original = public_flow.validate_connector
    def validate_with_other_requirements(provider, auth, options, config):
        options['compliance_policy'] = {'sw25': review()}
        return original(provider, auth, options, config)
    monkeypatch.setattr(public_flow, 'validate_connector', validate_with_other_requirements)
    public_flow.test_public_native_collect_routes_without_owner_observations(monkeypatch, kind, True, 'PASS')
