import pytest

from peaso.collectors.azure_remaining_services_1_native import _assignable_scope, _scope


@pytest.mark.parametrize('scope', [
    '/providers/Microsoft.PowerApps',
    '/providers/Microsoft.Management/serviceGroups',
    '/providers/Microsoft.BillingBenefits/savingsPlanOrders',
])
def test_provider_root_is_a_valid_builtin_role_assignable_scope(scope):
    assert _assignable_scope(scope) == scope
    with pytest.raises(ValueError):
        _scope(scope)


@pytest.mark.parametrize('scope', [
    '/providers/Microsoft.PowerApps/../subscriptions/other',
    '/providers/Microsoft.PowerApps?api-version=secret',
    '/providers/Other.Namespace',
])
def test_untrusted_assignable_scope_is_rejected(scope):
    with pytest.raises(ValueError):
        _assignable_scope(scope)
