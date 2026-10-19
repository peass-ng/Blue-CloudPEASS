"""Legacy predicate fixtures cannot re-admit owner-input checks to the product."""
from copy import deepcopy
import pytest
from peaso import engine
from peaso.checks import CHECKS
from peaso.checks.native_only import automated_checks,exclusions
from peaso.snapshot import make_snapshot
from tests.gcp_archived_native_contract import ARCHIVED_GCP_IDS,archived_check,evaluate_historical_snapshot


@pytest.mark.parametrize('check_id',sorted(ARCHIVED_GCP_IDS))
def test_real_engine_and_collection_plan_reject_archived_owner_controls(check_id):
    assert check_id in {check.id for check in CHECKS}
    assert check_id not in {check.id for check in automated_checks(CHECKS)}
    connector={'provider':'gcp','scopes':['projects/fixture-project'],
               'auth':{'method':'token','token':'inert-test-token'},'options':{}}
    with pytest.raises(ValueError,match='external policy or manual evidence'):
        engine.plan_collection({'connector':connector,'checks':[check_id]})
    snapshot=make_snapshot('gcp',connector['scopes'],[])
    with pytest.raises(ValueError,match='external policy or manual evidence'):
        engine.evaluate_snapshot(snapshot,checks=[check_id])


def test_historical_helper_never_changes_registry_or_exclusions():
    before=deepcopy(exclusions());registry=tuple(CHECKS)
    snapshot=make_snapshot('gcp',['projects/fixture-project'],[])
    assert evaluate_historical_snapshot(snapshot,checks=['gcp_c5_sbom'])=={'findings':[]}
    assert exclusions()==before and tuple(CHECKS)==registry
    with pytest.raises(ValueError,match='three explicit historical'):
        archived_check('gcp.storage.uniform_access')


@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_hosted_selector_availability_matches_automated_native_manifest(provider):
    from peaso.server.validation import _selector_index
    from peaso.checks import CHECK_ALIASES
    from peaso.checks.catalog import manual_requirement_ids
    admitted=_selector_index(provider)[1]
    active={c.id for c in automated_checks(CHECKS) if c.provider in (provider,'all')}
    assert active <= admitted
    assert not set(exclusions()).intersection(admitted)
    assert not manual_requirement_ids(provider).intersection(admitted)
    for alias,survivor in CHECK_ALIASES.items():
        if survivor in active:assert alias in admitted
        elif survivor in exclusions():assert alias not in admitted
