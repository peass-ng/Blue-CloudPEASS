"""New native declarations cannot be admitted with absent or incomplete witnesses."""
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks import azure_automation_aci_metadata_review_20261020 as module


@pytest.mark.parametrize('fault', ['absent', 'invalid_json', 'empty', 'missing_unknown_index'])
def test_incomplete_native_fixture_admission_fails_before_changing_registry(monkeypatch, fault):
    target = Path(module.__file__).with_name('azure_automation_aci_metadata_review_20261020_fixtures.json')
    original = target.read_text()
    read_text = Path.read_text
    fixtures = json.loads(original)
    if fault == 'missing_unknown_index':
        del fixtures[module.AUTOMATION]['unknown_index']

    def damaged(path, *args, **kwargs):
        if path != target:
            return read_text(path, *args, **kwargs)
        if fault == 'absent':
            raise FileNotFoundError('fixture unavailable')
        if fault == 'invalid_json':
            return '{'
        return '{}' if fault == 'empty' else json.dumps(fixtures)

    before = tuple(CHECKS)
    monkeypatch.setattr(Path, 'read_text', damaged)
    with pytest.raises((FileNotFoundError, json.JSONDecodeError, RuntimeError)):
        module.install()
    assert tuple(CHECKS) == before


def test_narrow_native_replacements_do_not_inherit_stronger_numbered_requirements():
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / 'docs/compliance-ledgers/native-extensions/azure-automation-aci-20261020.json').read_text())['checks']
    assert {r['spec']['id'] for r in rows} == {module.AUTOMATION, module.ACI}
    assert all(r['requirements'] == [] for r in rows)
    archived = json.loads((root / 'peaso/checks/native_only.json').read_text())['checks']
    assert archived['azure.gap.automation_account_encrypted_with_cmk']['native_alternative'] == module.AUTOMATION
    assert archived['azure_pci_10_2_1_1_16']['native_alternative'] == module.ACI
