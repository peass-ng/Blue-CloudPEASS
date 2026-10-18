"""Boolean proof selectors must reject numeric telemetry in the linear matcher."""

from peaso.attack_detection.rules import Rule, detect_azure_events


def test_linear_boolean_and_numeric_scalar_list_contract():
    base = {"event.id": "test", "event.time": "2026-10-18T00:00:00Z",
            "account.id": "scope", "actor.id": "actor", "target.id": "target"}

    def matches(selection, value):
        rule = Rule(id="test", title="Test", level="low", description="Test",
                    technique_id="test", product="azure", selection={"proof": selection})
        return detect_azure_events([{**base, "proof": value}], [rule])

    assert not matches(True, 1)
    assert not matches(False, 0)
    assert matches(True, True)
    assert matches(False, False)
    assert not matches([True, "safe"], 1)
    assert matches([True, "safe"], "safe")
    assert matches(1, 1.0)
