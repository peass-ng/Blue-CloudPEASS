"""The indexed matcher must preserve rule selection and presentation order."""

import random

from peaso.attack_detection.rules import Rule, _detect_events


def _rule(name: str, selection: dict, *, product: str = "aws") -> Rule:
    return Rule(
        id=name, title=name, level="medium", description=name,
        technique_id=name, product=product, selection=selection,
    )


def _event(source, name: str, event_id: str) -> dict:
    return {
        "cloud.provider": "aws", "event.source": source, "event.name": name,
        "event.outcome": "success", "event.id": event_id,
        "event.time": "2026-10-18T00:00:00Z", "account.id": "123456789012",
        "actor.id": "actor", "target.id": "target",
    }


def test_index_preserves_or_lists_wildcards_original_order_and_product() -> None:
    rules = [
        _rule("first", {"event.source": "iam.amazonaws.com", "event.name": ["Create", "Create"]}),
        _rule("wildcard", {"event.outcome": "success"}),
        _rule("second", {"event.source": ["sts.amazonaws.com", "iam.amazonaws.com"], "event.name": "Create"}),
        _rule("other", {"event.source": "ec2.amazonaws.com", "event.name": "Create"}),
        _rule("wrong-product", {"event.outcome": "success"}, product="gcp"),
    ]
    events = [
        _event("iam.amazonaws.com", "Create", "one"),
        _event("sts.amazonaws.com", "Create", "two"),
        _event({"malformed": "source"}, "Create", "three"),
    ]
    matches = _detect_events(events, rules, lambda event: event, "aws")
    assert [(match.event_id, match.rule_id) for match in matches] == [
        ("one", "first"), ("one", "wildcard"), ("one", "second"),
        ("two", "wildcard"), ("two", "second"), ("three", "wildcard"),
    ]


def test_index_agrees_with_linear_sigma_selection_for_mixed_rules() -> None:
    rng = random.Random(20261018)
    sources = ["iam.amazonaws.com", "sts.amazonaws.com", "ec2.amazonaws.com"]
    names = ["Create", "Update", "Delete"]
    rules = []
    for index in range(80):
        selection = {"event.outcome": "success"}
        for field, options in (("event.source", sources), ("event.name", names)):
            choice = rng.randrange(3)
            if choice == 1:
                selection[field] = rng.choice(options)
            elif choice == 2:
                selection[field] = [rng.choice(options), rng.choice(options)]
        rules.append(_rule(str(index), selection, product="aws" if index % 7 else "gcp"))
    events = [_event(rng.choice(sources), rng.choice(names), str(index)) for index in range(60)]
    expected = [
        (event["event.id"], rule.id)
        for event in events for rule in rules
        if rule.product == "aws" and all(
            event.get(field) in value if isinstance(value, list) else event.get(field) == value
            for field, value in rule.selection.items()
        )
    ]
    actual = _detect_events(events, rules, lambda event: event, "aws")
    assert [(match.event_id, match.rule_id) for match in actual] == expected


def test_index_preserves_python_numeric_equality_for_external_rules() -> None:
    # Rule objects can also be supplied directly by a caller. Python equality
    # treats 1 and 1.0 as equal, so the index must not drop that candidate.
    matches = _detect_events(
        [_event(1.0, "Create", "numeric")],
        [_rule("numeric-source", {"event.source": 1, "event.name": "Create"})],
        lambda event: event, "aws",
    )
    assert [(match.event_id, match.rule_id) for match in matches] == [("numeric", "numeric-source")]
