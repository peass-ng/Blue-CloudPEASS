"""Only the exact old registration assertion can use current admission proof."""
from dataclasses import replace
import importlib

import pytest

pytest_plugins = ('tests.aws_codebuild_historical_admission_compatibility_20261020',)


def original():
    return importlib.import_module('tests.test_aws_codebuild_buildspec_source_20261020').test_receipt_and_unregistered_declaration


def test_original_still_fails_but_current_successor_is_verified():
    bridge = importlib.import_module(pytest_plugins[0])
    with pytest.raises(AssertionError):
        original()()
    bridge.replay_and_verify(original())


def test_wrong_callable_cannot_be_intercepted():
    bridge = importlib.import_module(pytest_plugins[0])
    with pytest.raises(AssertionError):
        bridge.replay_and_verify(lambda: None)


def test_substituted_current_predicate_is_rejected_then_restored(monkeypatch):
    import peaso.checks as registry
    bridge = importlib.import_module(pytest_plugins[0])
    bridge.replay_and_verify(original())
    with monkeypatch.context() as patch:
        patch.setattr(registry, 'CHECKS', [replace(c, evaluate=lambda *_: ('PASS', {}))
            if c.id == 'aws.review.codebuild.selected_inline_buildspec_secret_indicators' else c for c in registry.CHECKS])
        with pytest.raises(AssertionError):
            bridge.replay_and_verify(original())
    bridge.replay_and_verify(original())
