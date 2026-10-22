"""A single remaining section must not serialize independent AI batches."""
import threading
import time


def test_single_section_uses_existing_two_review_slots(monkeypatch):
    from peaso.ai import pipeline
    barrier = threading.Barrier(2)
    monkeypatch.setattr(pipeline, 'review_concurrency', lambda: 2)
    monkeypatch.setattr(pipeline.isolation, 'remote', lambda: True)
    def invoke(stage, platform, entries, token, findings, reviews, end, limit):
        barrier.wait(timeout=2)
        return {'items': [{'finding_id': row['id'], 'verdict': 'FAIL',
                           'reason': ''} for row in findings]}
    monkeypatch.setattr(pipeline, 'invoke_before_deadline', invoke)
    findings = [{'id': f'finding-{i}', 'check_id': 'example', 'scope': 'scope',
                 'category': 'hardening', 'status': 'FAIL'} for i in range(80)]
    result, failed = pipeline.review_batches({'provider': 'aws'}, {}, [], None,
        findings, [], time.monotonic() + 5, stages=('hardening',))
    assert failed is False
    assert len(result['hardening']) == 80
    assert all(row['verdict'] == 'FAIL' for row in result['hardening'])
