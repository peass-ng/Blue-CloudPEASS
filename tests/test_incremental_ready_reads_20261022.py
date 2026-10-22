from concurrent.futures import Future
from peaso.collection_events import completed_reads


def test_completed_inventory_does_not_wait_for_prior_image_read():
    image, iam = Future(), Future()
    rows = [('image', image), ('iam', iam)]
    iam.set_result({'items': ['role']})
    reads = completed_reads(rows)
    assert next(reads) == rows[1]
    assert not image.done()
    image.set_result({'items': []})
    assert list(reads) == [rows[0]]


def test_explicit_global_resource_cap_retains_original_reduction_order():
    image, iam = Future(), Future()
    iam.set_result({'items': ['role']})
    rows = [('image', image), ('iam', iam)]
    assert list(completed_reads(rows, preserve_order=True)) == rows
