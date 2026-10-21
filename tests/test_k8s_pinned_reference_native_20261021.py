"""A delimiter alone cannot establish that an image reference is pinned."""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from peaso.checks.fixtures import CASES


def image_row(value):
    if isinstance(value, dict):
        if 'image' in value:
            return value
        for child in value.values():
            found = image_row(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = image_row(child)
            if found is not None:
                return found
    return None


@pytest.mark.parametrize('kind', ['podtemplate', 'replicaset', 'replicationcontroller', 'statefulset'])
@pytest.mark.parametrize('image,status', [
    ('registry.example/app@not-a-digest', 'UNKNOWN'),
    ('registry.example/app@sha256:abc', 'UNKNOWN'),
    ('registry.example/app@sha256:' + 'g' * 64, 'UNKNOWN'),
    ('registry.example/app@sha256:' + 'a' * 64, 'PASS'),
    ('registry.example/app:v2', 'PASS'),
    ('registry.example/app:latest', 'FAIL'),
])
def test_native_image_reference(kind, image, status):
    cid = f'k8s.ports.{kind}.pinned_image'
    # Use the registered native fixture for this workload shape.
    item = deepcopy(CASES[cid]['pass'])
    image_row(item)['image'] = image
    before = deepcopy(item)
    assert evaluate_check(cid, item, {})[0] == status
    assert item == before
