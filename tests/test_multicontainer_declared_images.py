"""New complete-declaration cases alongside unchanged predecessor test bodies."""
from copy import deepcopy

import pytest

from gcp_cloudrun_portable_fixtures import planner, fixture, IMAGE, REPO


def multi():
    data = fixture()
    second = {'uri': 'https://' + IMAGE + '-sidecar@sha256:' + 'b' * 64,
              'digest': 'sha256:' + 'b' * 64, 'repository': REPO,
              'name': REPO + '/dockerImages/nested%2Fapi-sidecar%40sha256%3A' + 'b' * 64}
    data['image_rows'].append(second)
    for revision in data['revision_reads'].values():
        revision['spec']['containers'] = [
            {'image': data['image_rows'][0]['uri'].removeprefix('https://')},
            {'image': second['uri'].removeprefix('https://')}]
    return data


def test_all_container_declarations_are_included_and_images_scanned_once():
    data = multi()
    original = deepcopy(data)
    result = planner.plan_sources(**data)
    assert len(result['deployment_paths']) == 6
    assert len(result['selected_artifact_images']) == 2
    assert {path['container_index'] for path in result['deployment_paths']} == {0, 1}
    assert all(path['association_kind'] == 'immutable_container_declaration'
               and path['runtime_image_proven'] is False for path in result['deployment_paths'])
    assert result['complete'] is False and result['content_status'] == 'not_inspected'
    assert result['container_limit'] == 'all_containers_immutable_declarations'
    assert data == original


def test_same_image_in_multiple_containers_is_one_selected_image():
    data = multi()
    for revision in data['revision_reads'].values():
        revision['spec']['containers'][1] = dict(revision['spec']['containers'][0])
    result = planner.plan_sources(**data)
    assert len(result['selected_artifact_images']) == 1
    assert len(result['deployment_paths']) == 6


@pytest.mark.parametrize('value', [IMAGE + ':latest', None, '',
    IMAGE.replace('/review/', '/foreign/') + '@sha256:' + 'b' * 64,
    'https://' + IMAGE + '@sha256:' + 'b' * 64])
def test_any_unresolved_or_foreign_sidecar_rejects_whole_plan(value):
    data = multi()
    next(iter(data['revision_reads'].values()))['spec']['containers'][1]['image'] = value
    with pytest.raises(ValueError):
        planner.plan_sources(**data)


def test_inconsistent_resolved_status_is_not_ignored():
    data = multi()
    next(iter(data['revision_reads'].values()))['status']['imageDigest'] = 'https://' + IMAGE + '@sha256:' + 'c' * 64
    with pytest.raises(ValueError, match='status_image_not_in_container_declarations'):
        planner.plan_sources(**data)


def test_missing_sidecar_inventory_is_not_a_complete_plan():
    data = multi()
    data['image_rows'].pop()
    with pytest.raises(ValueError, match='native_docker_image_missing_or_duplicate'):
        planner.plan_sources(**data)


def test_multicontainer_does_not_bypass_total_selected_image_bound():
    data = multi()
    revision = next(iter(data['revision_reads'].values()))
    for ordinal in range(3):
        digest = 'sha256:' + str(ordinal + 3) * 64
        image = IMAGE + '-extra' + str(ordinal)
        revision['spec']['containers'].append({'image': image + '@' + digest})
        data['image_rows'].append({'uri': 'https://' + image + '@' + digest, 'digest': digest,
            'repository': REPO, 'name': REPO + '/dockerImages/nested%2Fapi-extra' + str(ordinal) + '%40sha256%3A' + digest[7:]})
    with pytest.raises(ValueError, match='selected_image_reader_bound'):
        planner.plan_sources(**data)
