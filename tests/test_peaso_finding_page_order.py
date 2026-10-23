"""Heap-selected API pages keep the full sort's ordering and tie rules."""
import random

import pytest

from peaso import finding_page_order as paging


def literal_page(rows, *, group_by='service', sort_by=None, sort_order='asc', offset=0, limit=500):
    if sort_by is None:
        rows.sort(key=lambda pair: (str(pair[1].get(group_by, '')), pair[1]['id']))
    else:
        severity = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'informational': 4}
        def value(item):
            if sort_by == 'severity':
                name = str(item.get('severity') or '').casefold()
                return severity.get(name, 5), name
            if sort_by == 'resource_id':
                name = item.get('resource_name') or item.get('native_resource_id') or item.get('resource_id') or ''
            else:
                name = item.get(sort_by) or ''
            return str(name).casefold()
        rows.sort(key=lambda pair: pair[1]['id'])
        rows.sort(key=lambda pair: value(pair[1]), reverse=sort_order == 'desc')
    return rows[offset:offset + limit]


@pytest.fixture(scope='module')
def rows():
    randomizer = random.Random(89893)
    result = []
    for i in range(5000):
        card = {'id': f'id-{randomizer.randrange(1000):05d}', 'service': f'service-{randomizer.randrange(8)}',
            'check_id': f'check-{randomizer.randrange(6)}', 'finding_type': randomizer.choice(['configuration', 'permissions', None]),
            'severity': randomizer.choice(['CRITICAL', 'high', 'medium', 'low', 'info', 'informational', None, 'other']),
            'title': randomizer.choice(['Alpha', 'alpha', 'Bravo', '雲', '😀', '', None]),
            'account': f'account-{randomizer.randrange(12)}',
            'status': randomizer.choice(['FAIL', 'PASS', 'UNKNOWN', 'MANUAL']), 'resource_id': f'resource-{i % 20}',
            'resource_name': randomizer.choice([None, '', 'Named resource', '雲']),
            'native_resource_id': randomizer.choice([None, '', f'native-{i % 17}'])}
        result.append(({'ordinal': i}, card))
    return result


@pytest.mark.parametrize('sort_by', [None, 'severity', 'title', 'service', 'account', 'status', 'resource_id'])
@pytest.mark.parametrize('sort_order', ['asc', 'desc'])
@pytest.mark.parametrize('offset', [0, 123, 4990])
def test_all_api_sort_modes_and_directions_match_full_sort(rows, sort_by, sort_order, offset):
    options = dict(sort_by=sort_by, sort_order=sort_order, offset=offset, limit=27)
    actual = paging.finding_page(list(rows), **options)
    expected = literal_page(list(rows), **options)
    assert actual == expected
    assert all(actual[i] is expected[i] for i in range(len(actual)))


@pytest.mark.parametrize('group_by', ['service', 'check_id', 'resource_id', 'finding_type'])
def test_default_group_order_matches_full_sort(rows, group_by):
    assert paging.finding_page(list(rows), group_by=group_by, limit=50) == literal_page(
        list(rows), group_by=group_by, limit=50)


@pytest.mark.parametrize('sort_by', [None, 'severity', 'title'])
@pytest.mark.parametrize('sort_order', ['asc', 'desc'])
def test_duplicate_ids_and_equal_keys_keep_original_position_ties(monkeypatch, sort_by, sort_order):
    monkeypatch.setattr(paging, '_ordered_sample', lambda *args, **kwargs: False)
    rows = [({'ordinal': i}, {'id': 'same', 'service': 'same', 'severity': 'high', 'title': 'same'}) for i in range(5000)]
    options = dict(sort_by=sort_by, sort_order=sort_order, offset=27, limit=50)
    assert paging.finding_page(list(rows), **options) == literal_page(list(rows), **options)
    assert [row[0]['ordinal'] for row in paging.finding_page(list(rows), **options)] == list(range(27, 77))


def outcome(function):
    try:
        return function()
    except Exception as error:
        return type(error), str(error)


@pytest.mark.parametrize('identifier', [None, 1, ['id'], {'id': True}])
@pytest.mark.parametrize('sort_by', [None, 'severity'])
def test_unusual_archived_ids_keep_original_sort_or_error(rows, identifier, sort_by):
    values = list(rows)
    values[0] = (values[0][0], dict(values[0][1], id=identifier))
    assert outcome(lambda: paging.finding_page(list(values), sort_by=sort_by, limit=20)) == outcome(
        lambda: literal_page(list(values), sort_by=sort_by, limit=20))


def test_missing_archived_id_keeps_original_error(rows):
    values = list(rows)
    card = dict(values[0][1])
    del card['id']
    values[0] = (values[0][0], card)
    assert outcome(lambda: paging.finding_page(list(values), limit=20)) == outcome(
        lambda: literal_page(list(values), limit=20))


def test_small_and_deep_pages_keep_full_sort_path(monkeypatch, rows):
    def forbidden(*args, **kwargs):
        pytest.fail('heap selection for a broad page')
    monkeypatch.setattr(paging, 'nsmallest', forbidden)
    for values, offset, limit in [(rows[:30], 0, 10), (rows, 1000, 50), (rows, 4999, 100), (rows, 9000, 20), ([], 0, 20)]:
        assert paging.finding_page(list(values), offset=offset, limit=limit) == literal_page(
            list(values), offset=offset, limit=limit)


def test_heap_path_leaves_full_input_order_unchanged(rows):
    values = list(rows)
    paging.finding_page(values, sort_by='title', sort_order='desc', limit=20)
    assert values == rows


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('sort_by', [None, 'title'])
def test_ordered_inputs_keep_linear_timsort_path(monkeypatch, reverse, sort_by):
    rows = [({'ordinal': i}, {'id': f'{i:08d}', 'service': 'same', 'title': 'same'}) for i in range(5000)]
    if reverse:
        rows.reverse()
    def forbidden(*args, **kwargs):
        pytest.fail('heap selection on ordered input')
    monkeypatch.setattr(paging, 'nsmallest', forbidden)
    assert paging.finding_page(list(rows), sort_by=sort_by, limit=20) == literal_page(list(rows), sort_by=sort_by, limit=20)
