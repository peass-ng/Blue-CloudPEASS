"""Read metadata, never content, for exact Dataproc initialization actions."""

from __future__ import annotations

from urllib.parse import quote


def references(cluster):
    actions = ((cluster.get('config') or {}).get('initializationActions') or [])
    if not isinstance(actions, list) or len(actions) > 32:
        return None
    out = {}
    for action in actions:
        uri = action.get('executableFile') if isinstance(action, dict) else None
        if not isinstance(uri, str) or not uri.startswith('gs://'):
            continue
        bucket, sep, name = uri[5:].partition('/')
        if (not sep or not bucket or not name or name.endswith('/') or
                '?' in name or '#' in name or '//' in name):
            continue
        out[uri] = (bucket, name)
    return out


def metadata(row, bucket, name):
    if (not isinstance(row, dict) or row.get('bucket') != bucket or
            row.get('name') != name or not isinstance(row.get('generation'), str) or
            not row['generation'].isdigit() or row.get('timeDeleted')):
        raise ValueError('dataproc_init_object_metadata')
    retention = row.get('retention')
    if retention is not None and not isinstance(retention, dict):
        raise ValueError('dataproc_init_object_retention')
    for key in ('temporaryHold', 'eventBasedHold'):
        if key in row and type(row[key]) is not bool:
            raise ValueError('dataproc_init_object_hold')
    return {'generation': row['generation'],
            'temporaryHold': row.get('temporaryHold') is True,
            'eventBasedHold': row.get('eventBasedHold') is True,
            'retentionExpirationTime': row.get('retentionExpirationTime'),
            'retainUntilTime': (retention or {}).get('retainUntilTime')}


def collect(collector, cluster, scope):
    from .gcp import ReadError

    refs = references(cluster)
    if refs is None:
        return {'status': 'unavailable', 'objects': {}}
    out = {}
    for uri, (bucket, name) in refs.items():
        url = ('https://storage.googleapis.com/storage/v1/b/' + quote(bucket, safe='')
               + '/o/' + quote(name, safe=''))
        try:
            row, _ = collector.read(url, scope)
            out[uri] = {'status': 'collected', 'metadata': metadata(row, bucket, name)}
        except ReadError as exc:
            reason = (exc.error or {}).get('reason') if isinstance(exc.error, dict) else None
            out[uri] = {'status': 'not_found' if reason == 'NOT_FOUND' else 'unavailable'}
        except ValueError:
            out[uri] = {'status': 'unavailable'}
    return {'status': 'collected', 'objects': out}
