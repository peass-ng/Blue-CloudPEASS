"""Read-only SQL LTR metadata, using the location-scoped native ARM identity.

Contract: Microsoft.Sql LongTermRetentionBackups_ListByDatabase, 2023-08-01.
https://learn.microsoft.com/en-us/rest/api/sql/long-term-retention-backups/list-by-database?view=rest-sql-2023-08-01
"""
import re
from urllib.parse import quote

NATIVE_TYPE = 'Microsoft.Sql/locations/longTermRetentionServers/longTermRetentionDatabases/longTermRetentionBackups'
VERSION = '2023-08-01'
OPERATION = 'LongTermRetentionBackups_ListByDatabase'


def binding(database):
    rid = database.get('id') if isinstance(database, dict) else None
    location = database.get('location') if isinstance(database, dict) else None
    match = re.fullmatch(r'(/subscriptions/[^/?#%]+)/resourceGroups/[^/?#%]+/providers/Microsoft.Sql/servers/([^/?#%]+)/databases/([^/?#%]+)',
                         rid, re.I) if isinstance(rid, str) else None
    if (match is None or any(p in ('.', '..') for p in rid.split('/'))
            or any(ord(c) < 32 for c in rid)
            or not isinstance(location, str) or not re.fullmatch(r'[a-zA-Z0-9]{1,64}', location)):
        raise ValueError('SQL LTR database identity or location unavailable')
    scope, server, name = match.groups()
    path = (scope + '/providers/Microsoft.Sql/locations/' + location
            + '/longTermRetentionServers/' + quote(server, safe='')
            + '/longTermRetentionDatabases/' + quote(name, safe='')
            + '/longTermRetentionBackups')
    return path, server, name


def project(rows, database):
    path, server, name = binding(database)
    seen, output = set(), []
    for row in rows:
        rid = row.get('id') if isinstance(row, dict) else None
        props = row.get('properties') if isinstance(row, dict) else None
        if (not isinstance(rid, str)
                or not re.fullmatch(re.escape(path) + r'/[^/?#%]+', rid, re.I)
                or any(p in ('.', '..') for p in rid.split('/'))
                or any(ord(c) < 32 for c in rid)
                or rid.casefold() in seen
                or str(row.get('type', '')).casefold() != NATIVE_TYPE.casefold()
                or not isinstance(props, dict)
                or not isinstance(props.get('serverName'), str)
                or props['serverName'].casefold() != server.casefold()
                or not isinstance(props.get('databaseName'), str)
                or props['databaseName'].casefold() != name.casefold()
                or props.get('databaseDeletionTime') is not None):
            raise ValueError('foreign, deleted or malformed SQL LTR backup')
        seen.add(rid.casefold())
        output.append({'id': rid, 'type': NATIVE_TYPE, 'parent_id': database['id'],
                       'properties': {key: value for key, value in props.items() if key in (
                           'serverName', 'databaseName', 'serverCreateTime', 'backupTime',
                           'backupExpirationTime', 'backupStorageRedundancy',
                           'requestedBackupStorageRedundancy', 'backupStorageAccessTier', 'isBackupImmutable')},
                       '_provenance': {'source_operation': OPERATION, 'api_version': VERSION,
                                       'read_only': True, 'request_path': path, 'database_state': 'Live'}})
    return output
