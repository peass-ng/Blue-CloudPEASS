"""Read-only KMS tag/alias applicability inventory, with pagination coverage.

ListAliases is account/region-wide and cached by the shared Requests boundary;
each key receives only aliases whose TargetKeyId matches its native KeyId.
The runtime coordinator must admit READ_ACTIONS before collection.
"""
READ_ACTIONS = {('kms', 'list_aliases'), ('kms', 'list_resource_tags')}


def _project(read, fields, operation):
    status = read.status
    rows = []
    for row in read.items:
        if not isinstance(row, dict) or any(not isinstance(row.get(key), str) for key in fields):
            return [], {'status': 'malformed', 'source_operation': operation, 'reason': 'malformed_inventory_row'}
        rows.append({key: row[key] for key in fields})
    coverage = {'status': status, 'source_operation': operation}
    if read.error:
        coverage['error'] = dict(read.error)
    return rows, coverage


def enrich_key_inventory(requests, session, region, item):
    key_id = item['KeyId']
    tags = requests.pages(session, 'kms', region, 'list_resource_tags', 'Tags', KeyId=key_id)
    item['Tags'], tag_coverage = _project(tags, ('TagKey', 'TagValue'), 'kms:ListResourceTags')
    aliases = requests.pages(session, 'kms', region, 'list_aliases', 'Aliases')
    # Unassigned aliases legitimately omit TargetKeyId; preserve their validity
    # without associating them with an arbitrary key.
    selected, malformed = [], False
    for alias in aliases.items:
        if not isinstance(alias, dict) or not isinstance(alias.get('AliasName'), str):
            malformed = True
            break
        if 'TargetKeyId' in alias and not isinstance(alias['TargetKeyId'], str):
            malformed = True
            break
        if alias.get('TargetKeyId') == key_id:
            selected.append({'AliasName': alias['AliasName'], 'TargetKeyId': key_id})
    item['Aliases'] = [] if malformed else selected
    alias_coverage = {'status': 'malformed' if malformed else aliases.status, 'source_operation': 'kms:ListAliases'}
    if aliases.error:
        alias_coverage['error'] = dict(aliases.error)
    item.setdefault('_coverage', {}).update(Tags=tag_coverage, Aliases=alias_coverage)
    return item
