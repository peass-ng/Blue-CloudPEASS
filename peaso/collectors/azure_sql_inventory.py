"""Subscription projections of fully paged SQL children; original scopes preserved."""
from collections import Counter
import re


def authorized_database_scopes(snapshot, scope):
    """Join parent-scoped SQL reads only through the exact complete projection.

    Keep original collection scopes and identities. Merely sharing a subscription
    prefix cannot authorize a child join: the whole server roster, every native
    database page and the subscription projection must agree.
    """
    collections = snapshot['collections']
    parents = [c for c in collections if c['type'] == 'sql_server' and c['scope'].casefold() == scope.casefold()]
    projections = [c for c in collections if c['type'] == 'sql_database_inventory' and c['scope'].casefold() == scope.casefold()]
    native = [c for c in collections if c['type'] == 'sql_database' and c['scope'].casefold().startswith(scope.casefold() + '/')]
    if len(parents) != 1 or len(projections) != 1:
        return set()
    projection = projections[0]
    if (any(c['status'] not in ('collected', 'empty') for c in parents + native + projections)
            or projection.get('source_inventory') != 'sql_database'
            or projection.get('parent_inventory') != 'sql_server'):
        return set()
    expected = [row.get('id') for row in parents[0]['items']]
    pattern = re.escape(scope) + r'/resourceGroups/[^/?#]+/providers/Microsoft.Sql/servers/[^/?#]+'
    if any(not isinstance(rid, str) or not re.fullmatch(pattern, rid, re.I) for rid in expected):
        return set()
    expected = [rid.casefold() for rid in expected]
    if len(expected) != len(set(expected)) or Counter(c['scope'].casefold() for c in native) != Counter(expected):
        return set()
    rows = [row for c in native for row in c['items']]
    identifiers = [row.get('id') for row in rows]
    if (rows != projection['items'] or any(not isinstance(rid, str) for rid in identifiers)
            or len(identifiers) != len(set(rid.casefold() for rid in identifiers))):
        return set()
    for collection in native:
        prefix = collection['scope'].casefold() + '/databases/'
        if any(not re.fullmatch(re.escape(collection['scope']) + r'/databases/[^/?#]+', row['id'], re.I) for row in collection['items']):
            return set()
    return {c['scope'] for c in native}


def project(reader,scopes,wanted):
    for scope in scopes:
        for destination,source,parent in [('sql_database_inventory','sql_database','sql_server'),('sql_tde_inventory','sql_tde','sql_database_inventory')]:
            if destination not in wanted:continue
            parents=[c for c in reader.collections if c['type']==parent and c['scope'].casefold()==scope.casefold()]
            native=[c for c in reader.collections if c['type']==source and (c['scope'].casefold()==scope.casefold()or c['scope'].casefold().startswith(scope.casefold()+'/'))]
            complete=bool(parents) and all(c['status']in ('collected','empty')for c in parents)
            expected=[]
            for collection in parents:
                for item in collection['items']:
                    rid=item.get('id')
                    if not isinstance(rid,str)or not rid.casefold().startswith(scope.casefold()+'/'):complete=False;continue
                    if source=='sql_tde'and rid.rsplit('/',1)[-1].casefold()=='master':continue
                    expected.append(rid.casefold())
            if len(expected)!=len(set(expected)):complete=False
            child_scopes=[c['scope'].casefold()for c in native if c['scope'].casefold()!=scope.casefold()]
            if Counter(child_scopes)!=Counter(expected):complete=False
            if any(c['status']not in ('collected','empty')for c in native):complete=False
            if any(c['scope'].casefold()==scope.casefold()and c['items']for c in native):complete=False
            items=[item for c in native for item in c['items']]
            ids=[item.get('id')for item in items]
            if any(not isinstance(rid,str)or not rid.casefold().startswith(scope.casefold()+'/')for rid in ids)or len(ids)!=len(set(ids)):complete=False
            status=('collected'if items else 'empty')if complete else ('partial'if items else 'not_collected')
            reader.collections.append({'type':destination,'scope':scope,'service':'Microsoft.Sql','status':status,'items':items,
                                       'source_inventory':source,'parent_inventory':parent,
                                       **({}if complete else {'error':{'code':'sql_child_inventory_incomplete'}})})
