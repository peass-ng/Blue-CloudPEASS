"""Portable pure adapter over the original inline buildspec consumer."""
from copy import deepcopy
from . import aws_codebuild_buildspec_source_20261020 as predecessor
from peaso.collectors import aws_codebuild_buildspec_runtime_20261020 as runtime

DECLARATION = dict(predecessor.DECLARATION, ui_group='Secrets', requirements=[],
    dependencies=['aws_account', runtime.KIND],
    remediation='Remove credential literals from the selected inline buildspec and rotate confirmed exposed credentials. Use supported secret references.')


def evaluate(item, index):
    try:
        context = index['context']
        scope = context['scope']
        envelope, = [c for c in index['collections'][runtime.KIND] if c.get('scope') == scope]
        rows = envelope['items']
        capture = deepcopy(context['metadata'][runtime.CAPTURES][scope])
        if (context['provider'] != 'aws' or envelope['service'] != 'codebuild'
                or envelope['account_id'] != scope.split('/')[0] or envelope['status'] not in ('collected', 'partial')
                or sum(row == item for row in rows) != 1 or len(rows) != len(capture['selection'])
                or len({row['id'] for row in rows}) != len(rows)):
            raise ValueError()
        for row in rows:
            native = row[runtime.MARKER]
            if (row['id'] != native['id'] or native['scope'] != scope or native['capture'] != capture['capture']
                    or row['_provenance'] != {'scope': scope, 'capture': capture['capture'], 'selection_locator': row['id']}):
                raise ValueError()
        parent, = [c for c in index['collections']['aws_account'] if c.get('scope') == scope.split('/')[0] + '/global']
        if parent['status'] != 'collected' or len(parent['items']) != 1 or parent['items'][0]['Account'] != scope.split('/')[0]:
            raise ValueError()
        capture['items'] = [deepcopy(row[runtime.MARKER]) for row in rows]
        if envelope['status'] != 'collected':
            capture['complete'] = False
        return predecessor.evaluate(item[runtime.MARKER], capture)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return 'UNKNOWN', {'observed': 'Selected inline CodeBuild source was unavailable, incomplete or unbound.'}
