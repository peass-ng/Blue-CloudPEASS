"""Pure portable union consumer for ordinary collected and replayed snapshots."""
from copy import deepcopy
from . import aws_workload_command_source_20261020 as predecessor
from peaso.collectors import aws_workload_command_runtime_20261020 as runtime

DECLARATION = dict(predecessor.DECLARATION, control='security_configuration',
    ui_group='Secrets', requirements=[], dependencies=[runtime.KIND])


def evaluate(item, index):
    try:
        context = index['context']
        stored = context['metadata'][runtime.CAPTURE]
        scope = context['scope']
        envelope, = [c for c in index['collections'][runtime.KIND] if c['scope'] == scope]
        capture = deepcopy(stored['native'])
        selected_scopes = {row['scope'] for row in capture['selection'].values()}
        if (context['provider'] != 'aws' or stored['scope'] != scope
                or not selected_scopes <= set(stored['scopes']) or scope not in selected_scopes
                or envelope['service'] != 'workload' or envelope['status'] not in ('collected', 'partial')
                or sum(row == item for row in envelope['items']) != 1
                or set(item) != {'id', runtime.MARKER}):
            raise ValueError()
        if envelope['status'] != 'collected':
            capture['complete'] = False
        status, evidence = predecessor.evaluate_collection(capture)
        leaks = evidence.get('secret_leaks', [])
        ids = ['leak:' + leak['fingerprint'] for leak in leaks] if leaks else ['summary']
        expected = [{'id': runtime.KIND + ':' + ident, runtime.MARKER: ident} for ident in ids]
        if envelope['items'] != expected or item not in expected:
            raise ValueError()
        if status == 'FAIL':
            evidence['secret_leaks'] = [leak for leak in leaks if 'leak:' + leak['fingerprint'] == item[runtime.MARKER]]
            if len(evidence['secret_leaks']) != 1:
                raise ValueError()
        return status, evidence
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return 'UNKNOWN', {'observed': 'Selected ECS/classic Batch command evidence was unavailable, incomplete or unbound; images, environment files and EKS Batch are outside this check.'}
