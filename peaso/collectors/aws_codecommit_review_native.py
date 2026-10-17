"""Read-only PR review evidence; timestamps derive from exact native merge events."""
import copy
import re
from datetime import datetime, timezone

SPECS = {'codecommit_pull_request': ('codecommit', 'list_repositories', 'repositories')}
NATIVE_IDS = {'codecommit_pull_request': 'pullRequestId'}
READ_ACTIONS = {('codecommit', op) for op in ('list_repositories', 'list_pull_requests',
    'get_pull_request', 'describe_pull_request_events', 'get_pull_request_approval_states')}
_MERGE = {'isMerged', 'mergedBy', 'mergeCommitId', 'mergeOption'}
_FIELDS = {
 'repositories': {'repositoryName', 'repositoryId'},
 'pullRequest': {'pullRequestId', 'pullRequestStatus', 'authorArn', 'revisionId', 'pullRequestTargets'},
 'pullRequestTargets': {'repositoryName', 'destinationReference', 'mergeMetadata'},
 'mergeMetadata': _MERGE,
 'pullRequestEvents': {'pullRequestId', 'eventDate', 'pullRequestEventType', 'actorArn',
     'pullRequestMergedStateChangedEventMetadata', 'approvalStateChangedEventMetadata'},
 'pullRequestMergedStateChangedEventMetadata': {'repositoryName', 'destinationReference', 'mergeMetadata'},
 'approvalStateChangedEventMetadata': {'revisionId', 'approvalStatus'},
 'approvals': {'userArn', 'approvalState'},
}


def project_response(response, operation):
    """Drop descriptions, source references and approval-rule contents before cache."""
    from .aws import ReadFailure
    roots = {'list_repositories': 'repositories', 'list_pull_requests': 'pullRequestIds',
        'get_pull_request': 'pullRequest', 'describe_pull_request_events': 'pullRequestEvents',
        'get_pull_request_approval_states': 'approvals'}
    def project(value, key):
        if isinstance(value, list):
            return [project(row, key) for row in value]
        if key in _FIELDS:
            if not isinstance(value, dict):
                raise ReadFailure('malformed', 'codecommit_response_shape')
            return {k: project(v, k) for k, v in value.items() if k in _FIELDS[key]}
        if not isinstance(value, (str, bool, datetime)) or (isinstance(value, str) and len(value) > 8192):
            raise ReadFailure('malformed', 'codecommit_leaf_shape')
        return copy.deepcopy(value)
    root = roots[operation]
    if not isinstance(response, dict) or root not in response:
        raise ReadFailure('malformed', 'codecommit_response_shape')
    output = {root: project(response[root], root)}
    if 'nextToken' in response:
        token = response['nextToken']
        if not isinstance(token, str) or len(token) > 4096 or any(ord(c) < 32 for c in token):
            raise ReadFailure('malformed', 'codecommit_cursor_invalid')
        output['nextToken'] = token
    return output


def review_policy(options, scopes=None, *, strict=False):
    """Only operator-selected identities, never cloud observations or approval states."""
    policy = options.get('compliance_policy', {})
    fields = {'status', 'scope', 'security_reviewer_arns'}
    if not isinstance(policy, dict):
        raise ValueError('invalid CodeCommit review policy')
    if 'security_reviewer_arns' not in policy and not (strict and fields.intersection(policy)):
        return
    if set(policy) - fields - {'aws_backup_plan', 'aws_organizations', 'sw38_policy'}:
        raise ValueError('CodeCommit policy cannot supply observations')
    if not fields <= set(policy) or policy['status'] != 'collected':
        raise ValueError('incomplete CodeCommit review policy')
    scope = policy['scope']
    match = re.fullmatch(r'([0-9]{12})/([a-z][a-z0-9-]{1,62})', scope) if isinstance(scope, str) else None
    readers = policy['security_reviewer_arns']
    if (match is None or not isinstance(readers, list) or not 0 < len(readers) <= 256
            or any(not isinstance(r, str) for r in readers) or len(set(readers)) != len(readers)):
        raise ValueError('invalid CodeCommit review scope or reviewers')
    partition = 'aws-cn' if match[2].startswith('cn-') else 'aws-us-gov' if match[2].startswith('us-gov-') else 'aws'
    for reader in readers:
        if not re.fullmatch(r'arn:' + partition + r':(iam|sts)::' + match[1]
                           + r':(?:user|role|assumed-role)/[A-Za-z0-9_+=,.@/-]{1,1024}', reader):
            raise ValueError('foreign CodeCommit reviewer')
    if scopes is not None and list(scopes) != [scope]:
        raise ValueError('CodeCommit policy requires its exact selected scope')


def _stamp(value):
    if isinstance(value, datetime):
        stamp = value
    elif isinstance(value, str):
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    else:
        raise ValueError('missing CodeCommit timestamp')
    if stamp.tzinfo is None:
        raise ValueError('naive CodeCommit timestamp')
    return stamp.astimezone(timezone.utc).isoformat()


def pull_requests(requests, session, region, account):
    from .aws import ReadFailure, ReadResult
    def pages(operation, expression, **params):
        read = requests.pages(session, 'codecommit', region, operation, expression,
                              _tokens=('nextToken', 'nextToken'), **params)
        if read.status not in ('collected', 'empty'):
            raise ReadFailure(read.status, (read.error or {}).get('code', 'codecommit_read_incomplete'))
        return read.items
    def detail(operation, key, **params):
        value = requests.detail(session, 'codecommit', region, operation, **params)
        if value.get('collection_status') != 'collected':
            raise ReadFailure(value.get('collection_status', 'unknown'),
                              (value.get('error') or {}).get('code', 'codecommit_detail_unavailable'))
        return value[key]
    def principal(value):
        partition = session.get_partition_for_region(region)
        if not isinstance(value, str) or not re.fullmatch(r'arn:' + re.escape(partition)
                + r':(?:iam|sts)::' + account + r':(?:user|role|assumed-role)/[A-Za-z0-9_+=,.@/-]{1,1024}', value):
            raise ValueError('foreign CodeCommit principal')
        return value
    try:
        repos = pages('list_repositories', 'repositories')
        names, repo_ids = set(), set()
        for repo in repos:
            name, rid = repo.get('repositoryName'), repo.get('repositoryId')
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', name)
                    or not isinstance(rid, str) or not rid or name in names or rid in repo_ids):
                raise ValueError('ambiguous CodeCommit repository')
            names.add(name); repo_ids.add(rid)
        inventory = {}
        for name in sorted(names):
            for status in ('OPEN', 'CLOSED'):
                ids = pages('list_pull_requests', 'pullRequestIds', repositoryName=name, pullRequestStatus=status)
                if len(ids) != len(set(ids)):
                    raise ValueError('duplicate CodeCommit PR inventory')
                for pid in ids:
                    if not isinstance(pid, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', pid) or pid in inventory:
                        raise ValueError('ambiguous CodeCommit PR inventory')
                    inventory[pid] = (name, status)
        output = []
        for pid, (repo, status) in sorted(inventory.items()):
            raw = detail('get_pull_request', 'pullRequest', pullRequestId=pid)
            if raw.get('pullRequestId') != pid or raw.get('pullRequestStatus') != status:
                raise ValueError('CodeCommit PR identity changed')
            author = principal(raw.get('authorArn'))
            revision = raw.get('revisionId')
            targets = raw.get('pullRequestTargets')
            if not isinstance(revision, str) or not revision or not isinstance(targets, list) or len(targets) != 1:
                raise ValueError('CodeCommit PR revision or target unavailable')
            target = targets[0]
            merge = target.get('mergeMetadata', {})
            if target.get('repositoryName') != repo or type(merge.get('isMerged')) is not bool:
                raise ValueError('CodeCommit target identity unavailable')
            normalized = {'repositoryName': repo, 'mergeMetadata': {'IsMerged': merge['isMerged']}}
            row = {'pullRequestId': pid, 'pullRequestStatus': status, 'authorArn': author,
                   'pullRequestTargets': [normalized], 'ApprovalStates': [], 'ApprovalEvents': []}
            if merge['isMerged']:
                if status != 'CLOSED':
                    raise ValueError('CodeCommit merged PR still open')
                commit, branch = merge.get('mergeCommitId'), target.get('destinationReference')
                if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit) or not isinstance(branch, str) or not branch.startswith('refs/heads/'):
                    raise ValueError('CodeCommit merge identity unavailable')
                events = pages('describe_pull_request_events', 'pullRequestEvents', pullRequestId=pid)
                matches = []
                for event in events:
                    if event.get('pullRequestId') != pid:
                        raise ValueError('foreign CodeCommit event')
                    kind = event.get('pullRequestEventType')
                    if kind == 'PULL_REQUEST_MERGE_STATE_CHANGED':
                        em = event.get('pullRequestMergedStateChangedEventMetadata', {})
                        mm = em.get('mergeMetadata', {})
                        joined = (em.get('repositoryName') == repo
                                  and em.get('destinationReference') == branch
                                  and mm.get('isMerged') is True)
                        if 'mergeCommitId' in mm:
                            joined = joined and mm['mergeCommitId'] == commit
                        else:
                            # AWS can omit this optional event field. A closed PR
                            # cannot reopen: its unique, identical native merge
                            # actor/option/target anchors this event to that PR.
                            actor = principal(merge.get('mergedBy'))
                            option = merge.get('mergeOption')
                            joined = (joined and principal(event.get('actorArn')) == actor
                                      and principal(mm.get('mergedBy')) == actor
                                      and option in ('FAST_FORWARD_MERGE', 'SQUASH_MERGE', 'THREE_WAY_MERGE')
                                      and mm.get('mergeOption') == option)
                        if (em.get('repositoryName') == repo and em.get('destinationReference') == branch
                                and mm.get('isMerged') is True and not joined):
                            raise ValueError('contradictory CodeCommit merge event')
                        if joined:
                            matches.append(_stamp(event.get('eventDate')))
                    elif kind == 'PULL_REQUEST_APPROVAL_STATE_CHANGED':
                        state = event.get('approvalStateChangedEventMetadata', {})
                        if not isinstance(state.get('revisionId'), str):
                            raise ValueError('approval revision unavailable')
                        if state['revisionId'] == revision:
                            decision = state.get('approvalStatus')
                            if decision not in ('APPROVE', 'REVOKE'):
                                raise ValueError('approval status unavailable')
                            row['ApprovalEvents'].append({'UserArn': principal(event.get('actorArn')),
                                'ApprovalState': decision, 'eventDate': _stamp(event.get('eventDate'))})
                if len(matches) != 1:
                    raise ValueError('CodeCommit merge event unavailable or ambiguous')
                normalized['mergeMetadata']['MergedAt'] = matches[0]
                states = detail('get_pull_request_approval_states', 'approvals', pullRequestId=pid, revisionId=revision)
                seen = set()
                for state in states:
                    actor, decision = principal(state.get('userArn')), state.get('approvalState')
                    if actor in seen or decision not in ('APPROVE', 'REVOKE'):
                        raise ValueError('ambiguous CodeCommit approval state')
                    seen.add(actor)
                    row['ApprovalStates'].append({'UserArn': actor, 'ApprovalState': decision})
                row['_provenance'] = {'merge_time_source': 'DescribePullRequestEvents.eventDate',
                    'approval_revision': revision, 'merge_commit': commit, 'read_only': True}
            output.append(row)
        return ReadResult(output, 'collected' if output else 'empty')
    except ReadFailure as exc:
        return ReadResult([], exc.status, {'code': exc.code})
    except (ValueError, TypeError, KeyError, AttributeError):
        return ReadResult([], 'malformed', {'code': 'codecommit_native_join_invalid'})


FETCHERS = {'codecommit_pull_request': pull_requests}
