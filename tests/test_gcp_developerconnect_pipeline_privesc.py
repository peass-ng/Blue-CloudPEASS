"""Developer Connect repository writes require an exact privileged build consumer."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = 'projects/p1'
SOURCE = 'user:alice@example.com'
SA = 'build@p1.iam.gserviceaccount.com'
LINK = PROJECT + '/locations/us-central1/connections/c/gitRepositoryLinks/r'
ENTRY = next(e for e in privesc.catalog()['entries']
             if e['id'] == 'gcp-developerconnect-readwrite-token-pipeline-poison')


def case(*, token=True, proxy=False, link=LINK, approved=False, filename=True,
         push=True, extra_right=True, disabled=False, trigger=True,
         token_on_other=False, source_has_extra=False, incomplete=False,
         git_file=False, remote_file=False, proxy_uri=False,
         linked=True, reconciling=False):
    bind = lambda role, member: {'role': role, 'members': [member]}
    source_perms = ((['developerconnect.gitRepositoryLinks.fetchReadWriteToken'] if token else []) +
                    (['developerconnect.gitRepositoryLinks.gitProxyRead',
                      'developerconnect.gitRepositoryLinks.gitProxyWrite'] if proxy else []) +
                    (['secretmanager.versions.access'] if source_has_extra else []))
    event = {'gitRepositoryLink': link}
    if push:
        event['push'] = {'branch': '.*'}
    else:
        event['pullRequest'] = {'branch': '.*'}
    row = {'resourceName': PROJECT + '/locations/us-central1/triggers/t',
           'developerConnectEventConfig': event,
           'serviceAccount': PROJECT + '/serviceAccounts/' + SA,
           'approvalConfig': {'approvalRequired': approved},
           'disabled': disabled}
    if filename:
        row['filename'] = 'cloudbuild.yaml'
    if git_file:
        row['gitFileSource'] = {'path': 'cloudbuild.yaml',
                                **({'uri': 'https://example.com/other.git'} if remote_file else {})}
    collections = [
        ('project', PROJECT, [{'projectId': 'p1', 'name': 'projects/123'}]),
        ('iam_policy', PROJECT, [{'name': PROJECT, 'bindings':
                                 ([bind(PROJECT + '/roles/source', SOURCE)] if source_perms and not token_on_other else []) +
                                 ([bind(PROJECT + '/roles/build', 'serviceAccount:' + SA)] if extra_right else [])}]),
        ('iam_role', PROJECT, [
            {'name': PROJECT + '/roles/source', 'includedPermissions': source_perms},
            {'name': PROJECT + '/roles/build', 'includedPermissions':
             ['secretmanager.versions.access'] if extra_right else []},
            {'name': PROJECT + '/roles/other', 'includedPermissions': source_perms},
        ]),
        ('service_account', PROJECT, [{'email': SA, 'projectId': 'p1',
                                      'iamPolicy': {'bindings': []}}]),
        ('iam_deny_policy', PROJECT, [], 'empty'),
        ('cloudbuild_trigger', PROJECT, [row] if trigger else [],
         'partial' if incomplete else 'collected' if trigger else 'empty'),
        ('developerconnect_git_repository_link', PROJECT,
         [{'name': LINK, 'reconciling': reconciling,
           **({'gitProxyUri': 'https://proxy.developerconnect.dev/r'} if proxy_uri else {})}]
         if linked else [], 'collected' if linked else 'empty'),
    ]
    if token_on_other:
        collections.append(('iam_policy', PROJECT,
                            [{'name': LINK.rsplit('/gitRepositoryLinks/', 1)[0] +
                                      '/gitRepositoryLinks/other',
                              'bindings': [bind(PROJECT + '/roles/other', SOURCE)]}]))
    model = GcpModel(snapshot('gcp', collections))
    return {tid: grant.confidence for reach in Evaluator(model, [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()}


def test_exact_push_trigger_and_distinct_privilege():
    assert case() == {'serviceAccount:' + SA: 'conditional'}
    assert case(filename=False, git_file=True) == {'serviceAccount:' + SA: 'conditional'}
    assert case(token=False, proxy=True, proxy_uri=True) == {
        'serviceAccount:' + SA: 'conditional'}


def test_proxy_only_or_uncertain_trigger_stays_unknown():
    for options in ({'token': False, 'proxy': True}, {'approved': True},
                    {'filename': False}, {'push': False}, {'incomplete': True},
                    {'filename': False, 'git_file': True, 'remote_file': True},
                    {'linked': False}, {'reconciling': True}):
        assert case(**options).get('serviceAccount:' + SA) != 'conditional'


def test_no_source_access_or_no_privilege_gain_is_not_positive():
    for options in ({'token': False}, {'token_on_other': True},
                    {'extra_right': False}, {'source_has_extra': True},
                    {'disabled': True}, {'trigger': False}):
        assert case(**options).get('serviceAccount:' + SA) != 'conditional'
