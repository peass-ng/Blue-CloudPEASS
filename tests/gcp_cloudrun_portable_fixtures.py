"""Native Cloud Run fixture for portable multi-container tests."""
from peaso.collectors import gcp_cloudrun_content_sources as planner

SCOPE = 'projects/review'
SERVICE = SCOPE + '/locations/us-central1/services/api'
BASE = 'https://us-central1-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/review'
REPO = SCOPE + '/locations/us-central1/repositories/apps'
IMAGE = 'us-central1-docker.pkg.dev/review/apps/nested/api'


def fixture():
    uri = 'https://' + IMAGE + '@sha256:' + 'a' * 64
    def body(name):
        return {'metadata': {'name': name, 'namespace': '1234', 'uid': 'native-' + name, 'generation': 1},
                'status': {'observedGeneration': 1, 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
    service = body('api')
    service['status'].update(latestReadyRevisionName='api-unused', traffic=[
        {'revisionName': 'api-old', 'percent': 90},
        {'revisionName': 'api-new', 'percent': 10, 'latestRevision': True},
        {'revisionName': 'api-preview', 'tag': 'preview'},
        {'revisionName': 'api-inactive', 'percent': 0}])
    revisions = {}
    for name in ('api-old', 'api-new', 'api-preview'):
        revision = body(name)
        revision['metadata']['labels'] = {'serving.knative.dev/service': 'api'}
        revision['spec'] = {'containers': [{'image': IMAGE + ':mutable'}]}
        revision['status']['imageDigest'] = uri
        revisions[BASE + '/revisions/' + name] = revision
    return {'scope': SCOPE, 'services': [SERVICE],
            'projects': [{'projectId': 'review', 'name': 'projects/1234'}],
            'repositories': [{'name': REPO, 'format': 'DOCKER'}],
            'service_reads': {BASE + '/services/api': service}, 'revision_reads': revisions,
            'image_rows': [{'uri': uri, 'digest': 'sha256:' + 'a' * 64, 'repository': REPO,
                            'name': REPO + '/dockerImages/nested%2Fapi%40sha256%3A' + 'a' * 64}]}
