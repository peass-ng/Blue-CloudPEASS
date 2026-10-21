"""Pod/public-image CVE scans do not require unrelated registry selections."""
from copy import deepcopy
import pytest
from peaso.server.image_selection_options_20261021 import validate_image_options

DIGEST='sha256:'+'1'*64
SUB='/subscriptions/11111111-2222-3333-4444-555555555555'


def selected(provider):
    pod=dict(cluster_id='cluster', namespace='default', pod='app', uid='pod123',
        resource_version='42', container_type='regular', container_name='app',
        image='registry.example.com/owned/app@'+DIGEST)
    opts={'image_vulnerability_scans':True}
    if provider=='aws':
        opts['selected_aws_ecr_public_images']=[dict(scope='123456789012/us-east-1',
            registry_alias='ownedalias',repository_name='owned/app',image_digest=DIGEST)]
        scopes=['123456789012/us-east-1']
    else:
        opts['selected_registry_hosts']=['registry.example.com']
        if provider=='gcp':
            pod['cluster_id']='projects/myproject1/locations/us-central1/clusters/owned'
            option,scopes='selected_gke_pod_images',['projects/myproject1']
        elif provider=='azure':
            pod['cluster_id']=SUB+'/resourceGroups/owned/providers/Microsoft.ContainerService/managedClusters/owned'
            option,scopes='selected_azure_aks_pod_images',[SUB]
        else:
            option,scopes='selected_k8s_registry_images',['default']
        opts[option]=[pod]
    return opts,scopes


@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_exact_new_selection_without_unrelated_legacy_targets(provider):
    options,scopes=selected(provider)
    before=deepcopy(options)
    validate_image_options(provider,options,scopes)
    assert options==before


@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_malformed_selected_target_and_foreign_provider_rejected(provider):
    options,scopes=selected(provider)
    key=next(k for k in options if k.startswith('selected_') and k!='selected_registry_hosts')
    malformed=deepcopy(options);malformed[key][0]['unexpected']='field'
    with pytest.raises(ValueError):validate_image_options(provider,malformed,scopes)
    with pytest.raises(ValueError):validate_image_options('gcp' if provider!='gcp' else 'azure',options,scopes)


@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_flag_requires_boolean_even_for_supported_new_selector(provider):
    options,scopes=selected(provider)
    options['image_vulnerability_scans']='true'
    with pytest.raises(ValueError):validate_image_options(provider,options,scopes)


@pytest.mark.parametrize('provider,key',[
    ('aws','selected_aws_image_vulnerabilities'),
    ('gcp','selected_gcp_registry_image_vulnerabilities'),
    ('azure','selected_azure_acr_image_vulnerabilities')])
def test_new_selection_does_not_hide_invalid_legacy_selection(provider,key):
    options,scopes=selected(provider);options[key]=[{'unexpected':'field'}]
    with pytest.raises(ValueError):validate_image_options(provider,options,scopes)
