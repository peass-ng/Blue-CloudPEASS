"""Pure intake accepts exact CodeCommit builds without unrelated S3 selections."""
import pytest
from peaso.server import content_selection_preflight_20261021 as preflight

SCOPE='123456789012/eu-west-1'
BUILD='arn:aws:codebuild:eu-west-1:123456789012:build/AuditProject:11111111-2222-3333-4444-555555555555'
REPO='arn:aws:codecommit:eu-west-1:123456789012:AuditRepo'
COMMIT='a'*40


def pure():
    return preflight.s3, preflight.build_ref, preflight.registry, preflight.aks_image


def cc():
    return {'profile':'codebuild_codecommit_source','scope':SCOPE,'build_arn':BUILD,
            'repository_arn':REPO,'commit_id':COMMIT,'file_path':'/source/config.txt'}

def s3_build():
    return {'profile':'codebuild_s3_source','scope':SCOPE,
            'project_arn':'arn:aws:codebuild:eu-west-1:123456789012:project/AuditProject',
            'source_s3_uri':'s3://selected-source-bucket/jobs/source.zip'}

def options(*targets,source=None):
    row={'content_secret_scans':True,
         '_content_secret_scan_kinds':['build_deployment_referenced_source_content'],
         'selected_aws_build_deployment_sources':list(targets)}
    if source is not None:row['selected_aws_s3_sources']=source
    return row

def test_codecommit_only_has_no_s3_grant_or_io():
    s3,build,_,_=pure()
    row=options(cc())
    assert s3.selected_targets(row,[SCOPE])==[]
    assert build.selected_targets(row,[SCOPE])==[cc()]
    assert 'selected_aws_s3_sources' not in row

def test_mixed_and_legacy_s3_keep_exact_union():
    s3,build,_,_=pure()
    selected=build.source_target(s3_build())
    mixed=options(cc(),s3_build(),source=[selected])
    assert s3.selected_targets(mixed,[SCOPE])==[selected]
    assert build.selected_targets(mixed,[SCOPE])==[cc(),s3_build()]
    assert build.selected_targets(options(s3_build(),source=[selected]),[SCOPE])==[s3_build()]
    for invalid in (options(cc(),s3_build()),options(cc(),s3_build(),source=[{**selected,'key':'foreign.zip'}])):
        with pytest.raises(ValueError):build.selected_targets(invalid,[SCOPE])
    with pytest.raises(ValueError):
        build.selected_targets(options(cc(),source=[selected]),[SCOPE])

def test_preflight_rejects_trivy_runtime_keys():
    _,_,registry,aks=pure()
    for key in ('trivy_db_cache','trivy_cli'):
        with pytest.raises(ValueError,match='trivy_runtime_configuration'):
            registry.selected_targets({key:'/tmp/db'},[],[])
        with pytest.raises(ValueError,match='trivy_runtime_configuration'):
            aks.selected_targets({key:'/tmp/db'},[],[])
