"""Exact configured-selector/job-membership residuals; no runtime coverage criterion."""
from copy import deepcopy
from tests.test_peaso_s3_logging_macie_authority import verdict,macie_row,deny,LOG,MACIE
from peaso.checks.claude_aws_a_s3 import TRAIL,MACIE_JOB

def test_either_known_region_alternative_can_settle_matching_selector():
    for field in ("HomeRegion","IsMultiRegionTrail"):
        trail=deepcopy(TRAIL);deny(trail,field)
        assert verdict(LOG,"cloudtrail_account_inventory",[trail])=="PASS"

def test_false_region_alternatives_skip_unused_selector_but_unknown_cannot():
    trail=deepcopy(TRAIL);trail["IsMultiRegionTrail"]=False;trail["HomeRegion"]="eu-west-1"
    deny(trail,"EventSelectors")
    assert verdict(LOG,"cloudtrail_account_inventory",[trail])=="FAIL"
    deny(trail,"HomeRegion")
    assert verdict(LOG,"cloudtrail_account_inventory",[trail])=="UNKNOWN"

def test_empty_selected_parent_cannot_authenticate_retained_membership():
    trail=deepcopy(TRAIL);trail["EventSelectors"]["EventSelectors"][0]["DataResources"][0]["collection_status"]="empty"
    assert verdict(LOG,"cloudtrail_account_inventory",[trail])=="UNKNOWN"
    row=macie_row([MACIE_JOB]);row["Jobs"]["items"][0]["s3JobDefinition"]["collection_status"]="empty"
    assert verdict(MACIE,"macie2_account_classification_job_inventory",[row])=="UNKNOWN"

def test_selected_parent_own_status_coverage_is_authoritative():
    trail=deepcopy(TRAIL);deny(trail,"collection_status")
    assert verdict(LOG,"cloudtrail_account_inventory",[trail])=="UNKNOWN"
    row=macie_row([MACIE_JOB]);deny(row["Jobs"]["items"][0]["s3JobDefinition"],"collection_status")
    assert verdict(MACIE,"macie2_account_classification_job_inventory",[row])=="UNKNOWN"

def test_consistent_empty_jobs_and_selector_containers_preserve_outcomes():
    row=macie_row([]);row["Jobs"]["collection_status"]="empty"
    assert verdict(MACIE,"macie2_account_classification_job_inventory",[row])=="FAIL"
    row["ServiceState"]="service_not_enabled"
    assert verdict(MACIE,"macie2_account_classification_job_inventory",[row])=="NOT_APPLICABLE"
    trail=deepcopy(TRAIL);trail["EventSelectors"]["EventSelectors"]=[{"collection_status":"empty","DataResources":[]}]
    assert verdict(LOG,"cloudtrail_account_inventory",[trail])=="FAIL"

def test_disabled_global_service_cannot_keep_collected_or_nonempty_jobs():
    for status,jobs in (("collected",[MACIE_JOB]),("collected",[]),("empty",[MACIE_JOB])):
        row=macie_row(jobs);row["ServiceState"]="service_not_enabled";row["Jobs"]["collection_status"]=status
        assert verdict(MACIE,"macie2_account_classification_job_inventory",[row])=="UNKNOWN"

def test_disabled_jobs_status_and_items_must_be_available():
    for field in ("collection_status","items"):
        row=macie_row([]);row["ServiceState"]="service_not_enabled";row["Jobs"]["collection_status"]="empty";deny(row["Jobs"],field)
        assert verdict(MACIE,"macie2_account_classification_job_inventory",[row])=="UNKNOWN"

def test_independent_matching_resources_or_jobs_survive_empty_parent_peer():
    for reverse in (False,True):
        trail=deepcopy(TRAIL);good=deepcopy(trail["EventSelectors"]["EventSelectors"][0]["DataResources"][0]);bad=deepcopy(good);bad["collection_status"]="empty"
        resources=[good,bad]
        if reverse:resources.reverse()
        trail["EventSelectors"]["EventSelectors"][0]["DataResources"]=resources
        assert verdict(LOG,"cloudtrail_account_inventory",[trail])=="PASS"
        good_job=deepcopy(MACIE_JOB);bad_job=deepcopy(MACIE_JOB);bad_job["s3JobDefinition"]["collection_status"]="empty"
        jobs=[good_job,bad_job]
        if reverse:jobs.reverse()
        assert verdict(MACIE,"macie2_account_classification_job_inventory",[macie_row(jobs)])=="PASS"

def test_normal_native_objects_without_parent_status_remain_valid():
    assert verdict(LOG,"cloudtrail_account_inventory",[deepcopy(TRAIL)])=="PASS"
    assert verdict(MACIE,"macie2_account_classification_job_inventory",[macie_row([MACIE_JOB])])=="PASS"
