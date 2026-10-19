"""AppConfig PRE content hooks and broad associations from accepted events."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


HOOK = Rule(id="hook", title="Content hook", level="medium", description="hook",
    technique_id="aws-appconfig-content-extension-created", product="aws",
    selection={"event.source": "appconfig.amazonaws.com", "event.name": "CreateExtension",
               "event.outcome": "success", "request.appconfig_content_hook_created": True})
ASSOC = Rule(id="assoc", title="Broad association", level="medium", description="assoc",
    technique_id="aws-appconfig-application-extension-associated", product="aws",
    selection={"event.source": "appconfig.amazonaws.com", "event.name": "CreateExtensionAssociation",
               "event.outcome": "success", "request.appconfig_app_wide_extension_association": True})
PROFILE = Rule(id="profile", title="Secret profile", level="medium", description="profile",
    technique_id="aws-appconfig-secret-retrieval-profile-created", product="aws",
    selection={"event.source": "appconfig.amazonaws.com", "event.name": "CreateConfigurationProfile",
               "event.outcome": "success", "request.appconfig_secret_retrieval_profile": True})
DEPLOY = Rule(id="deployment", title="Secret deployment", level="medium", description="deployment",
    technique_id="aws-appconfig-secret-source-deployed", product="aws",
    selection={"event.source": "appconfig.amazonaws.com", "event.name": "StartDeployment",
               "event.outcome": "success", "request.appconfig_secret_source_deployment": True})
EXPERIMENT = Rule(id="experiment", title="Enabled experiment", level="medium", description="experiment",
    technique_id="aws-appconfig-disabled-flag-enabled-in-experiment", product="aws",
    selection={"event.source": "appconfig.amazonaws.com", "event.name": "CreateExperimentDefinition",
               "event.outcome": "success", "request.appconfig_enabled_experiment_defined": True})
RUN = Rule(id="run", title="Enabled experiment run", level="medium", description="run",
    technique_id="aws-appconfig-enabled-flag-experiment-running", product="aws",
    selection={"event.source": "appconfig.amazonaws.com", "event.name": "StartExperimentRun",
               "event.outcome": "success", "request.appconfig_enabled_experiment_running": True})


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], [HOOK, ASSOC, PROFILE, DEPLOY, EXPERIMENT, RUN])]


def test_content_hook_requires_accepted_lambda_action_and_role() -> None:
    action = {"name": "observe-canary",
        "uri": "arn:aws:lambda:us-east-1:222233334444:function:peasso-canary",
        "roleArn": "arn:aws:iam::222233334444:role/peasso-canary"}
    actions = {"PRE_CREATE_HOSTED_CONFIGURATION_VERSION": [action]}
    event = {"eventSource": "appconfig.amazonaws.com", "eventName": "CreateExtension",
        "eventCategory": "Management", "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": False, "awsRegion": "us-east-1", "recipientAccountId": "222233334444",
        "requestParameters": {"name": "peasso-canary", "actions": actions},
        "responseElements": {"id": "otp58kd", "versionNumber": 1,
            "arn": "arn:aws:appconfig:us-east-1:222233334444:extension/otp58kd/1", "actions": actions}}
    assert _hits(event) == [HOOK.technique_id]
    for change in ("notify", "foreign_role", "failed", "mismatch", "wrong_arn", "data_event"):
        item = deepcopy(event)
        if change == "notify":
            action_list = item["requestParameters"]["actions"].pop("PRE_CREATE_HOSTED_CONFIGURATION_VERSION")
            item["requestParameters"]["actions"]["ON_DEPLOYMENT_START"] = action_list
            item["responseElements"]["actions"] = item["requestParameters"]["actions"]
        if change == "foreign_role":
            item["requestParameters"]["actions"]["PRE_CREATE_HOSTED_CONFIGURATION_VERSION"][0]["roleArn"] = "arn:aws:iam::111122223333:role/other"
            item["responseElements"]["actions"] = item["requestParameters"]["actions"]
        if change == "failed": item["errorCode"] = "BadRequestException"
        if change == "mismatch": item["responseElements"]["actions"] = {}
        if change == "wrong_arn": item["responseElements"]["arn"] += "-other"
        if change == "data_event": item["eventCategory"] = "Data"
        assert _hits(item) == [], change


def test_application_association_requires_response_confirmation() -> None:
    extension = "arn:aws:appconfig:us-east-1:222233334444:extension/otp58kd/1"
    application = "arn:aws:appconfig:us-east-1:222233334444:application/dc7mzfi"
    event = {"eventSource": "appconfig.amazonaws.com", "eventName": "CreateExtensionAssociation",
        "eventCategory": "Management", "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": False, "awsRegion": "us-east-1", "recipientAccountId": "222233334444",
        "requestParameters": {"extensionIdentifier": "otp58kd", "resourceIdentifier": application},
        "responseElements": {"id": "lib88w5", "extensionArn": extension, "resourceArn": application,
            "arn": "arn:aws:appconfig:us-east-1:222233334444:extensionassociation/lib88w5",
            "extensionVersionNumber": 1}}
    assert _hits(event) == [ASSOC.technique_id]
    for change in ("profile", "wrong_extension", "wrong_resource", "failed"):
        item = deepcopy(event)
        if change == "profile":
            item["requestParameters"]["resourceIdentifier"] += "/configurationprofile/6f802mg"
            item["responseElements"]["resourceArn"] = item["requestParameters"]["resourceIdentifier"]
        if change == "wrong_extension": item["responseElements"]["extensionArn"] += "-other"
        if change == "wrong_resource": item["responseElements"]["resourceArn"] += "-other"
        if change == "failed": item["errorCode"] = "BadRequestException"
        assert _hits(item) == [], change


def test_secret_profile_and_deployment_require_matching_accepted_response() -> None:
    role = "arn:aws:iam::222233334444:role/peasso-canary"
    location = "secretsmanager://peasso-canary"
    base = {"eventSource": "appconfig.amazonaws.com", "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True, "readOnly": False,
        "awsRegion": "us-east-1", "recipientAccountId": "222233334444"}
    profile = {**base, "eventName": "CreateConfigurationProfile",
        "requestParameters": {"applicationId": "umvxf7b", "name": "reader",
            "locationUri": location, "retrievalRoleArn": role, "type": "AWS.Freeform"},
        "responseElements": {"applicationId": "umvxf7b", "id": "yfz3tfr",
            "locationUri": location, "retrievalRoleArn": role}}
    assert _hits(profile) == [PROFILE.technique_id]
    for change in ("hosted", "wrong_role", "wrong_application", "failed"):
        item = deepcopy(profile)
        if change == "hosted":
            item["requestParameters"]["locationUri"] = "hosted"
            item["responseElements"]["locationUri"] = "hosted"
        if change == "wrong_role": item["responseElements"]["retrievalRoleArn"] = role + "-other"
        if change == "wrong_application": item["responseElements"]["applicationId"] = "other01"
        if change == "failed": item["errorCode"] = "BadRequestException"
        assert _hits(item) == [], change

    deployment = {**base, "eventName": "StartDeployment",
        "requestParameters": {"applicationId": "umvxf7b", "environmentId": "yr7xfr1",
            "configurationProfileId": "yfz3tfr", "configurationVersion": "v1"},
        "responseElements": {"applicationId": "umvxf7b", "environmentId": "yr7xfr1",
            "configurationProfileId": "yfz3tfr", "configurationVersion": "v1",
            "configurationLocationUri": location, "deploymentNumber": 1}}
    assert _hits(deployment) == [DEPLOY.technique_id]
    for change in ("hosted", "wrong_version", "wrong_profile", "failed"):
        item = deepcopy(deployment)
        if change == "hosted": item["responseElements"]["configurationLocationUri"] = "hosted"
        if change == "wrong_version": item["responseElements"]["configurationVersion"] = "v2"
        if change == "wrong_profile": item["responseElements"]["configurationProfileId"] = "other01"
        if change == "failed": item["errorCode"] = "BadRequestException"
        assert _hits(item) == [], change


def test_experiment_requires_enabled_treatment_and_positive_exposure() -> None:
    base = {"eventSource": "appconfig.amazonaws.com", "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True, "readOnly": False,
        "awsRegion": "us-east-1", "recipientAccountId": "222233334444"}
    treatment = {"weight": 100.0, "flagValue": {"enabled": True}}
    control = {"weight": 0.0, "flagValue": {"enabled": False}}
    created = {**base, "eventName": "CreateExperimentDefinition",
        "requestParameters": {"applicationIdentifier": "qeqwkv7",
            "configurationProfileIdentifier": "j6qhtso", "environmentIdentifier": "jigkwyk",
            "treatments": [treatment], "control": control}, "responseElements": None}
    assert _hits(created) == [EXPERIMENT.technique_id]
    for change in ("no_treatment", "zero_weight", "enabled_control", "failed"):
        item = deepcopy(created)
        if change == "no_treatment": item["requestParameters"]["treatments"] = []
        if change == "zero_weight": item["requestParameters"]["treatments"][0]["weight"] = 0
        if change == "enabled_control": item["requestParameters"]["control"]["flagValue"]["enabled"] = True
        if change == "failed": item["errorCode"] = "BadRequestException"
        assert _hits(item) == [], change
    started = {**base, "eventName": "StartExperimentRun",
        "requestParameters": {"applicationIdentifier": "qeqwkv7",
            "experimentDefinitionIdentifier": "9jbcdhp", "exposurePercentage": 100.0},
        "responseElements": {"applicationId": "qeqwkv7", "experimentDefinitionId": "9jbcdhp",
            "status": "RUNNING", "exposurePercentage": 100.0,
            "experimentDefinitionSnapshot": {"control": control, "treatments": [treatment]}}}
    assert _hits(started) == [RUN.technique_id]
    for change in ("zero_exposure", "mismatch", "done", "failed"):
        item = deepcopy(started)
        if change == "zero_exposure":
            item["requestParameters"]["exposurePercentage"] = 0
            item["responseElements"]["exposurePercentage"] = 0
        if change == "mismatch": item["responseElements"]["experimentDefinitionId"] = "other01"
        if change == "done": item["responseElements"]["status"] = "DONE"
        if change == "failed": item["errorCode"] = "BadRequestException"
        assert _hits(item) == [], change
