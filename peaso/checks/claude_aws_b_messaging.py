"""claude_aws_b messaging/integration: MQ, MSK/Kafka, MSK Connect, SNS, SQS, SES, Step Functions, Transfer Family."""
from __future__ import annotations

import json
import re

from . import result
from .facts import Unavailable, get, list_of_objects, complete_items
from .claude_aws_b_common import (install, flag, absent_or, strings, account, policy_document, is_policy_public, kms_manager,
    has_public_principal, has_restrictive_source_arn_condition, is_condition_block_restrictive, is_condition_block_restrictive_organization,
    is_condition_block_restrictive_sns_endpoint, turbot_public_statements, wildcard_principal, turbot_unrestricted, wildcard_allow_statements,
    inventory, indexes, CONTEXT, ACCOUNT, _as_list)

P, C, X = "prowler.aws.", "aws-compliance.control.", "aws-perimeter.control."
CTX = {"context": dict(CONTEXT)}
KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/k1"

# =========================================================================== Amazon MQ
D_MQ = "https://docs.aws.amazon.com/amazon-mq/latest/api-reference/brokers-broker-id.html"


def _mq(engine, **config):
    return {"BrokerArn": "arn:aws:mq:us-east-1:111111111111:broker:b", "Configuration": {"BrokerArn": "arn:aws:mq:us-east-1:111111111111:broker:b", "EngineType": engine, **config}}


def _engine(item):
    return get(item, "Configuration.EngineType", str).upper()


@install("aws.cb.mq.activemq_active_standby", "mq_broker", "ActiveMQ broker uses the active/standby Multi-AZ deployment mode",
    _mq("ACTIVEMQ", DeploymentMode="ACTIVE_STANDBY_MULTI_AZ"), _mq("ACTIVEMQ", DeploymentMode="SINGLE_INSTANCE"),
    rows=[P + "mq_broker_active_deployment_mode"], severity="low", control="CP-10",
    remediation="Recreate the ActiveMQ broker with deployment mode ACTIVE_STANDBY_MULTI_AZ.", docs=[D_MQ],
    extra={"not_applicable": _mq("RABBITMQ", DeploymentMode="SINGLE_INSTANCE")})
def mq_active(item, index):
    engine = _engine(item)
    if engine != "ACTIVEMQ":
        return "NOT_APPLICABLE", {"engine": engine}
    mode = get(item, "Configuration.DeploymentMode", str)
    return result(mode != "ACTIVE_STANDBY_MULTI_AZ", deployment_mode=mode)


@install("aws.cb.mq.rabbitmq_cluster_deployment", "mq_broker", "RabbitMQ broker uses the cluster Multi-AZ deployment mode",
    _mq("RABBITMQ", DeploymentMode="CLUSTER_MULTI_AZ"), _mq("RABBITMQ", DeploymentMode="SINGLE_INSTANCE"),
    rows=[P + "mq_broker_cluster_deployment_mode"], severity="low", control="CP-10",
    remediation="Recreate the RabbitMQ broker with deployment mode CLUSTER_MULTI_AZ.", docs=[D_MQ],
    extra={"not_applicable": _mq("ACTIVEMQ", DeploymentMode="SINGLE_INSTANCE")})
def mq_cluster(item, index):
    engine = _engine(item)
    if engine != "RABBITMQ":
        return "NOT_APPLICABLE", {"engine": engine}
    mode = get(item, "Configuration.DeploymentMode", str)
    return result(mode != "CLUSTER_MULTI_AZ", deployment_mode=mode)


@install("aws.cb.mq.activemq_audit_logs", "mq_broker", "ActiveMQ broker publishes audit logs",
    _mq("ACTIVEMQ", Logs={"Audit": True, "General": False}), _mq("ACTIVEMQ", Logs={"Audit": False, "General": True}),
    rows=[C + "mq_broker_audit_log_enabled"], severity="medium", control="AU-2",
    remediation="Enable audit log publishing to CloudWatch Logs on the ActiveMQ broker.", docs=[D_MQ],
    extra={"not_applicable": _mq("RABBITMQ", Logs={"General": True})},
    note="Steampipe alarms every broker without Logs.Audit, but RabbitMQ brokers do not support audit logs (Logs.Audit is ActiveMQ-only), so RabbitMQ is NOT_APPLICABLE.")
def mq_audit(item, index):
    engine = _engine(item)
    if engine != "ACTIVEMQ":
        return "NOT_APPLICABLE", {"engine": engine, "reason": "audit logs are ActiveMQ-only"}
    audit = get(item, "Configuration.Logs.Audit", bool)
    return result(not audit, audit=audit)


@install("aws.cb.mq.engine_logging", "mq_broker", "MQ broker publishes general logs (and audit logs for ActiveMQ)",
    _mq("ACTIVEMQ", Logs={"Audit": True, "General": True}), _mq("ACTIVEMQ", Logs={"Audit": False, "General": True}),
    rows=[P + "mq_broker_logging_enabled"], severity="medium", control="AU-2",
    remediation="Enable general log publishing (and audit logs on ActiveMQ) to CloudWatch Logs.", docs=[D_MQ],
    extra={"rabbit_pass": _mq("RABBITMQ", Logs={"General": True})}, note="Prowler: ActiveMQ requires General and Audit; RabbitMQ requires General; other engines FAIL.")
def mq_logging(item, index):
    engine = _engine(item)
    logs = get(item, "Configuration.Logs", dict)
    general = absent_or(logs, "General", "General", False, bool)
    if engine == "ACTIVEMQ":
        audit = absent_or(logs, "General", "Audit", False, bool)
        return result(not (general and audit), general=general, audit=audit)
    if engine == "RABBITMQ":
        return result(not general, general=general)
    return result(True, engine=engine)


flag("aws.cb.mq.not_publicly_accessible", "mq_broker", "MQ broker is not publicly accessible", "Configuration.PubliclyAccessible",
     rows=[P + "mq_broker_not_publicly_accessible", C + "mq_broker_restrict_public_access"], severity="high", category="exposure", control="SC-7",
     remediation="Recreate the broker with PubliclyAccessible false inside private subnets.", sentinel="BrokerArn",
     base={"BrokerArn": "b", "Configuration": {"EngineType": "ACTIVEMQ"}}, good=False, bad=True, docs=[D_MQ])


# =========================================================================== MSK
D_MSK = "https://docs.aws.amazon.com/msk/1.0/apireference/v2-clusters.html"
MSK_ARN = "arn:aws:kafka:us-east-1:111111111111:cluster/c/1"


def _msk(**provisioned):
    return {"ClusterArn": MSK_ARN, "ClusterType": "PROVISIONED", "Provisioned": provisioned}


SERVERLESS = {"ClusterArn": MSK_ARN, "ClusterType": "SERVERLESS", "Serverless": {"VpcConfigs": []}}


def _cluster_type(item):
    kind = get(item, "ClusterType", str)
    if kind not in ("PROVISIONED", "SERVERLESS"):
        raise Unavailable("unknown MSK cluster type")
    return kind


def _prov(item, path, default):
    """Prowler defaults for omitted Provisioned members (the service model uses .get defaults)."""
    get(item, "Provisioned", dict)
    return absent_or(item, "ClusterArn", "Provisioned." + path, default)


def msk_check(cid, title, rows, sev, rem, passing, failing, *, serverless="PASS", note=None, control="CM-6", category="hardening", dependencies=None, extra=None):
    more = dict(extra or {})
    if serverless == "PASS":
        more.setdefault("serverless_pass", SERVERLESS)
    else:
        more.setdefault("not_applicable", SERVERLESS)

    def decorate(function):
        @install(cid, "msk_cluster", title, passing, failing, rows=rows, severity=sev, remediation=rem, docs=[D_MSK], note=note,
                 control=control, category=category, dependencies=dependencies, extra=more)
        def evaluate(item, index):
            if _cluster_type(item) == "SERVERLESS":
                if serverless == "PASS":
                    return result(False, cluster_type="SERVERLESS", reason="AWS-managed setting for MSK Serverless")
                return "NOT_APPLICABLE", {"cluster_type": "SERVERLESS"}
            return function(item, index)
        evaluate.__name__ = function.__name__
        return evaluate
    return decorate


@msk_check("aws.cb.kafka.cmk_encryption_at_rest", "MSK provisioned cluster encrypts data volumes with a customer managed KMS key",
    [P + "kafka_cluster_encryption_at_rest_uses_cmk"], "medium", "Recreate the cluster with a customer managed KMS key for data at rest.",
    _msk(EncryptionInfo={"EncryptionAtRest": {"DataVolumeKMSKeyId": KMS_ARN}}), _msk(EncryptionInfo={"EncryptionAtRest": {"DataVolumeKMSKeyId": "arn:aws:kms:us-east-1:111111111111:key/aws"}}),
    control="SC-28", dependencies=["msk_cluster", "kms_key"],
    extra={"index": inventory("kms_key", [{"Metadata": {"KeyMetadata": {"Arn": KMS_ARN, "KeyId": "k1", "KeyManager": "CUSTOMER"}}}, {"Metadata": {"KeyMetadata": {"Arn": "arn:aws:kms:us-east-1:111111111111:key/aws", "KeyId": "aws", "KeyManager": "AWS"}}}])})
def msk_cmk(item, index):
    key = _prov(item, "EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId", "")
    if not key:
        return result(True, data_volume_kms_key_id=None)
    return result(kms_manager(index, key) != "CUSTOMER", data_volume_kms_key_id=key)


@msk_check("aws.cb.kafka.enhanced_monitoring", "MSK provisioned cluster uses enhanced monitoring above DEFAULT",
    [P + "kafka_cluster_enhanced_monitoring_enabled"], "low", "Set the cluster EnhancedMonitoring level to PER_BROKER or higher.",
    _msk(EnhancedMonitoring="PER_BROKER"), _msk(EnhancedMonitoring="DEFAULT"), control="SI-4")
def msk_monitoring(item, index):
    level = _prov(item, "EnhancedMonitoring", "DEFAULT")
    return result(level == "DEFAULT", enhanced_monitoring=level)


@msk_check("aws.cb.kafka.tls_client_and_in_cluster", "MSK provisioned cluster uses TLS client-broker and in-cluster encryption",
    [P + "kafka_cluster_in_transit_encryption_enabled"], "medium", "Set ClientBroker to TLS and enable InCluster encryption.",
    _msk(EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}}), _msk(EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS_PLAINTEXT", "InCluster": True}}), control="SC-8",
    note="Prowler defaults: ClientBroker PLAINTEXT and InCluster False when omitted.")
def msk_transit(item, index):
    broker = _prov(item, "EncryptionInfo.EncryptionInTransit.ClientBroker", "PLAINTEXT")
    in_cluster = _prov(item, "EncryptionInfo.EncryptionInTransit.InCluster", False)
    return result(not (broker == "TLS" and in_cluster is True), client_broker=broker, in_cluster=in_cluster)


@msk_check("aws.cb.msk.client_broker_tls", "MSK provisioned cluster client-broker encryption is TLS only",
    [C + "msk_cluster_encryption_in_transit_with_tls_enabled"], "medium", "Set ClientBroker encryption in transit to TLS.",
    _msk(EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS"}}), _msk(EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS_PLAINTEXT"}}),
    serverless="NOT_APPLICABLE", control="SC-8",
    note="Steampipe reads provisioned->EncryptionInfo; serverless clusters (no provisioned block, always TLS) would alarm upstream and are NOT_APPLICABLE here.")
def msk_tls(item, index):
    broker = get(item, "Provisioned.EncryptionInfo.EncryptionInTransit.ClientBroker", str)
    return result(broker != "TLS", client_broker=broker)


@msk_check("aws.cb.kafka.public_access_disabled", "MSK cluster public access is disabled",
    [P + "kafka_cluster_is_public", C + "msk_cluster_not_publicly_accessible"], "high", "Set the broker ConnectivityInfo PublicAccess Type to DISABLED.",
    _msk(BrokerNodeGroupInfo={"ConnectivityInfo": {"PublicAccess": {"Type": "DISABLED"}}}), _msk(BrokerNodeGroupInfo={"ConnectivityInfo": {"PublicAccess": {"Type": "SERVICE_PROVIDED_EIPS"}}}),
    category="exposure", control="SC-7", note="Both sources: PublicAccess.Type == DISABLED; serverless clusters are private (prowler PASS). An omitted type is UNKNOWN rather than prowler's SERVICE_PROVIDED_EIPS default.")
def msk_public(item, index):
    kind = get(item, "Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type", str)
    return result(kind != "DISABLED", public_access_type=kind)


@msk_check("aws.cb.kafka.mutual_tls_authentication", "MSK provisioned cluster enables mutual TLS client authentication",
    [P + "kafka_cluster_mutual_tls_authentication_enabled"], "medium", "Enable TLS client authentication with an ACM Private CA.",
    _msk(ClientAuthentication={"Tls": {"Enabled": True}}), _msk(ClientAuthentication={"Tls": {"Enabled": False}}), control="IA-3")
def msk_mtls(item, index):
    value = _prov(item, "ClientAuthentication.Tls.Enabled", False)
    return result(value is not True, tls_authentication=value)


@msk_check("aws.cb.kafka.unauthenticated_access_disabled", "MSK cluster does not allow unauthenticated access",
    [P + "kafka_cluster_unrestricted_access_disabled", C + "msk_cluster_unauthenticated_access_disabled"], "high", "Disable unauthenticated client access and use IAM, SASL/SCRAM or TLS.",
    _msk(ClientAuthentication={"Unauthenticated": {"Enabled": False}}), _msk(ClientAuthentication={"Unauthenticated": {"Enabled": True}}), control="IA-2",
    note="Prowler defaults an omitted flag to False (PASS) while steampipe alarms on null; omitted flags are UNKNOWN here. Serverless requires IAM authentication (PASS).")
def msk_unauth(item, index):
    value = get(item, "Provisioned.ClientAuthentication.Unauthenticated.Enabled", bool)
    return result(value, unauthenticated=value)


def _versions(*values):
    return indexes(
        inventory("kafka_version", [{"Version": v, "Status": "ACTIVE"} for v in values]),
        inventory("msk_compatible_version", [{"ClusterArn": MSK_ARN, "CompatibleVersions": {
            "collection_status": "collected", "items": [
                {"SourceVersion": "2.8.1", "TargetVersions": ["3.7.x"]},
                {"SourceVersion": "3.7.x", "TargetVersions": []},
            ]}}]),
    )


@msk_check("aws.cb.kafka.latest_version", "MSK provisioned cluster runs an ACTIVE Kafka version with no newer compatible update",
    [P + "kafka_cluster_uses_latest_version"], "medium", "Review the cluster-specific compatible update list and plan a supported Kafka version upgrade with the workload owner.",
    _msk(CurrentBrokerSoftwareInfo={"KafkaVersion": "3.7.x"}, BrokerNodeGroupInfo={"InstanceType": "kafka.m5.large"}),
    _msk(CurrentBrokerSoftwareInfo={"KafkaVersion": "2.8.1"}, BrokerNodeGroupInfo={"InstanceType": "kafka.m5.large"}),
    control="SI-2", serverless="NOT_APPLICABLE",
    dependencies=["msk_cluster", "kafka_version", "msk_compatible_version"], extra={"index": _versions("2.8.1", "3.7.x", "4.2.x")},
    note="Pinned Prowler compared the last ListKafkaVersions entry, and an earlier native revision compared a global ACTIVE numeric maximum. "
         "Neither proves a broker-compatible upgrade: Standard and Express have different version support. This check uses the cluster ARN's "
         "GetCompatibleKafkaVersions source/targets plus the current broker type and ListKafkaVersions ACTIVE/DEPRECATED status. A DEPRECATED "
         "current version fails independently; an ACTIVE current version fails only when AWS returns an ACTIVE compatible target with a "
         "provably greater numeric Kafka version. AWS calls targets updates and does not support downgrades, but an older or incomparable "
         "target is inconsistent or ambiguous evidence, not proof of a newer update. Missing, denied, malformed, ambiguous or unlisted facts "
         "are UNKNOWN. PASS means no newer ACTIVE target was reported for this cluster, not "
         "globally newest Kafka, client compatibility, or a safe unattended upgrade.")
def msk_latest(item, index):
    def components(raw):
        # Kafka versions include 3.7.x and 3.9.x.kraft. Only numeric segments
        # before an unknown patch can establish order; metadata mode is not an
        # ordered Kafka component. Never compare version strings lexically.
        base = raw.removesuffix(".kraft")
        parts = base.split(".")
        if len(parts) not in (3, 4) or not all(part.isascii() and part.isdecimal() for part in parts[:2]):
            return None
        if not all(part.isascii() and part.isdecimal() for part in parts[2:] if part != "x"):
            return None
        if "x" in parts and (parts[-1] != "x" or parts.count("x") != 1):
            return None
        return tuple(None if part == "x" else int(part) for part in parts)

    version = get(item, "Provisioned.CurrentBrokerSoftwareInfo.KafkaVersion", str)
    arn = get(item, "ClusterArn", str)
    versions = complete_items(index, "kafka_version")
    if not versions:
        raise Unavailable("no Kafka versions listed")
    listed = {}
    for entry in versions:
        status = get(entry, "Status", str)
        if status not in ("ACTIVE", "DEPRECATED"):
            raise Unavailable("unrecognized Kafka version status")
        offered = get(entry, "Version", str)
        if offered in listed and listed[offered] != status:
            raise Unavailable("conflicting Kafka version status")
        listed[offered] = status
    if version not in listed:
        raise Unavailable("current Kafka version absent from offered versions")
    if listed[version] == "DEPRECATED":
        return result(True, kafka_version=version, version_status="DEPRECATED",
                      reason="current Kafka version is listed as deprecated; review cluster-specific targets before planning an upgrade")
    instance_type = get(item, "Provisioned.BrokerNodeGroupInfo.InstanceType", str)
    broker_type = "EXPRESS" if instance_type.startswith("express.") else "STANDARD" if instance_type.startswith("kafka.") else None
    if not broker_type or not re.fullmatch(r"(?:express|kafka)\.[a-z0-9.]+", instance_type):
        raise Unavailable("unknown MSK provisioned broker type")
    matches = [row for row in complete_items(index, "msk_compatible_version") if get(row, "ClusterArn", str) == arn]
    if len(matches) != 1:
        raise Unavailable("cluster-specific compatible version result missing or ambiguous")
    container = get(matches[0], "CompatibleVersions", dict)
    if container.get("collection_status") != "collected":
        raise Unavailable("cluster-specific compatible versions unavailable")
    sources = list_of_objects(get(container, "items", list))
    current = [row for row in sources if get(row, "SourceVersion", str) == version]
    if len(current) != 1:
        raise Unavailable("current source version missing or ambiguous in compatible versions")
    targets = get(current[0], "TargetVersions", list)
    if any(not isinstance(target, str) or not target for target in targets):
        raise Unavailable("malformed compatible Kafka version target")
    if any(target not in listed for target in targets):
        raise Unavailable("compatible target absent from listed Kafka versions")
    source_parts = components(version)
    if source_parts is None:
        raise Unavailable("unrecognized current Kafka version format")
    active_targets = set()
    for target in targets:
        if target == version or listed[target] != "ACTIVE":
            continue
        target_parts = components(target)
        if target_parts is None or len(target_parts) != len(source_parts):
            raise Unavailable("incomparable compatible Kafka version target")
        for source_part, target_part in zip(source_parts, target_parts):
            if source_part is None or target_part is None:
                raise Unavailable("incomparable compatible Kafka version target")
            if target_part > source_part:
                active_targets.add(target)
                break
            if target_part < source_part:
                raise Unavailable("older target in cluster-compatible update list")
        else:
            raise Unavailable("compatible target does not prove a newer Kafka version")
    return result(bool(active_targets), kafka_version=version, version_status="ACTIVE", broker_type=broker_type,
                  instance_type=instance_type, compatible_active_targets=sorted(active_targets),
                  assessment="cluster-specific offered update targets; client compatibility and upgrade readiness not evaluated")


# --------------------------------------------------------------------------- MSK Connect
D_MSKC = "https://docs.aws.amazon.com/MSKC/latest/mskc/API_ConnectorSummary.html"
_CONN = {"connectorArn": "arn:aws:kafkaconnect:us-east-1:111111111111:connector/c"}
flag("aws.cb.mskconnect.tls_to_cluster", "mskconnect_connector", "MSK Connect connector encrypts traffic to the cluster with TLS",
     "kafkaClusterEncryptionInTransit.encryptionType", rows=[P + "kafka_connector_in_transit_encryption_enabled", C + "mskconnect_connector_encryption_in_transit_with_tls_enabled"],
     severity="medium", remediation="Recreate the connector with kafkaClusterEncryptionInTransit encryptionType TLS.", sentinel="connectorArn", base=_CONN,
     good="TLS", bad="PLAINTEXT", expected=str, docs=[D_MSKC], control="SC-8")


@install("aws.cb.mskconnect.log_delivery", "mskconnect_connector", "MSK Connect connector has log delivery configured",
    {**_CONN, "logDelivery": {"workerLogDelivery": {"cloudWatchLogs": {"enabled": True, "logGroup": "g"}}}}, dict(_CONN),
    rows=[C + "mskconnect_connector_logging_enabled"], severity="medium", control="AU-2", remediation="Configure worker log delivery for the connector.", docs=[D_MSKC],
    note="Steampipe: log_delivery IS NOT NULL. ConnectorSummary omits logDelivery when it is not configured.")
def mskc_logs(item, index):
    value = absent_or(item, "connectorArn", "logDelivery", None, dict)
    return result(value is None, log_delivery=bool(value))


# =========================================================================== SNS
D_SNS = "https://docs.aws.amazon.com/sns/latest/api/API_GetTopicAttributes.html"
TOPIC = "arn:aws:sns:us-east-1:111111111111:t"


def _topic(policy=None, **attrs):
    body = {"TopicArn": TOPIC, **attrs}
    if policy is not None:
        body["Policy"] = policy
    return {"TopicArn": TOPIC, "Attributes": {"Attributes": body}}


def _attrs(item):
    attrs = get(item, "Attributes.Attributes", dict)
    get(attrs, "TopicArn" if "TopicArn" in attrs else "QueueArn", str)
    return attrs


def _topic_policy(item):
    attrs = _attrs(item)
    # GetTopicAttributes properties depend on caller authorization. TopicArn
    # authenticates identity, but cannot prove an omitted policy is absent.
    return policy_document(get(attrs, "Policy"))


def _stmt(principal, action="sns:Publish", condition=None, effect="Allow"):
    s = {"Effect": effect, "Principal": principal, "Action": action, "Resource": TOPIC}
    if condition is not None:
        s["Condition"] = condition
    return s


def _doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


OWN = _doc(_stmt({"AWS": "arn:aws:iam::111111111111:root"}))
PUBLIC = _doc(_stmt("*"))
_FEEDBACK = ("ApplicationFailureFeedbackRoleArn", "FirehoseFailureFeedbackRoleArn", "HTTPFailureFeedbackRoleArn", "LambdaFailureFeedbackRoleArn", "SQSFailureFeedbackRoleArn")


@install("aws.cb.sns.failure_feedback_role", "sns_topic", "SNS topic logs delivery status with a failure feedback role",
    _topic(OWN, LambdaFailureFeedbackRoleArn="arn:aws:iam::111111111111:role/f"), _topic(OWN),
    rows=[C + "sns_topic_notification_delivery_status_enabled"], severity="medium", control="AU-2",
    remediation="Configure delivery status logging (a *FailureFeedbackRoleArn) for the topic's subscription protocols.",
    docs=["https://docs.aws.amazon.com/sns/latest/dg/sns-topic-attributes.html"])
def sns_feedback(item, index):
    attrs = _attrs(item)
    configured = [k for k in _FEEDBACK if attrs.get(k)]
    return result(not configured, failure_feedback_roles=configured)


@install("aws.cb.sns.policy_no_unrestricted_wildcard", "sns_topic", "SNS topic policy has no unrestricted wildcard-principal Allow",
    _topic(OWN), _topic(PUBLIC), rows=[C + "sns_topic_policy_prohibit_public_access", C + "sns_topic_policy_prohibit_cross_account_access"],
    severity="high", category="exposure", control="AC-3", remediation="Remove wildcard principals or restrict them with aws:SourceAccount, aws:SourceArn or aws:PrincipalOrgID conditions.",
    docs=[D_SNS], extra={"no_policy": _topic(None)},
    note="Both aws-compliance queries select Allow statements with Principal AWS [\"*\"] and no restricting SourceOwner/SourceAccount/PrincipalOrgID/PrincipalAccount/PrincipalArn/SourceArn condition; the cross-account query only differs in counting. A topic without a policy is ok.")
def sns_public_c(item, index):
    statements = _topic_policy(item)
    if statements is None:
        return result(False, policy=None)
    hits = turbot_public_statements(statements)
    return result(bool(hits), public_statements=len(hits))


@install("aws.cb.sns.policy_prohibit_public_access_perimeter", "sns_topic", "SNS topic policy does not allow public access (perimeter)",
    _topic(OWN), _topic(PUBLIC), rows=[X + "sns_topic_policy_prohibit_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Remove wildcard principals or add restricting conditions to the topic policy.", docs=[D_SNS], extra={"not_applicable": _topic(None)},
    note="aws-perimeter resource_policy_public_sql; a topic without a readable policy is info (NOT_APPLICABLE).")
def sns_public_x(item, index):
    statements = _topic_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(statements)
    return result(bool(hits), public_statements=len(hits))


def _unconditioned_actions(statements, actions):
    hits = []
    for s in statements:
        if s.get("Effect") != "Allow" or not wildcard_principal(s) or s.get("Condition") is not None:
            continue
        acts = [a.lower() for a in _as_list(s.get("Action")) if isinstance(a, str)]
        if any(a in actions for a in acts):
            hits.append(s)
    return hits


for _cid, _row, _actions, _title in (
    ("aws.cb.sns.policy_no_public_publish", "sns_topic_policy_prohibit_publishing_access", ("sns:publish",), "SNS topic policy does not let everyone publish without conditions"),
    ("aws.cb.sns.policy_no_public_subscribe", "sns_topic_policy_prohibit_subscription_access", ("sns:subscribe", "sns:receive"), "SNS topic policy does not let everyone subscribe or receive without conditions"),
):
    def _sns_action(cid, row, actions, title):
        failing = _topic(_doc(_stmt("*", action=[a.replace("sns:", "SNS:").title().replace("Sns:", "SNS:") for a in actions])))

        @install(cid, "sns_topic", title, _topic(OWN), failing, rows=[C + row], severity="high", category="exposure", control="AC-3",
            remediation="Remove unconditioned wildcard-principal Allow statements for " + ", ".join(actions) + ".", docs=[D_SNS], extra={"no_policy": _topic(None)},
            note="Matches lowercased explicit actions " + ", ".join(actions) + " (policy_std); wildcard actions such as sns:* are not matched upstream.")
        def evaluate(item, index):
            statements = _topic_policy(item)
            if statements is None:
                return result(False, policy=None)
            hits = _unconditioned_actions(statements, actions)
            return result(bool(hits), statements=len(hits))
    _sns_action(_cid, _row, _actions, _title)


def prowler_sns_public(statements, audited_account):
    for statement in statements:
        if statement.get("Effect") == "Allow" and has_public_principal(statement):
            if has_restrictive_source_arn_condition(statement):
                return False
            if "Condition" in statement:
                cond = statement["Condition"]
                if is_condition_block_restrictive(cond, audited_account) or is_condition_block_restrictive_organization(cond) or is_condition_block_restrictive_sns_endpoint(cond):
                    continue
                return True
            return True
    return False


@install("aws.cb.sns.topic_not_publicly_accessible_prowler", "sns_topic", "SNS topic is not publicly accessible",
    _topic(_doc(_stmt("*", condition={"StringEquals": {"aws:SourceOwner": ACCOUNT}}))), _topic(PUBLIC),
    rows=[P + "sns_topics_not_publicly_accessible"], severity="high", category="exposure", control="AC-3",
    remediation="Restrict public principals with aws:SourceArn, aws:SourceAccount, aws:PrincipalOrgID or endpoint conditions.", docs=[D_SNS],
    extra={"index": CTX}, note="Prowler loop semantics: a public statement with a restrictive aws:SourceArn condition ends evaluation as PASS (break).")
def sns_public_p(item, index):
    statements = _topic_policy(item)
    if not statements:
        return result(False, policy=None)
    public = prowler_sns_public(statements, account(index))
    return result(public, public=public)


@install("aws.cb.sns.subscription_not_http", "sns_subscription", "Confirmed SNS subscription does not use plain HTTP",
    {"SubscriptionArn": TOPIC + ":s", "Protocol": "https", "TopicArn": TOPIC}, {"SubscriptionArn": TOPIC + ":s", "Protocol": "http", "TopicArn": TOPIC},
    rows=[P + "sns_subscription_not_using_http_endpoints"], severity="high", control="SC-8", remediation="Replace the http subscription with an https endpoint.",
    docs=["https://docs.aws.amazon.com/sns/latest/api/API_ListSubscriptions.html"], extra={"not_applicable": {"SubscriptionArn": "PendingConfirmation", "Protocol": "http"}})
def sns_http(item, index):
    arn = get(item, "SubscriptionArn", str)
    if arn == "PendingConfirmation":
        return "NOT_APPLICABLE", {"subscription_arn": arn}
    protocol = get(item, "Protocol", str)
    return result(protocol == "http", protocol=protocol)


# =========================================================================== SQS
D_SQS = "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html"
QUEUE = "arn:aws:sqs:us-east-1:111111111111:q"


def _queue(policy=None, **attrs):
    body = {"QueueArn": QUEUE, **attrs}
    if policy is not None:
        body["Policy"] = policy
    return {"QueueUrl": "https://sqs/q", "Attributes": {"Attributes": body}}


def _queue_policy(item):
    attrs = get(item, "Attributes.Attributes", dict)
    get(attrs, "QueueArn", str)
    if "Policy" not in attrs and "Policy" not in attrs.get("_coverage", {}):
        return None
    return policy_document(get(attrs, "Policy"))


SQS_PUBLIC = _doc({"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Resource": QUEUE})
SQS_OWN = _doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"}, "Action": "sqs:*", "Resource": QUEUE})


@install("aws.cb.sqs.dead_letter_queue", "sqs_queue", "SQS queue has a dead-letter queue (redrive policy)",
    _queue(RedrivePolicy='{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:111111111111:dlq","maxReceiveCount":5}'), _queue(),
    rows=[C + "sqs_queue_dead_letter_queue_configured"], severity="low", control="CP-10", remediation="Configure a RedrivePolicy pointing to a dead-letter queue.",
    docs=["https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html"],
    note="GetQueueAttributes(All) omits RedrivePolicy when unset; QueueArn proves the attributes were read.")
def sqs_dlq(item, index):
    value = absent_or(get(item, "Attributes.Attributes", dict), "QueueArn", "RedrivePolicy", None, str)
    return result(not value, redrive_policy=bool(value))


@install("aws.cb.sqs.cmk_encryption", "sqs_queue", "SQS queue is encrypted with a KMS key other than alias/aws/sqs",
    _queue(KmsMasterKeyId=KMS_ARN), _queue(KmsMasterKeyId="alias/aws/sqs"),
    rows=[C + "sqs_queue_encrypted_with_kms_cmk"], severity="medium", control="SC-28", remediation="Set KmsMasterKeyId to a customer managed KMS key.", docs=[D_SQS],
    note="Steampipe: KmsMasterKeyId null or 'alias/aws/sqs' alarms (SQS-managed SSE also alarms).")
def sqs_cmk(item, index):
    value = absent_or(get(item, "Attributes.Attributes", dict), "QueueArn", "KmsMasterKeyId", None, str)
    return result(not value or value == "alias/aws/sqs", kms_master_key_id=value)


@install("aws.cb.sqs.policy_no_wildcard_allow", "sqs_queue", "SQS queue policy has no wildcard-principal Allow",
    _queue(SQS_OWN), _queue(SQS_PUBLIC), rows=[C + "sqs_queue_policy_prohibit_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Remove Allow statements for Principal \"*\" from the queue policy.", docs=[D_SQS], extra={"no_policy": _queue()},
    note="aws-compliance ignores conditions; a queue without a policy is ok.")
def sqs_public_c(item, index):
    statements = _queue_policy(item)
    if statements is None:
        return result(False, policy=None)
    hits = wildcard_allow_statements(statements)
    return result(bool(hits), statements=len(hits))


@install("aws.cb.sqs.policy_prohibit_public_access_perimeter", "sqs_queue", "SQS queue policy does not allow public access (perimeter)",
    _queue(SQS_OWN), _queue(SQS_PUBLIC), rows=[X + "sqs_queue_policy_prohibit_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Remove wildcard principals or add restricting conditions to the queue policy.", docs=[D_SQS], extra={"not_applicable": _queue()},
    note="aws-perimeter resource_policy_public_sql; no policy is info (NOT_APPLICABLE).")
def sqs_public_x(item, index):
    statements = _queue_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(statements)
    return result(bool(hits), statements=len(hits))


def prowler_sqs_public(statements, audited_account):
    for s in statements:
        if s.get("Effect") != "Allow" or "Principal" not in s:
            continue
        principal = s["Principal"]
        star = (isinstance(principal, (str, list, dict)) and "*" in principal) or (
            isinstance(principal, dict) and any(isinstance(principal.get(k), (str, list)) and "*" in principal.get(k) for k in ("AWS", "CanonicalUser")))
        if not star:
            continue
        if "Condition" in s:
            if is_condition_block_restrictive(s["Condition"], audited_account, True):
                continue
            return True
        return True
    return False


@install("aws.cb.sqs.queue_not_public_prowler", "sqs_queue", "SQS queue is not publicly accessible",
    _queue(_doc({"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT}}})), _queue(SQS_PUBLIC),
    rows=[P + "sqs_queues_not_publicly_accessible"], severity="critical", category="exposure", control="AC-3",
    remediation="Restrict wildcard principals with account-scoped conditions or remove them.", docs=[D_SQS], extra={"index": CTX, "no_policy": _queue()})
def sqs_public_p(item, index):
    statements = _queue_policy(item)
    if not statements:
        return result(False, policy=None)
    public = prowler_sqs_public(statements, account(index))
    return result(public, public=public)


# =========================================================================== SES
D_SES = "https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_GetEmailIdentity.html"
IDENT = {"IdentityName": "example.com"}


def _ses(**detail):
    return {**IDENT, "Identity": {"IdentityType": "DOMAIN", **detail}}


@install("aws.cb.ses.dkim_signing", "ses_email_identity", "SES identity has successful DKIM verification and signing enabled",
    _ses(DkimAttributes={"Status": "SUCCESS", "SigningEnabled": True}), _ses(DkimAttributes={"Status": "SUCCESS", "SigningEnabled": False}),
    rows=[P + "ses_identity_dkim_enabled"], severity="medium", control="SC-8", remediation="Configure Easy DKIM (or BYODKIM), publish the DNS records and enable DKIM signing.", docs=[D_SES])
def ses_dkim(item, index):
    status = get(item, "Identity.DkimAttributes.Status", str)
    signing = get(item, "Identity.DkimAttributes.SigningEnabled", bool)
    return result(not (status == "SUCCESS" and signing), dkim_status=status, signing_enabled=signing)


@install("aws.cb.ses.identity_policies_not_public", "ses_email_identity", "SES identity sending authorization policies are not public",
    _ses(Policies={"p": json.dumps(_doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::222222222222:root"}, "Action": "ses:SendEmail", "Resource": "*"}))}),
    _ses(Policies={"p": json.dumps(_doc({"Effect": "Allow", "Principal": "*", "Action": "ses:SendEmail", "Resource": "*"}))}),
    rows=[P + "ses_identity_not_publicly_accessible"], severity="high", category="exposure", control="AC-3",
    remediation="Restrict SES sending authorization policies to specific principals or add restricting conditions.", docs=[D_SES],
    extra={"index": CTX, "not_applicable": _ses(Policies={}),
           "manual": _ses(Policies={"p": json.dumps(_doc({"Effect": "Allow", "Principal": "*", "Action": "ses:SendEmail", "Resource": "*"}, {"Effect": "Deny", "Principal": "*", "Action": "ses:SendEmail", "Resource": "*"}))})},
    note="Prowler: identities without policies yield no finding (NOT_APPLICABLE); a public Allow alongside any explicit Deny is MANUAL.")
def ses_public(item, index):
    policies = get(item, "Identity.Policies", dict)
    if not policies:
        return "NOT_APPLICABLE", {"policies": 0}
    docs = [policy_document(v) for v in policies.values()]
    public = any(is_policy_public(statements, account(index)) for statements in docs)
    if public and any(s.get("Effect") == "Deny" for statements in docs for s in statements):
        return "MANUAL", {"question": "Does the explicit Deny neutralise the public Allow in the SES identity policy?"}
    return result(public, public=public)


# =========================================================================== Step Functions
D_SFN = "https://docs.aws.amazon.com/step-functions/latest/apireference/API_DescribeStateMachine.html"
SM = {"stateMachineArn": "arn:aws:states:us-east-1:111111111111:stateMachine:s"}


@install("aws.cb.sfn.logging_not_off", "sfn_state_machine", "Step Functions state machine logging level is not OFF",
    {**SM, "loggingConfiguration": {"level": "ERROR"}}, {**SM, "loggingConfiguration": {"level": "OFF"}},
    rows=[C + "sfn_state_machine_logging_enabled"], severity="medium", control="AU-2", remediation="Set the state machine loggingConfiguration level to ALL, ERROR or FATAL with a log destination.", docs=[D_SFN],
    extra={"no_config": {**SM}}, note="Steampipe alarms only when level = OFF; no logging configuration is ok upstream.")
def sfn_logging_c(item, index):
    config = absent_or(item, "stateMachineArn", "loggingConfiguration", None, dict)
    level = config.get("level") if config else None
    return result(level == "OFF", level=level)


@install("aws.cb.stepfunctions.logging_enabled", "sfn_state_machine", "Step Functions state machine has logging configured and not OFF",
    {**SM, "loggingConfiguration": {"level": "ALL"}}, {**SM}, rows=[P + "stepfunctions_statemachine_logging_enabled"], severity="medium", control="AU-2",
    remediation="Configure state machine logging at level ALL, ERROR or FATAL.", docs=[D_SFN], note="Prowler: missing configuration or level OFF fails.")
def sfn_logging_p(item, index):
    config = absent_or(item, "stateMachineArn", "loggingConfiguration", None, dict)
    level = config.get("level") if config else None
    return result(not config or level == "OFF", level=level)


@install("aws.cb.stepfunctions.cmk_encryption", "sfn_state_machine", "Step Functions state machine is encrypted with a customer managed KMS key",
    {**SM, "encryptionConfiguration": {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": KMS_ARN}}, {**SM, "encryptionConfiguration": {"type": "AWS_OWNED_KEY"}},
    rows=[P + "stepfunctions_statemachine_encrypted_with_cmk"], severity="medium", control="SC-28", remediation="Configure encryptionConfiguration type CUSTOMER_MANAGED_KMS_KEY.", docs=[D_SFN])
def sfn_cmk(item, index):
    config = absent_or(item, "stateMachineArn", "encryptionConfiguration", None, dict)
    kind = config.get("type") if config else None
    return result(kind != "CUSTOMER_MANAGED_KMS_KEY", encryption_type=kind)


# =========================================================================== Transfer Family
D_TR = "https://docs.aws.amazon.com/transfer/latest/APIReference/API_DescribedServer.html"
SRV = {"ServerId": "s-1", "Server": {"Arn": "arn:aws:transfer:us-east-1:111111111111:server/s-1"}}
PQC = ("TransferSecurityPolicy-2025-03", "TransferSecurityPolicy-FIPS-2025-03", "TransferSecurityPolicy-AS2Restricted-2025-07")


def _srv(**server):
    return {**SRV, "Server": {**SRV["Server"], **server}}


@install("aws.cb.transfer.no_ftp_protocol", "transfer_server", "Transfer Family server does not enable plain FTP",
    _srv(Protocols=["SFTP"]), _srv(Protocols=["SFTP", "FTP"]), rows=[P + "transfer_server_in_transit_encryption_enabled", C + "transfer_server_no_ftp_protocol"],
    severity="high", control="SC-8", remediation="Remove FTP from the server protocols and use SFTP or FTPS.", docs=[D_TR])
def tr_ftp(item, index):
    protocols = strings(get(item, "Server.Protocols", list))
    return result("FTP" in protocols, protocols=protocols)


@install("aws.cb.transfer.fips_security_policy", "transfer_server", "Transfer Family server uses a FIPS security policy",
    _srv(SecurityPolicyName="TransferSecurityPolicy-FIPS-2024-01"), _srv(SecurityPolicyName="TransferSecurityPolicy-2024-01"),
    rows=[P + "transfer_server_fips_security_policy_enabled"], severity="medium", control="SC-13", remediation="Attach a TransferSecurityPolicy-FIPS-* security policy.",
    docs=["https://docs.aws.amazon.com/transfer/latest/userguide/security-policies.html"], note="Prowler: 'FIPS' is a dash-separated token of SecurityPolicyName; unretrieved policy is MANUAL upstream and UNKNOWN here.")
def tr_fips(item, index):
    name = get(item, "Server.SecurityPolicyName", str)
    if not name:
        raise Unavailable("security policy not retrieved")
    return result("FIPS" not in name.split("-"), security_policy=name)


@install("aws.cb.transfer.pqc_ssh_kex_policy", "transfer_server", "Transfer Family server uses a post-quantum hybrid SSH key exchange policy",
    _srv(SecurityPolicyName="TransferSecurityPolicy-2025-03"), _srv(SecurityPolicyName="TransferSecurityPolicy-2024-01"),
    rows=[P + "transfer_server_pqc_ssh_kex_enabled"], severity="low", control="SC-13", remediation="Attach one of " + ", ".join(PQC) + ".",
    docs=["https://docs.aws.amazon.com/transfer/latest/userguide/security-policies.html"], note="Prowler default transfer_pqc_ssh_allowed_policies allowlist.")
def tr_pqc(item, index):
    name = absent_or(item, "ServerId", "Server.SecurityPolicyName", None, str)
    return result(name not in PQC, security_policy=name, allowed=list(PQC))


@install("aws.cb.transfer.connector_logging_role", "transfer_connector", "Transfer Family connector has a CloudWatch logging role",
    {"ConnectorId": "c-1", "Connector": {"Arn": "a", "LoggingRole": "arn:aws:iam::111111111111:role/l"}}, {"ConnectorId": "c-1", "Connector": {"Arn": "a"}},
    rows=[C + "transfer_connector_logging_enabled"], severity="medium", control="AU-2", remediation="Assign a LoggingRole to the connector.",
    docs=["https://docs.aws.amazon.com/transfer/latest/APIReference/API_DescribedConnector.html"])
def tr_conn(item, index):
    role = absent_or(get(item, "Connector", dict), "Arn", "LoggingRole", None, str)
    return result(not role, logging_role=role)
