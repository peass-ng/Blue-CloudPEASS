import { AWS_REVIEWED_CHECK_IDS, AWS_SCALAR_EVIDENCE_REVIEW, AWS_GUARDDUTY_PROTECTION_LABELS } from "./awsReviewedCheckIds";

const label = (key: string) =>
  key.replaceAll("_", " ").replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\bKms\b/g, "KMS").replace(/\bId\b/g, "ID");
const concise = (value: string) =>
  value.length > 120 ? `${value.slice(0, 117)}…` : value;
const sensitive = (key: string) =>
  /(?:secret|password|private.?key|credential|access.?token|refresh.?token|session.?token|api.?key|sa_json)/i.test(key);
const bracketedIpv6 = (value: string) => /^\[[0-9a-fA-F:.%]+\](?::\d{1,5})?$/.test(value);
const structuredText = (value: string) =>
  /^[\[{]/.test(value.trim()) && !bracketedIpv6(value.trim());
const scalarItem = (value: unknown) =>
  typeof value === "number" || typeof value === "boolean" ||
  (typeof value === "string" && !structuredText(value));

/** Finding-specific next action, including reports archived before concise guidance. */
export function explainExposureAction(evidence: unknown, status: string): string {
  const item = evidence && typeof evidence === "object" && !Array.isArray(evidence)
    ? evidence as Record<string, unknown> : {};
  if (["UNKNOWN", "DENIED", "MANUAL", "EMPTY"].includes(status))
    return "Collect the missing configuration before deciding whether access needs to change.";
  if (status === "PASS") return "Keep the access restrictions in place.";
  if (item.exposure_kind === "external_share" || Array.isArray(item.external_scope_ids) && item.external_scope_ids.length)
    return "Restrict snapshot restore access to the accounts that need it.";
  if (item.data_exposure) {
    const source = item.source && typeof item.source === "object" ? item.source as Record<string, unknown> : {};
    if (["rds_snapshot", "rds_cluster_snapshot"].includes(String(source.resource_type)))
      return "Remove public snapshot restore access; share only with the accounts that need it.";
    return "If public data access is unnecessary, restrict the granting policy or ACL to the readers that need it.";
  }
  if (item.exposure_kind === "control_plane")
    return "Restrict control-plane access to the source networks that need it.";
  return "Consider whether this endpoint needs internet access; restrict unnecessary source networks or ports.";
}

/** The internet path check describes one asset. Surface its decisive facts first. */
export function explainInternetExposure(evidence: unknown, status: string): { summary: string; reasons: string[] } {
  const item = evidence && typeof evidence === "object" && !Array.isArray(evidence)
    ? evidence as Record<string, unknown> : {};
  const strings = (value: unknown) => Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string" && !!entry).slice(0, 8) : [];
  const ports = strings(item.exposed_ports);
  const addresses = strings(item.public_addresses);
  const external = strings(item.external_scope_ids);
  const path = Array.isArray(item.path) ? item.path.filter((step): step is Record<string, unknown> =>
    !!step && typeof step === "object" && !Array.isArray(step)) : [];
  const unresolved = Array.isArray(item.unresolved) ? item.unresolved.filter((step): step is Record<string, unknown> =>
    !!step && typeof step === "object" && !Array.isArray(step)) : [];
  const gaps = Array.isArray(item.gaps) ? item.gaps.filter((step): step is Record<string, unknown> =>
    !!step && typeof step === "object" && !Array.isArray(step)) : [];
  const location = addresses.length ? ` at ${addresses.slice(0, 2).join(", ")}${addresses.length > 2 ? " and other addresses" : ""}` : "";
  let summary: string;
  if (status === "FAIL") {
    if (external.length) summary = `Snapshot restore access is granted to external accounts: ${external.join(", ")}.`;
    else if (item.data_exposure) summary = `Public data access is allowed${location}.`;
    else if (ports.length) summary = `Internet access to ${ports.join(", ")}${location} is allowed.`;
    else summary = `Public access${location} is allowed.`;
    if (typeof item.observed === "string" && item.observed.trim()) summary = item.observed.trim();
    else if (unresolved.length) summary += " Some path layers remain unresolved.";
  } else if (status === "PASS") {
    summary = typeof item.blocked_by === "string" && item.blocked_by
      ? `Public path${location} is blocked by ${label(item.blocked_by)}.`
      : `No open public path was found${location}.`;
  } else {
    summary = `Internet exposure for this asset could not be determined${location}.`;
  }
  const reasons = status === "UNKNOWN" || unresolved.length > 0
    ? [
        ...unresolved.map((step) => [step.layer, step.reason].filter((part) => typeof part === "string" && part).join(": ")),
        ...gaps.map((step) => [step.type, step.status].filter((part) => typeof part === "string" && part).join(": ")),
        ...(typeof item.reason === "string" ? [item.reason] : []),
      ]
    : path.filter((step) => status === "PASS" && step.decision === "block")
      .map((step) => {
        const detail = typeof step.reason === "string" ? step.reason :
          typeof step.source_ranges === "string" ? step.source_ranges :
          Array.isArray(step.source_ranges) ? step.source_ranges.join(", ") : "";
        return [step.layer, detail].filter((part) => typeof part === "string" && part).join(": ");
      });
  return { summary, reasons: [...new Set(reasons)].slice(0, 5).map((reason) => concise(reason)) };
}

function valueText(value: unknown): string | undefined {
  if (typeof value === "string") return concise(value.trim()) || undefined;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  if (Array.isArray(value) && value.length) {
    const preview = value.slice(0, 3);
    if (preview.every(scalarItem))
      return `${preview.map((item) => concise(String(item))).join(", ")}${value.length > 3 ? `; ${value.length - 3} more supplied` : ""}`;
  }
  return undefined;
}

function scalarFacts(evidence: Record<string, unknown>): string[] {
  const facts: string[] = [];
  let inspected = 0;
  const visit = (value: unknown, path: string[], depth: number) => {
    if (facts.length >= 4 || inspected++ >= 40 || depth > 4) return;
    const key = path.at(-1) || "Value";
    if (path.some(sensitive)) return;
    const name = path.filter((part) => !/^(attributes|properties|data|value)$/i.test(part))
      .map(label).join(" ") || label(key);
    if (value === "") {
      facts.push(`${name} is empty in the supplied snapshot`);
      return;
    }
    if (value === null) {
      facts.push(`${name} has no recorded value`);
      return;
    }
    if (typeof value === "string" && structuredText(value)) {
      try {
        visit(JSON.parse(value), path, depth + 1);
      } catch {
        facts.push(`${name} contains a structured value that could not be summarized`);
      }
      return;
    }
    const readable = valueText(value);
    if (readable) {
      facts.push(["reason", "message", "semantics"].includes(key)
        ? `${name}: ${readable}` : `${name} is ${readable}`);
      return;
    }
    if (Array.isArray(value)) {
      facts.push(`${name} contains ${value.length} supplied record${value.length === 1 ? "" : "s"}`);
      for (const [index, item] of value.slice(0, 2).entries())
        if (typeof item === "string" && structuredText(item) || item && typeof item === "object")
          visit(item, [...path, `item ${index + 1}`], depth + 1);
      return;
    }
    if (value && typeof value === "object")
      for (const [child, item] of Object.entries(value)) visit(item, [...path, child], depth + 1);
  };
  for (const [key, value] of Object.entries(evidence).sort(([a], [b]) =>
    Number(["reason", "message", "semantics"].includes(b)) -
    Number(["reason", "message", "semantics"].includes(a)))) visit(value, [key], 0);
  return facts;
}

function firewallObservation(record: Record<string, unknown>, status: string): string | undefined {
  if (!Array.isArray(record.matching_allow_entries)) return undefined;
  if (["UNKNOWN", "DENIED", "MANUAL"].includes(status.toUpperCase()))
    return "This firewall rule's ingress permissions could not be determined from the collected configuration.";
  const requested = Array.isArray(record.ports) ? record.ports.filter((port): port is number =>
    typeof port === "number" && Number.isInteger(port) && port >= 0 && port <= 65535) : [];
  const matches: string[] = [];
  for (const raw of record.matching_allow_entries) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const entry = raw as Record<string, unknown>;
    const protocol = typeof entry.protocol === "string" && /^(tcp|udp|sctp|icmp|icmpv6|all|\d{1,3})$/.test(entry.protocol)
      ? entry.protocol : undefined;
    if (!protocol || typeof entry.ports !== "string") continue;
    if (protocol === "all" && entry.ports === "all") {
      matches.push("all protocols and ports");
      continue;
    }
    const range = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(entry.ports);
    const low = range ? Number(range[1]) : 0;
    const high = range ? Number(range[2] || range[1]) : 65535;
    if (entry.ports !== "all" && (!range || high < low || high > 65535)) continue;
    if (requested.length) {
      for (const port of requested.filter((port) => port >= low && port <= high)) matches.push(`${protocol}/${port}`);
    } else matches.push(entry.ports === "all" ? `all ${protocol} ports` : low === high ? `${protocol}/${low}` : `${protocol}/${low}-${high}`);
  }
  const unique = [...new Set(matches)];
  if (!unique.length) return record.matching_allow_entries.length === 0
    ? "No allow entry matches the checked protocols and ports." : undefined;
  const sources = Array.isArray(record.source_ranges) ? record.source_ranges.filter((entry): entry is string =>
    typeof entry === "string" && entry.length > 0 && entry.length < 80) : [];
  const from = sources.length ? ` from ${sources.slice(0, 3).join(", ")}${sources.length > 3 ? " and other source ranges" : ""}` : "";
  return `This firewall rule allows ${unique.slice(0, 4).join(", ")}${unique.length > 4 ? " and other checked ports" : ""}${from}.`;
}

function nativeConfigurationObservation(record: Record<string, unknown>): string | undefined {
  const names = (value: unknown) => Array.isArray(value) && value.length > 0 && value.every((entry) => typeof entry === "string")
    ? `${value.slice(0, 3).map((entry) => concise(String(entry))).join(", ")}${value.length > 3 ? ` and ${value.length - 3} more` : ""}` : undefined;
  if (Array.isArray(record.matching_ingress)) {
    const rule = record.matching_ingress.find((entry) => entry && typeof entry === "object" &&
      entry.protocol === "tcp" && Array.isArray(entry.ports) && entry.ports.length && Array.isArray(entry.source_ranges));
    if (rule) {
      const ports = rule.ports.filter((port: unknown) => typeof port === "number" && Number.isInteger(port) && port >= 0 && port <= 65535);
      const sources = rule.source_ranges.filter((source: unknown) => source === "0.0.0.0/0" || source === "::/0");
      if (ports.length && sources.length)
        return `A security-group rule allows ${ports.slice(0, 4).map((port: number) => `tcp/${port}`).join(", ")} from ${sources.join(", ")}.`;
    }
  }
  if (["Encrypted", "StorageEncrypted", "IsEncrypted"].includes(String(record.field)) && typeof record.configured === "boolean")
    return `Encryption is ${record.configured ? "enabled" : "disabled"}.`;
  if (record.field === "AssociatePublicIpAddress" && typeof record.configured === "boolean")
    return `Automatic public-IP assignment is ${record.configured ? "enabled" : "disabled"}.`;
  if (record.field === "SSEDescription.Status" && ["ENABLED", "DISABLED", "ENABLING"].includes(String(record.configured)))
    return `DAX storage encryption is ${String(record.configured).toLowerCase()}.`;
  if (record.field === "ClusterEndpointEncryptionType" && ["NONE", "TLS"].includes(String(record.configured)))
    return record.configured === "TLS" ? "The DAX endpoint uses TLS." : "The DAX endpoint does not use TLS.";
  const securityGroups = names(record.open_security_groups);
  if (record.publicly_accessible === true && securityGroups)
    return `The public instance has Internet-wide ingress allowed by security groups ${securityGroups}.`;
  const noLogs = names(record.containers_without_log_driver);
  if (noLogs) return `No log driver is configured for containers ${noLogs}.`;
  const volumes = names(record.unencrypted_volumes);
  if (volumes) return `EBS volumes ${volumes} are not encrypted.`;
  const dataSources = names(record.data_sources_without_cmk);
  if (dataSources) return `Data sources ${dataSources} have no configured KMS key ARN.`;
  if (typeof record.s3_logs_encryption_disabled === "boolean")
    return `The S3 log configuration ${record.s3_logs_encryption_disabled ? "disables" : "enables"} explicit export encryption.`;
  if (typeof record.key_manager === "string") return `The encryption key manager is ${concise(record.key_manager)}${typeof record.key_enabled === "boolean" ? `; the key is ${record.key_enabled ? "enabled" : "disabled"}` : ""}.`;
  if (typeof record.s3_encryption_mode === "string") return `The configured S3 encryption mode is ${concise(record.s3_encryption_mode)}.`;
  if (record.local_disk_encryption === null) return "No local-disk encryption configuration was reported.";
  const booleans: [string, string][] = [
    ["encrypted", "Storage encryption"], ["storage_encrypted", "Storage encryption"],
    ["atRestEncryptionEnabled", "Cache encryption at rest"], ["transitEncryptionEnabled", "Cache encryption in transit"],
    ["enable_network_policy", "Network-policy support"],
    ["local_disk_encryption", "Local-disk encryption configuration"],
    ["enable_in_transit_encryption", "In-transit encryption in the security configuration"],
    ["enable_at_rest_encryption", "At-rest encryption in the security configuration"],
    ["associate_public_ip_address", "Automatic public-IP assignment"],
    ["map_public_ip_on_launch", "Subnet automatic public-IP assignment"],
  ];
  for (const [key, subject] of booleans)
    if (typeof record[key] === "boolean") return `${subject} is ${record[key] ? "enabled" : "disabled"}.`;
  const namedLists: [string, string][] = [
    ["insecure_protocols", "Configured listener protocols"], ["deprecated_origin_protocols", "Configured deprecated origin protocols"],
    ["unencrypted_origins", "Origins with a modeled HTTP path"], ["non_acm_issued", "Certificates not reported as Amazon-issued"],
    ["non_fips_policies", "Listener policies without the FIPS marker"], ["insecure_policies", "Listener policies outside the reviewed secure list"],
    ["non_recommended_policies", "Listener policies outside the reviewed recommendation list"],
    ["blocking_containers", "Containers with blocking logging mode"], ["root_containers", "Nonprivileged host-network containers declaring root or no user"],
    ["public_mount_targets", "Mount targets in subnets with a modeled Internet-gateway route"],
    ["public_subnets", "Subnets with an Internet-gateway default route"],
    ["public_access_cidrs", "Configured public endpoint source ranges"],
    ["logging_levels", "Configured method logging levels"],
  ];
  for (const [key, subject] of namedLists) {
    const values = names(record[key]);
    if (values) return `${subject}: ${values}.`;
  }
  if (record.cloudfront_default_certificate === true) return "The distribution uses the default CloudFront certificate.";
  if (record.assign_public_ip === "ENABLED" || record.assign_public_ip === "DISABLED")
    return `Public-IP assignment is ${String(record.assign_public_ip).toLowerCase()}.`;
  if (record.enforces_ssl === false) return "No policy statement matching the checked non-TLS Deny condition was found.";
  if (record.public_policy === true) return "The resource policy contains a modeled public access grant.";
  if (typeof record.public_allow_statements === "number" && record.public_allow_statements > 0)
    return `The resource policy contains ${record.public_allow_statements} modeled public Allow statement${record.public_allow_statements === 1 ? "" : "s"}.`;
  if (record.authorizers === 0) return "No API authorizer is configured.";
  if (typeof record.export_encryption_disabled === "boolean")
    return `The S3 export configuration ${record.export_encryption_disabled ? "disables" : "enables"} explicit encryption.`;
  if (typeof record.tls === "string") return `The configured TLS mode is ${concise(record.tls)}.`;
  if (typeof record.minimum_protocol_version === "string") return `The viewer TLS policy is ${concise(record.minimum_protocol_version)}.`;
  if (typeof record.key_provider_type === "string") return `The local-disk key provider type is ${concise(record.key_provider_type)}.`;
  if (record.parameter === "require_secure_transport" || record.parameter === "rds.force_ssl")
    if (typeof record.value === "string") return `The ${record.parameter} setting is ${concise(record.value)}.`;
  if (record.server_audit_logging === "0") return "Database audit logging is disabled.";
  if (typeof record.public_allow_without_mount_target_condition === "number" && record.public_allow_without_mount_target_condition > 0)
    return `${record.public_allow_without_mount_target_condition} public Allow statement${record.public_allow_without_mount_target_condition === 1 ? " lacks" : "s lack"} the checked mount-target condition.`;
  if (record.scheme === "internet-facing") return "The load balancer is configured as internet-facing.";
  if (typeof record.master_public_dns_name === "string") return `The primary-node DNS name is ${concise(record.master_public_dns_name)}.`;
  if (typeof record.security_configuration === "string") {
    const modes = names(record.modes);
    if (modes) return `Configured S3 encryption modes: ${modes}.`;
  }
  if (record.managed_query_results === true) return "Managed query results are enabled.";
  if (typeof record.encryption_option === "string") return `The query-result encryption option is ${concise(record.encryption_option)}.`;
  if (record.encryption_option === null) return "No explicit query-result encryption option was reported.";
  const protocols = names(record.protocols);
  if (protocols) return `Configured protocols: ${protocols}.`;
  const actions = names(record.matching_actions);
  if (actions) return `Declared policy Allow actions matching this check: ${actions}.`;
  if (record.security_configuration === null && record.encryption_type_argument === null)
    return "No security configuration or fallback S3 encryption argument was reported.";
  if (Array.isArray(record.other_permitted_ranges)) {
    const ranges = record.other_permitted_ranges.filter((range): range is Record<string, unknown> =>
      !!range && typeof range === "object" && !Array.isArray(range) &&
      typeof range.MinRange === "number" && typeof range.MaxRange === "number");
    if (ranges.length) return `Public-access exceptions include ports ${ranges.slice(0, 3).map((range) =>
      range.MinRange === range.MaxRange ? range.MinRange : `${range.MinRange}-${range.MaxRange}`).join(", ")}.`;
  }
  if (record.components && typeof record.components === "object" && !Array.isArray(record.components)) {
    const components = record.components as Record<string, unknown>;
    const acl = components["aws.claude_a.s3.prowler_public_write_acl"];
    const policy = components["aws.claude_a.s3.prowler_policy_public_write"];
    if (typeof acl === "string" && typeof policy === "string") return `Public-write component results: ACL ${acl}; bucket policy ${policy}.`;
  }
  if (record.secret_encryption_configured === false || Array.isArray(record.encryption_config) && record.encryption_config.length === 0)
    return "No secrets encryption configuration is declared.";
  if (typeof record.environment_variables === "number" && record.environment_variables > 0 && record.kms_key_arn === null)
    return "The function has environment variables and no customer-managed KMS key ARN configured.";
  if (record.kms_key_id === "" && record.sqs_managed_sse === "false") return "Neither a KMS key nor SQS-managed encryption is configured.";
  if (record.standard_logging === false && record.realtime_log_config === null && record.v2_deliveries === 0)
    return "No standard, default-behavior real-time or v2 logging configuration was reported.";
  return undefined;
}

function reviewedAwsScalarObservation(checkId: string | undefined, record: Record<string, unknown>): string | undefined {
  const reviewed = checkId ? AWS_SCALAR_EVIDENCE_REVIEW[checkId] : undefined;
  if (!reviewed || record.field !== reviewed.field) return undefined;
  if (reviewed.boolean && typeof record.configured === "boolean")
    return `${reviewed.label} is ${record.configured ? "enabled" : "disabled"}.`;
  if (!reviewed.boolean && typeof record.configured === "string" && record.configured.trim() &&
      record.configured.length < 80 && !structuredText(record.configured))
    return `${reviewed.label} is ${concise(record.configured)}.`;
  return undefined;
}

function reviewedAwsObservation(checkId: string | undefined, record: Record<string, unknown>): string | undefined {
  if (!checkId || !AWS_REVIEWED_CHECK_IDS.has(checkId)) return undefined;
  const list = (value: unknown) => Array.isArray(value) && value.length && value.every((item) => typeof item === "string")
    ? value.slice(0, 3).map((item) => concise(String(item))).join(", ") + (value.length > 3 ? ` and ${value.length - 3} more` : "") : undefined;
  const number = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);
  if (checkId.startsWith("aws.a.accessanalyzer.")) {
    if (number(record.analyzer_count)) return `${record.analyzer_count} Access Analyzer analyzer${record.analyzer_count === 1 ? " is" : "s are"} present in this region.`;
    if (Array.isArray(record.analyzer_statuses)) return record.analyzer_statuses.length ? `Regional analyzer statuses: ${list(record.analyzer_statuses)}.` : "No Access Analyzer analyzer was found in the complete regional inventory.";
  }
  if (checkId === "aws.a.account.organization_member" && typeof record.organization_member === "boolean") return `This account ${record.organization_member ? "is" : "is not"} an AWS Organizations member.`;
  if (checkId === "aws.a.account.security_contact_present" && typeof record.security_contact_present === "boolean") return `An alternate security contact ${record.security_contact_present ? "is configured" : "is not configured"}.`;
  if (checkId.startsWith("aws.a.cloudtrail.")) {
    if (typeof record.bucket_access_logging === "boolean") return `The home trail's destination bucket has server access logging ${record.bucket_access_logging ? "configured" : "not configured"}.`;
    if (typeof record.kms_key_declared === "boolean") return `The home trail ${record.kms_key_declared ? "declares" : "does not declare"} a KMS key; default S3 encryption is separate.`;
    if (typeof record.delivery_at === "string" && typeof record.cutoff === "string") return `Recorded CloudWatch delivery: ${concise(record.delivery_at)}; required to be later than ${concise(record.cutoff)}.`;
    if (record.integration_declared === false) return "The home trail has no declared CloudWatch Logs integration.";
    if (record.delivery === "absent") return "No CloudWatch delivery timestamp is recorded for the home trail.";
    if (record.logging === false) return "Logging is disabled for the home trail.";
    if (record.logging === true && number(record.insight_selector_count)) return `The home trail has logging enabled and ${record.insight_selector_count} Insights selector${record.insight_selector_count === 1 ? "" : "s"}.`;
    if (Array.isArray(record.insight_selectors)) return `${record.insight_selectors.length} Insights selector${record.insight_selectors.length === 1 ? " is" : "s are"} configured on the logging trail.`;
    if (record.insight_selectors === "absent") return "No Insights selector is configured on the logging trail.";
  }
  if (checkId.startsWith("aws.a.cloudwatch.")) {
    if (checkId.endsWith("agentcore_data_protection")) {
      if (typeof record.data_protection_status === "string") return `The log group's data protection status is ${concise(record.data_protection_status)}.`;
      if (Array.isArray(record.inherited_properties)) return record.inherited_properties.includes("ACCOUNT_DATA_PROTECTION") ? "The log group inherits account-level data protection." : "No activated or inherited account-level data protection is recorded for this log group.";
    }
    if (typeof record.actions_enabled === "boolean") return `Alarm actions are ${record.actions_enabled ? "enabled" : "disabled"}.`;
    if (Array.isArray(record.alarm_actions)) return `${record.alarm_actions.length} ALARM-state action${record.alarm_actions.length === 1 ? " is" : "s are"} configured.`;
    if (record.state_actions && typeof record.state_actions === "object") {
      const actions = Object.entries(record.state_actions).filter(([, value]) => Array.isArray(value) && value.length);
      return actions.length ? `Configured alarm action states: ${actions.map(([key]) => key.replace(/Actions$/, "")).join(", ")}.` : "No ALARM, OK or INSUFFICIENT_DATA action is configured.";
    }
    if (Array.isArray(record.matching_roles)) return record.matching_roles.length ? "A role named CloudWatch-CrossAccountSharingRole is present; its effective trust is not assessed here." : "No role named CloudWatch-CrossAccountSharingRole was found.";
    if (checkId.endsWith("log_kms_encryption") && typeof record.kms_key_id === "string") return record.kms_key_id ? `A KMS key is associated with the log group: ${concise(record.kms_key_id)}.` : "No KMS key is associated with the log group; CloudWatch Logs default encryption still applies.";
    if (record.retention === "never_expire") return "The log group has no expiration configured.";
    if (number(record.retention_days)) return `Log retention is configured for ${record.retention_days} days.`;
  }
  if (checkId === "aws.a.kms.rotation_source_eligibility" && typeof record.rotation_enabled === "boolean") return `Automatic rotation is ${record.rotation_enabled ? "enabled" : "disabled"} for this eligible KMS key.`;
  if (checkId.startsWith("aws.b.ecr.")) {
    if (typeof record.image_tag_mutability === "string") return `The repository's tag mutability mode is ${concise(record.image_tag_mutability)}.`;
    if (record.lifecycle_policy === "absent") return "No lifecycle policy is configured for this repository.";
    if (Array.isArray(record.lifecycle_rules)) return `The lifecycle policy reports ${record.lifecycle_rules.length} rule${record.lifecycle_rules.length === 1 ? "" : "s"}; retention suitability is not assessed.`;
    if (typeof record.scan_on_push === "boolean") return `Basic image scan on push is ${record.scan_on_push ? "enabled" : "disabled"}.`;
    if (Array.isArray(record.matching_scanning_rules)) {
      const frequencies = record.matching_scanning_rules.flatMap(row => row && typeof row === "object" && typeof row.scan_frequency === "string" ? [row.scan_frequency] : []);
      return frequencies.length ? `Enhanced scan rules matching this repository configure ${[...new Set(frequencies)].join(", ")}.` : "No enhanced scanning rule matches this repository.";
    }
  }
  if (checkId.startsWith("aws.c2b.codebuild.")) {
    if (typeof record.project_visibility === "string") return `Build project visibility is ${concise(record.project_visibility)}.`;
    if (Array.isArray(record.credentials_in_source_urls)) {
      const positions = record.credentials_in_source_urls.flatMap(row => row && typeof row === "object" && typeof row.source === "string" && typeof row.credential === "string" ? [`${concise(row.source)} (${concise(row.credential)})`] : []);
      return positions.length ? `Credential-shaped Bitbucket source URLs: ${positions.join(", ")}; values are withheld.` : "No credential-shaped Bitbucket source URL matched this check.";
    }
    if (record.buildspec_file === null) return "No explicit buildspec path matches this check's filename pattern; author permissions are not assessed.";
    if (typeof record.buildspec_file === "string") return `The explicit buildspec path ${concise(record.buildspec_file)} matches this check's filename pattern.`;
    if (Array.isArray(record.unanchored_filters)) {
      const types = record.unanchored_filters.flatMap(row => row && typeof row === "object" && typeof row.type === "string" ? [row.type] : []);
      return types.length ? `Webhook filter types with unanchored alternatives: ${[...new Set(types)].join(", ")}.` : "No webhook filter with an unanchored high-risk alternative was found.";
    }
    if (Array.isArray(record.plaintext_sensitive_names)) return record.plaintext_sensitive_names.length ? `Plaintext variable names matching sensitive-name patterns: ${list(record.plaintext_sensitive_names)}; values are not inspected.` : "No plaintext variable name matches the sensitive-name patterns.";
    if (Array.isArray(record.credential_auth_types)) return record.credential_auth_types.length ? `Matching ${concise(String(record.source_type))} credential authentication types: ${list(record.credential_auth_types)}.` : "No regional credential matches this source type.";
    if (number(record.days_since_last_build)) return `The latest listed build finished ${record.days_since_last_build} whole days ago.`;
    if (number(record.days_since_latest_build)) return `The most recent completed build finished ${record.days_since_latest_build} whole days ago.`;
    if (record.last_build_status === "IN_PROGRESS" || record.build_in_progress === true) return "A build is in progress.";
    if (record.last_build === null) return "No build is recorded in the collected project history.";
    if (number(record.builds)) return `${record.builds} build records were collected without a completed or running build.`;
  }
  if (checkId.startsWith("aws.c2b.cloudformation.")) {
    if (typeof record.stack_drift_status === "string") return `The last recorded stack drift status is ${concise(record.stack_drift_status)}.`;
    if (number(record.notification_arns)) return `${record.notification_arns} stack notification destination${record.notification_arns === 1 ? " is" : "s are"} configured.`;
    if (typeof record.disable_rollback === "boolean") return `Rollback on stack-operation failure is ${record.disable_rollback ? "disabled" : "enabled"}.`;
    if (typeof record.termination_protection === "boolean") return `Stack termination protection is ${record.termination_protection ? "enabled" : "disabled"}.`;
    if (number(record.bootstrap_version)) return `The CDK bootstrap version is ${record.bootstrap_version}; this baseline requires ${record.recommended}.`;
  }
  if (checkId === "aws.c2b.codedeploy.lambda_not_all_at_once" && typeof record.deployment_config === "string") return `The Lambda deployment configuration is ${concise(record.deployment_config)}.`;
  if (checkId.startsWith("aws.c2b.ecr.") || checkId.startsWith("aws.c2b.eventbridge.") || checkId.startsWith("aws.c2b.codeartifact.")) {
    if (number(record.wildcard_statements)) return `${record.wildcard_statements} Allow statement${record.wildcard_statements === 1 ? " has" : "s have"} a wildcard AWS principal; conditions are not evaluated by this check.`;
    if (record.public_policy === false) return "The resource policy does not match this check's public-access model.";
    if (record.public_allow_statements === 0) return "No resource-policy statement matches this check's public-principal pattern.";
    if (typeof record.cross_account_policy === "boolean") return `The resource policy ${record.cross_account_policy ? "matches" : "does not match"} this check's external-account grant model.`;
    if (typeof record.scan_type === "string") {
      if (record.default_continuous_all_repositories === true) return "The enhanced registry uses its explicit empty-rules default: continuous scanning for all repositories.";
      if (typeof record.automated_all_repository_rule === "boolean") return `Registry mode is ${concise(record.scan_type)}; an automated all-repository rule is ${record.automated_all_repository_rule ? "configured" : "not configured"}.`;
      return `The registry scan mode is ${concise(record.scan_type)}.`;
    }
    if (typeof record.policy_attached === "boolean") return `The custom event bus ${record.policy_attached ? "has" : "does not have"} a resource policy attached.`;
    if (typeof record.replication_state === "string") return `Global endpoint replication state is ${concise(record.replication_state)}.`;
    if (Array.isArray(record.upstream_allowed)) return record.upstream_allowed.length ? `Internal or unknown-origin package names allowing upstream versions: ${list(record.upstream_allowed)}.` : "No reviewed internal or unknown-origin package name allows upstream versions.";
    if (record.policy === null) return "No resource policy is attached.";
  }
  if (checkId === "aws.c2b.acm.in_use_transparency_logging") {
    if (typeof record.transparency_logging === "string") return `Certificate transparency logging is ${concise(record.transparency_logging)}.`;
    if (record.certificate_type === "IMPORTED") return "The certificate is imported; this check does not require its ACM transparency preference.";
  }
  if (checkId === "aws.c2b.acm.in_use_secure_key_algorithm" || checkId === "aws.c2b.acmpca.pqc_key_algorithm") {
    if (typeof record.key_algorithm === "string") return `The declared certificate key algorithm is ${concise(record.key_algorithm)}.`;
  }
  if (checkId === "aws.c2b.acmpca.root_ca_disabled" && typeof record.status === "string") return `The root private CA status is ${concise(record.status)}.`;
  if (checkId.startsWith("aws.c2b.cognito.")) {
    if (Array.isArray(record.failing_clients) && typeof record.field === "string") return record.failing_clients.length ? `App clients without the required ${concise(record.field)} setting: ${list(record.failing_clients)}.` : `All collected app clients declare the required ${concise(record.field)} setting.`;
    if (record.web_acl === null) return "No WAF web ACL is associated with the user pool.";
    if (typeof record.web_acl === "string") return `The user pool is associated with web ACL ${concise(record.web_acl)}.`;
  }
  if (checkId === "aws.c2b.connect.contact_flow_logs" && typeof record.contactflow_logs === "string") return `The CONTACTFLOW_LOGS attribute is ${concise(record.contactflow_logs)}.`;
  if (checkId.startsWith("aws.c2b.directoryservice.")) {
    if (number(record.event_topics)) return `${record.event_topics} directory event topic${record.event_topics === 1 ? " is" : "s are"} configured.`;
    if (number(record.log_subscriptions)) return `${record.log_subscriptions} directory log subscription${record.log_subscriptions === 1 ? " is" : "s are"} configured.`;
    if (number(record.limit) && number(record.current)) return `Manual snapshot usage is ${record.current} of ${record.limit}; ${record.limit - record.current} slots remain.`;
    const days = record.remaining_days ?? record.remaining_calendar_days;
    if (days && typeof days === "object" && !Array.isArray(days)) {
      const values = Object.values(days).filter(number);
      if (values.length) return `The earliest registered LDAPS certificate expires in ${Math.min(...values)} ${record.remaining_calendar_days ? "calendar" : "whole"} days.`;
    }
    if (typeof record.authentication_protocol === "string") return `The RADIUS authentication protocol is ${concise(record.authentication_protocol)}.`;
    if (record.radius_status === null) return "No RADIUS completion status is recorded.";
    if (typeof record.radius_status === "string") return `The RADIUS configuration status is ${concise(record.radius_status)}.`;
  }
  if (checkId === "aws.c2b.fms.policies_compliant" && Array.isArray(record.non_compliant)) {
    const rows = record.non_compliant;
    if (rows.length) {
      const row = rows[0];
      if (row && typeof row === "object" && typeof row.policy === "string" && typeof row.account === "string") return `Firewall Manager policy ${concise(row.policy)} reports NON_COMPLIANT for account ${concise(row.account)}${rows.length > 1 ? ` and ${rows.length - 1} other evaluations` : ""}.`;
    }
    if (number(record.compliant_evaluations)) return `${record.compliant_evaluations} returned Firewall Manager evaluations report COMPLIANT; organization-wide coverage is not established.`;
  }
  if (checkId.startsWith("aws.c2b.bedrock.")) {
    if (record.prompt_attack_input_strength === null) return "No PROMPT_ATTACK input filter strength is configured.";
    if (typeof record.prompt_attack_input_strength === "string") return `The guardrail PROMPT_ATTACK input strength is ${concise(record.prompt_attack_input_strength)}.`;
    if (typeof record.sensitive_information_policy === "boolean") return `A sensitive-information policy ${record.sensitive_information_policy ? "is" : "is not"} declared; filter contents are not assessed here.`;
    if (Array.isArray(record.missing_filters)) return `Required grounding filter types not configured: ${list(record.missing_filters)}.`;
    if (Array.isArray(record.reasons)) return `Grounding filter configuration issues: ${list(record.reasons)}.`;
    if (Array.isArray(record.filters)) return `The required ${list(record.filters)} filters are declared enabled with blocking actions and positive thresholds.`;
    if (number(record.guardrails)) return `${record.guardrails} guardrail${record.guardrails === 1 ? " is" : "s are"} configured in this region; application attachment is not assessed.`;
    if (record.guardrail_identifier === null) return "No guardrail identifier is configured for the agent.";
    if (typeof record.guardrail_identifier === "string") return `The agent declares guardrail ${concise(record.guardrail_identifier)}.`;
    if (checkId.endsWith("prompt_cmk")) {
      if (record.kms_key_arn === null) return "No dedicated KMS key ARN is configured for this prompt.";
      if (typeof record.kms_key_arn === "string") return `The prompt declares KMS key ${concise(record.kms_key_arn)}.`;
    }
    if (typeof record.cloudwatch === "boolean" && typeof record.s3 === "boolean") return record.cloudwatch || record.s3 ? `Invocation logging declares ${[record.cloudwatch ? "CloudWatch" : "", record.s3 ? "S3" : ""].filter(Boolean).join(" and ")} configuration.` : "No CloudWatch or S3 invocation-log destination is configured.";
    if (number(record.prompts)) return `${record.prompts} managed prompt${record.prompts === 1 ? " is" : "s are"} present in the region.`;
    if (Array.isArray(record.missing_endpoint_services)) return record.missing_endpoint_services.length ? `Available VPC endpoints are missing for ${list(record.missing_endpoint_services)}.` : "All five checked Bedrock endpoint services have an available endpoint in this VPC.";
    if (typeof record.bedrock_full_access === "boolean") return `AmazonBedrockFullAccess ${record.bedrock_full_access ? "is" : "is not"} attached to this nonservice role; other grants are not assessed here.`;
    if (record.expired === true) return "This Bedrock service-specific credential is expired.";
    if (record.expired === false && number(record.days_remaining)) return `This Bedrock service-specific credential is unexpired with ${record.days_remaining} whole days remaining.`;
  }
  if (["aws_security_group_common_ports_ipv6_all", "aws_security_group_ssh_ipv6_all", "aws_security_group_tcp_udp_ipv6_all", "aws_msk_in_cluster_tls_enabled", "aws_client_vpn_authentication_configured", "aws.nist.codebuild_exact_aws_key_env_names", "aws.pci.codebuild.aws_key_environment_vars", "aws_g6_ecs_all_containers_logging", "aws_ec2_running_instance_cpu_alarm_present", "aws_sqs_queue_depth_alarm_present", "aws_g6_rds_cluster_members_enhanced_monitoring", "aws_nist_dynamodb_table_encrypted_with_kms", "aws_route53_hosted_zone_dnssec_enabled", "aws_lambda_code_signing_configured", "aws_cis_lightsail_bucket_access_logging", "aws_g6_ecr_public_repositories_absent", "aws_ec2_status_alarm", "aws_cis_lambda_config_recorded", "aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled", "aws.nist.all_cloudtrail_destination_bucket_access_logging", "aws_g6_all_cloudtrail_destination_bucket_access_logging", "aws_nist_cloudtrail_s3_logging_enabled", "aws_kms_imported_key_origin_spec", "aws.pci.iam.wildcard_action_scoped_resource", "aws_eventbridge_iam_user_change_alert", "aws_eventbridge_snapshot_change_alert", "aws.nist.cloudtrail_cloudwatch_integration", "aws_g6_cloudtrail_all_trails_cloudwatch_integration", "aws_backup_failure_notification", "aws_cis_batch_job_cloudwatch_logging", "aws.pci.codepipeline.first_stage_single_deploy", "aws_fedramp_cloudtrail_destination_kms", "aws_g6_cloudtrail_kms_destination_join", "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk", "aws_sns_delivery_failure_alarm_present"].includes(checkId)) {
    if (Array.isArray(record.offending_rules)) {
      const row = record.offending_rules[0];
      if (!row) return "No collected IPv6 ingress rule matches this check's world-source port pattern.";
      if (row && typeof row === "object" && typeof row.group_id === "string") return `${concise(row.group_id)} declares ::/0 ingress for ${row.protocol === "-1" ? "all protocols" : `${row.protocol} ports ${row.from_port}–${row.to_port}`}${record.offending_rules.length > 1 ? `; ${record.offending_rules.length - 1} additional matching rules` : ""}.`;
    }
    if (typeof record.in_cluster_tls === "boolean") return `MSK broker-to-broker TLS is ${record.in_cluster_tls ? "enabled" : "disabled"}.`;
    if (Array.isArray(record.authentication_types) && typeof record.server_certificate_present === "boolean") return `A server certificate is ${record.server_certificate_present ? "declared" : "not declared"}; authentication types: ${list(record.authentication_types) || "none"}.`;
    if (Array.isArray(record.matching_variable_names)) return record.matching_variable_names.length ? `Variable names matching this check: ${list(record.matching_variable_names)}; credential values are not inspected.` : "No variable name matches this check's exact AWS-key name pattern.";
    if (Array.isArray(record.containers_without_log_driver)) return record.containers_without_log_driver.length ? `Containers without a declared log driver: ${list(record.containers_without_log_driver)}.` : "Every container in this active task definition declares a log driver.";
    if (Array.isArray(record.matching_alarm_arns)) return record.matching_alarm_arns.length ? `${record.matching_alarm_arns.length} enabled direct-metric alarm${record.matching_alarm_arns.length === 1 ? " matches" : "s match"} this resource with configured actions; delivery is not verified.` : "No enabled direct-metric alarm with matching resource dimensions and configured actions was found.";
    if (Array.isArray(record.noncompliant_members)) return record.noncompliant_members.length ? `Cluster members missing required Enhanced Monitoring configuration: ${list(record.noncompliant_members)}.` : "No joined cluster member lacks the checked Enhanced Monitoring configuration.";
    if (typeof record.sse_type === "string" && typeof record.state === "string") return `The table reports SSE type ${record.sse_type} and state ${record.state}; default encryption is not equivalent to dedicated-key configuration.`;
    if (typeof record.serve_signature === "string" && Array.isArray(record.key_statuses)) return `DNSSEC serving state is ${concise(record.serve_signature)}; signing-key states: ${list(record.key_statuses) || "none"}.`;
    if (number(record.publisher_count) && typeof record.policy === "string") return `The signing configuration declares ${record.publisher_count} publisher${record.publisher_count === 1 ? "" : "s"} and policy ${concise(record.policy)}.`;
    if (typeof record.enabled === "boolean" && typeof record.destination_present === "boolean") return `Bucket access logging is ${record.enabled ? "enabled" : "disabled"}; a destination is ${record.destination_present ? "declared" : "not declared"}.`;
    if (record.policy === "documented_absent") return "The private ECR repository has a documented absent resource policy.";
    if (number(record.canonical_wildcard_statements)) return `${record.canonical_wildcard_statements} private ECR Allow statement${record.canonical_wildcard_statements === 1 ? " has" : "s have"} a wildcard AWS principal; conditions are not evaluated by this check.`;
    if (typeof record.recorder === "string") {
      if (typeof record.run_state === "string") return `Config recorder ${concise(record.recorder)} is ${concise(record.run_state)}.`;
      if (typeof record.recording_scope === "string") return `Config recorder ${concise(record.recorder)} declares ${concise(record.recording_scope)} scope; Lambda coverage follows its selected resource types.`;
    }
    if (number(record.monitoring_interval)) return `Enhanced Monitoring interval is ${record.monitoring_interval} seconds; role ${record.monitoring_role_present ? "present" : "absent"}, monitoring resource ${record.monitoring_resource_present ? "present" : "absent"}.`;
    if (typeof record.logging_enabled === "boolean" && typeof record.destination_bucket === "string") return `Trail destination bucket ${concise(record.destination_bucket)} has access logging ${record.logging_enabled ? "configured" : "not configured"}.`;
    if (typeof record.key_spec === "string" && typeof record.key_usage === "string") return `The imported key declares ${concise(record.key_spec)} with usage ${concise(record.key_usage)}.`;
    if (number(record.broad_scoped_statement_count)) return `${record.broad_scoped_statement_count} customer-policy Allow statement${record.broad_scoped_statement_count === 1 ? " declares" : "s declare"} broad actions on an exact resource ARN; effective permissions are not assessed.`;
    if (Array.isArray(record.missing_event_names)) return record.missing_event_names.length ? `Required event names without a matched enabled rule and target: ${list(record.missing_event_names)}.` : "Enabled rules and targets cover all required event names; delivery is not verified.";
    if (typeof record.destination_resolved === "boolean") return `The CloudWatch destination ${record.destination_resolved ? "resolves to a collected log group" : "does not resolve to a collected log group"}${typeof record.is_logging === "boolean" ? `; trail logging is ${record.is_logging ? "enabled" : "disabled"}` : ""}${typeof record.delivery_role_present === "boolean" ? `; delivery role ${record.delivery_role_present ? "present" : "absent"}` : ""}.`;
    if (typeof record.backup_failure_event_present === "boolean") return `Backup-failure events are ${record.backup_failure_event_present ? "included" : "not included"} in notifications; topic ${record.notification_topic_present ? "present" : "absent"}.`;
    if (Array.isArray(record.containers_without_awslogs)) return record.containers_without_awslogs.length ? `Container positions missing awslogs or its group: ${record.containers_without_awslogs.join(", ")}.` : "Every projected container declares awslogs and a log group.";
    if (number(record.deploy_action_count)) return record.first_deploy_stage_index === null ? "The pipeline has no stage containing a Deploy action." : `The first deployment stage (index ${record.first_deploy_stage_index}) contains ${record.deploy_action_count} Deploy action${record.deploy_action_count === 1 ? "" : "s"}.`;
    if (typeof record.trail_customer_key_enabled === "boolean") return `The trail ${record.trail_customer_key_enabled ? "has" : "does not have"} a declared enabled customer-managed key${record.destination_log_group_present ? `; its log-group key ${record.destination_customer_key_enabled ? "also meets" : "does not meet"} that criterion` : "; no CloudWatch log destination is declared"}.`;
  }
  if (checkId === "aws.c2b.acm.in_use_not_expiring_7_days" && number(record.expiration_days))
    return `The in-use certificate expires in ${record.expiration_days} days.`;
  if (checkId === "aws.c2b.bedrock.custom_model_cmk" && record.kms_key_arn === null)
    return "No customer-managed KMS key ARN is configured for this model.";
  if (checkId === "aws.c2b.bedrock.invocation_logs_encrypted") {
    const destinations = list(record.unencrypted);
    if (destinations) return `Log destinations without the checked explicit encryption metadata: ${destinations}.`;
  }
  if (checkId === "aws.c2b.cloudfront.s3_origin_bucket_exists") {
    const buckets = list(record.missing_buckets);
    if (buckets) return `Origin buckets reported as nonexistent: ${buckets}.`;
  }
  if (checkId === "aws.c2b.ecr.latest_image_no_medium_plus_findings") {
    if (record.scan_status === "FAILED") return "The selected image scan failed; vulnerability results could not be assessed.";
    if (record.scan_status === "COMPLETE" && record.severity_counts && typeof record.severity_counts === "object" && !Array.isArray(record.severity_counts)) {
      const counts = Object.entries(record.severity_counts).filter(([severity, count]) =>
        ["CRITICAL", "HIGH", "MEDIUM"].includes(severity) && number(count) && count > 0);
      if (counts.length) return `The selected image scan reports ${counts.map(([severity, count]) => `${count} ${severity.toLowerCase()}`).join(", ")} finding${counts.reduce((total, [, count]) => total + Number(count), 0) === 1 ? "" : "s"}.`;
    }
  }
  if (checkId === "aws.c2b.elasticache.cmk_enabled" && record.key_enabled === false)
    return "The configured encryption key is disabled.";
  if (checkId === "aws.c2b.elasticache.redis_auth_pre6" && record.auth_token_enabled === false)
    return "Redis AUTH tokens are disabled for this pre-6 replication group.";
  if (checkId === "aws.c2b.elbv2.listeners_secure_protocol") {
    const listeners = list(record.insecure_listeners);
    if (listeners && typeof record.required_protocol === "string")
      return `Listeners outside this check's ${concise(record.required_protocol)} requirement: ${listeners}.`;
  }
  if (checkId === "aws.c2b.emr.cluster_not_publicly_accessible") {
    const groups = [...(Array.isArray(record.public_master_groups) ? record.public_master_groups : []),
      ...(Array.isArray(record.public_slave_groups) ? record.public_slave_groups : [])];
    const names = list(groups);
    if (names) return `Cluster security groups allow Internet-wide all-protocol ingress: ${names}.`;
  }
  if (checkId === "aws.c2b.es.internal_user_database_enabled" && record.internal_user_database === false)
    return "The internal user database is disabled; other authentication methods are not assessed here.";
  if (checkId === "aws.cb.kafka.latest_version" && typeof record.kafka_version === "string") {
    const targets = list(record.compatible_active_targets);
    if (targets) return `Kafka ${concise(record.kafka_version)} has offered update targets: ${targets}.`;
  }
  if (checkId === "aws.cb.rds.instance_iam_auth_all_engines" && record.iam_database_authentication === false && record.supports_iam_database_authentication === true)
    return "IAM database authentication is disabled on this supported database configuration.";
  if (checkId.startsWith("aws.gap.ec2.instance_no_iam") && record.roles && typeof record.roles === "object" && !Array.isArray(record.roles)) {
    const entries = Object.entries(record.roles).filter(([, actions]) => Array.isArray(actions) && list(actions));
    if (entries.length) {
      const [role, actions] = entries[0];
      return `Instance role ${concise(role)} has modeled Allow actions: ${list(actions)}${entries.length > 1 ? `; ${entries.length - 1} other role(s) also match` : ""}.`;
    }
  }
  if (Array.isArray(record.matching_declared_ingress)) {
    const declarations = record.matching_declared_ingress.flatMap((row) => {
      if (!row || typeof row !== "object" || Array.isArray(row)) return [];
      const source = row.cidr_ipv4 === "0.0.0.0/0" ? row.cidr_ipv4 : row.cidr_ipv6 === "::/0" ? row.cidr_ipv6 : undefined;
      if (!source) return [];
      const protocol = ({tcp: "tcp", "6": "tcp", udp: "udp", "17": "udp"} as Record<string, string>)[String(row.ip_protocol)];
      if (row.ip_protocol === "-1") return [`all protocols and ports from ${source}`];
      if (!protocol || !Number.isInteger(row.from_port) || !Number.isInteger(row.to_port) ||
          row.from_port < 0 || row.to_port > 65535 || row.to_port < row.from_port) return [];
      return [`${protocol}/${row.from_port}${row.to_port === row.from_port ? "" : `–${row.to_port}`} from ${source}`];
    });
    if (declarations.length) return `A security-group rule allows ${[...new Set(declarations)].slice(0, 3).join("; ")}.`;
  }
  if (["aws.claude_a.vpc.default_sg_no_rules", "aws.claude_a.vpc.default_sg_in_use_no_rules"].includes(checkId) &&
      number(record.ingress_rules) && number(record.egress_rules))
    return `The default security group has ${record.ingress_rules} inbound and ${record.egress_rules} outbound rule entries.`;
  if (checkId === "aws.claude_a.vpc.sg_rule_count_within_50" && number(record.ingress) && number(record.egress))
    return `The security group has ${record.ingress} inbound and ${record.egress} outbound rule entries; the threshold is 50 per direction.`;
  if (checkId === "aws.claude_a.vpc.sg_name_not_launch_wizard" && typeof record.group_name === "string")
    return `The security-group name is ${concise(record.group_name)}.`;
  if (checkId === "aws.claude_a.vpc.vpn_both_tunnels_up") {
    const statuses = list(record.statuses);
    if (statuses) return `The two VPN tunnels report ${statuses}.`;
  }
  if (checkId.startsWith("aws.claude_a.networkfirewall.")) {
    if (typeof record.delete_protection === "boolean") return `Firewall deletion protection is ${record.delete_protection ? "enabled" : "disabled"}.`;
    if (typeof record.subnet_change_protection === "boolean") return `Firewall subnet-change protection is ${record.subnet_change_protection ? "enabled" : "disabled"}.`;
    if (number(record.destinations)) return `${record.destinations} firewall log destination${record.destinations === 1 ? " is" : "s are"} configured.`;
    if (number(record.subnet_mappings)) return `The firewall has ${record.subnet_mappings} subnet mapping${record.subnet_mappings === 1 ? "" : "s"}.`;
    if (number(record.rules)) return `The stateless rule group contains ${record.rules} rule${record.rules === 1 ? "" : "s"}.`;
    const actions = list(record.actions);
    if (actions) return `The configured stateless default actions are ${actions}.`;
  }
  if (checkId.startsWith("aws.a.iam.password_policy_")) {
    const labels: Record<string, string> = {RequireLowercaseCharacters: "Lowercase characters", RequireUppercaseCharacters: "Uppercase characters", RequireNumbers: "Numbers", RequireSymbols: "Symbols"};
    if (typeof record.field === "string" && labels[record.field] && typeof record.configured === "boolean")
      return `${labels[record.field]} are ${record.configured ? "required" : "not required"} by the account password policy.`;
    if (record.field === "MinimumPasswordLength" && number(record.configured)) return `The minimum password length is ${record.configured} characters.`;
    if (record.field === "PasswordReusePrevention" && number(record.configured)) return `Password reuse prevention covers ${record.configured} previous passwords.`;
    if (record.field === "MaxPasswordAge" && number(record.configured)) return record.configured === 0
      ? "The maximum password age setting is 0; password expiration is not enabled by this setting."
      : `The maximum password age setting is ${record.configured} days.`;
    if (record.password_policy === "absent") return "No account password policy was found in the complete collected inventory.";
  }
  if (checkId === "aws.a.iam.console_key_created_at_setup") {
    if (record.console_enabled === false) return "The credential report records console login as disabled.";
    if (record.first_key_rotation === "null") return "The credential report supplies no first-key rotation timestamp.";
  }
  if (number(record.matching_attachment_count) && checkId.endsWith("_no_cloudshell_full_access"))
    return `${record.matching_attachment_count} direct AWSCloudShellFullAccess attachment${record.matching_attachment_count === 1 ? " was" : "s were"} found.`;
  if (number(record.wildcard_statement_count))
    return `${record.wildcard_statement_count} declared Allow statement${record.wildcard_statement_count === 1 ? " matches" : "s match"} the literal wildcard-administrator pattern.`;
  if (typeof record.mfa_active === "boolean" && checkId.startsWith("aws.a.iam.report_"))
    return `The credential report records MFA as ${record.mfa_active ? "active" : "inactive"}.`;
  if (checkId === "aws.a.iam.root_console_summary_mfa") {
    if (record.root_console_enabled === false) return "The account summary reports no root console password.";
    if (typeof record.root_mfa_enabled === "boolean") return `The account summary reports root MFA as ${record.root_mfa_enabled ? "enabled" : "disabled"}.`;
  }
  if (checkId === "aws.a.iam.root_summary_mfa" && record.account_mfa_enabled === 1)
    return "The account summary reports root MFA as enabled.";
  if (checkId === "aws.a.iam.root_summary_no_keys" && number(record.account_access_keys_present))
    return `The account summary reports ${record.account_access_keys_present} root access key${record.account_access_keys_present === 1 ? "" : "s"}.`;
  if (checkId === "aws.a.iam.server_certificate_expiry_date" && typeof record.expires_at === "string")
    return `The certificate expiration timestamp is ${concise(record.expires_at)}.`;
  if (["aws.a.iam.user_no_direct_policies", "aws.a.iam.user_no_managed_policies"].includes(checkId) && number(record.managed_attachment_count) && number(record.inline_policy_count))
    return `The user has ${record.managed_attachment_count} direct managed-policy attachment${record.managed_attachment_count === 1 ? "" : "s"}${checkId.endsWith("_direct_policies") ? ` and ${record.inline_policy_count} inline polic${record.inline_policy_count === 1 ? "y" : "ies"}` : ""}.`;
  if (Array.isArray(record.matching_policy_sources)) {
    const policies = list(record.matching_policy_sources);
    if (policies) return `Customer-managed policies matching the literal wildcard-grant pattern: ${policies}.`;
    if (record.matching_policy_sources.length === 0) return "No customer-managed default policy matched the literal wildcard-grant pattern.";
  }
  if (checkId.startsWith("aws.claude_a.iam.") || checkId === "aws.claude_a.accessanalyzer.active_without_findings") {
    if (typeof record.attached_to_active_identity === "boolean")
      return `The policy ${record.attached_to_active_identity ? "has" : "has no"} collected attachment to a user, role or populated group.`;
    if (typeof record.role_attachment_found === "boolean")
      return record.role_attachment_found ? "A collected IAM role attachment was found for this policy." : "No collected IAM role attachment was found for this policy.";
    if (checkId.endsWith("_inline_kms_decrypt_restricted") && number(record.matching_statements))
      return `${record.matching_statements} inline Allow statement${record.matching_statements === 1 ? " matches" : "s match"} the checked broad KMS-decryption pattern.`;
    if (checkId.endsWith("_no_cloudshell_full_access") && typeof record.attached === "boolean")
      return `AWSCloudShellFullAccess is ${record.attached ? "directly attached" : "not directly attached"}.`;
    if (checkId.endsWith("_no_inline_policies") && number(record.inline_policy_count))
      return `${record.inline_policy_count} inline polic${record.inline_policy_count === 1 ? "y is" : "ies are"} configured.`;
    if (number(record.group_count)) return `The user belongs to ${record.group_count} collected group${record.group_count === 1 ? "" : "s"}.`;
    if (number(record.members)) return `The group has ${record.members} collected member${record.members === 1 ? "" : "s"}.`;
    if (number(record.active_keys)) return `The user has ${record.active_keys} active access key${record.active_keys === 1 ? "" : "s"}.`;
    if (typeof record.both_active === "boolean") return record.both_active ? "Both credential-report access-key slots are active." : "The credential report does not record both key slots as active.";
    if (number(record.mfa_devices)) return `${record.mfa_devices} MFA device${record.mfa_devices === 1 ? " is" : "s are"} recorded for this administrator user.`;
    if (number(record.devices) && record.devices === 0) return "No MFA device is recorded for this user.";
    const types = list(record.device_types);
    if (types) return `Recorded MFA device types: ${types}.`;
    if (number(record.keys) && record.keys === 0) return "Neither key slot supplies a rotation timestamp in the credential report.";
    if (Array.isArray(record.never_used_keys) && record.never_used_keys.every(slot => slot === 1 || slot === 2))
      return record.never_used_keys.length ? `Active key slots with no reported use: ${record.never_used_keys.join(", ")}.` : "No active key slot matched the checked never-used-key pattern.";
    if (Array.isArray(record.stale_keys) && !record.stale_keys.length) return "No active key slot exceeds the checked rotation-age limit.";
    if (typeof record.expires === "string") return `The certificate expiration timestamp is ${concise(record.expires)}.`;
    if (record.password_present === 0) return "The account summary reports no root console password.";
    if (record.password_present === 1 && (record.mfa_enabled === 0 || record.mfa_enabled === 1))
      return `The account summary reports a root password and MFA ${record.mfa_enabled ? "enabled" : "disabled"}.`;
    if (Array.isArray(record.enabled_features) && record.enabled_features.every(value => typeof value === "string"))
      return `Centralized root-credentials management is ${record.enabled_features.includes("RootCredentialsManagement") ? "listed as enabled" : "not listed as enabled"}.`;
    if (number(record.providers)) return `${record.providers} IAM SAML provider${record.providers === 1 ? " is" : "s are"} recorded.`;
    if (Array.isArray(record.entities)) {
      const names = list(record.entities);
      if (names) return `Identities with direct AWSCloudShellFullAccess attachments: ${names}.`;
      if (!record.entities.length) return "No collected identity directly attaches AWSCloudShellFullAccess.";
    }
    if (Array.isArray(record.members_without_mfa)) {
      const names = list(record.members_without_mfa);
      if (names) return `Administrative group members with inactive credential-report MFA: ${names}.`;
      if (!record.members_without_mfa.length) return "No reviewed administrative group member records inactive MFA.";
    }
    if (Array.isArray(record.cross_account_principals)) {
      const principals = list(record.cross_account_principals);
      if (principals) return `Declared external AWS trust principals: ${principals}.`;
      if (!record.cross_account_principals.length) return "No AWS trust principal matched this check's external-account pattern.";
    }
    if (checkId.endsWith("prowler_role_readonly_not_cross_account") && typeof record.principal === "string")
      return `The trust document names external AWS principal ${concise(record.principal)}.`;
    if (typeof record.readonly === "boolean") return `A policy named ReadOnlyAccess is ${record.readonly ? "attached" : "not attached"}.`;
    if (typeof record.administrator_access === "boolean") return `A policy named AdministratorAccess is ${record.administrator_access ? "attached" : "not attached"}.`;
    if (checkId.endsWith("role_trust_not_public") && record.public_statements === 0)
      return "No trust statement matched the reviewed public-principal pattern.";
    if (number(record.access_keys) && Array.isArray(record.non_iam_sts_services)) {
      const services = list(record.non_iam_sts_services);
      return `${record.access_keys} long-lived key${record.access_keys === 1 ? " is" : "s are"} configured; ${services ? `reported non-IAM/STS service access includes ${services}` : "no non-IAM/STS service access is reported"}.`;
    }
    if (checkId === "aws.claude_a.accessanalyzer.active_without_findings") {
      if (number(record.analyzers)) return `${record.analyzers} analyzers were collected.`;
      if (number(record.findings)) return `The collected active analyzers contain ${record.findings} finding${record.findings === 1 ? "" : "s"}.`;
      const statuses = list(record.statuses);
      if (statuses) return `Collected analyzer statuses: ${statuses}.`;
    }
  }
  if (checkId.startsWith("aws.claude_a.iam.prowler_")) {
    if (typeof record.admin_access === "boolean") return record.admin_access
      ? "The policy matches the reviewed administrator-access pattern." : "The policy does not match the reviewed administrator-access pattern.";
    if (Array.isArray(record.escalation_actions)) {
      const actions = list(record.escalation_actions);
      if (actions) return `The policy model finds a sensitive-action combination: ${actions}.`;
      if (!record.escalation_actions.length) return "No checked sensitive-action combination was found in the policy model.";
    }
    if (Array.isArray(record.unscoped_token_operations)) {
      const operations = list(record.unscoped_token_operations);
      if (operations) return `Token operations outside the checked workload-identity scope: ${operations}.`;
      if (!record.unscoped_token_operations.length) return "No token operation falls outside the checked workload-identity scope.";
    }
    if (typeof record.passrole_to_agentcore_on_all_roles === "boolean") return record.passrole_to_agentcore_on_all_roles
      ? "The policy model permits PassRole to AgentCore on any role." : "The policy does not match the checked unrestricted AgentCore PassRole pattern.";
    if (typeof record.confused_deputy_exposed === "boolean") return record.confused_deputy_exposed
      ? "The service trust matches the checked confused-deputy exposure pattern." : "The service trust does not match the checked confused-deputy exposure pattern.";
    if (number(record.unscoped_statements)) return `${record.unscoped_statements} service-trust statement${record.unscoped_statements === 1 ? " lacks" : "s lack"} the checked source boundary.`;
    if (checkId.endsWith("_inline_no_privilege_escalation") && Array.isArray(record.failing_policies) && !record.failing_policies.length)
      return "No inline policy matches the checked sensitive-action combinations.";
  }
  if (checkId.startsWith("aws.claude_a.vpc.") || checkId.startsWith("aws.claude_a.networkfirewall.")) {
    if (typeof record.world_all_traffic_rule_found === "boolean") return record.world_all_traffic_rule_found
      ? "Internet-wide ingress matches the checked all-traffic rule pattern." : "No Internet-wide ingress matches the checked all-traffic rule pattern.";
    if (typeof record.world_ingress_rule_found === "boolean") {
      const enis = list(record.customer_enis);
      return record.world_ingress_rule_found ? `Internet-wide ingress is declared${enis ? ` on customer interfaces ${enis}` : ""}.` : "No ingress rule matches this check's Internet-wide access pattern.";
    }
    if (typeof record.specific_public_range_match === "boolean") return record.specific_public_range_match
      ? "An ingress rule matches the checked public-address-range pattern." : "No ingress rule matches the checked public-address-range pattern.";
    if (record.wide_public_range_found === false) return "No public IPv4 range matches this check's /1–/23 rule criterion.";
    if (record.wide_public_range_found === true && typeof record.cidr === "string") return `Public IPv4 range ${concise(record.cidr)} is broader than /24 in an inbound or outbound rule.`;
    if (typeof record.eni_attachment_found === "boolean") return record.eni_attachment_found
      ? "A collected network interface attaches this security group." : "No collected network interface attaches this security group.";
    if (record.recognized_reference_found === false) return "No reference was found in the resource types evaluated by this check.";
    if (typeof record.used_by === "string") return `A collected ${label(record.used_by)} references this security group.`;
    if (typeof record.attached_by_group_name === "boolean") return record.attached_by_group_name
      ? `An interface lists security-group name ${concise(String(record.group_name))}.` : `No collected interface lists security-group name ${concise(String(record.group_name))}.`;
    if (Array.isArray(record.open_ports) && record.open_ports.every(port => number(port) && Number.isInteger(port) && port >= 0 && port <= 65535))
      return record.open_ports.length ? `Internet-wide security-group ingress allows ${record.open_ports.map(port => `tcp/${port}`).join(", ")}.` : "No Internet-wide TCP ingress matches this check's port list.";
    if (typeof record.ordered_world_ingress_allowed === "boolean") {
      const traffic = record.protocol === "-1" ? "all-protocol traffic" : record.protocol === "6" && number(record.port) ? `tcp/${record.port}` : undefined;
      if (traffic) return record.ordered_world_ingress_allowed ? `Ordered ACL ingress rules allow ${traffic} from a world source range.` : `Ordered ACL ingress rules do not allow the checked world-source ${traffic}.`;
    }
    if (Array.isArray(record.rule_numbers) && record.rule_numbers.every(number)) return record.rule_numbers.length
      ? `ACL Allow entries ${record.rule_numbers.join(", ")} match the checked world-source administration traffic; earlier Deny entries are not evaluated.`
      : "No ACL Allow entry matches the checked world-source administration traffic.";
    if (number(record.associations)) return `The network ACL has ${record.associations} recorded association${record.associations === 1 ? "" : "s"}.`;
    if (checkId.endsWith("flow_logs_active") && Array.isArray(record.statuses)) {
      const statuses = list(record.statuses);
      return statuses ? `Collected VPC flow-log statuses: ${statuses}.` : "No VPC-level flow-log record was found.";
    }
    if (typeof record.flow_log_found === "boolean") return record.flow_log_found ? "A VPC-level flow-log record was found." : "No VPC-level flow-log record was found.";
    if (typeof record.subnet_found === "boolean") return record.subnet_found ? "A collected subnet belongs to this VPC." : "No collected subnet belongs to this VPC.";
    if (Array.isArray(record.availability_zones)) {
      const zones = list(record.availability_zones);
      return zones ? `Collected VPC subnets occupy ${zones}.` : "No Availability Zone was found among collected VPC subnets.";
    }
    if (Array.isArray(record.regions)) {
      const regions = list(record.regions);
      return regions ? `The evaluated VPC inventory includes ${regions}.` : "No Region was found in the evaluated VPC inventory.";
    }
    if (number(record.attachments)) return `The Internet gateway has ${record.attachments} recorded attachment${record.attachments === 1 ? "" : "s"}.`;
    if (checkId.endsWith("route_table_no_default_igw_route") && Array.isArray(record.destinations)) {
      const destinations = list(record.destinations);
      return destinations ? `Default Internet-gateway route destinations: ${destinations}.` : "No default destination matches the checked Internet-gateway route pattern.";
    }
    if (checkId.endsWith("peering_routes_least_privilege") && Array.isArray(record.destinations) && !record.destinations.length)
      return "No peering route matches the checked default-or-primary-VPC destination pattern.";
    if (typeof record.mode === "string" && checkId.endsWith("block_public_access_igw")) return `The Internet-gateway block mode is ${concise(record.mode)}.`;
    if (typeof record.matching_service_name_found === "boolean") return record.matching_service_name_found
      ? "A VPC endpoint service name contains ec2." : "No collected VPC endpoint service name contains ec2.";
    if (number(record.subnets)) return `The interface endpoint lists ${record.subnets} subnet${record.subnets === 1 ? "" : "s"}.`;
    if (number(record.statements) && checkId.endsWith("gateway_endpoint_policy_not_open")) return `${record.statements} gateway-policy statement${record.statements === 1 ? " matches" : "s match"} the checked unconditioned public Allow pattern.`;
    if (Array.isArray(record.principal_accounts)) {
      const accounts = list(record.principal_accounts);
      if (accounts) return `Endpoint policy Allow principals outside the audited account: ${accounts}.`;
    }
    if (Array.isArray(record.unmatched_principal_accounts) && !record.unmatched_principal_accounts.length) return "No endpoint Allow principal falls outside the checked account-boundary model.";
    if (typeof record.acceptance_required === "boolean") return `Endpoint-service connection acceptance is ${record.acceptance_required ? "required" : "not required"}.`;
    if (Array.isArray(record.untrusted)) {
      const principals = list(record.untrusted);
      return principals ? `Allowed endpoint-service principal accounts outside the audited account: ${principals}.` : "No allowed endpoint-service principal account differs from the audited account.";
    }
    if (typeof record.status === "string" && typeof record.requester === "string" && typeof record.accepter === "string")
      return `Peering status is ${concise(record.status)}; owner accounts are ${concise(record.requester)} and ${concise(record.accepter)}.`;
    if (typeof record.firewall_found === "boolean") return record.firewall_found ? "A collected firewall has this VPC ID." : "No collected firewall has this VPC ID; other inspection architectures are not assessed.";
    if (typeof record.rule_group_reference_found === "boolean") return record.rule_group_reference_found
      ? "The firewall policy references at least one rule group." : "The firewall policy has no stateful or stateless rule-group reference.";
    if (typeof record.placement === "string" && typeof record.vpc_id === "string") return `The firewall reports ${label(record.placement)} placement in ${concise(record.vpc_id)}.`;
  }
  if (checkId.startsWith("aws.claude_a.guardduty.")) {
    const protection = AWS_GUARDDUTY_PROTECTION_LABELS[checkId];
    if (protection && typeof record.feature_enabled === "boolean")
      return record.feature_enabled
        ? `The ${protection} flag is enabled${record.detector_enabled === false ? "; the detector is disabled" : ""}.`
        : `No enabled ${protection} flag is reported.`;
    if (protection && typeof record.feature === "string" && typeof record.enabled === "boolean")
      return `The detector/feature flags ${record.enabled ? "jointly enable" : "do not jointly enable"} ${protection}.`;
    if (protection && typeof record.enabled === "boolean") return `GuardDuty ${protection} is ${record.enabled ? "enabled" : "not enabled"}.`;
    if (typeof record.archived === "boolean") return `The finding is ${record.archived ? "archived" : "not archived"}.`;
    if (number(record.active_severity_8_findings)) return `${record.active_severity_8_findings} active severity-8 GuardDuty finding${record.active_severity_8_findings === 1 ? " was" : "s were"} collected.`;
    if (number(record.findings)) return `${record.findings} high-severity GuardDuty finding${record.findings === 1 ? " was" : "s were"} collected.`;
    if (typeof record.ai_protection === "boolean") return `GuardDuty AI Protection is ${record.ai_protection ? "enabled" : "not enabled"}.`;
    if (typeof record.runtime_monitoring === "boolean") return `Unified GuardDuty Runtime Monitoring is ${record.runtime_monitoring ? "enabled" : "not enabled"}${record.legacy_eks_runtime === true ? "; legacy EKS runtime monitoring is reported" : ""}.`;
    if (Array.isArray(record.managed) && record.managed.every(value => typeof value === "boolean"))
      return `${record.managed.filter(Boolean).length} of ${record.managed.length} collected detectors ${record.managed.filter(Boolean).length === 1 ? "has" : "have"} the checked enabled-detector/administrator relationship.`;
    if (typeof record.administrator === "boolean" && number(record.members))
      return `An administrator relationship is ${record.administrator ? "reported" : "not reported"}; ${record.members} member account${record.members === 1 ? " is" : "s are"} listed.`;
  }
  if (checkId.startsWith("aws.claude_a.kms.")) {
    if (typeof record.key_state === "string") return `The key state is ${concise(record.key_state)}${typeof record.enabled === "boolean" ? ` and Enabled is ${record.enabled}` : ""}.`;
    if (typeof record.multi_region === "boolean") return `The key is configured as ${record.multi_region ? "multi-Region" : "single-Region"}.`;
    if (typeof record.rotation_enabled === "boolean") return `Automatic key rotation is ${record.rotation_enabled ? "enabled" : "disabled"}.`;
    if (record.rotation_enabled === null && typeof record.origin === "string") return `The key origin is ${concise(record.origin)}; this automatic-rotation criterion does not read a rotation flag for that origin.`;
    if (typeof record.public === "boolean") return record.public ? "The key policy matches the reviewed public-access model." : "The key policy does not match the reviewed public-access model.";
    if (record.public_statements === 0) return "No key-policy statement matches the reviewed public-principal pattern.";
  }
  if (checkId.startsWith("aws.claude_a.organizations.")) {
    if (typeof record.opt_out_content_match === "boolean") return record.opt_out_content_match
      ? "A collected policy contains default AI-service opt-out with child overrides blocked." : "No collected policy matches the checked default AI-service opt-out content.";
    if (typeof record.direct_region_deny_match === "boolean") return record.direct_region_deny_match
      ? `A directly attached policy matches the checked Region Deny${list(record.approved_regions) ? ` for exceptions ${list(record.approved_regions)}` : ""}.`
      : "No collected policy matches the checked directly attached broad Region Deny.";
    if (Array.isArray(record.attached_tag_policies)) {
      const policies = list(record.attached_tag_policies);
      return policies ? `Tag policies with a recorded target attachment: ${policies}.` : "No collected tag policy has a target attachment.";
    }
  }
  if (checkId.startsWith("aws.claude_a.securityhub.")) {
    if (record.hub === "not enabled") return "Security Hub is not enabled in the collected Region.";
    if (typeof record.standard_or_integration_found === "boolean") return record.standard_or_integration_found
      ? "Every collected hub has an enabled standard or non-self product integration." : "An evaluated hub has no enabled standard or non-self product integration.";
  }
  if ((checkId.startsWith("aws.claude_a.guardduty.") || checkId.startsWith("aws.claude_a.securityhub."))) {
    if (typeof record.issue === "string" && record.issue.trim()) return `${concise(record.issue)}.`;
    if (record.delegated_admin === true) return "Enabled delegated-administrator and automatic-enrollment settings were found.";
  }
  if (checkId.startsWith("aws.cb.inspector2.")) {
    if (Array.isArray(record.not_enabled_for)) {
      const types = list(record.not_enabled_for);
      return types ? `Inspector is not enabled for the present ${types} resource types.` : "Inspector is enabled for the resource types present in the collected Region.";
    }
    if (number(record.active_findings)) return `${record.active_findings} active Inspector finding${record.active_findings === 1 ? " was" : "s were"} collected.`;
    if (number(record.stale_findings) && number(record.max_age_days)) return `${record.stale_findings} active finding${record.stale_findings === 1 ? " exceeds" : "s exceed"} the ${record.max_age_days}-day first-observed age limit.`;
    if (Array.isArray(record.known_exploited)) {
      const cves = list(record.known_exploited);
      return cves ? `Active Inspector findings include CISA KEV-listed vulnerabilities: ${cves}.` : "No collected active finding has CISA KEV metadata.";
    }
    if (Array.isArray(record.overdue)) {
      const cves = list(record.overdue);
      return cves ? `CISA remediation due dates have passed for ${cves}.` : "No collected active KEV finding is past its reported CISA due date.";
    }
    if (typeof record.status_code === "string") return `Inspector scan status is ${concise(record.status_code)}${typeof record.reason === "string" ? ` (${label(record.reason).toLowerCase()})` : ""}.`;
    if (typeof record.last_scanned_at === "string") return `The latest reported Inspector scan is ${concise(record.last_scanned_at)}.`;
    if (record.last_scanned_at === null) return "No last-scan timestamp is reported for this active resource.";
  }
  if (checkId.startsWith("aws.cb.macie.")) {
    if (typeof record.automated_discovery === "string") return `Macie automated discovery is ${concise(record.automated_discovery).toLowerCase()}.`;
    if (typeof record.status === "string") return `Macie session status is ${concise(record.status)}.`;
  }
  if (checkId === "aws.cb.resourceexplorer2.index_exists" && number(record.indexes)) return `${record.indexes} Resource Explorer index${record.indexes === 1 ? " was" : "es were"} collected.`;
  if (checkId === "aws.cb.rolesanywhere.trust_anchor_pqc") {
    if (typeof record.key_algorithm === "string" && typeof record.status === "string") return `The linked Private CA uses ${concise(record.key_algorithm)} and reports ${concise(record.status)}.`;
    if (typeof record.source_type === "string") return `The trust-anchor source type is ${concise(record.source_type)}.`;
  }
  if (checkId.startsWith("aws.cb.route53.")) {
    if (Array.isArray(record.status_list)) return `The domain transfer lock is ${record.status_list.includes("clientTransferProhibited") ? "present" : "not listed"} in the registration status.`;
    if (number(record.days_to_expiry)) return `The domain registration has ${record.days_to_expiry} calendar days remaining.`;
    if (typeof record.expiration_date === "string") return `The domain registration expiration timestamp is ${concise(record.expiration_date)}.`;
    if (Array.isArray(record.log_groups)) {
      const groups = list(record.log_groups);
      return groups ? `DNS query logging targets ${groups}.` : "No public-zone DNS query-log destination is configured.";
    }
  }
  if (checkId.startsWith("aws.cb.secretsmanager.")) {
    if (record.rotation_rules_present === false) return "No rotation rules are reported for the Lambda-based rotation requirement.";
    if (record.rotation_rules_present === true && record.rotation_lambda === null) return "Rotation rules are present, but no rotation Lambda ARN is reported.";
    if (typeof record.rotation_lambda === "string") return "A rotation Lambda ARN and rotation rules are configured.";
    if (record.rotation_lambda === null) return "The Lambda-based rotation configuration is not reported by this check.";
    if (record.rotation_rules === null) return "No automatic rotation rules are reported.";
    if (record.rotation_rules && typeof record.rotation_rules === "object" && !Array.isArray(record.rotation_rules)) {
      const rules = record.rotation_rules as Record<string, unknown>;
      if (number(rules.AutomaticallyAfterDays)) return `Automatic rotation is scheduled after ${rules.AutomaticallyAfterDays} days.`;
      if (typeof rules.ScheduleExpression === "string") return `The configured rotation schedule is ${concise(rules.ScheduleExpression)}.`;
      return "A rotation-rules object is present; its schedule values are available in technical details.";
    }
    if (number(record.days_since_change)) return `The last recorded secret change was ${record.days_since_change} calendar days ago.`;
    if (record.last_changed === null) return "No last-change timestamp is reported for this secret.";
    if (number(record.days_after_creation)) return `Last reported access was ${record.days_after_creation} calendar days after creation.`;
    if (number(record.days_since) && number(record.automatically_after_days)) return `${record.days_since} calendar days have passed since ${record.rotated === true ? "rotation" : "creation"}; the configured interval is ${record.automatically_after_days} days.`;
    if (number(record.days_since_rotation)) return `The last reported rotation was ${record.days_since_rotation} days ago.`;
    if (record.last_rotated === null) return "No last-rotation timestamp is reported for this secret.";
    if (typeof record.last_accessed === "string") return `The last reported access is ${concise(record.last_accessed)}.`;
    if (record.last_accessed === null) return "No last-access timestamp is reported for this secret.";
    if (number(record.days_since_access)) return `The last reported access was ${record.days_since_access} calendar days ago.`;
    if (record.public_policy === false) return "The secret resource policy does not match the reviewed public-access model.";
    if (record.public_allow_statements === 0) return "No secret-policy statement matches the reviewed public-principal pattern.";
    if (record.kms_key_id === "alias/aws/secretsmanager") return "The secret uses the AWS-managed Secrets Manager encryption key.";
    if (typeof record.kms_key_id === "string") return `The configured KMS key reference is ${concise(record.kms_key_id)}.`;
  }
  if (checkId.startsWith("aws.cb.servicecatalog.") && Array.isArray(record.account_shares)) {
    const accounts = list(record.account_shares);
    return accounts ? `The portfolio is shared with individual accounts ${accounts}.` : "No individual-account portfolio share was collected.";
  }
  if (checkId.startsWith("aws.cb.shield.") && typeof record.shield_advanced_protection_found === "boolean")
    return record.shield_advanced_protection_found ? "A Shield Advanced protection is registered for this resource." : "No Shield Advanced protection is registered for this resource; baseline Standard protection is separate.";
  if (checkId.startsWith("aws.cb.ssm.")) {
    if (checkId.endsWith("block_public_document_sharing") && typeof record.setting_value === "string")
      return `The SSM console public-sharing permission is ${concise(record.setting_value)}${record.setting_value === "Enable" ? " (public sharing allowed)" : record.setting_value === "Disable" ? " (public sharing blocked)" : ""}.`;
    if (checkId.endsWith("automation_logs_to_cloudwatch") && typeof record.setting_value === "string") return `The Automation customer-script log destination is ${concise(record.setting_value)}.`;
    if (Array.isArray(record.account_ids)) {
      if (record.account_ids.includes("all")) return "The SSM document is shared publicly (all accounts).";
      const accounts = list(record.account_ids);
      return accounts ? `Document sharing names accounts ${accounts}.` : "No document-sharing account IDs are reported.";
    }
    if (typeof record.status === "string" && typeof record.compliance_type === "string") return `The ${concise(record.compliance_type)} compliance summary reports ${concise(record.status)}.`;
    if (number(record.items) && number(record.non_compliant)) return `${record.non_compliant} of ${record.items} collected ${checkId.includes("patch") ? "Patch" : "Association"} items ${record.non_compliant === 1 ? "is" : "are"} not reported COMPLIANT.`;
  }
  if (checkId === "aws.cb.ssmincidents.active_with_response_plans") {
    if (record.replication_set === null) return "No Incident Manager replication set was collected.";
    if (typeof record.status === "string" && number(record.response_plans)) return `The first replication set reports ${concise(record.status)}; ${record.response_plans} response plan${record.response_plans === 1 ? " is" : "s are"} configured.`;
  }
  if (checkId === "aws.cb.trustedadvisor.check_ok" && typeof record.status === "string") return `The Trusted Advisor check reports ${concise(record.status)}.`;
  if (checkId.startsWith("aws.cb.waf.") || checkId.startsWith("aws.cb.wafregional.") || checkId.startsWith("aws.cb.wafv2.")) {
    if (number(record.predicates)) return `The legacy WAF rule contains ${record.predicates} condition${record.predicates === 1 ? "" : "s"}.`;
    if (number(record.activated_rules)) return `The legacy WAF rule group contains ${record.activated_rules} activated rule${record.activated_rules === 1 ? "" : "s"}.`;
    if (number(record.rules)) {
      const unit = checkId.endsWith("web_acl_has_rules_or_fms_groups")
        ? record.rules === 1 ? "rule or Firewall Manager group" : "rules or Firewall Manager groups"
        : record.rules === 1 ? "rule-list entry" : "rule-list entries";
      return `The web ACL contains ${record.rules} ${unit}.`;
    }
    if (number(record.destinations)) return `The web ACL has ${record.destinations} configured log destination${record.destinations === 1 ? "" : "s"}.`;
    if (number(record.resources)) return `The legacy web ACL has ${record.resources} recorded resource association${record.resources === 1 ? "" : "s"}.`;
    if (typeof record.cloudwatch_metrics_enabled === "boolean") return `Rule-group CloudWatch metrics are ${record.cloudwatch_metrics_enabled ? "enabled" : "disabled"}.`;
    if (Array.isArray(record.metrics_disabled)) {
      const names = list(record.metrics_disabled);
      return names ? `Rules or groups without recorded enabled CloudWatch metrics: ${names}.` : "All checked rules and groups record enabled CloudWatch metrics.";
    }
  }
  if (checkId === "aws.cb.wellarchitected.no_high_or_medium_risks" && record.risks && typeof record.risks === "object" && !Array.isArray(record.risks)) {
    const risks = Object.entries(record.risks).filter(([severity, count]) => ["HIGH", "MEDIUM"].includes(severity) && number(count) && count > 0);
    return risks.length ? `The workload review records ${risks.map(([severity, count]) => `${count} ${severity.toLowerCase()}`).join(", ")} risk items.` : "The workload review records no positive high or medium risk counts.";
  }
  if (checkId === "aws.a.config.region_recorder_enabled") {
    if (record.recorder === "absent") return "No AWS Config recorder was found in the complete regional inventory.";
    if (Array.isArray(record.recorders)) {
      const rows = record.recorders.filter(row => row && typeof row === "object" && typeof row.name === "string" && typeof row.recording === "boolean" && typeof row.last_status === "string");
      const row = rows.find(row => !row.recording || row.last_status === "Failure") || rows[0];
      if (row) return `Config recorder ${concise(row.name)} is ${row.recording ? "recording" : "not recording"}; its last status is ${concise(row.last_status)}.`;
    }
  }
  if (checkId === "aws.a.guardduty.region_enabled") {
    if (record.detector === "absent") return "No GuardDuty detector was found in the complete regional inventory.";
    if (typeof record.status === "string") return `The regional GuardDuty detector reports ${concise(record.status)}.`;
  }
  if (checkId.startsWith("aws.b.")) {
    if (number(record.observed_configurations) && ["backup_plan", "backup_vault"].includes(String(record.inventory)))
      return `${record.observed_configurations} ${label(String(record.inventory))} configuration${record.observed_configurations === 1 ? " was" : "s were"} collected in this scope.`;
    if (number(record.backup_plans) && number(record.backup_report_plans)) return `${record.backup_plans} backup plan${record.backup_plans === 1 ? " is" : "s are"} configured; ${record.backup_report_plans} report plan${record.backup_report_plans === 1 ? " was" : "s were"} collected.`;
    if (["BackupRetentionPeriod", "AutomatedSnapshotRetentionPeriod"].includes(String(record.field)) && number(record.configured))
      return `Configured ${record.field === "BackupRetentionPeriod" ? "automatic backup" : "automated snapshot"} retention is ${record.configured} days.`;
    if (checkId === "aws.b.dynamodb.kms_description") {
      if (record.sse_description === null) return "No explicit SSEDescription is reported; DynamoDB-owned default encryption still applies.";
      if (record.sse_description && typeof record.sse_description === "object") return "An explicit DynamoDB SSEDescription object is reported.";
    }
    if (checkId === "aws.b.dynamodb.encryption_type") {
      if (typeof record.sse_type === "string") return `The table reports SSE type ${concise(record.sse_type)}; this is an encryption mode.`;
      if (record.encryption === "DynamoDB-owned default SSE") return "The table uses DynamoDB-owned default encryption.";
    }
    if (typeof record.audit_logging === "boolean" && checkId === "aws.b.eks.audit_log_category") return `The EKS audit-log category is ${record.audit_logging ? "enabled" : "not enabled"}.`;
    if (record.field === "Cluster.cluster.resourcesVpcConfig.endpointPublicAccess" && typeof record.configured === "boolean")
      return `The EKS public API endpoint is ${record.configured ? "enabled" : "disabled"}.`;
    if (checkId === "aws.b.eks.disable_public_endpoint" && record.endpoint_public_access === true) {
      const ranges = list(record.public_access_cidrs);
      return ranges ? `The EKS public API endpoint allows source ranges ${ranges}.` : "The public API endpoint reports no explicit source ranges; this check applies its world-source default.";
    }
    if (checkId === "aws.b.eks.no_default_vpc" && typeof record.is_default === "boolean") return `The cluster VPC is ${record.is_default ? "marked default" : "not marked default"}.`;
    if (typeof record.auto_enable === "boolean" && typeof record.auto_enable_service === "string") return `Inspector ${label(record.auto_enable_service)} automatic organization enrollment is ${record.auto_enable ? "enabled" : "disabled"}.`;
    if (Array.isArray(record.matching_layer_arns)) return record.matching_layer_arns.length ? "A Lambda Insights extension-layer ARN is configured." : "No configured layer ARN matches LambdaInsightsExtension.";
    if (record.reserved_concurrency === "not_configured") return "No reserved concurrency is configured for the function.";
    if (number(record.reserved_concurrency)) return `Reserved concurrency is ${record.reserved_concurrency}${record.reserved_concurrency === 0 ? "; event processing is stopped by this setting" : ""}.`;
    if (Array.isArray(record.allow_origins)) {
      const origins = list(record.allow_origins);
      return origins ? `Configured function-URL CORS origins: ${origins}.` : "No function-URL CORS origins are configured.";
    }
    if (typeof record.source_type === "string" && typeof record.enabled === "boolean" && Array.isArray(record.required) && Array.isArray(record.present)) {
      const present = record.present;
      const missing = record.required.filter(value => typeof value === "string" && !present.includes(value));
      return `The ${concise(record.source_type)} event subscription is ${record.enabled ? "enabled" : "disabled"}${missing.length ? `; missing categories: ${missing.join(", ")}` : "; the required categories are listed"}.`;
    }
    if (Array.isArray(record.required_categories) && Array.isArray(record.exported_categories) && typeof record.engine === "string") {
      const exported = record.exported_categories;
      const missing = record.required_categories.filter(value => typeof value === "string" && !exported.includes(value));
      return missing.length ? `The ${concise(record.engine)} database is not configured to export ${missing.join(", ")}.` : `The ${concise(record.engine)} database declares all checked log exports.`;
    }
    if (typeof record.master_username === "string") return `The database master username is ${concise(record.master_username)}; password strength is not assessed.`;
    if (Array.isArray(record.shared_accounts)) {
      if (record.shared_accounts.includes("all")) return "The self-owned SSM document is shared publicly (all accounts).";
      const accounts = list(record.shared_accounts);
      return accounts ? `Document sharing names accounts ${accounts}.` : "No document-sharing account is configured.";
    }
  }
  if (checkId === "aws.gap.account.distinct_primary_billing_operations_security_contacts") {
    if (Array.isArray(record.failures)) {
      const failure = record.failures.find(value => typeof value === "string");
      if (failure === "contacts share a phone") return "At least two account contacts share a phone number.";
      if (failure === "contacts share a name") return "At least two account contacts share a name.";
      if (failure === "contacts share a email") return "At least two alternate contacts share an email address.";
      if (typeof failure === "string") return `Account contacts: ${concise(failure)}.`;
    }
    if (number(record.contacts)) return `${record.contacts} account contacts were compared without retaining their raw contact values.`;
  }
  const arrays: [string, string][] = [
    ["methods_without_authorization", "Methods declaring no authorization"], ["methods_without_validator", "Methods without a request validator"],
    ["http_listeners_without_redirect", "HTTP listeners without the checked HTTPS redirect"],
    ["listeners_without_acm_certificate", "Listeners without an ACM certificate ARN"],
    ["non_pq_policies", "Listener policies outside the reviewed post-quantum list"],
    ["failing_policies", "Inline policies matching the checked permission pattern"],
    ["stale_enabled_credentials", "Credential slots flagged by the recorded use-age criterion"],
    ["destinations", "Peering route destinations flagged by this check"], ["failures", "Trail settings that do not satisfy this check"],
  ];
  for (const [key, subject] of arrays) {
    if (key === "failing_policies" && !checkId.includes("_inline_")) continue;
    const values = list(record[key]); if (values) return `${subject}: ${values}.`;
  }
  if (record.admin_access === true) return "The policy matches the reviewed administrator-access pattern.";
  if (record.administrator_access === true) return "A policy named AdministratorAccess is attached.";
  if (record.full_access === true) return `The policy model grants the full reviewed ${checkId.includes("kms") ? "KMS" : checkId.includes("cloudtrail") ? "CloudTrail" : "service"} action set on Resource *.`;
  if (record.subscribe_on_all === true) return "The policy model allows Marketplace Subscribe on Resource *.";
  if (record.permissive === true) return "The policy declares role-assumption permission on wildcard resources.";
  if (number(record.matching_statement_rows)) return `${record.matching_statement_rows} declared policy row${record.matching_statement_rows === 1 ? " matches" : "s match"} this check's action and resource pattern.`;
  if (checkId === "aws.claude_a.iam.custom_policy_kms_decrypt_restricted" && number(record.matching_statements)) return `${record.matching_statements} policy statement${record.matching_statements === 1 ? " matches" : "s match"} the reviewed broad KMS-decryption pattern.`;
  if (number(record.public_statements) && record.public_statements > 0) return `${record.public_statements} declared resource-policy statement${record.public_statements === 1 ? " permits" : "s permit"} modeled public access.`;
  if (number(record.unrestricted_public_statements) && record.unrestricted_public_statements > 0)
    return `${record.unrestricted_public_statements} wildcard bucket-policy Allow statement${record.unrestricted_public_statements === 1 ? " lacks" : "s lack"} a supported access restriction.`;
  if (record.public_acl === true) return "The stored bucket ACL declares public read access; runtime blocking is assessed separately.";
  const groups = list(record.public_acl_groups);
  if (groups) return `The stored bucket ACL grants access to public groups: ${groups}.`;
  if (checkId.includes(".s3.") && Array.isArray(record.public) && record.public.length) return "The check recorded public ACL or policy grant declarations.";
  if (record.bucket_logging === "absent") return "No bucket server-access logging destination is configured.";
  if (record.mfa_delete === "Disabled") return "Bucket MFA Delete is disabled.";
  if (record.mfa_delete === "not_reported") return "The bucket versioning response did not report MFA Delete.";
  if (record.retention_days === null && record.source_requires_explicit_retention === true) return "No explicit finite log-retention period is configured.";
  if (record.account_mfa_enabled === 0 || record.account_mfa_enabled === false) return "The account summary reports root MFA as disabled.";
  if (record.virtual_root_mfa_present === true || record.virtual_root_mfa === true) return "An assigned virtual MFA device was found for root.";
  if (record.credential_flags && typeof record.credential_flags === "object" && !Array.isArray(record.credential_flags)) {
    const flags = record.credential_flags as Record<string, unknown>;
    if (flags.mfa_active === "false") return "The root credential report records MFA as inactive.";
  }
  if (number(record.active_key_count)) return `${record.active_key_count} access key${record.active_key_count === 1 ? " is" : "s are"} active.`;
  if (record.field === "SummaryMap.AccountAccessKeysPresent" && number(record.configured)) return `The account summary reports ${record.configured} root access key${record.configured === 1 ? "" : "s"}.`;
  if (record.field === "PasswordPolicy.MaxPasswordAge" && number(record.configured)) return `Password expiry is configured for ${record.configured} days.`;
  if (Array.isArray(record.stale_keys) && record.stale_keys.length && record.stale_keys.every((slot) => slot === 1 || slot === 2))
    return `Credential-report key slots flagged by the use-age criterion: ${record.stale_keys.join(", ")}.`;
  if (record.role_attachment_found === false) return "No collected IAM role attachment was found for this policy.";
  if (record.endpoint_present === false && typeof record.service_name === "string") return `No VPC endpoint was found for ${concise(record.service_name)}.`;
  if (Array.isArray(record.roles) && record.roles.length === 0 && ["aws.claude_a.iam.securityaudit_role_exists", "aws.claude_a.iam.support_role_exists"].includes(checkId))
    return "No collected role matches this check's required managed-policy attachment.";
  if (record.last_authenticated === null) return "No service-authentication timestamp was reported.";
  if (record.last_used === null) return "No role last-use timestamp was reported.";
  if (typeof record.last_used === "string") return `The recorded role last-use timestamp is ${concise(record.last_used)}.`;
  if (number(record.days_since_use)) return `The recorded last use was ${record.days_since_use} days ago.`;
  if (record.kms_rules === 0) return "No default-encryption rule names a KMS key; this does not imply plaintext storage.";
  if (record.match === null && checkId === "aws.claude_a.s3.object_level_logging") return "No matching bucket object-data selector was recorded.";
  if (record.job === null && checkId === "aws.claude_a.s3.protected_by_macie") return "No collected classification job explicitly includes the bucket.";
  if (typeof record.index_document === "string") return `Website hosting has an index document: ${concise(record.index_document)}.`;
  if (typeof record.health_check_type === "string") return `Auto Scaling health checks use ${concise(record.health_check_type)}.`;
  if (Array.isArray(record.endpoint_types)) { const types = list(record.endpoint_types); if (types) return `Configured API endpoint types: ${types}.`; }
  if (record.listener_count === 0) return "No load-balancer listeners are configured.";
  if (Array.isArray(record.web_acl_families) && record.web_acl_families.length === 0) return "No collected WebACL association matched the load balancer.";
  if (record.expiring && typeof record.expiring === "object" && !Array.isArray(record.expiring)) {
    const days = Object.values(record.expiring).filter(number);
    if (days.length) return `A listener certificate has ${Math.min(...days)} days remaining.`;
  }
  if (number(record.matching_rules)) return `${record.matching_rules} ingress rule${record.matching_rules === 1 ? " matches" : "s match"} the checked source and port pattern.`;
  if (number(record.unauthorized_rules)) return `${record.unauthorized_rules} IPv4 Internet-wide ingress rule${record.unauthorized_rules === 1 ? " is" : "s are"} outside the checked single-port 80/443 pattern.`;
  const noRules = list(record.security_groups_without_rules);
  if (noRules && record.direction === "IpPermissionsEgress") return `Security groups with no outbound rules: ${noRules}.`;
  if (typeof record.attribute === "string" && typeof record.configured === "string") {
    const subject = ({ "access_logs.s3.enabled": "Load-balancer S3 access logging", "routing.http.drop_invalid_header_fields.enabled": "Invalid-header dropping" } as Record<string, string>)[record.attribute];
    if (subject && ["true", "false"].includes(record.configured)) return `${subject} is ${record.configured === "true" ? "enabled" : "disabled"}.`;
  }
  if (typeof record.desync_mitigation_mode === "string" && record.drop_invalid_headers === "false") return `Desync mitigation is ${concise(record.desync_mitigation_mode)} and invalid-header dropping is disabled.`;
  if (Array.isArray(record.tunnel_logging) && record.tunnel_logging.every((item) => item === false)) return "None of the collected VPN tunnels enables logging.";
  if (Array.isArray(record.bucket_statements) && !record.bucket_statements.length && Array.isArray(record.object_statements) && !record.object_statements.length)
    return "No matching non-TLS Deny statement covers the bucket or its objects.";
  if (typeof record.latest_cloudwatch_delivery === "string") return `The latest reported CloudWatch Logs delivery is ${concise(record.latest_cloudwatch_delivery)}.`;
  if (typeof record.created_at === "string" && typeof record.cutoff === "string") return `The key was created at ${concise(record.created_at)}; the check cutoff is ${concise(record.cutoff)}.`;
  if (typeof record.created === "string" && typeof record.cutoff === "string") return `The key was created at ${concise(record.created)}; the check cutoff is ${concise(record.cutoff)}.`;
  if (number(record.minimum_password_length) && number(record.minimum) && record.minimum_password_length < record.minimum)
    return `The minimum password length is ${record.minimum_password_length}; this check requires ${record.minimum}.`;
  if (record.composition && typeof record.composition === "object" && !Array.isArray(record.composition)) {
    const disabled = Object.entries(record.composition).filter(([, value]) => value === false).map(([key]) => label(key));
    if (disabled.length) return `Disabled password-composition requirements: ${disabled.join(", ")}.`;
  }
  if (number(record.password_reuse_prevention) && record.password_reuse_prevention < 24) return `Password reuse prevention is configured for ${record.password_reuse_prevention} previous passwords; this check requires 24.`;
  if (number(record.maximum_password_age) && record.maximum_password_age > 90) return `The maximum password age is ${record.maximum_password_age} days; this check allows at most 90.`;
  if (number(record.minimum_password_length)) return `The minimum password length is ${record.minimum_password_length}.`;
  if (Array.isArray(record.flagged_identities)) {
    const actor = record.flagged_identities.find((entry) => entry && typeof entry === "object" && typeof entry.actor_arn === "string" && number(entry.ratio));
    if (actor) return `The activity model flagged ${concise(actor.actor_arn)} at an action ratio of ${actor.ratio}${number(record.threshold) ? ` (threshold ${record.threshold})` : ""}.`;
  }
  if (checkId === "aws.claude_a.iam.user_inline_no_assume_role_text") {
    const policies = list(record.policies);
    if (policies) return `Inline policy documents or names containing the text AssumeRole: ${policies}.`;
  }
  if (Array.isArray(record.access)) { const access = list(record.access); if (access) return `Subnet route classifications: ${access}.`; }
  if (Array.isArray(record.public_flags) && record.public_flags.length && record.public_flags.every((value) => typeof value === "boolean"))
    return `Subnet route classifications: ${record.public_flags.map((value) => value ? "public" : "private").join(", ")}.`;
  if (Array.isArray(record.event_selectors) && record.event_selectors.length === 0) return "The basic event-selector list is empty.";
  if (record.recent_use && typeof record.recent_use === "object" && !Array.isArray(record.recent_use)) {
    const uses = Object.entries(record.recent_use).filter(([, value]) => typeof value === "string");
    if (uses.length) return `Reported root activity: ${uses.slice(0, 2).map(([key, value]) => `${label(key)} at ${concise(String(value))}`).join("; ")}.`;
  }
  if (record.console_login === true && record.mfa_device_count === 0) return "Console login is configured, but no MFA device was recorded.";
  if (Array.isArray(record.unrestricted_trust_statements) && record.unrestricted_trust_statements.length)
    return "The role trust policy declares an unconditional Allow for a wildcard principal.";
  if (checkId === "aws.claude2_a.cloudwatch.cross_account_sharing_role_absent") {
    const principals = list(record.trusted_principals);
    if (principals) return `Declared principals in the cross-account sharing role's trust document: ${principals}.`;
  }
  if (checkId === "aws.s3.no_public_acl" && Array.isArray(record.public_acl_grants) && record.public_acl_grants.length)
    return "The bucket ACL declares a public-group grant; runtime blocking is assessed separately.";
  if (checkId === "aws.s3.default_encryption") { const algorithms = list(record.algorithms); if (algorithms) return `Bucket default-encryption algorithms: ${algorithms}.`; }
  if (checkId === "aws.s3.public_access_block") {
    const settings = record.effective_settings && typeof record.effective_settings === "object" ? record.effective_settings as Record<string, unknown>
      : record.settings && typeof record.settings === "object" ? record.settings as Record<string, unknown> : {};
    const keys = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"];
    const missing = keys.filter((key) => settings[key] === false);
    if (missing.length) return `Effective Block Public Access protections not enabled: ${missing.join(", ")}.`;
    if (keys.every((key) => settings[key] === true)) return "All four effective Block Public Access protections are enabled.";
  }
  return undefined;
}

/** Describe only supplied facts. Keep nested records available in technical details. */
export function explainFindingEvidence(evidence: unknown, status: string, checkId?: string): string {
  if (evidence == null || evidence === "")
    return ["UNKNOWN", "DENIED", "EMPTY", "MANUAL", "NOT_APPLICABLE"].includes(
      status.toUpperCase(),
    )
      ? "No observed evidence was supplied for this undetermined result."
      : "No observed evidence was supplied.";

  if (typeof evidence === "string" && structuredText(evidence)) {
    try {
      return explainFindingEvidence(JSON.parse(evidence), status, checkId);
    } catch {
      return "Observed evidence contains a structured value that could not be summarized. Open technical details for its recorded form.";
    }
  }

  const scalar = valueText(evidence);
  if (scalar) return `Observed value: ${scalar}.`;
  if (Array.isArray(evidence))
    return evidence.length
      ? `${evidence.length} evidence records were supplied. Open technical details to review them.`
      : "No observed evidence was supplied.";
  if (typeof evidence !== "object") return "No readable evidence was supplied.";

  const entries = Object.entries(evidence as Record<string, unknown>);
  const record = evidence as Record<string, unknown>;
  if (typeof record.observed === "string" && record.observed.trim() && !structuredText(record.observed))
    return ["UNKNOWN", "DENIED", "MANUAL"].includes(status.toUpperCase())
      ? `${record.observed.trim()} The overall assessment remains undetermined.` : record.observed.trim();
  if (checkId === "aws.cb.inspector2.coverage_scan_active" && typeof record.status_code === "string" &&
      typeof record.reason === "string" && /^[A-Z0-9_]+$/.test(record.reason)) {
    const observation = reviewedAwsObservation(checkId, record);
    if (observation) return ["UNKNOWN", "DENIED", "MANUAL"].includes(status.toUpperCase())
      ? `${observation} The overall assessment remains undetermined.` : observation;
  }
  if (checkId === "aws_nist_dynamodb_table_encrypted_with_kms" && record.reason === "complete table detail has no KMS SSE description")
    return "No explicit KMS SSE metadata is reported; DynamoDB default encryption still applies." + (["UNKNOWN", "DENIED", "MANUAL"].includes(status.toUpperCase()) ? " The overall assessment remains undetermined." : "");
  if (typeof record.reason === "string" && record.reason.trim() && !structuredText(record.reason))
    return concise(record.reason.trim());
  const firewall = firewallObservation(record, status);
  if (firewall) return firewall;
  const awsScalar = reviewedAwsScalarObservation(checkId, record);
  if (awsScalar) return ["UNKNOWN", "DENIED", "MANUAL"].includes(status.toUpperCase())
    ? `${awsScalar} The overall assessment remains undetermined.` : awsScalar;
  const configuration = nativeConfigurationObservation(record);
  if (configuration) return ["UNKNOWN", "DENIED", "MANUAL"].includes(status.toUpperCase())
    ? `${configuration} The overall assessment remains undetermined.` : configuration;
  const aws = reviewedAwsObservation(checkId, record);
  if (aws) return ["UNKNOWN", "DENIED", "MANUAL"].includes(status.toUpperCase())
    ? `${aws} The overall assessment remains undetermined.` : aws;
  if (record.source === "Explicit demo fixture" &&
      typeof record.encryption === "string" &&
      /missing in fixture snapshot/i.test(record.encryption))
    return "Missing in fixture snapshot: encryption information was not supplied, so this demo evidence does not establish the configuration.";
  if (typeof record.default_encryption_configuration === "boolean") {
    const presence = record.default_encryption_configuration ? "present" : "absent";
    const count = typeof record.rule_count === "number"
      ? ` ${record.rule_count} rule${record.rule_count === 1 ? "" : "s"} recorded.`
      : "";
    return `Collected default encryption configuration is ${presence}.${count}`;
  }
  const facts = scalarFacts(record);
  if (!facts.length)
    return entries.length
      ? "The recorded evidence has no concise non-sensitive values to summarize. Open technical details for available fields."
      : "No observed evidence was supplied.";
  const displayed = facts.slice(0, 3).join("; ");
  return facts.length > 3
    ? `Observed evidence: ${displayed}. More recorded details are available below.`
    : `Observed evidence: ${displayed}.`;
}
