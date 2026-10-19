import { expect, test } from "@playwright/test";
import { explainExposureAction, explainFindingEvidence, explainInternetExposure } from "../src/findingExplanation";

test("public HTTPS has one direct observation without repeating path layers", () => {
  const result = explainInternetExposure({
    exposed_ports: ["tcp/443"],
    public_addresses: ["https://9gi0nszlth.execute-api.ca-central-1.amazonaws.com"],
    path: [{ layer: "route", decision: "allow" }, { layer: "authorization", decision: "allow" }],
  }, "FAIL");
  expect(result.summary).toBe("Internet access to tcp/443 at https://9gi0nszlth.execute-api.ca-central-1.amazonaws.com is allowed.");
  expect(result.reasons).toEqual([]);
});

test("UNKNOWN never describes candidate ports as allowed", () => {
  const result = explainInternetExposure({
    exposed_ports: ["tcp/443"], public_addresses: ["https://api.example.com"],
    observed: "Internet access to tcp/443 is allowed.",
    unresolved: [{ layer: "authorization", reason: "route authorization not collected" }],
  }, "UNKNOWN");
  expect(result.summary).toBe("Internet exposure for this asset could not be determined at https://api.example.com.");
  expect(result.reasons).toEqual(["authorization: route authorization not collected"]);
});

test("partial FAIL and stopped instances retain their uncertainty", () => {
  const partial = explainInternetExposure({
    exposed_ports: ["tcp/22"], public_addresses: ["54.1.2.3"],
    unresolved: [{ layer: "route", reason: "route inventory missing" }],
  }, "FAIL");
  expect(partial.summary).toContain("Some path layers remain unresolved.");
  expect(partial.reasons).toEqual(["route: route inventory missing"]);
  const stopped = explainInternetExposure({
    exposed_ports: ["tcp/22"], public_addresses: ["54.1.2.3"],
    observed: "Configured internet access to tcp/22 at 54.1.2.3 is allowed. The instance is stopped or deallocated.",
  }, "FAIL");
  expect(stopped.summary).toContain("stopped or deallocated");
});

test("data shares and blocked endpoints are not explained as open ports", () => {
  expect(explainInternetExposure({ external_scope_ids: ["123456789012"] }, "FAIL").summary)
    .toBe("Snapshot restore access is granted to external accounts: 123456789012.");
  expect(explainInternetExposure({ data_exposure: true }, "FAIL").summary)
    .toBe("Public data access is allowed.");
  const blocked = explainInternetExposure({ exposed_ports: ["tcp/22"], blocked_by: "security_group" }, "PASS");
  expect(blocked.summary).toBe("Public path is blocked by security group.");
});

test("native firewall summary names only the matched protocol and checked port", () => {
  expect(explainFindingEvidence({ ports: [53], protocols: ["tcp", "udp"], source_ranges: ["0.0.0.0/0"],
    matching_allow_entries: [{ protocol: "tcp", ports: "52-53" }],
    semantics: "Declared per-rule ingress; deny rules and targets are not evaluated",
  }, "FAIL")).toBe("This firewall rule allows tcp/53 from 0.0.0.0/0.");
  expect(explainFindingEvidence({ ports: [9200, 9300], source_ranges: ["::/0"],
    matching_allow_entries: [{ protocol: "udp", ports: "9200-9200" }],
  }, "FAIL")).toBe("This firewall rule allows udp/9200 from ::/0.");
});

test("native firewall does not claim effective reachability or invent missing sources", () => {
  expect(explainFindingEvidence({ ports: [53], matching_allow_entries: [{ protocol: "tcp", ports: "all" }] }, "FAIL"))
    .toBe("This firewall rule allows tcp/53.");
  expect(explainFindingEvidence({ ports: [53], source_ranges: ["0.0.0.0/0"],
    matching_allow_entries: [{ protocol: "all", ports: "all" }],
  }, "UNKNOWN")).toContain("could not be determined");
  expect(explainFindingEvidence({ ports: [53], source_ranges: ["0.0.0.0/0"],
    matching_allow_entries: [{ protocol: "all", ports: "all" }],
  }, "FAIL")).toBe("This firewall rule allows all protocols and ports from 0.0.0.0/0.");
  expect(explainFindingEvidence({ ports: [53], matching_allow_entries: [] }, "PASS"))
    .toBe("No allow entry matches the checked protocols and ports.");
});

test("archived exposure actions follow asset type rather than a generic network instruction", () => {
  expect(explainExposureAction({ exposure_kind: "api" }, "FAIL"))
    .toBe("Consider whether this endpoint needs internet access; restrict unnecessary source networks or ports.");
  expect(explainExposureAction({ exposure_kind: "external_share" }, "FAIL")).toContain("snapshot restore");
  expect(explainExposureAction({ data_exposure: true, source: { resource_type: "rds_snapshot" } }, "FAIL"))
    .toContain("public snapshot restore");
  expect(explainExposureAction({ data_exposure: true }, "FAIL")).toContain("policy or ACL");
  expect(explainExposureAction({ exposure_kind: "control_plane" }, "FAIL")).toContain("control-plane");
  expect(explainExposureAction({ exposed_ports: ["tcp/22"] }, "UNKNOWN")).toContain("Collect the missing configuration");
  expect(explainExposureAction({}, "PASS")).toBe("Keep the access restrictions in place.");
});

test("native AWS observations explain actual predicate evidence without plaintext or reachability claims", () => {
  // These shapes are the corresponding registered predicates' real FAIL fixture outputs.
  expect(explainFindingEvidence({ field: "Encrypted", configured: false }, "FAIL")).toBe("Encryption is disabled.");
  expect(explainFindingEvidence({ field: "AssociatePublicIpAddress", configured: true, expected: [false] }, "FAIL"))
    .toBe("Automatic public-IP assignment is enabled.");
  expect(explainFindingEvidence({ field: "SSEDescription.Status", configured: "DISABLED", expected: ["ENABLED"] }, "FAIL"))
    .toBe("DAX storage encryption is disabled.");
  expect(explainFindingEvidence({ publicly_accessible: true, open_security_groups: ["sg-1"] }, "FAIL"))
    .toBe("The public instance has Internet-wide ingress allowed by security groups sg-1.");
  expect(explainFindingEvidence({ containers_without_log_driver: ["sidecar"] }, "FAIL"))
    .toBe("No log driver is configured for containers sidecar.");
  expect(explainFindingEvidence({ unencrypted_volumes: ["vol-1"] }, "FAIL")).toBe("EBS volumes vol-1 are not encrypted.");
  expect(explainFindingEvidence({ data_sources_without_cmk: ["ds1"] }, "FAIL"))
    .toBe("Data sources ds1 have no configured KMS key ARN.");
  expect(explainFindingEvidence({ s3_logs_encryption_disabled: true }, "FAIL"))
    .toBe("The S3 log configuration disables explicit export encryption.");
});

test("native observations preserve known values without resolving missing assessment inputs", () => {
  expect(explainFindingEvidence({ field: "StorageEncrypted", configured: false }, "UNKNOWN"))
    .toBe("Encryption is disabled. The overall assessment remains undetermined.");
  expect(explainFindingEvidence({ field: "StorageEncrypted" }, "UNKNOWN")).not.toContain("Encryption is disabled");
  expect(explainFindingEvidence({ unencrypted_volumes: [] }, "UNKNOWN")).not.toContain("are not encrypted");
});

test("enriched AWS evidence states the computed predicate observation without guessing from counters", () => {
  expect(explainFindingEvidence({ caching_settings: 1, encrypted_cache_setting_found: false,
    observed: "None of the cached method settings enables encryption." }, "FAIL"))
    .toBe("None of the cached method settings enables encryption.");
  expect(explainFindingEvidence({ trails_considered: 1, observed: "No evaluated trail satisfies this check's logging and event-selector requirements." }, "FAIL"))
    .toBe("No evaluated trail satisfies this check's logging and event-selector requirements.");
  expect(explainFindingEvidence({ caching_settings: 1 }, "FAIL")).not.toContain("None of the cached method settings");
  expect(explainFindingEvidence({ public_allow_statements: 1 }, "FAIL"))
    .toBe("The resource policy contains 1 modeled public Allow statement.");
});

test("specific encryption mismatches take precedence over an unrelated enabled setting", () => {
  expect(explainFindingEvidence({ encrypted: true, key_manager: "AWS", key_enabled: true }, "FAIL"))
    .toBe("The encryption key manager is AWS; the key is enabled.");
  expect(explainFindingEvidence({ enable_at_rest_encryption: true, local_disk_encryption: false }, "FAIL"))
    .toBe("Local-disk encryption configuration is disabled.");
  expect(explainFindingEvidence({ enable_at_rest_encryption: true, s3_encryption_mode: "SSE-KMS" }, "FAIL"))
    .toBe("The configured S3 encryption mode is SSE-KMS.");
  expect(explainFindingEvidence({ managed_query_results: false, encryption_option: null }, "FAIL"))
    .toBe("No explicit query-result encryption option was reported.");
  expect(explainFindingEvidence({ cloudfront_default_certificate: true }, "FAIL"))
    .toBe("The distribution uses the default CloudFront certificate.");
});

test("AWS security-group observations use matched ports rather than every requested port", () => {
  expect(explainFindingEvidence({ ports: [7199, 9160, 8888], matching_ingress: [
    { protocol: "tcp", ports: [8888], source_ranges: ["::/0"] },
  ] }, "FAIL")).toBe("A security-group rule allows tcp/8888 from ::/0.");
  expect(explainFindingEvidence({ ports: [22], matching_ingress: [] }, "UNKNOWN")).not.toContain("allows tcp/22");
});

test("reviewed AWS summaries require supplied facts and the reviewed check identity", () => {
  expect(explainFindingEvidence({ admin_access: true }, "FAIL", "aws.claude_a.iam.prowler_aws_attached_policy_no_admin"))
    .toBe("The policy matches the reviewed administrator-access pattern.");
  expect(explainFindingEvidence({ admin_access: true }, "FAIL", "aws.unreviewed.example"))
    .not.toContain("reviewed administrator-access pattern");
  expect(explainFindingEvidence({ policy_arn: "arn:aws:iam::123456789012:policy/app" }, "FAIL", "aws.claude_a.iam.custom_policy_attached_to_role"))
    .not.toContain("No collected IAM role attachment");
  expect(explainFindingEvidence({ role_attachment_found: false }, "UNKNOWN", "aws.claude_a.iam.custom_policy_attached_to_role"))
    .toBe("No collected IAM role attachment was found for this policy. The overall assessment remains undetermined.");
  expect(explainFindingEvidence({ matching_rules: 1 }, "FAIL", "aws.claude_a.vpc.sg_world_v4_common20"))
    .toBe("1 ingress rule matches the checked source and port pattern.");
});

test("password evidence prioritizes the actual failed requirement without inventing unread fields", () => {
  const cid = "aws.a.iam.password_policy_strong_min_length_14_reuse_24_age_90";
  expect(explainFindingEvidence({ minimum_password_length: 14, minimum: 14, composition: { RequireSymbols: true },
    password_reuse_prevention: 24, maximum_password_age: 120 }, "FAIL", cid))
    .toBe("The maximum password age is 120 days; this check allows at most 90.");
  expect(explainFindingEvidence({ minimum_password_length: 14, minimum: 14, composition: { RequireSymbols: false } }, "FAIL", cid))
    .toBe("Disabled password-composition requirements: Require Symbols.");
  const generic = explainFindingEvidence({ policy_arn: "arn:aws:iam::123456789012:policy/app" }, "FAIL", "aws.claude_a.iam.custom_policy_attached_to_role");
  expect(generic).not.toContain("No collected IAM role attachment");
});

test("manual and native security boundaries remain declared facts rather than effective-access claims", () => {
  expect(explainFindingEvidence({ console_login: true, mfa_device_count: 0 }, "FAIL", "aws.iam.console_mfa"))
    .toBe("Console login is configured, but no MFA device was recorded.");
  expect(explainFindingEvidence({ public_acl_grants: [{ Permission: "READ", Grantee: { URI: "http://acs.amazonaws.com/groups/global/AllUsers" } }] }, "MANUAL", "aws.s3.no_public_acl"))
    .toContain("declares a public-group grant; runtime blocking is assessed separately");
  expect(explainFindingEvidence({ algorithms: ["AES256"] }, "PASS", "aws.s3.default_encryption"))
    .toBe("Bucket default-encryption algorithms: AES256.");
  const summary = explainFindingEvidence({ effective_settings: { BlockPublicAcls: true, IgnorePublicAcls: null,
    BlockPublicPolicy: false, RestrictPublicBuckets: true } }, "FAIL", "aws.s3.public_access_block");
  expect(summary).toBe("Effective Block Public Access protections not enabled: BlockPublicPolicy.");
  expect(summary).not.toContain("IgnorePublicAcls");
});
