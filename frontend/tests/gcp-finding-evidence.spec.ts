import { expect, test } from "@playwright/test";
import { explainGcpFindingEvidence } from "../src/gcpFindingEvidence";

test("GCP scalar evidence states observed settings without field-path clutter", () => {
  expect(explainGcpFindingEvidence("gcp.compute.secure_boot", { field: "shieldedInstanceConfig.enableSecureBoot", configured: false }, "FAIL"))
    .toBe("Secure Boot is disabled.");
  expect(explainGcpFindingEvidence("gcp.sql.no_public_ip", { field: "settings.ipConfiguration.ipv4Enabled", configured: true }, "FAIL"))
    .toBe("Public IPv4 for this Cloud SQL instance is enabled.");
  expect(explainGcpFindingEvidence("gcp.gke.secrets_encryption", { field: "databaseEncryption.state", configured: "DECRYPTED" }, "FAIL"))
    .toBe("Application-layer Secrets encryption is disabled.");
  expect(explainGcpFindingEvidence("gcp.network.custom_subnets", { field: "autoCreateSubnetworks", configured: false }, "PASS"))
    .toBe("The VPC subnet mode is custom.");
});

test("missing malformed or unknown values keep uncertainty fallback", () => {
  for (const value of [null, {}, { field: "wrong", configured: false }, { field: "shieldedInstanceConfig.enableSecureBoot", configured: "false" }]) {
    expect(explainGcpFindingEvidence("gcp.compute.secure_boot", value, "FAIL")).toBeUndefined();
  }
  expect(explainGcpFindingEvidence("gcp.compute.secure_boot", { field: "shieldedInstanceConfig.enableSecureBoot", configured: false }, "UNKNOWN")).toBeUndefined();
  expect(explainGcpFindingEvidence("unowned", { field: "deletionProtection", configured: true }, "PASS")).toBeUndefined();
  expect(explainGcpFindingEvidence("gcp.gke.secrets_encryption", { field: "databaseEncryption.state", configured: "__proto__" }, "PASS")).toBeUndefined();
});
