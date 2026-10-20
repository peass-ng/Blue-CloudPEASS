import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { azureReviewObservation } from "../src/azureReviewEvidence";

const branches = JSON.parse(readFileSync(new URL("../../tests/fixtures/azure-key-age-evidence-review-20261020.json", import.meta.url), "utf8"));
for (const row of branches as { status: string; evidence: unknown }[])
  test(`native key ages ${row.status} use collection-bound facts`, () => {
    const finding = { provider: "azure", check_id: "azure.claude.storage_access_keys_rotated_90", ...row } as Finding;
    const text = azureReviewObservation(finding);
    if (row.status === "UNKNOWN") expect(text).toBeUndefined();
    else {
      expect(text).toBeTruthy();
      expect(text!.length).toBeLessThan(110);
      expect(text!.includes("older than 90 days")).toBe(row.status === "FAIL");
      expect(azureReviewObservation({ ...finding, status: row.status === "PASS" ? "FAIL" : "PASS" })).toBeUndefined();
    }
  });

for (const seconds of [7776000, 7776000.000001, 7775999.999999])
  test(`sub-millisecond boundary ${seconds} is not rounded into another verdict`, () => {
    const now = Date.parse("2026-10-20T00:00:00Z");
    const time = seconds > 7776000 ? "2026-07-21T23:59:59.999999Z"
      : seconds < 7776000 ? "2026-07-22T00:00:00.000001Z" : "2026-07-22T00:00:00Z";
    const finding = { provider: "azure", check_id: "azure.claude.storage_access_keys_rotated_90", status: seconds > 7776000 ? "FAIL" : "PASS",
      evidence: { time_source: "scan_capture", threshold_seconds: 7776000, captured_at: new Date(now).toISOString(),
        key_age_seconds: { key1: seconds, key2: 86400 }, key_creation_time: { key1: time, key2: "2026-10-19T00:00:00Z" } } } as Finding;
    expect(azureReviewObservation(finding)).toBeTruthy();
    expect(azureReviewObservation(finding)!.includes("older than 90 days")).toBe(seconds > 7776000);
  });
