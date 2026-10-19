import { expect, test } from "@playwright/test";
import { explainExposureCheck } from "../src/exposureCheckExplanation";

test("how the check works names the asset’s recorded access layers", () => {
  expect(explainExposureCheck({ path: [{ layer: "listener" }, { layer: "authorization" }] }))
    .toBe("Checks the collected listeners and route authorization for an allowed Internet path. No traffic is sent.");
  expect(explainExposureCheck({ source: { resource_type: "rds_snapshot" } }))
    .toBe("Checks the snapshot’s restore or sharing attributes for public access or grants to other accounts.");
});

test("missing or unrecognized layers are not invented", () => {
  const fallback = explainExposureCheck(null);
  expect(fallback).toContain("Missing required layers");
  expect(explainExposureCheck({ path: [{ layer: "__proto__" }, { layer: "unrecognized" }] })).toBe(fallback);
});
