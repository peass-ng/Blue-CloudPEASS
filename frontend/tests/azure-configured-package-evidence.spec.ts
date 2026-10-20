import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { selectedConfigurationContentObservation } from "../src/selectedConfigurationContentEvidence";
const rows = Object.values(JSON.parse(readFileSync(new URL("../../tests/fixtures/azure-configured-package-evidence-review-20261020.json", import.meta.url), "utf8")))[0] as (Finding & { capture_branch: string })[];
for (const f of rows) test(`native configured package ${f.capture_branch} stays scoped`, () => {
  const before = structuredClone(f), text = selectedConfigurationContentObservation(f);
  if (f.status === "UNKNOWN") expect(text).toBeUndefined();
  else {
    expect(text).toContain("stored deployment package");
    expect(text!.split(/\s+/).length).toBeLessThanOrEqual(35);
    if (f.status === "PASS") expect(text).toContain("Both offline detectors");
    else expect(text).toContain("not validated");
    if (!f.evidence!.complete) expect(text).toContain("incomplete");
  }
  expect(f).toEqual(before);
});
for (const fault of ["status", "detector", "path", "global_leak", "raw_member"]) test(`native partial package rejects ${fault}`, () => {
  const f = structuredClone(rows.find(f => f.capture_branch === "partial_positive")!);
  const e = f.evidence as { parts: { engines: {status: string}[];path: string;source_text?: string}[];secret_leaks:unknown[] };
  expect(selectedConfigurationContentObservation(f)).toContain("incomplete");
  if (fault === "status") f.status = "PASS";
  else if (fault === "detector") e.parts.at(-1)!.engines[0].status = "unavailable";
  else if (fault === "path") e.parts.at(-1)!.path = "unbound";
  else if (fault === "global_leak") e.secret_leaks = [];
  else e.parts.at(-1)!.source_text = "never-render";
  expect(selectedConfigurationContentObservation(f)).toBeUndefined();
});
