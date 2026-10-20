import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { azureReviewObservation } from "../src/azureReviewEvidence";
const rows = JSON.parse(readFileSync(new URL("../../tests/fixtures/azure-final-native-evidence-review-20261020.json", import.meta.url), "utf8")) as Record<string, {status: string;evidence:Record<string, unknown>;expected_observation:string|null}[]>;
for (const [cid, cases] of Object.entries(rows)) for (const row of cases)
  test(`${cid} ${row.status} uses current native declaration`, () => {
    const finding = { provider: "azure", check_id: cid, ...row } as Finding;
    expect(azureReviewObservation(finding) ?? null).toBe(row.expected_observation);
    if (row.status !== "UNKNOWN") {
      expect(azureReviewObservation(finding)!.length).toBeLessThan(190);
      expect(azureReviewObservation({...finding,status:row.status==="PASS"?"FAIL":"PASS"})).toBeUndefined();
      expect(azureReviewObservation({...finding,evidence:{...row.evidence,native_declaration_id:"unreviewed",observed:"Everything is fully protected."}})).toBeUndefined();
    }
  });
