import { test, expect } from "@playwright/test";
import { scanDuration } from "../src/scanDuration";
import type { Scan } from "../src/types";

const base: Scan = { id: "duration-fixture", connector_id: "c", categories: [], status: "completed", created_at: "2026-10-19T11:32:00Z" };

test("duration uses final wall time, including queueing, rather than summed worker times", () => {
  expect(scanDuration({ ...base, timeline: [
    { status: "queued", at: base.created_at }, { status: "collecting", at: "2026-10-19T11:34:00Z" },
    { status: "completed", at: "2026-10-19T11:40:05Z" },
  ] })).toBe("Completed in 8m 5s");
  expect(scanDuration({ ...base, updated_at: "2026-10-19T12:34:03Z" })).toBe("Completed in 1h 2m 3s");
  expect(scanDuration({ ...base, status: "failed", updated_at: "2026-10-19T11:32:45Z" })).toBe("Duration: 45s");
  expect(scanDuration({ ...base, status: "queue_exhausted", timeline: [
    { status: "queued", at: base.created_at }, { status: "queue_exhausted", at: "2026-10-19T12:32:00Z" },
  ] })).toBe("Duration: 1h");
});

test("legacy, running and malformed timestamps do not invent completed durations", () => {
  expect(scanDuration(base)).toBeUndefined();
  expect(scanDuration({ ...base, updated_at: base.created_at })).toBeUndefined();
  expect(scanDuration({ ...base, updated_at: "invalid" })).toBeUndefined();
  expect(scanDuration({ ...base, updated_at: "2026-10-18T00:00:00Z" })).toBeUndefined();
  expect(scanDuration({ ...base, status: "collecting", updated_at: "2026-10-19T11:40:05Z" })).toBeUndefined();
});

test("scan history and detail show total completion duration", async ({ page }) => {
  await page.route("**/api/**", route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/me") ? { tenant_id: "duration-fixture" } : path.endsWith("/health") ? { status: "ok" }
      : path.endsWith("/scans") ? { items: [{ ...base, display_name: "aws-Guardian-Manifest-all-scopes-19.10.26", timeline: [
        { status: "queued", at: base.created_at }, { status: "completed", at: "2026-10-19T11:40:05Z" },
      ] }] } : { items: [] };
    return route.fulfill({ json });
  });
  await page.goto("/#Scans");
  await expect(page.locator(".scan-row").first()).toContainText("Completed in 8m 5s");
  await page.getByRole("button", { name: "aws-Guardian-Manifest-all-scopes-19.10.26", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("Completed in 8m 5s");
});
