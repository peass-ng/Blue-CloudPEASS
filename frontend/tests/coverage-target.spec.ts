import { expect, test } from "@playwright/test";

test("paged coverage identifies an uncollected credential target without changing ordinary rows", async ({ page }) => {
  const roleB = "arn:aws:iam::947000000000:role/RoleB";
  const hostile = "<img src=x onerror=alert(1)>";
  const ordinary = {
    check_id: "cloudtrail-collection",
    status: "collected",
    reason: "Collection completed",
  };
  const firstPage = [
    ordinary,
    { service: "s3", status: "denied", error: "AccessDenied" },
    ...Array.from({ length: 198 }, (_, i) => ({
      check_id: `ordinary-${i}`,
      status: "collected",
    })),
  ];
  const secondPage = [
    {
      level: "credential_target",
      scope: "947000000000",
      role_arn: roleB,
      status: "not_collected",
      error_code: "duplicate_account_target",
      code: "duplicate_account_target",
    },
    {
      level: "credential_target",
      scope: "947000000001",
      role_arn: "arn:aws:iam::947000000001:role/UnsafeTrust",
      status: "not_collected",
      error_code: "external_id_not_required_by_trust",
    },
    {
      level: "credential_target",
      scope: "947000000002",
      role_arn: "arn:aws:iam::947000000002:role/Platform",
      status: "not_collected",
      code: "platform_owned_account",
    },
    {
      level: "credential_target",
      scope: "947000000003",
      role_arn: "arn:aws:iam::947000000003:role/OverLimit",
      status: "not_collected",
      error: { code: "role_target_limit" },
    },
    {
      type: hostile,
      scope: "947000000000",
      role_arn: `arn:aws:iam::947000000000:role/${hostile}`,
      status: "not_collected",
      code: "duplicate_account_target",
    },
  ];
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const json = path.endsWith("/health")
      ? { status: "ok" }
      : path.endsWith("/me")
        ? { tenant_id: "validation", plan: "free", weekly_limit: 1, weekly_used: 0 }
        : path.endsWith("/scans")
          ? { items: [{ id: "coverage-fixture", status: "completed", created_at: "2026-01-01" }] }
          : path.endsWith("/summary")
            ? { stats: { resource_count: 0, finding_count: 0 }, findings: [], resources: [] }
            : path.endsWith("/coverage")
              ? Number(url.searchParams.get("offset")) === 0
                ? { items: firstPage, total: 205, next_offset: 200 }
                : { items: secondPage, total: 205, next_offset: null }
              : { items: [] };
    await route.fulfill({ json });
  });

  await page.goto("/#Dashboard");
  const rows = page.locator(".coverage-row");
  const ordinaryRow = rows.filter({ hasText: ordinary.check_id });
  await expect(ordinaryRow).toHaveCount(1);
  await expect(ordinaryRow.locator("strong")).toHaveText(ordinary.check_id);
  await expect(ordinaryRow.locator(".badge")).toHaveText("collected");
  await expect(ordinaryRow.locator("p")).toHaveText(ordinary.reason);
  const errorRow = rows.filter({ hasText: "AccessDenied" });
  await expect(errorRow.locator("strong")).toHaveText("s3");
  await expect(errorRow.locator(".badge")).toHaveText("denied");
  await expect(errorRow.locator("p")).toHaveText("AccessDenied");
  await expect(page.getByText("200 of 205 coverage records loaded")).toBeVisible();
  await page.getByRole("button", { name: "Load more coverage" }).click();

  const target = rows.filter({ hasText: roleB });
  await expect(target).toHaveCount(1);
  await expect(target.locator("strong")).toHaveText("credential_target");
  await expect(target.locator("p").first()).toHaveText(roleB);
  await expect(target.locator("p").last()).toContainText("Skipped: another role already audits account 947000000000.");
  await expect(target.locator("code")).toHaveText("duplicate_account_target");
  await expect(target.locator(".badge")).toHaveText("not collected");
  await expect(rows.filter({ hasText: "UnsafeTrust" })).toContainText("Role refused: its trust policy does not require an ExternalID. Add the sts:ExternalId condition shown in onboarding.");
  await expect(rows.filter({ hasText: "UnsafeTrust" }).locator("code")).toHaveText("external_id_not_required_by_trust");
  await expect(rows.filter({ hasText: "Platform" })).toContainText("Role refused: this account belongs to the CSPM platform.");
  await expect(rows.filter({ hasText: "Platform" }).locator("code")).toHaveText("platform_owned_account");
  await expect(rows.filter({ hasText: "OverLimit" })).toContainText("Skipped: the scan reached its role-target limit.");
  await expect(rows.filter({ hasText: "OverLimit" }).locator("code")).toHaveText("role_target_limit");
  await expect(rows).toHaveCount(205);
  await expect(ordinaryRow.locator("p")).toHaveText(ordinary.reason);
  await expect(errorRow.locator("p")).toHaveText("AccessDenied");
  await expect(page.getByText("205 of 205 coverage records loaded")).toHaveCount(0);

  const hostileRow = rows.filter({ hasText: hostile }).last();
  await expect(hostileRow.locator("strong")).toHaveText(hostile);
  await expect(hostileRow.locator("p").first()).toContainText(hostile);
  await expect(hostileRow.locator("img")).toHaveCount(0);
});
