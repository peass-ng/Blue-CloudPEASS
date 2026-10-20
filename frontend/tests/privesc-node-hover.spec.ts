import { expect, test } from "@playwright/test";

test("node hover highlights complete incoming and outgoing paths and restores the map", async ({ page }) => {
  // A sibling branch off an ancestor is not a path through the hovered node.
  // The B-C cycle also verifies traversal terminates without dropping relations.
  const pairs = [["start", "before"], ["before", "middle"], ["middle", "after"], ["after", "end"],
    ["after", "middle"], ["before", "sibling"], ["unrelated", "other"]];
  const nodes = [...new Set(pairs.flat())].map(id => ({ id, label: id, kind: "principal", type: "aws_role", provider: "aws", scope: "account" }));
  const edges = pairs.map(([source, target]) => ({ id: `${source}-${target}`, source, target, confidence: "derived", techniques: ["technique"],
    technique_details: [{ id: "technique", severity: "high" }] }));
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan", status: "completed", connector_id: "c", categories: ["privesc"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", findings: [], coverage: [], stats: {} };
    if (path.endsWith("/graphs/privesc")) json = { nodes, edges };
    await route.fulfill({ json });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  const middle = page.locator('.react-flow__node[data-id="middle"]');
  await expect(middle).toBeVisible();
  await expect(page.getByText("Laying out escalation paths…")).toHaveCount(0);
  await page.getByRole("button", { name: "Fit view", exact: true }).click();
  await middle.scrollIntoViewIfNeeded();
  const position = await middle.getAttribute("style");
  await middle.hover();
  const highlighted = () => page.locator(".react-flow__edge.is-hl").evaluateAll(items => items.map(item => item.getAttribute("data-id")).sort());
  await expect.poll(highlighted).toEqual(["start-before", "before-middle", "middle-after", "after-end", "after-middle"].sort());
  await expect(page.locator('.react-flow__node[data-id="start"] .pe-node')).toHaveClass(/is-hl/);
  await expect(page.locator('.react-flow__node[data-id="end"] .pe-node')).toHaveClass(/is-hl/);
  await expect(page.locator('.react-flow__node[data-id="sibling"] .pe-node')).toHaveClass(/is-dim/);
  await expect(page.locator('.react-flow__edge[data-id="unrelated-other"]')).toHaveClass(/is-dim/);
  await expect(middle).toHaveAttribute("style", position!);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.getByRole("heading", { name: "Privilege Escalation Map" }).hover();
  await expect(page.locator(".pe-node.is-hl, .pe-node.is-dim, .react-flow__edge.is-hl, .react-flow__edge.is-dim")).toHaveCount(0);
});
