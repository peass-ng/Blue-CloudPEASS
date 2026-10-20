import { test, expect } from "@playwright/test";
import { createServer } from "node:http";
import { gzipSync } from "node:zlib";

test("compressed graph artifacts decode without credentials and show omitted relationships", async ({ page, context }) => {
  let received: Record<string, string | string[] | undefined> = {};
  const graph = {
    nodes: [{ id: "fixture-node", label: "Compressed evidence fixture", type: "vpc", provider: "aws", scope: "fixture" }],
    edges: [],
    truncated: true,
    edges_truncated: true,
    omitted_underlying_edges: 9500,
    projection: { collapsed: true, node_count: 10001, edge_count: 10000 },
  };
  const body = gzipSync(Buffer.from(JSON.stringify(graph)), { level: 1 });
  const server = createServer((request, response) => {
    received = request.headers;
    response.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Encoding": "gzip",
      "Content-Length": body.length,
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
    });
    response.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Fixture server did not bind");
  try {
    await page.addInitScript(() => sessionStorage.setItem("peaso.api-token", "fixture-api-token"));
    await context.addCookies([{ name: "fixture-cookie", value: "fixture-only", url: "http://127.0.0.1:5173" }]);
    await page.route("**/api/**", (route) => {
      const path = new URL(route.request().url()).pathname;
      const value = path.endsWith("/health") ? { status: "ok" }
        : path.endsWith("/me") ? { tenant_id: "fixture-owner", plan: "free", weekly_limit: 1, weekly_used: 0 }
        : path.endsWith("/catalog") ? { checks: [], limitations: [] }
        : path === "/api/scans" ? { items: [{ id: "bounded", status: "completed", categories: ["network"], created_at: "2026-10-10" }] }
        : path.endsWith("/summary") ? { resources: [], findings: [], coverage: [], graphs: {}, stats: {} }
        : path.endsWith("/graphs/network") ? { download_url: `http://127.0.0.1:${address.port}/fixture.json`, format: "json", expires_in: 300 }
        : { items: [] };
      return route.fulfill({ json: value });
    });
    await page.goto("/#Network%20Map");
    await expect(page.getByRole("status").filter({ hasText: "outside this view" })).toContainText("9,500");
    await expect(page.getByRole("button", { name: "Load inventory page", exact: true })).toHaveCount(1);
    const node = page.locator('.react-flow__node[data-id="network:fixture-node"]');
    await expect(node).toContainText("Compressed");
    await expect(node.locator(".network-node-heading")).toHaveAttribute("aria-label", "Open Compressed evidence fixture");
    expect(received.authorization).toBeUndefined();
    expect(received.cookie).toBeUndefined();
    expect(received.referer).toBeUndefined();
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
