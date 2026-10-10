import { useQuery } from "@tanstack/react-query";
import { demoRequest } from "./fixtures";
import type {
  PrivescAdminResult,
  PrivescBroadResult,
  PrivescGraph,
  PrivescPath,
  PrivescPrincipalCard,
} from "./types";
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export const tokenKey = "peaso.api-token";
export async function request<T>(
  path: string,
  init: RequestInit = {},
  demo = false,
): Promise<T> {
  if (demo) return demoRequest(path, init) as T;
  const token = sessionStorage.getItem(tokenKey);
  const response = await fetch(`/api${path}`, {
    ...init,
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const data = await response.json();
      message =
        typeof data.detail === "string"
          ? data.detail
          : typeof data.error === "string"
            ? data.error
            : message;
    } catch {
      /* No evidence details or credentials in fallback */
    }
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  const data = await response.json();
  if (isDownloadEnvelope(data)) {
    const artifact = await fetchArtifact(data.download_url);
    return artifact.json() as Promise<T>;
  }
  return data as T;
}
export const json = (body: unknown, method = "POST"): RequestInit => ({
  method,
  body: JSON.stringify(body),
});
export function useApi<T>(
  path: string,
  demo: boolean,
  enabled = true,
  poll = false,
) {
  return useQuery<T>({
    queryKey: [demo ? "demo" : "live", path],
    queryFn: () => request<T>(path, {}, demo),
    enabled,
    retry: 1,
    refetchInterval: poll ? 4000 : false,
  });
}
export function items<T>(data: { items: T[] } | undefined): T[] {
  return Array.isArray(data?.items) ? data.items : [];
}
export async function downloadReport(
  id: string,
  format: string,
  demo: boolean,
) {
  let blob: Blob;
  if (demo) {
    const report = await request<unknown>(`/scans/${id}/report`, {}, true);
    blob = new Blob(
      [
        format === "json"
          ? JSON.stringify(report, null, 2)
          : "# PEASO fixture report\n\nExplicit demo data; not a cloud assessment.",
      ],
      { type: format === "json" ? "application/json" : "text/markdown" },
    );
  } else {
    const token = sessionStorage.getItem(tokenKey);
    const response = await fetch(
      `/api/scans/${encodeURIComponent(id)}/report?format=${format}`,
      {
        credentials: "include",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      },
    );
    if (!response.ok)
      throw new ApiError(response.status, "Report download failed");
    blob = await response.blob();
    if (
      blob.size < 8192 &&
      response.headers.get("content-type")?.includes("application/json")
    ) {
      const envelope = JSON.parse(await blob.text());
      if (isDownloadEnvelope(envelope)) {
        blob = await (await fetchArtifact(envelope.download_url)).blob();
      }
    }
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `peaso-${id}.${format === "json" ? "json" : "md"}`;
  a.click();
  URL.revokeObjectURL(url);
}

type DownloadEnvelope = {
  download_url: string;
  expires_in?: number;
  format?: string;
};
function isDownloadEnvelope(value: unknown): value is DownloadEnvelope {
  return (
    !!value &&
    typeof value === "object" &&
    "download_url" in value &&
    typeof value.download_url === "string"
  );
}
async function fetchArtifact(value: string) {
  const url = new URL(value, location.origin);
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password
  )
    throw new Error("Invalid artifact download URL");
  const response = await fetch(url.href, {
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
    headers: {
      Accept: "application/json, text/markdown, application/octet-stream",
    },
  });
  if (!response.ok)
    throw new ApiError(
      response.status,
      "Evidence download failed. Retry to request a fresh link.",
    );
  return response;
}

// Privilege Escalation Map endpoints (docs/peaso-privesc.md).
const scanPath = (scanId: string) => `/scans/${encodeURIComponent(scanId)}`;
export const privescApi = {
  graph: (scanId: string) => `${scanPath(scanId)}/graphs/privesc`,
  admins: (scanId: string, maxDepth = 6, includeUnknown = true) =>
    `${scanPath(scanId)}/privesc/admins?max_depth=${maxDepth}&include_unknown=${includeUnknown}`,
  paths: (scanId: string, from: string, to = "", maxDepth = 6) => {
    const params = new URLSearchParams({ from, source: from });
    if (to) {
      params.set("to", to);
      params.set("target", to);
    }
    params.set("max_depth", String(maxDepth));
    return `${scanPath(scanId)}/privesc/paths?${params}`;
  },
  broad: (scanId: string, minTargets = 50) =>
    `${scanPath(scanId)}/privesc/broad?min_targets=${minTargets}`,
  principal: (scanId: string, principalId: string) =>
    `${scanPath(scanId)}/privesc/principals/${encodeURIComponent(principalId)}`,
  findings: (scanId: string) =>
    `${scanPath(scanId)}/findings?categories=privesc&limit=500`,
  finding: (scanId: string, findingId: string) =>
    `${scanPath(scanId)}/findings/${encodeURIComponent(findingId)}`,
};
/** Query endpoints may return a bare list or an `{items}` envelope. */
export function listOf<T>(data: T[] | { items?: T[] } | undefined): T[] {
  if (Array.isArray(data)) return data;
  return Array.isArray(data?.items) ? data.items : [];
}
export function usePrivescGraph(scanId: string, demo: boolean) {
  return useApi<PrivescGraph>(privescApi.graph(scanId), demo, !!scanId);
}
export function usePrivescAdmins(scanId: string, demo: boolean, enabled = true) {
  return useApi<PrivescAdminResult[] | { items: PrivescAdminResult[] }>(
    privescApi.admins(scanId),
    demo,
    !!scanId && enabled,
  );
}
export function usePrivescPaths(
  scanId: string,
  demo: boolean,
  from: string,
  to = "",
  maxDepth = 6,
) {
  return useApi<PrivescPath[] | { items: PrivescPath[] }>(
    privescApi.paths(scanId, from, to, maxDepth),
    demo,
    !!scanId && !!from,
  );
}
export function usePrivescBroad(
  scanId: string,
  demo: boolean,
  enabled = true,
  minTargets = 50,
) {
  return useApi<PrivescBroadResult[] | { items: PrivescBroadResult[] }>(
    privescApi.broad(scanId, minTargets),
    demo,
    !!scanId && enabled,
  );
}
export function usePrivescPrincipal(
  scanId: string,
  demo: boolean,
  principalId: string,
) {
  return useApi<PrivescPrincipalCard>(
    privescApi.principal(scanId, principalId),
    demo,
    !!scanId && !!principalId,
  );
}
