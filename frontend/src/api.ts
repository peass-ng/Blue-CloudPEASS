import { useQuery } from "@tanstack/react-query";
import { demoRequest } from "./fixtures";
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
  return response.json() as Promise<T>;
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
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `peaso-${id}.${format === "json" ? "json" : "md"}`;
  a.click();
  URL.revokeObjectURL(url);
}
