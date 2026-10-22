import type { Scan } from "./types";

/** Total launch-to-terminal time, including queueing and worker startup. */
export function scanDuration(scan: Scan): string | undefined {
  if (!["completed", "failed", "cancelled", "timed_out", "queue_exhausted", "credentials_expired"].includes(scan.status)) return;
  const start = Date.parse(scan.created_at);
  const event = (Array.isArray(scan.timeline) ? [...scan.timeline].reverse() : [])
    .find((item) => item.status === scan.status);
  const end = Date.parse(event?.at || scan.updated_at || "");
  // Legacy rows can have updated_at=created_at as a placeholder, not a finish time.
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start || (!event && end === start)) return;
  const seconds = Math.floor((end - start) / 1000);
  const hours = Math.floor(seconds / 3600), minutes = Math.floor((seconds % 3600) / 60), remainder = seconds % 60;
  const duration = seconds === 0 && end > start ? "<1s" : [
    hours ? `${hours}h` : "", minutes ? `${minutes}m` : "", remainder || !seconds ? `${remainder}s` : "",
  ].filter(Boolean).join(" ");
  return `${scan.status === "completed" ? "Completed in" : "Duration:"} ${duration}`;
}
