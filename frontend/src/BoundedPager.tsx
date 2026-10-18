import { useState } from "react";
import type { FormEvent } from "react";

/** Controls for server-offset collections; callers decide how many pages stay mounted. */
export function BoundedPager({
  first, last, total, unit, pageSize, loading, canPrevious, canNext, error,
  onPrevious, onNext, onJump, onRetry, statusText, nextLabel = "Next page",
}: {
  first: number; last: number; total: number; unit: string; pageSize: number;
  loading: boolean; canPrevious: boolean; canNext: boolean; error?: string;
  onPrevious: () => void; onNext: () => void; onJump: (offset: number) => void;
  onRetry?: () => void; statusText?: string; nextLabel?: string;
}) {
  const [input, setInput] = useState("");
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(pages, Math.floor(Math.max(0, first - 1) / pageSize) + 1);
  function jump(event: FormEvent) {
    event.preventDefault();
    const target = Number(input);
    if (!Number.isInteger(target) || target < 1 || target > pages) return;
    onJump((target - 1) * pageSize);
    setInput("");
  }
  return <div className="pagination-footer" aria-live="polite">
    <span>{statusText || `${unit} ${total ? `${first.toLocaleString()}–${last.toLocaleString()} of ${total.toLocaleString()}` : "0 of 0"}`}</span>
    <div className="button-row">
      <button type="button" disabled={!canPrevious || loading} onClick={onPrevious}>Previous page</button>
      <button type="button" disabled={!canNext || loading} onClick={onNext}>{loading ? "Loading…" : nextLabel}</button>
      {pages > 1 && <form onSubmit={jump}><label>Page <input aria-label={`Go to ${unit.toLowerCase()} page`} type="number" min={1} max={pages} value={input} onChange={event => setInput(event.target.value)} placeholder={`${current} / ${pages}`} /></label> <button type="submit" disabled={loading}>Go</button></form>}
    </div>
    {error && <span role="alert">{error} <button type="button" className="text-button" onClick={onRetry || onNext} disabled={loading}>Retry page</button></span>}
  </div>;
}
