import { ArrowLeft, ArrowRight, CornerDownLeft } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";

/** Controls for server-offset collections; callers decide how many pages stay mounted. */
export function BoundedPager({
  first, last, total, unit, pageSize, loading, canPrevious, canNext, error,
  onPrevious, onNext, onJump, onRetry, statusText, nextLabel = "Next page", compact = false,
}: {
  first: number; last: number; total: number; unit: string; pageSize: number;
  loading: boolean; canPrevious: boolean; canNext: boolean; error?: string;
  onPrevious: () => void; onNext: () => void; onJump: (offset: number) => void;
  onRetry?: () => void; statusText?: string; nextLabel?: string; compact?: boolean;
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
  return <div className={`pagination-footer${compact ? " pagination-compact" : ""}`} aria-live="polite">
    <span>{statusText || `${unit} ${total ? `${first.toLocaleString()}–${last.toLocaleString()} of ${total.toLocaleString()}` : "0 of 0"}`}</span>
    <div className="button-row">
      <button type="button" aria-label="Previous page" title="Previous page" disabled={!canPrevious || loading} onClick={onPrevious}>{compact ? <ArrowLeft size={14} /> : "Previous page"}</button>
      <button type="button" aria-label={nextLabel} title={nextLabel} disabled={!canNext || loading} onClick={onNext}>{compact ? <ArrowRight size={14} /> : loading ? "Loading…" : nextLabel}</button>
      {pages > 1 && <form onSubmit={jump}><label>{!compact && "Page "}<input aria-label={`Go to ${unit.toLowerCase()} page`} type="number" min={1} max={pages} value={input} onChange={event => setInput(event.target.value)} placeholder={compact ? String(current) : `${current} / ${pages}`} /></label>{compact && <span className="pager-total">/ {pages}</span>} <button type="submit" aria-label={compact ? "Go to page" : "Go"} title="Go to page" disabled={loading}>{compact ? <CornerDownLeft size={13} /> : "Go"}</button></form>}
    </div>
    {error && <span role="alert">{error} <button type="button" className="text-button" onClick={onRetry || onNext} disabled={loading}>Retry page</button></span>}
  </div>;
}
