import { useEffect, useRef } from "react";
import type { ReactNode } from "react";
import {
  AlertCircle,
  ArrowRight,
  LoaderCircle,
  X,
  ShieldCheck,
} from "lucide-react";
export function ProviderIcon({
  provider,
  size = 28,
}: {
  provider: string;
  size?: number;
}) {
  return (
    <img
      className="provider-icon"
      src={`/icons/${["aws", "gcp", "azure", "k8s"].includes(provider) ? provider : "generic"}.svg`}
      width={size}
      height={size}
      alt={`${provider} provider`}
    />
  );
}
export function Badge({ value }: { value: string }) {
  return (
    <span
      className={`badge ${value.toLowerCase().replace(/[^a-z_]/g, "")}`}
      title={value.replaceAll("_", " ")}
    >
      {value.toLowerCase().replaceAll("_", " ")}
    </span>
  );
}
export function State({
  loading,
  error,
  empty,
  onRetry,
  title,
  children,
}: {
  loading?: boolean;
  error?: unknown;
  empty?: boolean;
  onRetry?: () => void;
  title?: string;
  children?: ReactNode;
}) {
  if (loading)
    return (
      <div className="state" role="status">
        <LoaderCircle className="spin" />
        <h3>Loading evidence</h3>
        <p>Requesting the latest data from your API.</p>
      </div>
    );
  if (error)
    return (
      <div className="state error" role="alert">
        <AlertCircle />
        <h3>Data could not be loaded</h3>
        <p>
          {error instanceof Error ? error.message : "The API is unavailable."}
        </p>
        {onRetry && (
          <button className="button" onClick={onRetry}>
            Try again
          </button>
        )}
      </div>
    );
  if (empty)
    return (
      <div className="state">
        <ShieldCheck />
        <h3>{title || "No evidence yet"}</h3>
        <p>
          Connect a cloud environment and run a scan. Missing evidence does not
          mean a resource is secure.
        </p>
        {children}
      </div>
    );
  return <>{children}</>;
}
export function Panel({
  title,
  kicker,
  children,
  action,
  className = "",
}: {
  title?: string;
  kicker?: string;
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {title && (
        <div className="panel-heading">
          <div>
            {kicker && <span className="eyebrow">{kicker}</span>}
            <h2>{title}</h2>
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
export function EmptyAction({
  onClick,
  children,
}: {
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button className="button primary" onClick={onClick}>
      {children}
      <ArrowRight size={16} />
    </button>
  );
}
export function Inspector({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => dialog?.close();
  }, []);
  return (
    <dialog ref={ref} className="inspector" onCancel={onClose}>
      <div className="inspector-heading">
        <h2>{title}</h2>
        <button
          className="icon-button"
          aria-label="Close inspector"
          onClick={onClose}
        >
          <X />
        </button>
      </div>
      {children}
    </dialog>
  );
}
export function Evidence({ data }: { data: unknown }) {
  const full =
    typeof data === "string"
      ? data
      : JSON.stringify(data ?? "No evidence supplied", null, 2);
  const limit = 100000;
  function download() {
    const blob = new Blob([full], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "peaso-evidence.json";
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <>
      <pre className="evidence">
        {full.length > limit ? full.slice(0, limit) : full}
      </pre>
      {full.length > limit && (
        <div className="notice">
          <p>
            Evidence preview limited to {limit.toLocaleString()} characters. The
            full evidence remains available.
          </p>
          <button className="button" onClick={download}>
            Download full evidence
          </button>
        </div>
      )}
    </>
  );
}
export function date(value?: string) {
  if (!value) return "Not available";
  const d = new Date(value);
  return Number.isNaN(d.getTime())
    ? "Not available"
    : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function sourceHref(value?: string) {
  if (!value) return undefined;
  try {
    const url = new URL(value, location.origin);
    return ["https:", "http:"].includes(url.protocol) ? url.href : undefined;
  } catch {
    return undefined;
  }
}
