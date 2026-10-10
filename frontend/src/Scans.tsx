import { useState } from "react";
import type { FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  CalendarClock,
  Download,
  Play,
  Square,
  Trash2,
  Eye,
  Plus,
} from "lucide-react";
import { categories } from "./types";
import type { Connector, Scan, Schedule } from "./types";
import { downloadReport, items, json, request, useApi } from "./api";
import { Badge, date, Evidence, Inspector, Panel, State } from "./ui";
export const terminalStatuses = [
  "completed",
  "failed",
  "cancelled",
  "timed_out",
];
export function Scans({
  demo,
  onSelect,
}: {
  demo: boolean;
  onSelect: (scan: Scan) => void;
}) {
  const scansQuery = useApi<{ items: Scan[] }>("/scans", demo, true, true);
  const connectorsQuery = useApi<{ items: Connector[] }>("/connectors", demo);
  const schedulesQuery = useApi<{ items: Schedule[] }>("/schedules", demo);
  const client = useQueryClient();
  const [launch, setLaunch] = useState(false);
  const [schedule, setSchedule] = useState<Schedule | null | undefined>();
  const [inspect, setInspect] = useState<Scan>();
  const [error, setError] = useState("");
  function refresh() {
    void client.invalidateQueries({ queryKey: [demo ? "demo" : "live"] });
  }
  const cancel = useMutation({
    mutationFn: (id: string) =>
      request(`/scans/${encodeURIComponent(id)}/cancel`, json({}), demo),
    onSuccess: refresh,
    onError: (e) => setError(e.message),
  });
  const updateSchedule = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      request(
        `/schedules/${encodeURIComponent(id)}`,
        json({ enabled }, "PATCH"),
        demo,
      ),
    onSuccess: refresh,
    onError: (e) => setError(e.message),
  });
  const deleteSchedule = useMutation({
    mutationFn: (id: string) =>
      request(
        `/schedules/${encodeURIComponent(id)}`,
        { method: "DELETE" },
        demo,
      ),
    onSuccess: refresh,
    onError: (e) => setError(e.message),
  });
  async function download(scan: Scan, format: string) {
    try {
      setError("");
      await downloadReport(scan.id, format, demo);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Download failed");
    }
  }
  return (
    <>
      <div className="section-top">
        <p>Run an assessment. Keep every result tied to its snapshot.</p>
        <button
          className="button primary"
          disabled={demo}
          onClick={() => setLaunch(true)}
        >
          <Play size={16} />
          Launch scan
        </button>
      </div>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <Panel
        title="Scan history"
        kicker="NATIVE SNAPSHOT ENGINE"
        action={
          <span className="count-pill">
            {items(scansQuery.data).length} scans
          </span>
        }
      >
        <State
          loading={scansQuery.isPending}
          error={scansQuery.error}
          onRetry={() => void scansQuery.refetch()}
          empty={
            !scansQuery.isPending &&
            !scansQuery.error &&
            !items(scansQuery.data).length
          }
          title="Your first scan starts here"
        >
          <button
            className="button primary"
            disabled={demo}
            onClick={() => setLaunch(true)}
          >
            Launch a scan
          </button>
        </State>
        <div className="card-list">
          {items(scansQuery.data).map((s) => (
            <article className="scan-row" key={s.id}>
              <div
                className={`scan-symbol ${s.status === "completed" ? "done" : ""}`}
              >
                <Play size={16} />
              </div>
              <div className="grow">
                <button
                  className="text-button scan-id"
                  onClick={() => setInspect(s)}
                >
                  {s.id}
                </button>
                <p>
                  {items(connectorsQuery.data).find(
                    (c) => c.id === s.connector_id,
                  )?.name || s.connector_id}{" "}
                  · {date(s.created_at)}
                </p>
                <div className="scan-categories">
                  {s.categories?.map((c) => (
                    <span key={c}>{c.replaceAll("_", " ")}</span>
                  ))}
                </div>
              </div>
              <Badge value={s.status} />
              {s.input_mode && s.input_mode !== "live" && (
                <Badge value={s.input_mode} />
              )}
              {s.status === "completed" ? (
                <>
                  <button className="button" onClick={() => onSelect(s)}>
                    <Eye size={15} />
                    View
                  </button>
                  <button
                    className="icon-button"
                    aria-label={`Download JSON ${s.id}`}
                    onClick={() => void download(s, "json")}
                  >
                    <Download size={17} />
                  </button>
                </>
              ) : (
                !terminalStatuses.includes(s.status) && (
                  <button
                    className="button"
                    disabled={cancel.isPending || demo}
                    onClick={() => cancel.mutate(s.id)}
                  >
                    <Square size={13} />
                    Cancel
                  </button>
                )
              )}
            </article>
          ))}
        </div>
      </Panel>
      <Panel
        title="Scheduled assessments"
        kicker="STAY CURRENT"
        action={
          <button
            className="button"
            disabled={demo}
            onClick={() => setSchedule(null)}
          >
            <Plus size={16} />
            Add schedule
          </button>
        }
      >
        <State
          loading={schedulesQuery.isPending}
          error={schedulesQuery.error}
          onRetry={() => void schedulesQuery.refetch()}
        >
          <>
            {items(schedulesQuery.data).length ? (
              items(schedulesQuery.data).map((s) => (
                <article className="scan-row" key={s.id}>
                  <div className="scan-symbol">
                    <CalendarClock size={18} />
                  </div>
                  <div className="grow">
                    <button
                      className="text-button"
                      disabled={demo}
                      onClick={() => setSchedule(s)}
                    >
                      {s.name ||
                        items(connectorsQuery.data).find(
                          (c) => c.id === s.connector_id,
                        )?.name ||
                        s.id}
                    </button>
                    <p>
                      Every {s.interval_hours} hours · Next{" "}
                      {date(s.next_run_at)}
                    </p>
                  </div>
                  <button
                    className="button"
                    disabled={demo || updateSchedule.isPending}
                    onClick={() =>
                      updateSchedule.mutate({ id: s.id, enabled: !s.enabled })
                    }
                  >
                    {s.enabled ? "Pause" : "Resume"}
                  </button>
                  <button
                    className="icon-button danger"
                    disabled={demo || deleteSchedule.isPending}
                    aria-label={`Delete schedule ${s.id}`}
                    onClick={() => deleteSchedule.mutate(s.id)}
                  >
                    <Trash2 size={17} />
                  </button>
                </article>
              ))
            ) : (
              <div className="compact-empty">
                <CalendarClock />
                <div>
                  <h3>No schedules yet</h3>
                  <p>Create a recurring scan within your account quota.</p>
                </div>
              </div>
            )}
          </>
        </State>
      </Panel>
      {launch && (
        <LaunchForm
          demo={demo}
          connectors={items(connectorsQuery.data)}
          connectorError={connectorsQuery.error}
          onClose={() => setLaunch(false)}
        />
      )}
      {schedule !== undefined && (
        <LaunchForm
          demo={demo}
          connectors={items(connectorsQuery.data)}
          connectorError={connectorsQuery.error}
          schedule={schedule}
          onClose={() => setSchedule(undefined)}
        />
      )}
      {inspect && (
        <Inspector title="Scan details" onClose={() => setInspect(undefined)}>
          <Badge value={inspect.status} />
          <Evidence data={inspect} />
          {inspect.status === "completed" && (
            <div className="button-row">
              <button
                className="button primary"
                onClick={() => {
                  onSelect(inspect);
                  setInspect(undefined);
                }}
              >
                Review findings
              </button>
              <button
                className="button"
                onClick={() => void download(inspect, "markdown")}
              >
                Download Markdown
              </button>
            </div>
          )}
        </Inspector>
      )}
    </>
  );
}
function LaunchForm({
  demo,
  connectors,
  connectorError,
  onClose,
  schedule,
}: {
  demo: boolean;
  connectors: Connector[];
  connectorError: unknown;
  onClose: () => void;
  schedule?: Schedule | null;
}) {
  const client = useQueryClient();
  const [connector, setConnector] = useState(
    schedule?.connector_id || connectors[0]?.id || "",
  );
  const [selected, setSelected] = useState<string[]>(
    schedule?.categories || categories.map((c) => c.id),
  );
  const [checks, setChecks] = useState("");
  const [frameworks, setFrameworks] = useState("");
  const [hours, setHours] = useState(schedule?.interval_hours || 168);
  const [error, setError] = useState("");
  const isSchedule = schedule !== undefined;
  const mutation = useMutation({
    mutationFn: (payload: unknown) =>
      request(
        isSchedule
          ? schedule
            ? `/schedules/${encodeURIComponent(schedule.id)}`
            : "/schedules"
          : "/scans",
        {
          ...json(payload, schedule ? "PATCH" : "POST"),
          headers: !isSchedule
            ? { "Idempotency-Key": crypto.randomUUID() }
            : {},
        },
        demo,
      ),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: [demo ? "demo" : "live"] });
      onClose();
    },
  });
  function submit(e: FormEvent) {
    e.preventDefault();
    if (!connector) return setError("Choose a connector first.");
    if (!selected.length)
      return setError("Select at least one assessment category.");
    if (isSchedule && (!Number.isFinite(hours) || hours < 1))
      return setError("Schedule interval must be at least one hour.");
    mutation.mutate({
      connector_id: connector,
      categories: selected,
      checks: checks
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      frameworks: frameworks
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      ...(isSchedule
        ? { interval_hours: hours, enabled: schedule?.enabled ?? true }
        : {}),
    });
  }
  return (
    <Inspector
      title={isSchedule ? "Assessment schedule" : "Launch an assessment"}
      onClose={onClose}
    >
      <form className="form" onSubmit={submit}>
        {!!connectorError && <State error={connectorError} />}
        <label>
          Connector
          <select
            value={connector}
            onChange={(e) => setConnector(e.target.value)}
            required
          >
            <option value="">Select an environment</option>
            {connectors.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
        {!connectors.length && (
          <p className="form-error">Add a connector before launching a scan.</p>
        )}
        <fieldset>
          <legend>Assessment categories</legend>
          {categories.map((c) => (
            <label key={c.id} className="checkbox">
              <input
                type="checkbox"
                checked={selected.includes(c.id)}
                onChange={(e) =>
                  setSelected(
                    e.target.checked
                      ? [...selected, c.id]
                      : selected.filter((x) => x !== c.id),
                  )
                }
              />
              {c.label}
            </label>
          ))}
        </fieldset>
        <label>
          Check IDs (optional, comma separated)
          <input
            value={checks}
            onChange={(e) => setChecks(e.target.value)}
            placeholder="Empty = supported checks in selected categories"
          />
        </label>
        <label>
          Frameworks (optional, comma separated)
          <input
            value={frameworks}
            onChange={(e) => setFrameworks(e.target.value)}
            placeholder="For example: HackTricks Cloud Best Practices"
          />
        </label>
        {isSchedule && (
          <label>
            Interval in hours
            <input
              type="number"
              min={1}
              max={8760}
              required
              value={hours}
              onChange={(e) => setHours(Number(e.target.value))}
            />
          </label>
        )}
        <p className="muted small">
          Only native supported collectors and checks run. Unsupported scope and
          missing permissions are reported as coverage limitations.
        </p>
        {(error || mutation.error) && (
          <p className="form-error" role="alert">
            {error || mutation.error?.message}
          </p>
        )}
        <button
          className="button primary"
          disabled={mutation.isPending || !connectors.length}
          type="submit"
        >
          {mutation.isPending
            ? "Submitting…"
            : isSchedule
              ? "Save schedule"
              : "Start scan"}
        </button>
      </form>
    </Inspector>
  );
}
