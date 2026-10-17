import { useState } from "react";
import type { FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { ArrowRight, Network } from "lucide-react";
import { json, request } from "./api";
import { Badge, Evidence, Inspector, State } from "./ui";
import type { GraphNode } from "./types";
export type ConfigurationDecision = {
  decision: "allowed" | "blocked" | "unknown";
  provider: string;
  snapshot_id: string;
  query: unknown;
  endpoints: unknown;
  routes: unknown;
  policy_decisions: unknown;
  translations: unknown;
  unresolved_dependencies: unknown;
  evidence_refs: unknown;
  modeled_configuration: boolean;
  application_listening: string;
  new_flow_only: boolean;
};
type AssessmentQuery = {
  source_resource_id: string;
  destination_resource_id: string;
  protocol: string;
  destination_port: number;
  source_port?: number;
  address_family: string;
};
function matchesAssessment(result: ConfigurationDecision, requested: AssessmentQuery): boolean {
  if (!result || typeof result !== "object" || typeof result.snapshot_id !== "string" || !result.snapshot_id ||
      typeof result.provider !== "string" || !result.provider || result.modeled_configuration !== true ||
      result.new_flow_only !== true || !["allowed", "blocked", "unknown"].includes(result.decision) ||
      !result.query || typeof result.query !== "object") return false;
  const query = result.query as Record<string, unknown>;
  return query.source_resource_id === requested.source_resource_id &&
    query.destination_resource_id === requested.destination_resource_id &&
    query.protocol === requested.protocol && query.destination_port === requested.destination_port &&
    (query.source_port ?? undefined) === requested.source_port &&
    query.address_family === requested.address_family;
}
export function ConnectionAssessment({
  scanId,
  nodes,
  source = "",
  destination = "",
  onClose,
  onShowMap,
}: {
  scanId: string;
  nodes: GraphNode[];
  source?: string;
  destination?: string;
  onClose: () => void;
  onShowMap?: (result: ConfigurationDecision) => void;
}) {
  const [from, setFrom] = useState(source),
    [to, setTo] = useState(destination),
    [protocol, setProtocol] = useState("tcp"),
    [destinationPort, setDestinationPort] = useState("443"),
    [sourcePort, setSourcePort] = useState(""),
    [family, setFamily] = useState("ipv4"),
    [error, setError] = useState("");
  const evaluation = useMutation({
    mutationFn: async (body: AssessmentQuery) => {
      const result = await request<ConfigurationDecision>(
        `/scans/${encodeURIComponent(scanId)}/reachability`,
        json(body),
      );
      if (!matchesAssessment(result, body)) throw new Error("Assessment response did not match the selected connection.");
      return result;
    },
  });
  function edit(setter: (value: string) => void, value: string) {
    setter(value);
    setError("");
    evaluation.reset();
  }
  const endpoints = nodes.filter(
    (n) => typeof n.resource_id === "string" && !n.aggregate,
  );
  function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    evaluation.reset();
    if (!from.trim() || !to.trim())
      return setError("Select or enter both resource IDs.");
    const port = Number(destinationPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      return setError("Destination port must be between 1 and 65535.");
    const sourceValue = sourcePort.trim() ? Number(sourcePort) : undefined;
    if (
      sourceValue !== undefined &&
      (!Number.isInteger(sourceValue) || sourceValue < 1 || sourceValue > 65535)
    )
      return setError("Source port must be between 1 and 65535.");
    evaluation.mutate({
      source_resource_id: from.trim(),
      destination_resource_id: to.trim(),
      protocol,
      destination_port: port,
      ...(sourceValue !== undefined ? { source_port: sourceValue } : {}),
      address_family: family,
    });
  }
  return (
    <Inspector title="Assess a configuration path" onClose={onClose}>
      <div className="notice">
        <Network size={20} />
        <p>
          This assessment uses the selected immutable snapshot. A configuration
          decision does not prove an application is listening or that a
          connection succeeds.
        </p>
      </div>
      <form className="form" onSubmit={submit}>
        <label>
          Source resource ID
          <input
            list="configuration-endpoints"
            value={from}
            onChange={(e) => edit(setFrom, e.target.value)}
            disabled={evaluation.isPending}
            required
            maxLength={2048}
            placeholder="Select a captured resource or enter its global report ID"
            autoComplete="off"
          />
        </label>
        <ArrowRight size={17} className="mint" />
        <label>
          Destination resource ID
          <input
            list="configuration-endpoints"
            value={to}
            onChange={(e) => edit(setTo, e.target.value)}
            disabled={evaluation.isPending}
            required
            maxLength={2048}
            autoComplete="off"
          />
        </label>
        <datalist id="configuration-endpoints">
          {endpoints.map((n) => (
            <option key={n.id} value={String(n.resource_id)}>
              {String(n.label || n.name || n.native_id || n.id)} · {n.type} ·{" "}
              {n.scope}
            </option>
          ))}
        </datalist>
        <div className="form-columns">
          <label>
            Protocol
            <select
              value={protocol}
              onChange={(e) => edit(setProtocol, e.target.value)}
              disabled={evaluation.isPending}
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </label>
          <label>
            Address family
            <select value={family} onChange={(e) => edit(setFamily, e.target.value)} disabled={evaluation.isPending}>
              <option value="ipv4">IPv4</option>
              <option value="ipv6">IPv6</option>
            </select>
          </label>
        </div>
        <div className="form-columns">
          <label>
            Destination port
            <input
              type="number"
              min={1}
              max={65535}
              required
              value={destinationPort}
              onChange={(e) => edit(setDestinationPort, e.target.value)}
              disabled={evaluation.isPending}
            />
          </label>
          <label>
            Source port (optional)
            <input
              type="number"
              min={1}
              max={65535}
              value={sourcePort}
              onChange={(e) => edit(setSourcePort, e.target.value)}
              disabled={evaluation.isPending}
              placeholder="Unknown"
            />
          </label>
        </div>
        <p className="muted small">
          An omitted source port or missing route, policy, translation or CNI
          facts may leave the decision unknown. Namespace membership does not
          imply a subnet.
        </p>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <button
          className="button primary"
          type="submit"
          disabled={evaluation.isPending}
        >
          {evaluation.isPending
            ? "Evaluating snapshot…"
            : "Assess configuration"}
        </button>
      </form>
      <State loading={evaluation.isPending} error={evaluation.error}>
        {evaluation.data && (
          <div className="configuration-result">
            <h3>Configuration decision</h3>
            <Badge value={evaluation.data.decision} />
            {onShowMap && <button type="button" className="button primary" onClick={() => onShowMap(evaluation.data!)}>Show path on map</button>}
            <p className="muted small">
              Application listening:{" "}
              {evaluation.data.application_listening || "unknown"} · New flow
              only
            </p>
            <h3>Selected endpoints</h3>
            <Evidence data={evaluation.data.endpoints} />
            <h3>Routes and policies</h3>
            <Evidence
              data={{
                routes: evaluation.data.routes,
                policy_decisions: evaluation.data.policy_decisions,
                translations: evaluation.data.translations,
              }}
            />
            <h3>Unresolved dependencies</h3>
            <Evidence data={evaluation.data.unresolved_dependencies} />
            <h3>Snapshot evidence references</h3>
            <Evidence
              data={{
                snapshot_id: evaluation.data.snapshot_id,
                evidence_refs: evaluation.data.evidence_refs,
              }}
            />
          </div>
        )}
      </State>
    </Inspector>
  );
}
