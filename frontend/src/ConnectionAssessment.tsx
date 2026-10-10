import { useState } from "react";
import type { FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { ArrowRight, Network } from "lucide-react";
import { json, request } from "./api";
import { Badge, Evidence, Inspector, State } from "./ui";
import type { GraphNode } from "./types";
type ConfigurationDecision = {
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
export function ConnectionAssessment({
  scanId,
  nodes,
  source = "",
  destination = "",
  onClose,
}: {
  scanId: string;
  nodes: GraphNode[];
  source?: string;
  destination?: string;
  onClose: () => void;
}) {
  const [from, setFrom] = useState(source),
    [to, setTo] = useState(destination),
    [protocol, setProtocol] = useState("tcp"),
    [destinationPort, setDestinationPort] = useState("443"),
    [sourcePort, setSourcePort] = useState(""),
    [family, setFamily] = useState("ipv4"),
    [error, setError] = useState("");
  const evaluation = useMutation({
    mutationFn: (body: unknown) =>
      request<ConfigurationDecision>(
        `/scans/${encodeURIComponent(scanId)}/reachability`,
        json(body),
      ),
  });
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
            onChange={(e) => setFrom(e.target.value)}
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
            onChange={(e) => setTo(e.target.value)}
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
              onChange={(e) => setProtocol(e.target.value)}
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </label>
          <label>
            Address family
            <select value={family} onChange={(e) => setFamily(e.target.value)}>
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
              onChange={(e) => setDestinationPort(e.target.value)}
            />
          </label>
          <label>
            Source port (optional)
            <input
              type="number"
              min={1}
              max={65535}
              value={sourcePort}
              onChange={(e) => setSourcePort(e.target.value)}
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
