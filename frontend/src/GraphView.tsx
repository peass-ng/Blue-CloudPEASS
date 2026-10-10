import { useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BaseEdge,
  Controls,
  Handle,
  Position,
  ReactFlow,
} from "@xyflow/react";
import type {
  Edge,
  EdgeProps,
  Node,
  NodeProps,
  ReactFlowInstance,
} from "@xyflow/react";
import ELK from "elkjs/lib/elk-api.js";
import elkWorkerUrl from "elkjs/lib/elk-worker.min.js?url";
import type { ElkEdgeSection, ElkNode, ELK as ElkInstance } from "elkjs";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  ArrowLeft,
  Search,
  Layers,
  Table2,
  Network,
  Focus,
} from "lucide-react";
import { useApi } from "./api";
import type { Graph, GraphEdge, GraphNode } from "./types";
import { Evidence, Inspector, Panel, ProviderIcon, State } from "./ui";
import { projectView, structuralIndex } from "./graphProjection";
import type { GroupLevel, ProjectedNode } from "./graphProjection";
import "@xyflow/react/dist/style.css";
const MAX_NODES = 120,
  MAX_EDGES = 400;
type MapNode = Node<
  { label: string; provider: string; subtitle: string; group?: boolean },
  "asset"
>;
type RoutedEdge = Edge<
  { sections: ElkEdgeSection[]; label: string; count: number },
  "routed"
>;
function AssetNode({ data }: NodeProps<MapNode>) {
  return (
    <div className={`map-node ${data.group ? "map-group" : ""}`}>
      <Handle type="target" position={Position.Left} />
      <ProviderIcon provider={data.provider} size={24} />
      <div>
        <strong>{data.label}</strong>
        <span>{data.subtitle}</span>
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
function Routed({ id, data, selected }: EdgeProps<RoutedEdge>) {
  return (
    <>
      {data?.sections.map((s, index) => {
        const points = [s.startPoint, ...(s.bendPoints || []), s.endPoint];
        const path = points
          .map((p, i) => `${i ? "L" : "M"} ${p.x} ${p.y}`)
          .join(" ");
        const midpoint = points[Math.floor(points.length / 2)];
        return (
          <g key={index}>
            <BaseEdge
              id={`${id}-${index}`}
              path={path}
              style={{
                stroke: selected ? "#c4ffee" : "#659ba8",
                strokeWidth: selected ? 3 : 1.6,
              }}
            />
            {index === 0 && (
              <text
                x={midpoint.x - 8}
                y={midpoint.y - 9}
                textAnchor="end"
                style={{ fill: "#a5c5ce", fontSize: 9, pointerEvents: "none" }}
              >
                {data.count > 1 ? `${data.label} ×${data.count}` : data.label}
              </text>
            )}
          </g>
        );
      })}
    </>
  );
}
const nodeTypes = { asset: AssetNode },
  edgeTypes = { routed: Routed };
const emptyGraph: Graph = { nodes: [], edges: [] };
export function GraphView({
  scanId,
  kind,
  demo,
}: {
  scanId: string;
  kind: "iam" | "network";
  demo: boolean;
}) {
  const query = useApi<Graph>(
    `/scans/${encodeURIComponent(scanId)}/graphs/${kind}`,
    demo,
    !!scanId,
  );
  const graph = query.data || emptyGraph;
  const [search, setSearch] = useState(""),
    [mode, setMode] = useState<"map" | "table">("map"),
    [level, setLevel] = useState<GroupLevel>("scope"),
    [scope, setScope] = useState(""),
    [service, setService] = useState(""),
    [network, setNetwork] = useState(""),
    [subnet, setSubnet] = useState(""),
    [risk, setRisk] = useState("");
  const [inspect, setInspect] = useState<ProjectedNode | GraphEdge>(),
    [nodes, setNodes] = useState<MapNode[]>([]),
    [edges, setEdges] = useState<RoutedEdge[]>([]),
    [layoutError, setLayoutError] = useState(""),
    [layingOut, setLayingOut] = useState(false),
    [page, setPage] = useState(0);
  const elk = useRef<ElkInstance | null>(null),
    flow = useRef<ReactFlowInstance<MapNode, RoutedEdge> | null>(null),
    fitted = useRef(false);
  useEffect(() => {
    elk.current = new ELK({ workerFactory: () => new Worker(elkWorkerUrl) });
    return () => {
      elk.current?.terminateWorker();
      elk.current = null;
    };
  }, []);
  useEffect(() => {
    setScope("");
    setService("");
    setNetwork("");
    setSubnet("");
    setRisk("");
    setLevel("scope");
    setSearch("");
    setPage(0);
    fitted.current = false;
  }, [scanId, kind]);
  const structural = useMemo(() => structuralIndex(graph), [graph]);
  const matching = useMemo(() => {
    const riskMatches = new Set(
      graph.nodes
        .filter(
          (n) =>
            !risk ||
            (Array.isArray(n.risk_annotations) &&
              n.risk_annotations.some(
                (a) =>
                  typeof a === "object" &&
                  a !== null &&
                  "type" in a &&
                  a.type === risk,
              )),
        )
        .map((n) => n.id),
    );
    const primaryRiskMatches = new Set(riskMatches);
    if (risk)
      for (const e of graph.edges) {
        if (
          primaryRiskMatches.has(e.source) ||
          primaryRiskMatches.has(e.target)
        ) {
          riskMatches.add(e.source);
          riskMatches.add(e.target);
        }
      }
    return graph.nodes.filter(
      (n) =>
        (!scope || String(n.scope || "Unscoped") === scope) &&
        (!service ||
          String(n.service || n.type || n.kind || "Other") === service) &&
        (!network ||
          (structural.network(n)?.id ||
            `unassigned:${n.scope || "Unscoped"}`) === network) &&
        (!subnet ||
          (structural.subnet(n)?.id ||
            `unassigned:${n.scope || "Unscoped"}`) === subnet) &&
        (!risk || riskMatches.has(n.id)) &&
        `${n.label || n.name || n.id} ${n.type || ""} ${n.service || ""} ${n.scope || ""}`
          .toLowerCase()
          .includes(search.toLowerCase()),
    );
  }, [graph, structural, scope, service, network, subnet, search, risk]);
  const view = useMemo(
    () => projectView(graph, matching, level, page, MAX_NODES, MAX_EDGES),
    [graph, matching, level, page],
  );
  useEffect(() => {
    let active = true;
    setLayingOut(true);
    setLayoutError("");
    const input: ElkNode = {
      id: "root",
      layoutOptions: {
        "elk.algorithm": "layered",
        "elk.direction": "RIGHT",
        "elk.edgeRouting": "ORTHOGONAL",
        "elk.spacing.nodeNode": "45",
        "elk.layered.spacing.nodeNodeBetweenLayers": "110",
      },
      children: view.nodes.map((n) => ({ id: n.id, width: 240, height: 74 })),
      edges: view.edges.map((e) => ({
        id: String(e.id),
        sources: [e.source],
        targets: [e.target],
      })),
    };
    elk.current
      ?.layout(input)
      .then((result) => {
        if (!active) return;
        setNodes(
          (result.children || []).map((n) => {
            const original = view.nodes.find((x) => x.id === n.id)!;
            const internal =
              original.internal_edges?.reduce(
                (total, e) => total + Number(e.underlying_count || 1),
                0,
              ) || 0;
            return {
              id: n.id,
              type: "asset",
              position: { x: n.x || 0, y: n.y || 0 },
              data: {
                label: String(original.label || original.name || original.id),
                provider: String(original.provider || "generic"),
                subtitle: original.group
                  ? `${original.underlying_count} assets · ${internal} internal relations`
                  : String(
                      original.service || original.type || "Observed asset",
                    ),
                group: !!original.group,
              },
              sourcePosition: Position.Right,
              targetPosition: Position.Left,
            };
          }),
        );
        setEdges(
          (result.edges || []).map((e) => {
            const original = view.edges.find((x) => x.id === e.id)!;
            return {
              id: e.id,
              source: original.source,
              target: original.target,
              type: "routed",
              data: {
                sections: e.sections || [],
                label: String(
                  original.label || original.type || "Observed relationship",
                ),
                count: Number(original.underlying_count || 1),
              },
              ariaLabel: String(
                original.label || original.type || "Observed relationship",
              ),
            };
          }),
        );
        setLayingOut(false);
      })
      .catch((error) => {
        if (active) {
          setLayoutError(
            error instanceof Error ? error.message : "Graph layout failed",
          );
          setLayingOut(false);
        }
      });
    return () => {
      active = false;
    };
  }, [view]);
  useEffect(() => {
    if (!layingOut && nodes.length && !fitted.current && flow.current) {
      requestAnimationFrame(() => {
        void flow.current?.fitView({ padding: 0.2 });
      });
      fitted.current = true;
    }
  }, [nodes, layingOut]);
  function reset() {
    fitted.current = false;
    setLevel("scope");
    setScope("");
    setService("");
    setNetwork("");
    setSubnet("");
    setPage(0);
  }
  function expand(n: ProjectedNode) {
    if (!n.group) return;
    const key = String(n.group_key);
    fitted.current = false;
    if (level === "scope") {
      setScope(key);
      setLevel(kind === "network" ? "network" : "service");
    } else if (level === "network") {
      setNetwork(key);
      setLevel(
        graph.nodes.find((x) => x.id === key)?.type === "namespace"
          ? "assets"
          : "subnet",
      );
    } else if (level === "subnet") {
      setSubnet(key);
      setLevel("assets");
    } else {
      setService(key);
      setLevel("assets");
    }
    setPage(0);
    setInspect(undefined);
  }
  const scroll = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({
    count: matching.length,
    getScrollElement: () => scroll.current,
    estimateSize: () => 66,
    overscan: 10,
  });
  const projection = graph.projection;
  const collapsed = projection?.collapsed;
  return (
    <>
      <div className="section-top">
        <p>
          {kind === "iam"
            ? "Declared access and trust · defensive IAM review."
            : "Explore structural inventory and conditional rule candidates."}
        </p>
        <span className="count-pill">
          {projection?.node_count ?? graph.nodes.length} assets ·{" "}
          {projection?.edge_count ?? graph.edges.length} relationships
        </span>
      </div>
      <div className="notice">
        <Layers size={18} />
        <p>
          {kind === "iam"
            ? "Relationships reflect snapshot evidence. Conditions, deny policies and runtime context may change effective access. This map does not establish an executable access path."
            : "Groups follow explicit structural resource references, preserving provider scope and GCP global/shared network semantics. CIDR overlap does not establish connectivity. Rule candidates do not prove routed reachability."}
        </p>
      </div>
      {collapsed && (
        <div className="notice">
          <p>
            The API has projected this graph. Aggregate counts, node_refs,
            resource_refs and edge_refs are retained in inspectors; supplied
            evidence may be sampled. {projection?.expansion}
          </p>
        </div>
      )}
      <Panel className="graph-panel">
        <div className="graph-toolbar">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Search graph"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
              placeholder="Find an asset, service or scope…"
            />
          </div>
          {kind === "iam" && (
            <select
              className="risk-select"
              aria-label="IAM risk filter"
              value={risk}
              onChange={(e) => {
                setRisk(e.target.value);
                setPage(0);
              }}
            >
              <option value="">All declared relationships</option>
              <option value="high_risk_grant">High-risk grants</option>
              <option value="external_trust">External trust</option>
              <option value="inactive_identity">Inactive identities</option>
            </select>
          )}
          <div className="segmented">
            <button
              aria-pressed={mode === "map"}
              onClick={() => setMode("map")}
            >
              <Network size={16} />
              Map
            </button>
            <button
              aria-pressed={mode === "table"}
              onClick={() => setMode("table")}
            >
              <Table2 size={16} />
              Table
            </button>
          </div>
        </div>
        <div className="graph-breadcrumb">
          <button className="text-button" onClick={reset}>
            All scopes
          </button>
          {[scope, network, subnet, service]
            .filter(Boolean)
            .map((value, index) => (
              <span key={index}>
                / {graph.nodes.find((n) => n.id === value)?.label || value}
              </span>
            ))}
          {level !== "assets" && (
            <button
              className="text-button push-right"
              onClick={() => {
                fitted.current = false;
                setLevel("assets");
                setPage(0);
              }}
            >
              Show assets
            </button>
          )}
          {level !== "scope" && (
            <button className="text-button" onClick={reset}>
              <ArrowLeft size={13} />
              Overview
            </button>
          )}
          <button
            className="text-button"
            onClick={() => void flow.current?.fitView({ padding: 0.2 })}
          >
            <Focus size={13} />
            Fit view
          </button>
        </div>
        {!scanId ? (
          <State empty title="Select a scan to explore the map" />
        ) : (
          <State
            loading={query.isPending}
            error={query.error}
            onRetry={() => void query.refetch()}
            empty={!!query.data && !graph.nodes.length}
            title="No graph evidence collected"
          >
            <>
              {mode === "map" ? (
                <div
                  className="graph-canvas"
                  aria-label={`${kind} relationship map`}
                >
                  {layoutError ? (
                    <State error={new Error(layoutError)} />
                  ) : (
                    <>
                      <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        nodeTypes={nodeTypes}
                        edgeTypes={edgeTypes}
                        onInit={(instance) => {
                          flow.current = instance;
                        }}
                        nodesDraggable={false}
                        nodesConnectable={false}
                        edgesReconnectable={false}
                        deleteKeyCode={null}
                        minZoom={0.1}
                        maxZoom={2}
                        onNodeClick={(_, n) =>
                          setInspect(view.nodes.find((x) => x.id === n.id))
                        }
                        onEdgeClick={(_, e) =>
                          setInspect(view.edges.find((x) => x.id === e.id))
                        }
                        colorMode="dark"
                      >
                        <Background color="#233747" gap={24} />
                        <Controls showInteractive={false} />
                      </ReactFlow>
                      {layingOut && (
                        <div className="graph-loading" role="status">
                          Routing evidence relationships…
                        </div>
                      )}
                      {!layingOut && !view.nodes.length && (
                        <div className="graph-empty">
                          <State empty title="No matching assets" />
                        </div>
                      )}
                    </>
                  )}
                </div>
              ) : (
                <div
                  className="graph-table"
                  ref={scroll}
                  role="region"
                  tabIndex={0}
                  aria-label="Graph asset table"
                >
                  <div
                    style={{
                      height: virtual.getTotalSize(),
                      position: "relative",
                    }}
                  >
                    {virtual.getVirtualItems().map((v) => {
                      const n = matching[v.index];
                      return (
                        <button
                          className="graph-table-row"
                          key={n.id}
                          style={{
                            position: "absolute",
                            top: v.start,
                            height: v.size,
                            width: "100%",
                          }}
                          onClick={() => setInspect(n)}
                        >
                          <ProviderIcon
                            provider={String(n.provider || "generic")}
                            size={24}
                          />
                          <strong>{n.label || n.name || n.id}</strong>
                          <span>{n.service || n.type || "Asset"}</span>
                          <span>{n.scope || "Unscoped"}</span>
                        </button>
                      );
                    })}
                  </div>
                  {!matching.length && (
                    <State empty title="No matching assets" />
                  )}
                </div>
              )}
              <div className="graph-footer">
                <span>
                  {mode === "map"
                    ? `${view.nodes.length} visible nodes · ${view.edges.length} visible edge groups`
                    : `${matching.length} matching assets`}{" "}
                  · {view.internalCount} internal relationships retained ·{" "}
                  {view.outsideCount} relationships outside filters
                </span>
                {mode === "map" && view.total > MAX_NODES && (
                  <div>
                    <button
                      className="button"
                      disabled={!page}
                      onClick={() => setPage(page - 1)}
                    >
                      Previous
                    </button>
                    <span>
                      {" "}
                      Page {page + 1} of{" "}
                      {Math.ceil(view.total / MAX_NODES)}{" "}
                    </span>
                    <button
                      className="button"
                      disabled={(page + 1) * MAX_NODES >= view.total}
                      onClick={() => setPage(page + 1)}
                    >
                      Next
                    </button>
                  </div>
                )}
              </div>
              {mode === "map" &&
                (view.total > MAX_NODES || view.edgeTotal > MAX_EDGES) && (
                  <p className="notice small">
                    Visible view limited to {MAX_NODES} nodes and {MAX_EDGES}{" "}
                    edge groups. Narrow the scope, search or use the complete
                    supplied asset table.
                  </p>
                )}
            </>
          </State>
        )}
      </Panel>
      {inspect && (
        <Inspector
          title={
            "source" in inspect
              ? "Relationship evidence"
              : inspect.group
                ? "Group evidence"
                : "Asset evidence"
          }
          onClose={() => setInspect(undefined)}
        >
          <h3>
            {String(
              inspect.label ||
                inspect.name ||
                inspect.id ||
                inspect.type ||
                "Observed relationship",
            )}
          </h3>
          {!!inspect.group && (
            <button
              className="button primary"
              onClick={() => expand(inspect as ProjectedNode)}
            >
              Explore group
            </button>
          )}
          <Evidence data={inspect} />
          {"underlying_edges" in inspect &&
            Array.isArray(inspect.underlying_edges) && (
              <>
                <h3>
                  Underlying evidence · {String(inspect.underlying_count)}{" "}
                  relationships
                </h3>
                {inspect.underlying_edges.map((e, i) => (
                  <button
                    key={i}
                    className="relationship-row"
                    onClick={() => setInspect(e)}
                  >
                    {e.source} → {e.target}
                    <span>{e.label || e.type || "Observed relationship"}</span>
                  </button>
                ))}
              </>
            )}
          {!("source" in inspect) && (
            <>
              <h3>
                {inspect.group ? "Internal relationships" : "Related evidence"}
              </h3>
              {(inspect.group
                ? (inspect as ProjectedNode).internal_edges || []
                : graph.edges.filter(
                    (e) => e.source === inspect.id || e.target === inspect.id,
                  )
              ).map((e, i) => (
                <button
                  key={i}
                  className="relationship-row"
                  onClick={() => setInspect(e)}
                >
                  {e.source} → {e.target}
                  <span>
                    {e.label || e.type || "Observed relationship"} ·{" "}
                    {Number(e.underlying_count || 1)} evidence records
                  </span>
                </button>
              ))}
            </>
          )}
        </Inspector>
      )}
    </>
  );
}
