import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { Search, SlidersHorizontal, ChevronRight } from "lucide-react";
import type { Catalog, Finding, Report } from "./types";
import { Badge, Evidence, Inspector, Panel, State } from "./ui";
import { catalogFrameworksPath, items, request, useApi } from "./api";
import { useInfiniteQuery } from "@tanstack/react-query";
import { explainFindingEvidence, explainInternetExposure } from "./findingExplanation";
import { Remediation } from "./Remediation";
type FindingPage = {
  items: Finding[];
  total?: number;
  next_offset?: number | null;
  offset?: number;
  facets?: { services?: string[]; statuses?: string[]; frameworks?: string[] };
};
const col = createColumnHelper<Finding>();
const assetLabel = (finding: Finding) =>
  finding.resource_name || finding.native_resource_id || finding.resource_id;
type SortField = "severity" | "title" | "service" | "account" | "status" | "resource_id";
function accountLabel(finding: Finding): string {
  if ("account" in finding && typeof finding.account === "string" && finding.account)
    return finding.account;
  const scope = finding.scope?.trim() || "";
  const resource = finding.native_resource_id || finding.resource_id || "";
  if (finding.provider === "aws") {
    const account = scope.match(/(?:^|\/)(\d{12})(?:\/|$)/)?.[1] ||
      resource.match(/^arn:[^:]*:[^:]*:[^:]*:(\d{12}):/)?.[1];
    return account || (scope && !scope.includes("/") ? scope : "Unknown");
  }
  if (finding.provider === "gcp") {
    const project = scope.match(/(?:^|\/)projects\/([^/]+)/)?.[1] ||
      resource.match(/(?:^|\/)projects\/([^/]+)/)?.[1];
    if (project) return project;
    const owner = scope.match(/(?:^|\/)(folders|organizations)\/([^/]+)/) ||
      resource.match(/(?:^|\/)(folders|organizations)\/([^/]+)/);
    return owner ? owner[2] :
      scope && !scope.includes("/") ? scope : "Unknown";
  }
  if (finding.provider === "azure") {
    const subscription = scope.match(/(?:^|\/)subscriptions\/([^/]+)/i)?.[1] ||
      resource.match(/(?:^|\/)subscriptions\/([^/]+)/i)?.[1];
    if (subscription) return subscription;
    const tenant = scope.match(/(?:^|\/)(tenants)\/([^/]+)/i) ||
      resource.match(/(?:^|\/)(tenants)\/([^/]+)/i);
    return tenant ? tenant[2] :
      scope && !scope.includes("/") ? scope : "Unknown";
  }
  if (finding.provider === "k8s")
    return resource.match(/^k8s:\/\/([^/]+)/)?.[1] || "Unknown";
  return scope.split("/")[0] || "Unknown";
}
export function Findings({
  scanId,
  category,
  demo,
}: {
  scanId: string;
  category: string;
  demo: boolean;
}) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [service, setService] = useState("");
  const [framework, setFramework] = useState("");
  const [sort, setSort] = useState<{ field: SortField; order: "asc" | "desc" }>();
  const catalog = useApi<Catalog>(catalogFrameworksPath, demo);
  const summary = useApi<Report>(
    `/scans/${encodeURIComponent(scanId)}/summary`,
    demo,
    !!scanId,
  );
  const selectedChecklist = catalog.data?.framework_versions?.find(
    (row) => row.id === framework,
  );
  const [group, setGroup] = useState("service");
  const [expandedServices, setExpandedServices] = useState<Set<string>>(new Set());
  const [inspect, setInspect] = useState<Finding>();
  const [debouncedSearch, setDebouncedSearch] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 250);
    return () => clearTimeout(timer);
  }, [search]);
  const query = useInfiniteQuery({
    queryKey: [
      demo ? "demo" : "live",
      "findings",
      scanId,
      category,
      debouncedSearch,
      severity,
      status,
      service,
      framework,
      group,
      sort?.field,
      sort?.order,
    ],
    initialPageParam: 0,
    queryFn: ({ pageParam, signal }) => {
      const params = new URLSearchParams({
        limit: "200",
        offset: String(pageParam),
        group_by: group,
      });
      for (const [key, value] of Object.entries({
        categories: category,
        search: debouncedSearch,
        severity,
        status,
        service,
        framework,
      })) {
        if (value) params.set(key, value);
      }
      if (sort) {
        params.set("sort_by", sort.field);
        params.set("sort_order", sort.order);
      }
      return request<FindingPage>(
        `/scans/${encodeURIComponent(scanId)}/findings?${params}`,
        { signal },
        demo,
      );
    },
    getNextPageParam: (last) => last.next_offset ?? undefined,
    enabled: !!scanId,
    retry: 1,
  });
  const firstPage = query.data?.pages[0];
  const all = useMemo(
    () => query.data?.pages.flatMap((page) => items(page)) || [],
    [query.data],
  );
  const serverFiltered = typeof firstPage?.total === "number";
  const facets = firstPage?.facets;
  const frameworkOptions = useMemo(
    () =>
      Array.from(
        new Set(
          [
            ...(catalog.data?.frameworks || []).map((row) =>
              typeof row === "string"
                ? row
                : row && typeof row === "object" && "name" in row
                  ? String(row.name)
                  : "",
            ),
            ...(facets?.frameworks || []),
            ...all.flatMap((finding) => finding.frameworks || []),
          ].filter(Boolean),
        ),
      ).sort(),
    [catalog.data?.frameworks, facets?.frameworks, all],
  );
  const filtered = useMemo(
    () =>
      all
        .filter(
          (f) =>
            serverFiltered ||
            ((!category || f.category === category) &&
              (!severity || f.severity === severity) &&
              (!status || f.status === status) &&
              (!service || f.service === service) &&
              (!framework || (selectedChecklist
                ? f.framework_ids?.includes(framework) ||
                  (!!selectedChecklist.name && f.frameworks?.includes(String(selectedChecklist.name)))
                : f.frameworks?.includes(framework))) &&
              `${f.title} ${f.resource_id} ${f.resource_name || ""} ${f.native_resource_id || ""} ${f.check_id} ${f.scope} ${JSON.stringify(f.evidence)}`
                .toLowerCase()
                .includes(search.toLowerCase())),
        )
        .sort((a, b) => {
          if (sort && !serverFiltered) {
            if (sort.field === "severity") {
              const rank: Record<string, number> = {
                critical: 0, high: 1, medium: 2, low: 3,
                info: 4, informational: 4,
              };
              const leftRank = rank[a.severity.toLowerCase()] ?? 5;
              const rightRank = rank[b.severity.toLowerCase()] ?? 5;
              const difference = leftRank - rightRank ||
                a.severity.localeCompare(b.severity);
              return difference * (sort.order === "asc" ? 1 : -1);
            }
            const left = sort.field === "account" ? accountLabel(a)
              : sort.field === "resource_id" ? assetLabel(a) : String(a[sort.field]);
            const right = sort.field === "account" ? accountLabel(b)
              : sort.field === "resource_id" ? assetLabel(b) : String(b[sort.field]);
            return left.localeCompare(right, undefined, { numeric: true }) *
              (sort.order === "asc" ? 1 : -1);
          }
          if (sort && serverFiltered) return 0;
          return String(a[group as keyof Finding]).localeCompare(
            String(b[group as keyof Finding]),
          );
        }),
    [
      all,
      category,
      severity,
      status,
      service,
      framework,
      search,
      group,
      serverFiltered,
      selectedChecklist,
      sort,
    ],
  );
  const columns = useMemo(
    () => [
      col.accessor("severity", {
        header: "Severity",
        cell: (i) => <Badge value={i.getValue()} />,
      }),
      col.accessor("title", {
        header: "Finding / check",
        cell: (i) => (
          <button
            className="finding-title"
            onClick={() => setInspect(i.row.original)}
          >
            {i.getValue()}
            <span>{i.row.original.check_id}</span>
          </button>
        ),
      }),
      col.accessor("service", {
        header: "Service",
        cell: (i) => (
          <span className="service-cell" title={i.getValue()}>
            {i.getValue()}
          </span>
        ),
      }),
      col.accessor("resource_id", {
        header: "Asset",
        cell: (i) => (
          <div className="asset-cell">
            <span title={assetLabel(i.row.original)} className="truncate">
              {assetLabel(i.row.original)}
            </span>
            {i.row.original.resource_name &&
              i.row.original.native_resource_id && (
                <span
                  className="native-asset-id"
                  title={i.row.original.native_resource_id}
                >
                  {i.row.original.native_resource_id}
                </span>
              )}
            {/* Collection-level rows ("inventory:<type>") repeat per region;
                the scope is what tells them apart. */}
            {i.row.original.resource_id?.startsWith("inventory:") &&
              i.row.original.scope && (
                <span className="native-asset-id" title={i.row.original.scope}>
                  {i.row.original.scope}
                </span>
              )}
          </div>
        ),
      }),
      col.display({
        id: "account",
        header: "Account",
        cell: (i) => accountLabel(i.row.original),
      }),
      col.accessor("status", {
        header: "Status",
        cell: (i) => <Badge value={i.getValue()} />,
      }),
    ],
    [],
  );
  const table = useReactTable({
    data: filtered,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });
  const rows = table.getRowModel().rows;
  const groupedServices = category === "exposure" && group === "service";
  const visibleRows = useMemo(() => {
    if (!groupedServices) return rows.map((row) => ({ kind: "finding" as const, row }));
    const services = new Map<string, typeof rows>();
    for (const row of rows) {
      const name = row.original.service || "Unknown service";
      if (!services.has(name)) services.set(name, []);
      services.get(name)!.push(row);
    }
    return [...services].flatMap(([name, findings]) => [
      { kind: "service" as const, name, findings },
      ...(expandedServices.has(name) ? findings.map((row) => ({ kind: "finding" as const, row })) : []),
    ]);
  }, [rows, groupedServices, expandedServices]);
  const sortableColumns: Record<string, SortField> = {
    severity: "severity", title: "title", service: "service",
    resource_id: "resource_id", account: "account", status: "status",
  };
  const parent = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({
    count: visibleRows.length,
    getScrollElement: () => parent.current,
    estimateSize: (index) => visibleRows[index]?.kind === "service" ? 58 : 87,
    overscan: 8,
  });
  const lastVisible = virtual.getVirtualItems().at(-1)?.index ?? -1;
  const browsingKey = JSON.stringify([scanId, category, debouncedSearch, severity, status, service, framework, group, sort]);
  useEffect(() => setExpandedServices(new Set()), [browsingKey]);
  useEffect(() => {
    if (parent.current) parent.current.scrollTop = 0;
    virtual.scrollToOffset(0);
  }, [browsingKey]);
  useEffect(() => {
    if (!serverFiltered || !query.hasNextPage || query.isFetching || query.isFetchNextPageError ||
        (!groupedServices && (all.length < 20 || lastVisible < visibleRows.length - 20))) return;
    void query.fetchNextPage({ cancelRefetch: false });
  }, [serverFiltered, query.hasNextPage, query.isFetching, query.isFetchNextPageError, groupedServices, all.length, visibleRows.length, lastVisible, query.fetchNextPage]);
  return (
    <>
      <div className="section-top">
        <p>Configuration findings, grounded in collected evidence.</p>
        <span className="count-pill">
          {filtered.length} /{" "}
          {firstPage?.total ??
            all.filter((f) => !category || f.category === category).length}{" "}
          findings
        </span>
      </div>
      {selectedChecklist && (
        <div className="notice">
          <p>
            Selected checklist: {String(selectedChecklist.name)}. Findings are filtered across the complete assessment.
          </p>
        </div>
      )}
      <Panel className="findings-panel">
        <div className="filters">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Search findings"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search assets, checks and metadata…"
            />
          </div>
          <label className="compact-label">
            <span className="sr-only">Severity</span>
            <select
              aria-label="Severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All severities</option>
              {["critical", "high", "medium", "low", "info"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <select
            aria-label="Status"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="">All statuses</option>
            {Array.from(
              new Set([
                ...(facets?.statuses || []),
                ...all.map((f) => f.status),
                ...(demo
                  ? []
                  : [
                      "PASS",
                      "FAIL",
                      "UNKNOWN",
                      "DENIED",
                      "EMPTY",
                      "MANUAL",
                      "NOT_APPLICABLE",
                    ]),
              ]),
            )
              .sort()
              .map((s) => (
                <option key={s}>{s}</option>
              ))}
          </select>
          <select
            aria-label="Service"
            value={service}
            onChange={(e) => setService(e.target.value)}
          >
            <option value="">All services</option>
            {Array.from(
              new Set([
                ...(facets?.services || []),
                ...all.map((f) => f.service),
              ]),
            )
              .sort()
              .map((s) => (
                <option key={s}>{s}</option>
              ))}
          </select>
        </div>
        <div className="filter-secondary">
          <SlidersHorizontal size={15} />
          <select
            aria-label="Compliance framework"
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
          >
            <option value="">All compliance frameworks</option>
            {frameworkOptions.map((s) => (
                <option key={s}>{s}</option>
              ))}
            {(catalog.data?.framework_versions || []).filter((row) =>
              row.provider === summary.data?.provider || row.provider === "all"
            ).map((row, i) => (
              <option key={String(row.id || i)} value={String(row.id)}>
                {String(row.name || row.id)}
              </option>
            ))}
          </select>
          <label>
            Group by{" "}
            <select
              aria-label="Group findings"
              value={group}
              onChange={(e) => setGroup(e.target.value)}
            >
              <option value="service">Service</option>
              <option value="check_id">Check</option>
              <option value="resource_id">Asset</option>
            </select>
          </label>
          <button
            className="text-button"
            onClick={() => {
              setSearch("");
              setSeverity("");
              setStatus("");
              setService("");
              setFramework("");
            }}
          >
            Reset filters
          </button>
        </div>
        {!scanId ? (
          <State empty title="Select a scan to review evidence" />
        ) : (
          <State
            loading={query.isPending}
            error={query.error && !query.data ? query.error : undefined}
            onRetry={() => void query.refetch()}
          >
            <div
              className="table-scroll"
              ref={parent}
              role="region"
              aria-label="Findings table"
              tabIndex={0}
            >
              <table className="findings-table">
                <thead>
                  {table.getHeaderGroups().map((g) => (
                    <tr key={g.id}>
                      {g.headers.map((h) => (
                        <th key={h.id} aria-sort={sort?.field === sortableColumns[h.id]
                          ? sort.order === "asc" ? "ascending" : "descending"
                          : "none"}>
                          <button className="text-button" type="button" onClick={() => {
                            const field = sortableColumns[h.id];
                            setSort((current) => ({
                              field,
                              order: current?.field === field && current.order === "asc" ? "desc" : "asc",
                            }));
                          }}>
                            {flexRender(h.column.columnDef.header, h.getContext())}
                          </button>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {virtual.getVirtualItems().length > 0 && (
                    <tr aria-hidden="true">
                      <td
                        colSpan={6}
                        style={{
                          height: virtual.getVirtualItems()[0]?.start || 0,
                          padding: 0,
                        }}
                      />
                    </tr>
                  )}
                  {virtual.getVirtualItems().map((v) => {
                    const item = visibleRows[v.index];
                    if (item.kind === "service") {
                      const counts = item.findings.reduce((result, finding) => {
                        result[finding.original.status] = (result[finding.original.status] || 0) + 1;
                        return result;
                      }, {} as Record<string, number>);
                      return <tr key={`service-${item.name}`} className="service-group-row"><td colSpan={6}>
                        <button type="button" className="service-group-button" aria-expanded={expandedServices.has(item.name)}
                          onClick={() => setExpandedServices((current) => {
                            const next = new Set(current);
                            if (next.has(item.name)) next.delete(item.name); else next.add(item.name);
                            return next;
                          })}>
                          <ChevronRight size={16} className={expandedServices.has(item.name) ? "expanded" : ""} />
                          <strong>{item.name}</strong>
                          <span>{item.findings.length} findings{query.hasNextPage ? " loaded" : ""}</span>
                          {Object.entries(counts).map(([status, count]) => <span key={status}>{count} {status}</span>)}
                        </button>
                      </td></tr>;
                    }
                    const row = item.row;
                    const current = String(
                      row.original[group as keyof Finding],
                    );
                    const previous =
                      !groupedServices && v.index > 0
                        ? String(
                            rows[v.index - 1].original[group as keyof Finding],
                          )
                        : "";
                    return (
                      <tr key={row.id} style={{ height: 87 }}>
                        {row.getVisibleCells().map((cell, index) => (
                          <td key={cell.id}>
                            {index === 1 && !groupedServices && !sort && current !== previous && (
                              <span className="group-label">
                                {group === "resource_id"
                                  ? assetLabel(row.original)
                                  : current}
                              </span>
                            )}
                            {flexRender(
                              cell.column.columnDef.cell,
                              cell.getContext(),
                            )}
                          </td>
                        ))}
                      </tr>
                    );
                  })}
                  {virtual.getVirtualItems().length > 0 && (
                    <tr aria-hidden="true">
                      <td
                        colSpan={6}
                        style={{
                          height: Math.max(
                            0,
                            virtual.getTotalSize() -
                              (virtual.getVirtualItems().at(-1)?.end || 0),
                          ),
                          padding: 0,
                        }}
                      />
                    </tr>
                  )}
                </tbody>
              </table>
              {!rows.length && (
                <div className="state">
                  <Search />
                  <h3>
                    {all.length ||
                    search ||
                    severity ||
                    status ||
                    service ||
                    framework
                      ? "No findings match these filters"
                      : "No findings recorded"}
                  </h3>
                  <p>
                    {all.length ||
                    search ||
                    severity ||
                    status ||
                    service ||
                    framework
                      ? "Try another search or reset your filters."
                      : "Review scan coverage before drawing a security conclusion."}
                  </p>
                </div>
              )}
            </div>
            {serverFiltered && (
              <div className="pagination-footer">
                <span>
                  {all.length} loaded of {firstPage?.total} matching findings ·
                  Filters search the complete assessment
                </span>
                {query.hasNextPage && (
                  <button
                    className="button"
                    disabled={query.isFetchingNextPage}
                    onClick={() => void query.fetchNextPage({ cancelRefetch: false })}
                  >
                    {query.isFetchingNextPage
                      ? "Loading more…"
                      : "Load more findings"}
                  </button>
                )}
                {query.isFetchNextPageError && (
                  <span role="alert">
                    More results could not be loaded.{" "}
                    <button
                      className="text-button"
                      onClick={() => void query.fetchNextPage({ cancelRefetch: false })}
                    >
                      Retry
                    </button>
                  </span>
                )}
              </div>
            )}
          </State>
        )}
      </Panel>
      {inspect && (
        <FindingInspector
          finding={inspect}
          scanId={scanId}
          demo={demo}
          lazy={!demo}
          onClose={() => setInspect(undefined)}
        />
      )}
    </>
  );
}
function FindingInspector({
  finding,
  scanId,
  demo,
  lazy,
  onClose,
}: {
  finding: Finding;
  scanId: string;
  demo: boolean;
  lazy: boolean;
  onClose: () => void;
}) {
  const detail = useApi<Finding>(
    `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(finding.id)}`,
    demo,
    lazy && !demo,
  );
  const observed = detail.data || finding;
  const internetExposure = observed.check_id === "analysis.internet_exposure";
  const exposure = internetExposure ? explainInternetExposure(observed.evidence, observed.status) : undefined;
  const definition = <>
    <h3>What this check evaluates</h3>
    <p>{observed.description}</p>
    {Array.isArray(observed.evaluated) && observed.evaluated.length > 0 && <>
      <h4>Fields read</h4>
      <ul>{observed.evaluated.map((field, index) => <li key={`${field}-${index}`}>{field}</li>)}</ul>
    </>}
    <dl>
      {observed.pass_when && <><dt>Pass</dt><dd>{observed.pass_when}</dd></>}
      {observed.fail_when && <><dt>Fail</dt><dd>{observed.fail_when}</dd></>}
      {observed.not_applicable_when && <><dt>Not applicable</dt><dd>{observed.not_applicable_when}</dd></>}
    </dl>
  </>;
  return (
    <Inspector title="Finding evidence" onClose={onClose}>
      <div className="inspector-badges">
        <Badge value={observed.severity} />
        <Badge value={observed.status} />
      </div>
      <h3>{observed.title}</h3>
      {internetExposure && <State loading={lazy && !demo && detail.isPending}
        error={lazy && !demo ? detail.error : undefined} onRetry={() => void detail.refetch()}>
        <h3>Affected asset</h3>
        <p><strong>{assetLabel(observed)}</strong> · {observed.service} · {observed.scope}</p>
        <h3>Why this result</h3>
        <p>{exposure?.summary}</p>
        {!!exposure?.reasons.length && <ul>{exposure.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
        {observed.evidence != null && <details><summary>Technical evidence details</summary><Evidence data={observed.evidence} /></details>}
        <h3>Defensive remediation</h3>
        <Remediation legacy={observed.remediation} details={observed.remediation_details} />
      </State>}
      {internetExposure && <details><summary>Check and report metadata</summary>
      <dl>
        <dt>Check</dt>
        <dd>{observed.check_id}</dd>
        <dt>Asset</dt>
        <dd>{assetLabel(observed)}</dd>
        {observed.native_resource_id && (
          <>
            <dt>Native ID</dt>
            <dd>{observed.native_resource_id}</dd>
          </>
        )}
        <dt>Report resource ID</dt>
        <dd>{observed.resource_id}</dd>
        <dt>Scope</dt>
        <dd>{observed.scope}</dd>
        <dt>Frameworks</dt>
        <dd>{observed.frameworks?.join(" · ") || "No framework mapping"}</dd>
      </dl>
      </details>}
      {!internetExposure && <dl>
        <dt>Check</dt><dd>{observed.check_id}</dd>
        <dt>Asset</dt><dd>{assetLabel(observed)}</dd>
        {observed.native_resource_id && <><dt>Native ID</dt><dd>{observed.native_resource_id}</dd></>}
        <dt>Report resource ID</dt><dd>{observed.resource_id}</dd>
        <dt>Scope</dt><dd>{observed.scope}</dd>
        <dt>Frameworks</dt><dd>{observed.frameworks?.join(" · ") || "No framework mapping"}</dd>
      </dl>}
      {observed.description && (
        <section aria-label="Check explanation">
          {internetExposure ? <details><summary>Check definition</summary>{definition}</details> : definition}
        </section>
      )}
      {!internetExposure && <State
        loading={lazy && !demo && detail.isPending}
        error={lazy && !demo ? detail.error : undefined}
        onRetry={() => void detail.refetch()}
      >
        <h3>Observed evidence</h3>
        <p>{explainFindingEvidence(observed.evidence, observed.status)}</p>
        {observed.evidence != null && (
          <details>
            <summary>Technical evidence details</summary>
            <Evidence data={observed.evidence} />
          </details>
        )}
        <h3>Defensive remediation</h3>
        <Remediation legacy={observed.remediation} details={observed.remediation_details} />
      </State>}
      <button className="button" onClick={onClose}>
        Back to findings
        <ChevronRight size={16} />
      </button>
    </Inspector>
  );
}
