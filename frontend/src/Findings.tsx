import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { Search, SlidersHorizontal, ChevronRight } from "lucide-react";
import type { Finding } from "./types";
import { Badge, Evidence, Inspector, Panel, State } from "./ui";
import { items, request, useApi } from "./api";
import { useInfiniteQuery } from "@tanstack/react-query";
type FindingPage={items:Finding[];total?:number;next_offset?:number|null;offset?:number;facets?:{services?:string[];statuses?:string[];frameworks?:string[]}};
const col = createColumnHelper<Finding>();
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
  const [group, setGroup] = useState("service");
  const [inspect, setInspect] = useState<Finding>();
  const [debouncedSearch,setDebouncedSearch]=useState('');
  useEffect(()=>{const timer=setTimeout(()=>setDebouncedSearch(search),250);return()=>clearTimeout(timer);},[search]);
  const query=useInfiniteQuery({queryKey:[demo?'demo':'live','findings',scanId,category,debouncedSearch,severity,status,service,framework,group],initialPageParam:0,queryFn:({pageParam})=>{
    const params=new URLSearchParams({limit:'200',offset:String(pageParam),group_by:group});
    for(const [key,value] of Object.entries({categories:category,search:debouncedSearch,severity,status,service,framework})){if(value)params.set(key,value);}
    return request<FindingPage>(`/scans/${encodeURIComponent(scanId)}/findings?${params}`,{},demo);
  },getNextPageParam:(last)=>last.next_offset??undefined,enabled:!!scanId,retry:1});
  const firstPage=query.data?.pages[0];
  const all=useMemo(()=>query.data?.pages.flatMap(page=>items(page))||[],[query.data]);
  const serverFiltered=typeof firstPage?.total==='number';
  const facets=firstPage?.facets;
  const filtered = useMemo(
    () =>
      all
        .filter(
          (f) => serverFiltered ||
            (!category || f.category === category) &&
            (!severity || f.severity === severity) &&
            (!status || f.status === status) &&
            (!service || f.service === service) &&
            (!framework || f.frameworks?.includes(framework)) &&
            `${f.title} ${f.resource_id} ${f.check_id} ${f.scope} ${JSON.stringify(f.evidence)}`
              .toLowerCase()
              .includes(search.toLowerCase()),
        )
        .sort((a, b) =>
          String(a[group as keyof Finding]).localeCompare(
            String(b[group as keyof Finding]),
          ),
        ),
    [all, category, severity, status, service, framework, search, group,serverFiltered],
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
        cell: (i) => <span className="service-cell">{i.getValue()}</span>,
      }),
      col.accessor("resource_id", {
        header: "Asset",
        cell: (i) => (
          <span title={i.getValue()} className="truncate">
            {i.getValue()}
          </span>
        ),
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
  const parent = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parent.current,
    estimateSize: () => 87,
    overscan: 8,
  });
  return (
    <>
      <div className="section-top">
        <p>Configuration findings, grounded in collected evidence.</p>
        <span className="count-pill">
          {filtered.length} /{" "}
          {all.filter((f) => !category || f.category === category).length}{" "}
          findings
        </span>
      </div>
      <Panel className="findings-panel">
        <div className="filters">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Search findings"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search assets, checks, evidence…"
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
            {Array.from(new Set([...(facets?.statuses||[]),...all.map((f)=>f.status),...(demo?[]:['PASS','FAIL','UNKNOWN','DENIED','EMPTY','MANUAL','NOT_APPLICABLE'])]))
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
            {Array.from(new Set([...(facets?.services||[]),...all.map((f) => f.service)]))
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
            {Array.from(new Set([...(facets?.frameworks||[]),...all.flatMap((f) => f.frameworks || [])]))
              .sort()
              .map((s) => (
                <option key={s}>{s}</option>
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
            error={query.error&&!query.data?query.error:undefined}
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
                        <th key={h.id}>
                          {flexRender(
                            h.column.columnDef.header,
                            h.getContext(),
                          )}
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {virtual.getVirtualItems().length > 0 && (
                    <tr aria-hidden="true">
                      <td
                        colSpan={5}
                        style={{
                          height: virtual.getVirtualItems()[0]?.start || 0,
                          padding: 0,
                        }}
                      />
                    </tr>
                  )}
                  {virtual.getVirtualItems().map((v) => {
                    const row = rows[v.index];
                    const current = String(
                      row.original[group as keyof Finding],
                    );
                    const previous =
                      v.index > 0
                        ? String(
                            rows[v.index - 1].original[group as keyof Finding],
                          )
                        : "";
                    return (
                      <tr key={row.id} style={{ height: 87 }}>
                        {row.getVisibleCells().map((cell, index) => (
                          <td key={cell.id}>
                            {index === 1 && current !== previous && (
                              <span className="group-label">{current}</span>
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
                        colSpan={5}
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
                    {(all.length||search||severity||status||service||framework)
                      ? "No findings match these filters"
                      : "No findings recorded"}
                  </h3>
                  <p>
                    {(all.length||search||severity||status||service||framework)
                      ? "Try another search or reset your filters."
                      : "Review scan coverage before drawing a security conclusion."}
                  </p>
                </div>
              )}
            </div>
            {serverFiltered&&<div className="pagination-footer"><span>{all.length} loaded of {firstPage?.total} matching findings · Filters search the complete assessment</span>{query.hasNextPage&&<button className="button" disabled={query.isFetchingNextPage} onClick={()=>void query.fetchNextPage()}>{query.isFetchingNextPage?'Loading more…':'Load more findings'}</button>}{query.error&&<span role="alert">More results could not be loaded. <button className="text-button" onClick={()=>void query.fetchNextPage()}>Retry</button></span>}</div>}
          </State>
        )}
      </Panel>
      <p className="muted small">
        A passing check applies only to its observed scope. Unknown, skipped and
        denied collections are not passing checks.
      </p>
      {inspect && <FindingInspector finding={inspect} scanId={scanId} demo={demo} lazy={serverFiltered} onClose={()=>setInspect(undefined)}/>}
    </>
  );
}
function FindingInspector({finding,scanId,demo,lazy,onClose}:{finding:Finding;scanId:string;demo:boolean;lazy:boolean;onClose:()=>void}){
 const detail=useApi<Finding>(`/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(finding.id)}`,demo,lazy&&!demo);
 const observed=detail.data||finding;
 return <Inspector title="Finding evidence" onClose={onClose}><div className="inspector-badges"><Badge value={observed.severity}/><Badge value={observed.status}/></div><h3>{observed.title}</h3><dl><dt>Check</dt><dd>{observed.check_id}</dd><dt>Asset</dt><dd>{observed.resource_id}</dd><dt>Scope</dt><dd>{observed.scope}</dd><dt>Frameworks</dt><dd>{observed.frameworks?.join(' · ')||'No framework mapping'}</dd></dl><State loading={lazy&&!demo&&detail.isPending} error={lazy&&!demo?detail.error:undefined} onRetry={()=>void detail.refetch()}><h3>Observed evidence</h3><Evidence data={observed.evidence}/><h3>Defensive remediation</h3><Evidence data={observed.remediation}/></State><button className="button" onClick={onClose}>Back to findings<ChevronRight size={16}/></button></Inspector>;
}
