import ELK from "elkjs/lib/elk-api.js";
import elkWorkerUrl from "elkjs/lib/elk-worker.min.js?url";
import type { ELK as ElkInstance } from "elkjs";

// One shared ELK web worker for every map. Spawning a worker parses the ~1.5 MB
// GWT bundle (seconds on a loaded machine), so a per-view worker made every
// navigation pay that cost again; the shared instance is created once and
// pre-warmed when the browser is idle.
let shared: ElkInstance | null = null;
export function sharedElk(): ElkInstance {
  if (!shared)
    shared = new ELK({ workerFactory: () => new Worker(elkWorkerUrl) });
  return shared;
}
export function prewarmElk() {
  const warm = () =>
    void sharedElk()
      .layout({ id: "warm", children: [{ id: "a", width: 1, height: 1 }] })
      .catch(() => undefined);
  const idle = (
    window as Window & { requestIdleCallback?: (cb: () => void) => number }
  ).requestIdleCallback;
  if (idle) idle(warm);
  else setTimeout(warm, 500);
}
