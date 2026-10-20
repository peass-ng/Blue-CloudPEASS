import type { Finding } from "./types";
const rules:Record<string,readonly[string,string,string]>={
  "gcp.review.workbench.terminal_access_disabled":["notebook-disable-terminal","disabled","The notebook terminal"],
  "gcp.review.workbench.file_download_disabled":["notebook-disable-downloads","disabled","JupyterLab file downloads"],
  "gcp.review.workbench.auto_upgrade_schedule_declared":["notebook-upgrade-schedule","schedule_declared",""],
};
export function gcpWorkbenchHead3Observation(f:Finding):string|undefined {
  const r=rules[f.check_id],raw=f.evidence;
  if (!r || f.provider!=="gcp" || !["PASS","FAIL"].includes(f.status) || !raw || typeof raw!=="object" || Array.isArray(raw))return;
  const e=raw as Record<string,unknown>;
  const value=e[r[1]];
  if (typeof value!=="boolean" || (f.status==="PASS")!==value || e.setting!=="gceSetup.metadata."+r[0]
      || typeof e.instance!=="string" || !/^projects\/[A-Za-z0-9_-]+\/locations\/[a-z0-9-]+\/instances\/[A-Za-z0-9_-]+$/.test(e.instance)
      || f.scope!==undefined && !e.instance.startsWith(f.scope+"/locations/")) return;
  if (r[1]==="schedule_declared") return value?"An automatic upgrade schedule is configured for this Workbench instance."
    :"This Workbench instance has no automatic upgrade schedule configured.";
  return `${r[2]} ${r[0]==="notebook-disable-downloads"?"are":"is"} ${value?"disabled":"enabled"} in Workbench settings.`;
}
