import { expect,test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { publicSourceSecretObservation } from "../src/publicSourceSecretEvidence";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";
const read=(p:string)=>JSON.parse(readFileSync(new URL("../../"+p,import.meta.url),"utf8"));
const azure=read("docs/check-review/azure-function-package-integrated-public-native-20261020.json");
const gcp=read("docs/check-review/gcp-function-paired-native-dtos-20261020.json");
const current=read("docs/check-review/gcp-function-paired-native-current-dtos-20261020.json");
const two=read("docs/check-review/azure-function-package-integrated-two-secret-native-20261020.json");
const samples:{name:string;finding:Finding}[]=[
  ...azure.captures.flatMap((r:{name:string;findings:Finding[]})=>r.findings.map((finding,i)=>({name:`azure-${r.name}-${i}`,finding}))),
  ...gcp.records.flatMap((r:{case:string;public_findings:Finding[]})=>r.public_findings.map((finding,i)=>({name:`gcp-${r.case}-${i}`,finding}))),
  ...current.records.flatMap((r:{case:string;public_findings:Finding[]})=>r.public_findings.map((finding,i)=>({name:`gcp-current-${r.case}-${i}`,finding}))),
  ...two.capture.findings.map((finding:Finding,i:number)=>({name:`azure-two-${i}`,finding})),
];
for (const {name,finding} of samples) test(`actual public source ${name} is brief and scoped`,()=>{
  const before=structuredClone(finding),text=publicSourceSecretObservation(finding);
  if (finding.status==="FAIL") {
    expect(text).toContain("not validated");
    expect(text!.split(/\s+/).length).toBeLessThanOrEqual(35);
    expect(explainObservedEvidence(finding, "unused fallback")).toBe(text);
    if (finding.evidence?.complete===false) expect(text).toContain("incomplete");
  } else expect(text).toBeUndefined();
  expect(finding).toEqual(before);
});
for (const provider of ["azure","gcp"]) for (const fault of ["provider","status","fingerprint","link","scope","engine","raw","unrelated_leak"])
  test(`public ${provider} source refuses ${fault}`,()=>{
    const f=structuredClone(samples.find(r=>r.finding.provider===provider && r.finding.status==="FAIL")!.finding);
    expect(publicSourceSecretObservation(f)).toBeTruthy();
    const e=f.evidence as Record<string,unknown>;
    const field=provider==="azure"?"package_source_assertions":"function_secret_pairs";
    const record=(e[field] as Record<string,unknown>[])[0];
    const section=provider==="azure"?(record.parts as Record<string,unknown>[])[0]:record;
    if (fault==="provider") f.provider="k8s";
    else if (fault==="status") f.status="PASS";
    else if (fault==="fingerprint") f.secret_fingerprint="0".repeat(64);
    else if (fault==="link") f.linked_check_ids!.push("foreign");
    else if (fault==="scope") record.scope="unbound";
    else if (fault==="engine") (section.engines as {status:string}[])[0].status="unavailable";
    else {
      const leak=(section[provider==="azure"?"leaks":"secret_leaks"] as Record<string,unknown>[])[0];
      if (fault==="raw") leak.value="never-render";else leak.fingerprint="0".repeat(64);
    }
    expect(publicSourceSecretObservation(f)).toBeUndefined();
  });
