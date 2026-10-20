import { expect,test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { awsWorkloadCommandObservation } from "../src/awsWorkloadCommandEvidence";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";
const capture=JSON.parse(readFileSync(new URL("../../tests/fixtures/aws-workload-command-brief-native-20261020.json",import.meta.url),"utf8"));
const samples:{name:string;finding:Finding}[]=capture.records.flatMap((r:{case:string;findings:Finding[]})=>r.findings.map((finding,i)=>({name:r.case+"-"+i,finding})));
for(const {name,finding} of samples)test(`native command copy ${name}`,()=>{
 const before=structuredClone(finding),text=awsWorkloadCommandObservation(finding);
 if(["PASS","FAIL"].includes(finding.status)){
  expect(text).toContain("command literals");
  expect(explainObservedEvidence(finding,"unused fallback")).toContain(text!);
  if(finding.evidence?.complete===false)expect(text).toContain("incomplete");
 }
 expect(finding).toEqual(before);
});
for(const fault of ["provider","status","fingerprint","link","scope","engine","raw","path"])test(`command copy rejects ${fault}`,()=>{
 const f=structuredClone(samples.find(s=>s.finding.status==="FAIL")!.finding);expect(awsWorkloadCommandObservation(f)).toBeTruthy();
 const leak=(f.evidence!.secret_leaks as {locations:Record<string,unknown>[];detectors:Record<string,unknown>[];raw?:string}[])[0];
 if(fault==="provider")f.provider="gcp";
 else if(fault==="status")f.status="PASS";
 else if(fault==="fingerprint")f.secret_fingerprint="0".repeat(64);
 else if(fault==="link")f.linked_check_ids!.push("foreign");
 else if(fault==="scope")leak.locations[0].scope="foreign";
 else if(fault==="engine")leak.detectors[0].engine="unknown";
 else if(fault==="path")leak.locations[0].path="foreign";
 else leak.raw="must never render";
 expect(awsWorkloadCommandObservation(f)).toBeUndefined();
});
