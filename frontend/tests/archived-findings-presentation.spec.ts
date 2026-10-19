import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';

const warning='This archived result uses an earlier or unverified check definition. Run a new assessment to apply the current definition.';
const historical={version:'archived-finding-presentation-v1',status:'historical_definition',basis:'corrected_evaluator_unbound',allow_summary:false,message:warning};
const base={id:'archived',category:'hardening',check_id:'native.check',title:'Archived check',provider:'aws',service:'service',resource_id:'original-resource',scope:'123456789012/us-east-1',severity:'high',status:'FAIL',frameworks:[],description:'Original archived evaluator description.',pass_when:'Original archived pass criterion.',fail_when:'Original archived fail criterion.',remediation:'Original archived action.',evidence:{enabled:false},guidance_refresh:historical};
async function mock(page:Page,finding:Record<string,unknown>,envelope?:Record<string,unknown>){
 await page.route('**/api/**',async route=>{
  const path=new URL(route.request().url()).pathname;let json:unknown={items:[]};
  if(path.endsWith('/me'))json={tenant_id:'test',plan:'free'};
  if(path.endsWith('/scans'))json={items:[{id:'scan-1',status:'completed',connector_id:'c',created_at:'2026-01-01',categories:['hardening']}]};
  if(path.endsWith('/summary'))json={provider:'aws',resources:[],findings:[],coverage:[],stats:{}};
  if(path.endsWith('/findings'))json={items:[finding],total:1,next_offset:null};
  if(path.endsWith('/findings/archived'))json=envelope||finding;
  await route.fulfill({json});
 });
 await page.goto('/#Hardening%20Findings');
 await page.getByRole('button',{name:`Archived check ${finding.check_id}`}).click();
}
for(const sample of [
 {provider:'azure',check_id:'azure.storage.no_shared_key',evidence:{field:'properties.allowSharedKeyAccess',configured:true}},
 {provider:'gcp',check_id:'gcp.compute.secure_boot',evidence:{field:'shieldedInstanceConfig.enableSecureBoot',configured:false}},
 {provider:'aws',check_id:'analysis.internet_exposure',evidence:{exposed_ports:['tcp/443'],public_addresses:['example.test'],path:[{layer:'security_group',decision:'allow'}]}},
 {provider:'aws',check_id:'native.check',evidence:{enabled:false}},
])test(`archived ${sample.check_id} does not reinterpret original evidence`,async({page})=>{
 const finding={...base,...sample};await mock(page,finding);
 const dialog=page.getByRole('dialog');
 await expect(dialog.getByText('Recorded result: FAIL. Review the original technical evidence below.',{exact:true})).toBeVisible();
 await expect(dialog.getByText(warning,{exact:true})).toBeVisible();
 await expect(dialog.locator('.remediation-actions')).toHaveText('Original archived action.');
 await dialog.getByText('How this check works',{exact:true}).click();
 await expect(dialog.getByText(base.description,{exact:true})).toBeVisible();
 await dialog.getByText('Evaluation details',{exact:true}).click();
 await expect(dialog.getByText(base.fail_when,{exact:true})).toBeVisible();
 await dialog.getByText('Technical evidence details',{exact:true}).click();
 await expect(dialog.getByRole('button',{name:'Download full evidence'})).toBeVisible();
});

test('archived source-version summary survives a blocked refresh on a narrow viewport',async({page})=>{
 await page.setViewportSize({width:390,height:844});
 await mock(page,{...base,evidence_summary:'Original source-version observation.'});
 const dialog=page.getByRole('dialog');
 await expect(dialog.getByText('Original source-version observation.',{exact:true})).toBeVisible();
 await expect(dialog.getByText(/Recorded result:/)).toHaveCount(0);
 expect(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBeTruthy();
 await page.screenshot({path:'/tmp/archived-finding-mobile.png'});
});

test('presigned finding merges presentation whitelist while protecting archived facts and transport credentials',async({page})=>{
 const presentation={description:'Refreshed reviewed explanation.',rationale:'Refreshed rationale.',remediation:'Refreshed reviewed action.',remediation_details:{summary:'Refreshed reviewed action.',steps:['Refreshed reviewed action.'],cli:[],references:[]},evidence_summary:'Approved stored observation.',guidance_refresh:historical,
  status:'PASS',severity:'critical',evidence:{enabled:true},check_id:'wrong',resource_id:'wrong',pass_when:'Overwritten criterion',fail_when:'Overwritten failure'};
 let artifactHeaders:Record<string,string>={};
 await page.addInitScript(()=>sessionStorage.setItem('hacktricks-cspm.api-token','synthetic-archive-token'));
 await page.route('https://artifact.validation.test/**',async route=>{
  artifactHeaders=await route.request().allHeaders();
  await route.fulfill({headers:{'Access-Control-Allow-Origin':'*'},json:base});
 });
 await mock(page,base,{download_url:'https://artifact.validation.test/archive?signature=synthetic',finding_presentation:presentation});
 const dialog=page.getByRole('dialog');
 await expect(dialog.getByText('Approved stored observation.',{exact:true})).toBeVisible();
 await expect(dialog.locator('.remediation-actions')).toHaveText('Refreshed reviewed action.');
 await expect(dialog.locator('.inspector-badges')).toContainText('fail');
 await expect(dialog.locator('.inspector-badges')).toContainText('high');
 await expect(dialog.locator('.inspector-badges')).not.toContainText('critical');
 await dialog.getByText('How this check works',{exact:true}).click();
 await expect(dialog.getByText('Refreshed reviewed explanation.',{exact:true})).toBeVisible();
 await dialog.getByText('Evaluation details',{exact:true}).click();
 await expect(dialog.getByText(base.fail_when,{exact:true})).toBeVisible();
 await expect(dialog.getByText('Overwritten failure')).toHaveCount(0);
 await dialog.getByText('Technical evidence details',{exact:true}).click();
 await expect(dialog.locator('.evidence-field')).toContainText('No');
 await dialog.getByText('Identifiers & frameworks',{exact:true}).click();
 await expect(dialog.locator('.finding-detail-metadata dd').filter({hasText:base.resource_id})).toBeVisible();
 await page.screenshot({path:'/tmp/archived-finding-desktop.png'});
 expect(artifactHeaders.authorization).toBeUndefined();expect(artifactHeaders.cookie).toBeUndefined();expect(artifactHeaders.referer).toBeUndefined();
});
