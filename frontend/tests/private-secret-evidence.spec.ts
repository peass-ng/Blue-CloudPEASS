import { expect, test, type Page } from '@playwright/test';
const value = 'synthetic-FULL-secret-<img src=x onerror=alert(1)>-Q9w8!';
const base = { id:'secret-fixture', category:'hardening', check_id:'fixture.secret', title:'Secret setting', provider:'aws', service:'lambda', resource_id:'secret:fixture', scope:'123456789012/us-east-1', severity:'high', status:'FAIL', frameworks:[], finding_type:'secrets', secret_fingerprint:'a'.repeat(64), evidence_summary:'An offline detector observed a secret.', evidence:{} };
const privateEvidence = { status:'available', complete:true, matches:[{ fingerprint:'a'.repeat(64), value, detectors:[{engine:'kingfisher',rule:'synthetic'}], locations:[{resource_id:'arn:synthetic:function',path:'/app/private/config.env',line:27,image_digest:'sha256:manifest',layer:'sha256:layer'}, {resource_id:'arn:synthetic:function',path:'Environment.Variables',field:'DB_PASSWORD',line:null}] }] };
async function setup(page:Page, secretEvidence:unknown=privateEvidence, envelope=false, grouped=false) {
 const row = grouped ? {...base,grouped:true,member_count:1,affected_asset_count:1,status_counts:{FAIL:1},member_filters:{categories:'hardening'}} : base;
 await page.route('**/api/**', async route=>{
  const path=new URL(route.request().url()).pathname; let json:unknown={items:[]};
  if(path.endsWith('/me')) json={tenant_id:'test',plan:'free'};
  if(path.endsWith('/scans')) json={items:[{id:'scan-1',status:'completed',connector_id:'c',created_at:'2026-01-01',categories:['hardening']}]};
  if(path.endsWith('/summary')) json={provider:'aws',resources:[],findings:[],coverage:[],stats:{}};
  if(path.endsWith('/findings')) json={items:[row],total:1,next_offset:null};
  if(path.endsWith('/findings/secret-fixture')) json=envelope?{download_url:'https://artifact.validation.test/safe.json',secret_evidence:secretEvidence}:{...base,secret_evidence:secretEvidence};
  if(path.endsWith('/finding-groups/secret-fixture')) json={...row,members:[],members_total:0,next_offset:null,secret_evidence:secretEvidence};
  await route.fulfill({json});
 });
 await page.route('https://artifact.validation.test/**',route=>route.fulfill({headers:{'Access-Control-Allow-Origin':'*'},json:base}));
 await page.goto('/#Hardening%20Findings');
 await page.getByLabel('Group findings').selectOption('check_id');
 await expect(page.getByText(value,{exact:true})).toHaveCount(0);
 await page.getByRole('button',{name:'Secret setting fixture.secret'}).click();
}
for(const envelope of [false,true])test(`full values and original locations render in authorized detail (${envelope?'download envelope':'inline'})`,async({page})=>{
 await setup(page,privateEvidence,envelope);
 const dialog=page.getByRole('dialog');const section=dialog.getByRole('region',{name:'Matched secret values'});
 await expect(section.getByText(value,{exact:true})).toBeVisible();
 await expect(section.getByText('/app/private/config.env',{exact:true})).toBeVisible();
 await expect(section.getByText('27',{exact:true})).toBeVisible();
 await expect(section.getByText('sha256:manifest',{exact:true})).toBeVisible();
 await expect(section.getByText('sha256:layer',{exact:true})).toBeVisible();
 await expect(section.getByText('Unknown — no original file line was reported',{exact:true})).toBeVisible();
 await expect(section.locator('img')).toHaveCount(0);
});
test('historic findings explicitly require re-scan without a fake secret',async({page})=>{
 await setup(page,{status:'unavailable',matches:[],message:'Full matched values were not retained. Run a fresh scan.'});
 const dialog=page.getByRole('dialog');
 await expect(dialog.getByText('Full matched values were not retained. Run a fresh scan.',{exact:true})).toBeVisible();
 await expect(dialog.getByText(value,{exact:true})).toHaveCount(0);
});
test('additional bounded detail pages merge full values and every original location',async({page})=>{
 await setup(page,{...privateEvidence,next_offset:1,total_locations:3});
 await page.route('**/api/scans/scan-1/findings/secret-fixture?secret_offset=1',route=>route.fulfill({json:{...base,secret_evidence:{...privateEvidence,next_offset:null,matches:[{...privateEvidence.matches[0],locations:[{resource_id:'image',path:'/app/second.env',line:42}]}]}}}));
 const section=page.getByRole('region',{name:'Matched secret values'});
 await section.getByRole('button',{name:'Show more matched values and locations'}).click();
 await expect(section.getByText('/app/second.env',{exact:true})).toBeVisible();
 await expect(section.getByText('/app/private/config.env',{exact:true})).toBeVisible();
 await expect(section.getByText(value,{exact:true})).toHaveCount(1);
 await expect(section.getByRole('button',{name:'Show more matched values and locations'})).toHaveCount(0);
});

test('grouped detail retains complete detector pair and observed component without exposing list values',async({page})=>{
 const primary='synthetic-access-id',component='synthetic-complete-secret-key-Q12!';
 const pair=primary+':'+component;
 const first={status:'available',complete:true,next_offset:2,matches:[
  {...privateEvidence.matches[0],value:primary,locations:[{resource_id:'fixture',path:'/app/aws.env',line:1}]},
  {...privateEvidence.matches[0],fingerprint:'b'.repeat(64),value:pair,locations:[{resource_id:'fixture',path:null,detector_input_path:'/app/aws.env',line:null,location_kind:'detector_composite'}]}
 ]};
 await setup(page,first,false,true);
 await page.route('**/api/scans/scan-1/finding-groups/secret-fixture?**',async route=>{
  const url=new URL(route.request().url());
  expect(url.searchParams.get('secret_offset')).toBe('2');
  expect(url.searchParams.get('categories')).toBe('hardening');
  await route.fulfill({json:{...base,grouped:true,secret_evidence:{...first,next_offset:null,matches:[
   {...privateEvidence.matches[0],fingerprint:'c'.repeat(64),value:component,locations:[{resource_id:'fixture',path:'/app/aws.env',line:2}]}
  ]}}});
 });
 const section=page.getByRole('region',{name:'Matched secret values'});
 await expect(section.getByText(primary,{exact:true})).toBeVisible();
 await expect(section.getByText(pair,{exact:true})).toBeVisible();
 await expect(section.getByText('Not asserted for this detector-composed representation',{exact:true})).toBeVisible();
 await expect(section.getByText(/This representation was not found verbatim in the inspected bytes/)).toBeVisible();
 await section.getByRole('button',{name:'Show more matched values and locations'}).click();
 await expect(section.getByText(component,{exact:true})).toBeVisible();
 await expect(section.getByText('2',{exact:true})).toBeVisible();
 await expect(section.getByText(pair,{exact:true})).toBeVisible();
});

test('decoded-only detail labels detector input without asserting literal origin',async({page})=>{
 await setup(page,{status:'available',complete:true,matches:[{...privateEvidence.matches[0],
  locations:[{resource_id:'fixture',path:null,detector_input_path:'/app/encoded.env',line:null,location_kind:'detector_decoded'}]}]});
 const section=page.getByRole('region',{name:'Matched secret values'});
 await expect(section.getByText(value,{exact:true})).toBeVisible();
 await expect(section.getByText('Decoded match reported by the detector. The value was not found verbatim in the inspected bytes.',{exact:true})).toBeVisible();
 await expect(section.getByText('Scanned input',{exact:true})).toBeVisible();
 await expect(section.getByText('/app/encoded.env',{exact:true})).toBeVisible();
 await expect(section.getByText('Not asserted for this decoded-only value',{exact:true})).toBeVisible();
});
