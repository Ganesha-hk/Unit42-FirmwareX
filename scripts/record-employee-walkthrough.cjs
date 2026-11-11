const fs=require('fs'),crypto=require('crypto'),assert=require('assert');
const {chromium}=require(process.env.FWX_PLAYWRIGHT_MODULE || 'playwright');
const root=require('path').resolve(__dirname,'..'),out=root+'/evidence/employee-firmware-walkthrough-2026-11-10';
(async()=>{
const env=Object.fromEntries(fs.readFileSync(root+'/work/submission-instance/.env','utf8').trim().split('\n').map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)];}));
const manifest=JSON.parse(fs.readFileSync(root+'/fixtures/manifests/openwrt-24.10.4.json'));
const source=manifest.images[0],file=root+'/work/corpus/'+source.local_name;
assert.equal(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),source.sha256);
const employee='EMP-'+crypto.randomBytes(3).toString('hex').toUpperCase(),password=crypto.randomBytes(24).toString('base64url');
const browser=await chromium.launch({headless:true});
try{
const context=await browser.newContext({viewport:{width:1440,height:1000},recordVideo:{dir:out,size:{width:1440,height:1000}}});
const page=await context.newPage();page.setDefaultTimeout(30000);const start=Date.now(),chapters=[];
await page.addInitScript(()=>{addEventListener('DOMContentLoaded',()=>{const p=document.createElement('div');p.id='recording-pointer';p.style.cssText='position:fixed;width:15px;height:15px;background:#167f75aa;border:2px solid white;border-radius:50%;z-index:99999;pointer-events:none;transform:translate(-50%,-50%);left:-30px';document.body.append(p);document.addEventListener('mousemove',e=>{p.style.left=e.clientX+'px';p.style.top=e.clientY+'px';});});});
async function pause(label,seconds=8){chapters.push({time_seconds:Math.round((Date.now()-start)/1000),chapter:label});console.log(label);await page.waitForTimeout(seconds*1000);}
async function click(selector){const el=page.locator(selector).first();await el.scrollIntoViewIfNeeded();const b=await el.boundingBox();await page.mouse.move(b.x+b.width/2,b.y+b.height/2,{steps:25});await page.waitForTimeout(700);await el.click();await page.waitForTimeout(1000);}
async function type(selector,value,secret=false){await click(selector);if(secret)await page.locator(selector).fill(value);else await page.locator(selector).pressSequentially(value,{delay:75});await page.waitForTimeout(800);}
async function tab(id){await click('[data-tab="'+id+'"]');await page.evaluate(()=>window.scrollTo({top:0,behavior:'smooth'}));}
await page.goto('http://127.0.0.1:8001/');await pause('Employee login page',7);
await click('#show-register');await pause('Register with employee ID, personal password and company code',7);
await type('#register-id',employee);await type('#register-password',password,true);await type('#register-confirm',password,true);await type('#company-code',env.FWX_COMPANY_REGISTRATION_CODE,true);await pause('Registration fields filled; all secrets masked',5);
await click('#register-form button[type=submit]');await page.locator('#auth-message').filter({hasText:'Account created'}).waitFor();await pause('Account created',6);
await type('#employee-password',password,true);await click('#login-form button');await page.locator('#workspace').waitFor({state:'visible'});await pause('Logged in to the workspace',7);
await page.goto('http://127.0.0.1:8002/');await pause('Browse the actual local OpenWrt firmware folder',12);
await page.getByText(source.local_name,{exact:true}).hover();await pause('Real downloaded OpenWrt file; .bin is the local upload suffix',7);
await page.goto('http://127.0.0.1:8001/');await page.locator('#workspace').waitFor({state:'visible'});
await type('#display-name','OpenWrt 24.10.4 - Router firmware review');
const chooser=page.waitForEvent('filechooser');await click('#image-file');await (await chooser).setFiles(file);await pause('Select the same checksum-verified image for upload',7);
await page.locator('#provenance').selectOption('public_open_source');await page.locator('#license').fill('GPL-2.0');await page.locator('#source-url').fill(source.url);await click('#source-url');await pause('Public firmware source and license declaration',8);
await click('#upload');await pause('Real analysis running; no simulated results',6);await page.locator('#status').filter({hasText:'Selected checks complete'}).waitFor({timeout:210000});await page.evaluate(()=>window.scrollTo({top:0,behavior:'smooth'}));await pause('Analysis overview and inventory counts',12);
const id=await page.locator('#firmware-select').inputValue();const resp=await context.request.get('http://127.0.0.1:8001/api/v1/firmware/'+id+'/report');assert(resp.ok());const raw=await resp.text(),report=JSON.parse(raw);assert.equal(report.sha256,source.sha256);assert.equal(report.jobs.at(-1).status,'complete');fs.writeFileSync(out+'/report.json',raw);
for(const details of await page.locator('#stages details').all()){await details.locator('summary').click();await details.scrollIntoViewIfNeeded();await pause('Selected program checks and their completion evidence',9);}
await tab('files');await pause('Extracted filesystem explorer; unknown names remain pseudonymized',8);
const summary=page.locator('#tree summary').first();if(await summary.count()){await summary.click();await pause('Expand a filesystem directory',6);}
const filebutton=page.locator('#tree button').first();if(await filebutton.isVisible()){await filebutton.click();await page.locator('#file-detail').scrollIntoViewIfNeeded();await pause('Filesystem metadata and hashes',8);}
await tab('mitigations');await pause('Binary hardening matrix',12);await page.locator('#risk-sort').selectOption('asc');await pause('Sort the hardening results',7);await page.locator('#risk-sort').selectOption('desc');
await tab('findings');await pause('Twenty review candidates, not twenty confirmed vulnerabilities',10);await page.locator('#finding-confidence').selectOption('heuristic');await pause('Filter findings by confidence',7);await page.locator('#finding-confidence').selectOption('');await click('.finding');await page.locator('#evidence-detail').scrollIntoViewIfNeeded();await pause('Read the redacted evidence behind a candidate',12);
await tab('cfg');await pause('Control-flow graph from the selected symbolic analysis',10);await click('#zoom-in');await pause('Inspect graph at a closer scale',6);await click('#zoom-reset');if(await page.locator('#graph .node').count()){await page.locator('#graph .node').first().click();await page.locator('#node-detail').scrollIntoViewIfNeeded();await pause('Graph node address and successors',8);}
await tab('telemetry');await pause('Actual job stage timings',10);await page.locator('#telemetry summary').click();await page.locator('#metrics').scrollIntoViewIfNeeded();await pause('Resource and sandbox metrics',9);
await page.evaluate(()=>window.scrollTo({top:0,behavior:'smooth'}));const jsonDownload=page.waitForEvent('download');await click('#export');await (await jsonDownload).saveAs(out+'/dashboard-export.json');await pause('Export the assessment as JSON',6);
await click('#view-report');await pause('Security report executive summary',12);await page.locator('#report-overlay').evaluate(e=>e.scrollTo({top:600,behavior:'smooth'}));await pause('Report scope and coverage limits',12);
await page.getByRole('heading',{name:'Detailed findings',exact:true}).scrollIntoViewIfNeeded();await pause('Detailed findings and recommended review steps',12);await page.locator('.report-finding').first().scrollIntoViewIfNeeded();await pause('Finding classification, evidence and next steps',12);
await page.getByRole('heading',{name:'Assessment identity',exact:true}).scrollIntoViewIfNeeded();await pause('Image checksum and assessment identity',8);await page.locator('#report-overlay').evaluate(e=>e.scrollTo({top:0,behavior:'smooth'}));await pause('Completed report, with bounded selected-check coverage',8);
const download=page.waitForEvent('download');await click('#report-download');await (await download).saveAs(out+'/assessment.html');await page.screenshot({path:out+'/report-preview.png'});await pause('HTML report saved for submission',6);await click('#report-close');await click('#logout');await page.locator('#employee-id').waitFor();await pause('Logged out; walkthrough complete',5);
const video=await page.video().path();await context.close();fs.renameSync(video,out+'/FirmwareX-employee-to-report.webm');fs.writeFileSync(out+'/recording.json',JSON.stringify({mode:'Automated screen recording with paced mouse movement and typing; not human-recorded',employee_id:employee,firmware_id:id,image:source,sha256:report.sha256,folder_selection:'Actual local folder shown in browser directory listing; native OS file picker is not captured by browser video',chapters,duration_seconds:Math.round((Date.now()-start)/1000)},null,2));console.log('COMPLETE');
}finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exit(1)});
