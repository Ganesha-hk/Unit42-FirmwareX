// Actual dashboard selection and application report export for each uploaded image.
const fs=require('fs'),assert=require('assert'),path=require('path');
const {chromium}=require(process.env.FWX_PLAYWRIGHT_MODULE || 'playwright');
(async()=>{
const out='evidence/cross-e2e',cases=JSON.parse(fs.readFileSync(out+'/pipeline-results.json'));
const env=Object.fromEntries(fs.readFileSync('.env','utf8').trim().split('\n').map(l=>{const i=l.indexOf('=');return [l.slice(0,i),l.slice(i+1)];}));
const browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
await page.goto('http://127.0.0.1:8000/');await page.locator('#token').fill(env.FWX_API_TOKEN);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});const results=[];
for(const c of cases){
 const expected=JSON.parse(fs.readFileSync(path.join(out,c.report)));
 await page.locator('#firmware-select').selectOption(c.firmware_id);
 await page.waitForFunction(fid=>current?.firmware_id===fid&&document.getElementById('status').textContent==='Analysis complete',c.firmware_id,{timeout:10000});
 await page.locator('[data-tab="mitigations"]').click();await page.waitForFunction(()=>document.querySelectorAll('#matrix tr').length===2);
 assert((await page.locator('#matrix').textContent()).includes(c.architecture));
 await page.locator('[data-tab="cfg"]').click();assert(await page.locator('#graph .node').count()>0);
 await page.locator('[data-tab="telemetry"]').click();assert(await page.locator('#trace-list .stage').count()===11);
 await page.locator('#view-report').click();await page.locator('#report-overlay').waitFor({state:'visible'});
 assert(await page.locator('.report-finding').count()===expected.findings.length);
 assert((await page.locator('#readable-report').textContent()).includes(c.architecture));
 const d=page.waitForEvent('download');await page.locator('#report-download').click();await(await d).saveAs(out+'/'+c.architecture+'-report.html');
 const html=fs.readFileSync(out+'/'+c.architecture+'-report.html','utf8');assert(!html.includes('<script'));assert(!html.includes(env.FWX_API_TOKEN));
 for(const sentinel of ['PipelineSecretSentinel123','UnitTestPassword123','PROPRIETARY-CONTENT-SENTINEL'])assert(!html.includes(sentinel));
 await page.emulateMedia({media:'print'});await page.pdf({path:out+'/'+c.architecture+'-report.pdf',format:'A4',printBackground:true});await page.emulateMedia({media:'screen'});
 await page.screenshot({path:out+'/'+c.architecture+'-report-preview.png'});await page.locator('#report-close').click();
 results.push({architecture:c.architecture,firmware_id:c.firmware_id,findings:expected.findings.length,passed:true,checks:['dashboard uploaded-image selection','architecture matrix','CFG','11 spans','application report finding count','HTML download','PDF print','redaction']});
}
assert.deepEqual(errors,[]);await browser.close();fs.writeFileSync(out+'/browser-results.json',JSON.stringify({results,page_errors:errors},null,2));console.log('PASS: five actual dashboard reports exported');
})().catch(e=>{console.error(e);process.exit(1)});
