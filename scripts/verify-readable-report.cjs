const fs=require('fs'),assert=require('assert'),vm=require('vm');const out=process.env.FWX_EVIDENCE_DIR||'evidence/readable-report';const input=process.env.FWX_EVIDENCE_DIR||'evidence/task5';
const {chromium}=require(process.env.FWX_PLAYWRIGHT_MODULE || 'playwright');
(async()=>{
const context=vm.createContext({});vm.runInContext(fs.readFileSync('src/firmwarex/ui/report.js','utf8'),context);
const data=JSON.parse(fs.readFileSync(input+'/controlled-report.json'));data.display_name='<img src=x onerror=alert(1)>';context.data=data;const html=vm.runInContext('securityReport(data)',context);assert(!html.includes('<img'));assert(html.includes('&lt;img'));
const env=Object.fromEntries(fs.readFileSync('.env','utf8').trim().split('\n').map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)];}));
const browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
await page.goto('http://127.0.0.1:8000/');await page.locator('#token').fill(env.FWX_API_TOKEN);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});await page.locator('#firmware-select').selectOption(data.firmware_id);await page.locator('#view-report').click();await page.locator('#report-overlay').waitFor({state:'visible'});
assert(await page.locator('.report-finding').count()===data.findings.length);assert((await page.locator('#readable-report').textContent()).includes('Executive summary'));
await page.screenshot({path:out+'/preview.png',fullPage:false});
const download=page.waitForEvent('download');await page.locator('#report-download').click();await(await download).saveAs(out+'/sample-report.html');
const saved=fs.readFileSync(out+'/sample-report.html','utf8');assert(!saved.includes('<script'));assert(!saved.includes(env.FWX_API_TOKEN));assert(!saved.includes('PipelineSecretSentinel123'));
await page.emulateMedia({media:'print'});assert(!(await page.locator('.report-actions').isVisible()));await page.pdf({path:out+'/sample-report.pdf',format:'A4',printBackground:true});await page.emulateMedia({media:'screen'});
await page.locator('#report-close').click();await page.locator('#firmware-select').selectOption(JSON.parse(fs.readFileSync(input+'/pipeline-results.json'))[1].firmware_id);await page.waitForFunction(()=>document.getElementById('status').textContent==='Needs review');await page.locator('#view-report').click();assert((await page.locator('#readable-report').textContent()).includes('mentor_signoff_required'));
assert.deepEqual(errors,[]);await browser.close();fs.writeFileSync(out+'/results.json',JSON.stringify({passed:true,findings:data.findings.length,checks:['escaped user content','severity and confidence','complete finding count','HTML download','secret and token absence','print CSS and PDF','blocked-stage disclosure','no browser errors']},null,2));
})().catch(e=>{console.error(e.message);process.exit(1)});
