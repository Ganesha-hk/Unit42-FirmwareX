const fs=require('fs'),assert=require('assert');
const {chromium}=require(process.env.FWX_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const env=Object.fromEntries(fs.readFileSync('.env','utf8').trim().split('\n').map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)];}));
 const id=JSON.parse(fs.readFileSync('evidence/recheck-2026-11-09/openwrt/demo.json')).firmware_id;
 const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage();await page.goto('http://127.0.0.1:8000/');
  await page.locator('#token').fill(env.FWX_API_TOKEN);await page.locator('#login-form button').click();
  await page.locator('#workspace').waitFor({state:'visible'});await page.locator('#firmware-select').selectOption(id);
  await page.locator('#stages details').first().waitFor();
  assert(!/mentor/i.test(await page.locator('body').innerText()));
  assert((await page.locator('#execution-mode').innerText())==='Sandboxed execution');
  assert((await page.locator('#stages').innerText()).includes('incomplete'));
  assert((await page.locator('#stages').innerText()).includes('selected checks completed'));
  const response=await page.request.get('http://127.0.0.1:8000/api/v1/firmware/'+id+'/report',{headers:{Authorization:'Bearer '+env.FWX_API_TOKEN}});
  assert(response.ok());assert(!/mentor/i.test(await response.text()));
  console.log('PASS: neutral historical report labels, stage details, and preserved incomplete status');
 }finally{await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
