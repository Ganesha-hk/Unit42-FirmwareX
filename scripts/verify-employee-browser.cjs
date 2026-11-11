// Real local browser/database authentication verification; no firmware mutation.
const fs=require('fs'),crypto=require('crypto'),assert=require('assert');
const {chromium}=require(process.env.FWX_PLAYWRIGHT_MODULE || 'playwright');
(async()=>{
 const env=Object.fromEntries(fs.readFileSync('work/submission-instance/.env','utf8').trim().split('\n').map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)];}));
 const out='evidence/employee-access-2026-11-10';
 const employee='QA-'+crypto.randomBytes(6).toString('hex').toUpperCase(), password=crypto.randomBytes(24).toString('base64url');
 const browser=await chromium.launch({headless:true});
 try {
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage();
  await page.goto('http://127.0.0.1:8001/');
  await page.locator('#employee-id').waitFor();
  await page.screenshot({path:out+'/login.png'});
  assert((await context.request.get('http://127.0.0.1:8001/api/v1/firmware')).status()===401);
  await page.locator('#show-register').click();
  await page.screenshot({path:out+'/register.png'});
  await page.locator('#register-id').fill(employee);
  await page.locator('#register-password').fill(password);
  await page.locator('#register-confirm').fill(password);
  await page.locator('#company-code').fill('incorrect-company-code');
  await page.locator('#register-form button[type=submit]').click();
  await page.locator('#auth-message').filter({hasText:'company registration code is invalid'}).waitFor();
  await page.locator('#company-code').fill(env.FWX_COMPANY_REGISTRATION_CODE);
  await page.locator('#register-form button[type=submit]').click();
  await page.locator('#auth-message').filter({hasText:'Account created'}).waitFor();
  await page.locator('#employee-password').fill(password);
  await page.locator('#login-form button').click();
  await page.locator('#workspace').waitFor({state:'visible'});
  assert((await page.locator('#signed-in-employee').innerText())===employee);
  const response=await context.request.get('http://127.0.0.1:8001/api/v1/firmware');
  assert(response.ok());
  const records=(await response.json()).firmware;
  assert(records.length>0);
  await page.locator('#firmware-select').selectOption(records[0].firmware_id);
  await page.locator('#status').filter({hasText:'Selected checks complete'}).waitFor();
  await page.reload();await page.locator('#workspace').waitFor({state:'visible'});
  await page.locator('#logout').click();await page.locator('#employee-id').waitFor();
  assert((await context.request.get('http://127.0.0.1:8001/api/v1/firmware')).status()===401);
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:out+'/login-mobile.png'});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  fs.writeFileSync(out+'/browser.json',JSON.stringify({result:'PASS',checks:['wrong company code rejected','employee registration stored in PostgreSQL','employee login','existing real firmware report retained and accessible','session survives refresh','logout revokes access','mobile layout'],test_employee:employee,firmware_records:records.length},null,2));
  console.log('PASS: employee registration/login/logout and existing firmware report');
 } finally {await browser.close();}
})().catch(e=>{console.error(e.message);process.exit(1)});
