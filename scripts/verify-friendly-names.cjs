const {chromium}=require(process.env.FWX_PLAYWRIGHT_MODULE || 'playwright');
const fs=require('fs'),assert=require('assert');
(async()=>{
 const env=Object.fromEntries(fs.readFileSync('.env','utf8').trim().split('\n').map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)];}));
 const id=JSON.parse(fs.readFileSync('evidence/task5/pipeline-results.json'))[0].firmware_id;
 const browser=await chromium.launch({headless:true});const page=await browser.newPage();
 await page.goto('http://127.0.0.1:8000/');await page.locator('#token').fill(env.FWX_API_TOKEN);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.locator('#firmware-select').selectOption(id);await page.locator('#rename').waitFor();await page.waitForFunction(()=>!document.getElementById('rename').disabled);
 page.once('dialog',dialog=>dialog.accept('My router — test analysis'));
 await page.locator('#rename').click();await page.getByText('Firmware name saved.',{exact:true}).waitFor();
 assert((await page.locator('#firmware-select option:checked').textContent()).includes('My router — test analysis'));
 await page.reload();await page.locator('#token').fill(env.FWX_API_TOKEN);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});await page.locator('#firmware-select').selectOption(id);
 await page.waitForFunction(()=>!document.getElementById('rename').disabled);
 assert((await page.locator('#firmware-select option:checked').textContent()).includes('My router — test analysis'));
 assert(await page.locator('#identity').isHidden());assert(await page.locator('#display-name').getAttribute('required')!==null);
 await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
 await page.screenshot({path:'evidence/usability/friendly-names-mobile.png',fullPage:true});
 await browser.close();fs.writeFileSync('evidence/usability/results.json',JSON.stringify({passed:true,checks:['friendly labels','rename saved across reload','technical details collapsed','upload name required','mobile width']},null,2));
})().catch(error=>{console.error(error.message);process.exit(1);});
