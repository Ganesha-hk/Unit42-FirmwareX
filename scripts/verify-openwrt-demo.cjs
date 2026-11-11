// Real-image browser evidence for selected profile checks.
const fs = require('fs'), path = require('path'), assert = require('assert');
const {chromium} = require(process.env.FWX_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const env = Object.fromEntries(fs.readFileSync(process.env.FWX_ENV_FILE || '.env', 'utf8').trim().split('\n').map(line => {
    const i = line.indexOf('='); return [line.slice(0, i), line.slice(i + 1)];
  }));
  const base = process.env.FWX_BASE_URL || 'http://127.0.0.1:8000';
  const out = process.env.FWX_EVIDENCE_DIR || 'evidence/mentor-accuracy-2026-11-07/openwrt-demo';
  fs.mkdirSync(path.join(out, 'video'), {recursive: true});
  const browser = await chromium.launch({headless: true});
  try {
    const context = await browser.newContext({viewport: {width: 1280, height: 900},
      extraHTTPHeaders: {Authorization: 'Bearer ' + env.FWX_API_TOKEN},
      recordVideo: {dir: path.join(out, 'video'), size: {width: 1280, height: 900}}});
    const page = await context.newPage();
    await page.goto(base + '/');
    await page.locator('#workspace').waitFor({state: 'visible'});
    if (process.env.FWX_EXPECT_EMPTY === '1') {
      assert.strictEqual(await page.locator('#firmware-select option[value]:not([value=""])').count(), 0);
    }
    await page.locator('#display-name').fill('OpenWrt 24.10.4 — verified service assessment');
    await page.locator('#image-file').setInputFiles('work/corpus/openwrt-24.10.4-x86-64-generic-squashfs-rootfs.img.gz.bin');
    await page.locator('#provenance').selectOption('public_open_source');
    await page.locator('#license').fill('GPL-2.0');
    await page.locator('#source-url').fill('https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/openwrt-24.10.4-x86-64-generic-squashfs-rootfs.img.gz');
    await page.locator('#upload').click();
    await page.locator('#status').filter({hasText: /^(Selected checks complete|Needs review|Analysis failed)$/}).waitFor({timeout: 210000});
    const id = await page.locator('#firmware-select').inputValue();
    const response = await context.request.get(base + '/api/v1/firmware/' + id + '/report',
      {headers: {Authorization: 'Bearer ' + env.FWX_API_TOKEN}});
    assert(response.ok());
    const reportText = await response.text();
    const report = JSON.parse(reportText), job = report.jobs.at(-1);
    fs.writeFileSync(path.join(out, 'report.json'), reportText);
    assert(report.files.length && report.binaries.length);
    assert(job.result.stages.emulation.executions.some(e => e.reason === 'http_harness_verified' && e.status === 'completed' && e.startup === 'listening' && e.request === 'sent' && e.response === 'http_200_marker_verified' && e.cleanup === 'process_reaped'));
    assert(job.status === 'complete');
    assert(job.result.stages.emulation.status === 'completed' && job.result.stages.emulation.coverage === 'selected_profiles_only');
    assert(job.result.stages.symbolic.status === 'completed' && job.result.stages.symbolic.coverage === 'selected_profiles_only');
    const profiled = job.result.stages.symbolic.analyses.find(a => a.input_scope === 'multipart_header_empty_body');
    assert(profiled && profiled.status === 'completed' && profiled.input_scope === 'multipart_header_empty_body');
    assert.deepStrictEqual(profiled.telemetry.terminal_returns, [0]);
    assert(!report.findings.some(f => f.source === 'fwx_environment_0' && f.sink === 'strcpy'));
    assert((await page.locator('#status').innerText()) === 'Selected checks complete');
    await page.locator('[data-tab="mitigations"]').click();
    await page.locator('[data-tab="findings"]').click();
    await page.locator('.finding').first().click();
    await page.locator('#view-report').click();
    await page.locator('#report-overlay').waitFor({state: 'visible'});
    const download = page.waitForEvent('download');
    await page.locator('#report-download').click();
    await (await download).saveAs(path.join(out, 'assessment.html'));
    await page.screenshot({path: path.join(out, 'demo-report.png')});
    const videoPath = await page.video().path();
    await context.close();
    fs.writeFileSync(path.join(out, 'report.json'), reportText);
    fs.writeFileSync(path.join(out, 'demo.json'), JSON.stringify({firmware_id: id, job_id: job.job_id,
      sha256: report.sha256, status: job.status, initially_empty: process.env.FWX_EXPECT_EMPTY === '1',
      scope: 'Real OpenWrt upload, exact selected binary profiles, loopback HTTP response, and one completed multipart-header/empty-body symbolic path. Whole-firmware coverage remains limited.',
      video: path.basename(videoPath)}, null, 2));
    console.log('PASS: recorded OpenWrt upload and dashboard report (' + job.status + ')');
  } finally { await browser.close(); }
})().catch(error => {console.error(error.message); process.exit(1);});
