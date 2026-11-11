/* Export recorded tests through the unmodified FirmwareX application renderer.
 * No invented full-pipeline jobs, no target execution, no database modifications.
 */
const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('assert'),crypto=require('crypto');
const {chromium}=require(process.env.FWX_PLAYWRIGHT_MODULE || 'playwright');
const out=process.env.FWX_REPORT_DIR;assert(out,'Set FWX_REPORT_DIR');fs.mkdirSync(out,{recursive:true});
const source='evidence/task6/symbolic-results.json',records=JSON.parse(fs.readFileSync(source));
const renderer='src/firmwarex/ui/report.js',css=fs.readFileSync('src/firmwarex/ui/report.css','utf8');
const context=vm.createContext({});vm.runInContext(fs.readFileSync(renderer,'utf8'),context);
(async()=>{const browser=await chromium.launch({headless:true});const manifest=[];
for(const architecture of ['x86_64','ARM32','ARM64','MIPS','MIPSEL']){
 let data,scope,origin;
 if(architecture==='x86_64'){
  origin='evidence/completion/controlled-report.json';data=JSON.parse(fs.readFileSync(origin));
  data.display_name='x86_64 - controlled integrated assessment';scope='controlled integrated pipeline';
 }else{
  origin=source;const record=records.find(r=>r.case.startsWith('cross-')&&r.result.findings[0]?.architecture===architecture);assert(record);
  const result=record.result;assert(result.status==='completed');
  scope='recorded symbolic component test only';
  data={schema_version:'1.0.0',firmware_id:result.findings[0].firmware_id,display_name:architecture+' - controlled symbolic component test',sha256:null,size:null,files:[],binaries:[],findings:result.findings,evidence:result.evidence,
   jobs:[{job_id:record.job_id,status:'partial (component test only)',result:{stages:{symbolic:{status:result.status,reason:'Recorded controlled fixture '+record.case},integrated_pipeline:{status:'not performed',reason:'This component test is not a full uploaded-firmware assessment.'}}}}],
   safety:{untrusted_execution:'PENDING HUMAN REVIEW',raw_reveal:'disabled'},
   limitations:['Source: '+origin+'; case: '+record.case+'. Exported from recorded software output; no analysis rerun.',
    'Only the symbolic component result is included. Separate QEMU tests are not merged into this assessment.',
    'Zero audited binaries/files means no inventory or hardening report was attached to this component record; it does not mean the fixture contained no binary.',
    'Image SHA-256 and image size are unavailable in this source record. The firmware ID identifies a shared controlled-test collection.',
    'Finding confidence and severity are the recorded analyzer values; they do not establish a real vendor vulnerability.']};
 }
 assert(data.findings.every(f=>f.architecture===architecture));context.data=data;
 const html='<!doctype html><html><head><meta charset="utf-8"><title>FirmwareX '+architecture+' assessment</title><style>'+css+'</style></head><body><div id="report-overlay"><main id="readable-report">'+vm.runInContext('securityReport(data)',context)+'</main></div></body></html>';
 const base=path.join(out,'FirmwareX-'+architecture+'-report');fs.writeFileSync(base+'.json',JSON.stringify(data,null,2));fs.writeFileSync(base+'.html',html);
 const page=await browser.newPage();await page.route('**/*',route=>route.abort());await page.setContent(html);await page.emulateMedia({media:'print'});
 assert(await page.locator('.report-finding').count()===data.findings.length);
 await page.pdf({path:base+'.pdf',format:'A4',printBackground:true});await page.close();
 manifest.push({architecture,scope,findings:data.findings.length,source:origin,source_sha256:crypto.createHash('sha256').update(fs.readFileSync(origin)).digest('hex'),pdf:path.basename(base+'.pdf')});
}
await browser.close();fs.writeFileSync(path.join(out,'manifest.json'),JSON.stringify({renderer,renderer_sha256:crypto.createHash('sha256').update(fs.readFileSync(renderer)).digest('hex'),analysis_rerun:false,reports:manifest},null,2));console.log(JSON.stringify(manifest));})().catch(error=>{console.error(error);process.exit(1)});
