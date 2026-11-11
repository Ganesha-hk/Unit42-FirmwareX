"""Offline consistency gate for the complete cross-architecture evidence bundle."""
import hashlib,json,xml.etree.ElementTree as ET
from pathlib import Path
from firmwarex.findings import validate
root=Path('/evidence');cases=json.loads((root/'pipeline-results.json').read_text());storage=json.loads((root/'storage-results.json').read_text());browser=json.loads((root/'browser-results.json').read_text());pdf=json.loads((root/'pdf-verification.json').read_text());build=json.loads((root/'fixture-build.json').read_text());quotas=json.loads((root/'quotas.json').read_text())
assert {c['architecture'] for c in cases}=={'x86_64','ARM32','ARM64','MIPS','MIPSEL'} and len(cases)==5
assert len(storage)==len(browser['results'])==len(pdf)==5 and browser['page_errors']==[]
assert len(build)==4 and all(b['sha256']==b['repeat_sha256'] for b in build)
assert len(quotas)==4 and all(q['cleanup_verified'] for q in quotas)
unit=ET.parse(root/'unit-tests.xml').getroot().find('testsuite');assert int(unit.attrib['tests'])==85 and all(int(unit.attrib[k])==0 for k in ['failures','errors','skipped'])
results=[]
for c in cases:
 assert c['result']=='PASS' and c['status']=='complete' and all(c['checks'].values())
 r=json.loads((root/c['report']).read_text());assert r['sha256']==c['sha256'] and len(r['findings'])==c['findings']
 for f in r['findings']:validate(f)
 s=next(s for s in storage if s['architecture']==c['architecture']);b=next(b for b in browser['results'] if b['architecture']==c['architecture']);p=next(p for p in pdf if p['architecture']==c['architecture'])
 assert s['schema_valid'] and s['normal_output_sentinels']==0 and s['cleanup_verified'] and s['audit_verified'] and b['passed'] and p['text_and_redaction_checks']
 assert s['job_id']==c['job_id'] and b['firmware_id']==c['firmware_id']
 artifacts={suffix:hashlib.sha256((root/(c['architecture']+'-report.'+suffix)).read_bytes()).hexdigest() for suffix in ['json','html','pdf']}
 results.append({'architecture':c['architecture'],'result':'PASS','pipeline_status':c['status'],'findings':c['findings'],'endianness':c['endianness'],'fixture_sha256':c['sha256'],'job_id':c['job_id'],'firmware_id':c['firmware_id'],'report':c['architecture']+'-report.pdf','report_hashes':artifacts})
regression=json.loads((root/'regression/pipeline-results.json').read_text());assert [x['status'] for x in regression]==['complete','partial']
assert len(json.loads((root/'regression/api-guards.json').read_text()))==8
assert json.loads((root/'regression/browser-results.json').read_text())['passed']
summary={'controlled_e2e':'PASS','architectures':results,'unit_tests_passed':85,'shared_production_profile_quota_network_cases':4,'regression_pipeline_cases':2,'api_guard_cases':8,'dashboard_regression':True,'new_pdfs':5,'rendered_pages':sum(p['pages'] for p in pdf),'real_vendor_dynamic_execution':'PENDING HUMAN REVIEW','full_PRD_acceptance':'NOT ACCEPTED','limitations':['Controlled SquashFS fixtures with two ELF files; not representative vendor boot compatibility.','QEMU executes the benign service binary; symbolic engine analyzes the separate taint fixture without executing shell commands.','Quota fault injection uses controlled host workloads under the same production container profile; it is not a separate guest-ISA quota suite.','Non-x86 diagnostic finding is modeled CWE-78 taint-to-sink, not an observed native crash or exploit.','The measurements are controlled-fixture timings, not the representative real-image symbolic performance KPI.']}
(root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({'controlled_e2e':'PASS','architectures':5,'unit_tests':85,'pdfs':5,'pages':summary['rendered_pages']}))
