import json,xml.etree.ElementTree as ET
from pathlib import Path
from firmwarex.findings import validate
root=Path('/evidence');corpus=json.loads((root/'corpus-results.json').read_text());assert corpus['successes']==corpus['denominator']==6
reports=[json.loads((root/f'real-image-{i}.json').read_text()) for i in range(6)];findings=[]
for report in reports:
 assert report['jobs'][-1]['status']=='partial'
 for stage in ['symbolic','emulation']:assert report['jobs'][-1]['result']['stages'][stage]['status']=='blocked'
 for finding in report['findings']:validate(finding);findings.append(finding)
quotas=json.loads((root/'quotas.json').read_text());assert len(quotas)==4 and all(q['cleanup_verified'] for q in quotas)
sym=json.loads((root/'symbolic-results.json').read_text());emu=json.loads((root/'integration.json').read_text());assert len(sym)==42 and len(emu)==36
unit=ET.parse(root/'unit-tests.xml').getroot().find('testsuite');assert unit.attrib['tests']=='78' and unit.attrib['failures']=='0' and unit.attrib['errors']=='0'
coverage=ET.parse(root/'coverage.xml').getroot().attrib
summary={'acceptance':'NOT ACCEPTED','unit_tests':78,'unit_line_coverage_percent':round(float(coverage['line-rate'])*100,2),'symbolic_cases':42,'emulation_cases':36,'architectures':5,'independent_pipeline_quota_cases':4,'guard_cases':9,'corpus_successes':6,'corpus_denominator':6,'real_image_findings_schema_validated':len(findings),'real_image_binary_counts':[len(r['binaries']) for r in reports],'real_image_end_to_end_seconds':[r['wall_seconds'] for r in corpus['results']],'timing_scope':'static/scanner with dynamic stages blocked; NOT a symbolic benchmark','real_image_dynamic_execution':'BLOCKED pending mentor sign-off','controlled_demo':json.loads((root/'demo.json').read_text())}
(root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
