"""Apply only evidence-backed optional-stage acceptance updates; preserve all IDs."""
from pathlib import Path
import json
import re

root=Path(__file__).resolve().parents[1]
evidence='evidence/mentor-accuracy-2026-11-07/'
extended=json.loads((root/evidence/'extended-results.json').read_text())
assert {r['feature'] for r in extended if r['status']=='complete'}=={'fuzz','snapshots'}
updates={
 'FWX-EMU-005':('emulation/snapshots.py; snapshots image; pipeline.py','Real ARM counter advances; restore twice; cleanup; complete queued pipeline',evidence+'snapshots.json; '+evidence+'extended-snapshots.json','PASS','Could verified for registered ARM fixture; arbitrary vendor snapshots remain unsupported.'),
 'FWX-FUZZ-001':('fuzz/corpus.py; fuzz/runner.py; pipeline.py','12 real QEMU/GDB HTTP/UPnP/MQTT trials and full queued pipeline',evidence+'fuzz-result.json; '+evidence+'extended-fuzz.json','PASS','Should verified for controlled service; no claim of generic vendor service support.'),
 'FWX-FUZZ-002':('fuzz/corpus.py; fuzz/runner.py','Seeded corpus; bounded deletion minimization; diagnostic replay verified for all protocols',evidence+'fuzz-result.json; '+evidence+'extended-fuzz.json','PASS','Replay stored as seed/deletion recipe and fingerprint, not raw payload; minimization is bounded, not globally minimal.'),
 'FWX-FUZZ-003':('fuzz/runner.py; normalized persistence','Multiple protocol crashes with the same stack produce one persisted finding',evidence+'fuzz-result.json; '+evidence+'extended-fuzz.json','PASS','Dedup verified for one registered binary/common stack; not an assertion of semantic equivalence for arbitrary crashes.'),
}
corpus=json.loads((root/evidence/'corpus/corpus-results.json').read_text())
assert corpus['denominator']==6 and corpus['successes']==6 and len(corpus['results'])==6
for key in ['FWX-KPI-001','FWX-DOD-002']:
    updates[key]=('extract.py; frozen OpenWrt 24.10.4 six-image manifest','All six hash-verified inputs satisfy extraction, inventory, ELF and no-parse-error success rule',evidence+'corpus/corpus-results.json','PASS','6/6 (100%) on the declared frozen corpus only; not a cross-vendor success-rate claim.')
demo=json.loads((root/evidence/'openwrt-demo/demo.json').read_text())
report=json.loads((root/evidence/'openwrt-demo/report.json').read_text())
assert demo['firmware_id']==report['firmware_id'] and demo['sha256']==report['sha256']
assert report['files'] and report['binaries'] and report['findings']
assert (root/evidence/'openwrt-demo/video'/demo['video']).stat().st_size>0
assert any(x.get('reason')=='http_harness_verified' and x['status']=='completed' for x in report['jobs'][-1]['result']['stages']['emulation']['executions'])
updates['FWX-EMU-003']=('emulation/qemu_system.py; vendor_analysis.py; controlled NVRAM shim','ARM boot/peripheral/fallback cases plus actual OpenWrt uhttpd serving a synthetic loopback page','evidence/task3/integration.json; '+evidence+'service-verified/comparison.json','PASS','Best-effort Should: controlled full-system boot and real userland service verified; arbitrary board boot, original vendor web apps and complete service coverage are not established.')
for key in ['FWX-EVID-005','FWX-DOD-001']:
    updates[key]=('API upload; pipeline; dashboard/report; verify-openwrt-demo.cjs','Real frozen OpenWrt upload recorded through dashboard report; 171 ELF binaries and 20 CWE-labelled candidates',evidence+'openwrt-demo/demo.json; '+evidence+'openwrt-demo/report.json; '+evidence+'openwrt-demo/video/'+demo['video'],'PASS','Upload-to-report/recording obligation verified. Overall analysis remains partial; this does not satisfy real-image taint/crash or symbolic performance obligations.')
updates['FWX-ARCH-003']=('locks/; infra/images/; pinned control and analysis images','Dependency resolution, pip check and runtime smoke with angr, Unicorn and Z3','evidence/day1/runtime-smoke-retry.log; evidence/cross-e2e/runtime-provenance.json','PASS','Pinned open-source stack verified in the declared images; license/provenance review of all release inputs remains separate.')
updates['FWX-ARCH-004']=('emulation/runner.py; analysis/engine.py; isolated pipeline image','Five-architecture QEMU/symbolic matrix, Unicorn smoke and real angr source/sink regression','evidence/task3/integration.json; evidence/day1/runtime-smoke-retry.log; '+evidence+'symbolic-accuracy.json','PASS','Common-case controlled coverage verified; vendor full-system compatibility remains bounded and partial.')
updates['FWX-SAFE-001']=('sandbox.py; production sandbox profiles','Static, emulation, analysis and pipeline quota/network probes; no-egress interfaces and cleanup','evidence/acceptance-2026-11-08/quotas-static.json; evidence/acceptance-2026-11-08/quotas-emulation.json; evidence/acceptance-2026-11-08/quotas-analysis.json; evidence/acceptance-2026-11-08/quotas-pipeline.json','PASS','All four implemented launch scopes passed the declared probes; this is not a proof against every future code path.')
updates['FWX-SAFE-002']=('sandbox.py; fuzz/runner.py; loopback-only service profiles','Network probes show only lo, no route, no Docker socket; fuzz services use fixed job-private loopback','evidence/acceptance-2026-11-08/quotas-pipeline.json; evidence/task3/egress.pcap; evidence/task3/packet-summary.txt','PASS','Controlled services and production profiles tested; no third-party or live-device traffic is used.')
updates['FWX-SCHEMA-021']=('schemas/finding-v1.schema.json; findings.py; pipeline.py; output_policy.py','Schema validator and runtime validator checked 10 persisted reports / 179 findings, including fuzz, snapshots, OpenWrt and corpus reports','evidence/mentor-accuracy-2026-11-07/release-contracts.json; schemas/finding-v1.schema.json','PASS','Report schema and normalization contract verified; this does not prove every historical artifact has been migrated.')
updates['FWX-SCHEMA-023']=('analysis/engine.py; findings.py; scanner mappings','Real bounded symbolic negative/positive cases and null-write classification; unsupported update-path claims absent','evidence/acceptance-2026-11-08/symbolic-accuracy.json; evidence/task4/symbolic-results.json','PASS','CWE-476 null dereference and CWE-787 bounded writes are evidence-backed in controlled cases; calibration remains open.')
prov=json.loads((root/'evidence/acceptance-2026-11-08/provenance-redaction.json').read_text())
assert prov['status']=='passed' and prov['sentinel_matches']==0
updates['FWX-SCOPE-001']=('fixtures/manifests; input provenance policy; OpenWrt frozen corpus manifest','All declared fixtures carry licenses; OpenWrt manifest includes public source/license and six frozen hashes','evidence/acceptance-2026-11-08/provenance-redaction.json; fixtures/manifests/openwrt-24.10.4.json','PASS','Scope verified for declared inputs only; user-provided proprietary firmware remains subject to upload provenance review.')
updates['FWX-SCOPE-005']=('private raw storage; output_policy.py; sanitized evidence exports','Committed docs/evidence scanned for prohibited sentinels; raw inputs remain ignored private storage and are not exported','evidence/acceptance-2026-11-08/provenance-redaction.json; docs/mentor-authorization.md','PASS','This verifies declared evidence/export scope; it does not claim universal redaction of every future or private artifact.')
classification=json.loads((root/'evidence/acceptance-2026-11-08/classification-sample.json').read_text())
assert classification['status']=='passed' and classification['sample_size']>=6
for key in ['FWX-SCHEMA-022','FWX-KPI-004','FWX-DOD-005']:
    updates[key]=('findings.py; analysis/engine.py; scanners/secrets.py; static_findings.py','Six labeled static, taint, crash, credential and crypto samples checked against source/evidence rules', 'evidence/acceptance-2026-11-08/classification-sample.json','PASS','Controlled labelled classification sample passes. Independent review of arbitrary vendor findings remains a release-review activity.')
coverage=json.loads((root/'evidence/acceptance-2026-11-08/coverage-audit.json').read_text())
assert coverage['status']=='passed_for_declared_implementation'
for key in ['FWX-KPI-003','FWX-DOD-003']:
    updates[key]=('sandbox.py; tasks.py; controllers; no-egress profiles','All four launch scopes pass wall/CPU/memory/network/privilege/cleanup probes', 'evidence/acceptance-2026-11-08/coverage-audit.json','PASS','Pass covers all declared execution launch scopes and the tested job denominator; dispatcher authority is documented separately.')
updates['FWX-KPI-005']=('output_policy.py; pipeline.py; api.py; tasks.py','Output quota, persisted-report schema/redaction and committed-evidence sentinel coverage audit', 'evidence/acceptance-2026-11-08/coverage-audit.json; evidence/hardening-2026-11-07/output-quotas.json','PASS','Pass covers declared persisted diagnostic-output paths and fixtures; restricted raw input storage is outside plaintext report output.')
delivery=json.loads((root/'evidence/acceptance-2026-11-08/delivery-baseline.json').read_text())
assert delivery['status']=='passed'
updates['FWX-DELIV-001']=('modular repository; CONTRIBUTING.md; local commit history','Repository baseline verifies required delivery files, commit history and documented PR workflow', 'evidence/acceptance-2026-11-08/delivery-baseline.json','PASS','Actual PR review remains a separate governance requirement.')
path=root/'docs/final-validation.md'
lines=path.read_text().splitlines();seen=set()
for i,line in enumerate(lines):
    key=line.split(' ',1)[0]
    if key in updates:
        first=line.split(' | ')[0]
        lines[i]=' | '.join((first,*updates[key]));seen.add(key)
assert seen==set(updates)
path.write_text('\n'.join(lines)+'\n')
path=root/'docs/requirements-traceability.md'
lines=path.read_text().splitlines()
for i,line in enumerate(lines):
    key=line.split(' | ')[0]
    if key in updates:
        fields=line.split(' | ');implementation,test,proof,result,note=updates[key]
        lines[i]=' | '.join(fields[:3]+[implementation,test,proof,result+' — '+note])
path.write_text('\n'.join(lines)+'\n')
rows=[line.split(' | ') for line in (root/'docs/final-validation.md').read_text().splitlines() if line.startswith('FWX-')]
ids=[row[0].split(' ')[0] for row in rows]
assert len(ids)==112 and len(set(ids))==112
counts={status:sum(row[4]==status for row in rows) for status in ['PASS','FAIL']}
assert sum(counts.values())==112
summary={'requirements':112,**counts,'newly_verified':list(updates),'acceptance':'NOT ACCEPTED','failed_ids':[row[0].split(' ')[0] for row in rows if row[4]=='FAIL']}
(root/evidence/'validation-counts.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary))
