"""Conservative evidence ledger. Missing acceptance evidence stays FAIL."""
from pathlib import Path
import json
root=Path(__file__).resolve().parents[1]
rows=[]
for line in (root/'docs/requirements-traceability.md').read_text().splitlines():
 if line.startswith('FWX-'):
  cells=[x.strip() for x in line.split('|')];assert len(cells)==7;rows.append(cells)
assert len(rows)==112 and len({r[0] for r in rows})==112
passes={}
def mark(ids,implementation,test,evidence,note):
 for id in ids.split():passes[id]=(implementation,test,evidence,note)
mark('FWX-STATIC-001 FWX-STATIC-002 FWX-STATIC-003 FWX-STATIC-004 FWX-STATIC-005 FWX-STATIC-006','extract.py, inventory.py, static.py, static_findings.py','six-format fixtures; frozen 6-image corpus; checksec and unit tests','evidence/day1/format-integration.json; evidence/day1/checksec-comparison.json; evidence/task6/corpus-results.json; evidence/task6/unit-tests.xml','Tested formats and recognizable headers; arbitrary vendor encoding is not guaranteed; hardening metadata has documented symbol limitations.')
mark('FWX-ARCH-001 FWX-ARCH-002','compose.yaml, api.py, tasks.py, models.py, sandbox.py','real queued pipeline, PostgreSQL findings and migrations','evidence/task6/pipeline.log; evidence/task6/migration.log','Modular stages share one disposable no-egress job container; dispatcher is trusted infrastructure.')
mark('FWX-EMU-001 FWX-EMU-002 FWX-EMU-004','emulation/runner.py and controlled registry','five architectures and HTTP/UPnP/MQTT service matrix','evidence/task6/integration.json; evidence/task3/capture-integration.json','Controlled software QEMU; no KVM required. Vendor execution remains gated.')
mark('FWX-SYM-001 FWX-SYM-002 FWX-SYM-003 FWX-SYM-004','analysis/engine.py and controller.py','source/sink, stack/heap/fault, negatives and six budget cases','evidence/task6/symbolic-results.json','Bounded candidate findings; unsupported models and unproven bounds remain explicit.')
mark('FWX-SECRET-001 FWX-SECRET-002 FWX-SAFE-007 FWX-SAFE-008','scanners/secrets.py, redaction.py, persistence.py','scanner repeat persistence and denied/audited reveal','evidence/task6/redaction.log; evidence/task6/analysis-guards.json','Heuristic detection; raw reveal disabled, not an implemented approval-to-reveal workflow.')
mark('FWX-SAFE-003 FWX-SAFE-004 FWX-DELIV-008 FWX-DOD-004','sandbox.py','nonroot/host/mount/network denial and wall/CPU/memory termination with cleanup','evidence/task6/quotas.json','Tested production pipeline profile. Mentor/PR review separate and not approved.')
mark('FWX-SAFE-005','api.py admission; tasks.py recovery','16-job backpressure and stale-job recovery','evidence/task2-completion/recovery-admission.json','Previously verified unchanged admission limit; not a multi-host load guarantee.')
mark('FWX-SCOPE-002 FWX-SCOPE-003 FWX-SCOPE-004','image-only input, no-device/no-network sandbox, diagnostic output','reviewed input/execution interfaces and controlled diagnostic suites','docs/architecture.md; evidence/task6/integration.json; evidence/task6/symbolic-results.json','No live devices, kernel exploitation, shellcode or weaponized exploit generation.')
mark(' '.join('FWX-API-%03d'%i for i in range(1,8)),'api.py','seven-route integration, authentication guards, real-image reports','evidence/task6/pipeline.log; evidence/task6/api-guards.log; evidence/task6/real-image-0.json','Findings are candidates with confidence. All required routes exist; report includes blocked-stage restrictions.')
mark(' '.join('FWX-UI-%03d'%i for i in range(1,5)),'ui/','file metadata, risk sorting, CFG interaction, filtered evidence browser tests','evidence/task5/browser-results.json; evidence/usability/results.json; evidence/task6/report-browser.log','CFG available for controlled analyzed targets; unknown file names pseudonymized.')
mark(' '.join('FWX-SCHEMA-%03d'%i for i in range(1,21)),'findings.py; schemas/finding-v1.schema.json; persistence.py','field validation unit tests and persisted normalized findings','evidence/task6/unit-tests.xml; evidence/task6/symbolic-results.json; evidence/task6/real-image-0.json','Appendix A field contract; nullable diagnostics remain null when not established.')
mark('FWX-DELIV-003 FWX-EVID-002','docs/architecture.md','diagram reviewed against Compose, sandbox, persistence and source','docs/architecture.md; compose.yaml','Mermaid diagram and explicit trust/storage/control boundaries.')
mark('FWX-DELIV-005 FWX-DELIV-006 FWX-EVID-003','versioned schema; current real OpenWrt output','frozen-hash image extraction/static/scanner reporting','evidence/task6/real-image-0.json; fixtures/manifests/openwrt-24.10.4.json','Real-image static/scanner leads; no claim of real-image dynamic findings.')
mark('FWX-DELIV-007','api.py, ui/, docs/runbook.md','seven endpoints, readable report and browser acceptance','evidence/task6/pipeline.log; evidence/task6/report-browser.log; docs/runbook.md','REST choice; JSON, HTML and browser print PDF available.')
mark('FWX-TEST-001 FWX-EVID-009','unit and real integration suites','78 unit tests plus emulation/symbolic suites; whole-package unit coverage','evidence/task6/unit-tests.xml; evidence/task6/coverage.xml; evidence/task6/integration.json; evidence/task6/symbolic-results.json','29% whole-package unit coverage; sandbox integration not combined into coverage. No invented threshold.')
mark('FWX-EVID-001','Git history, README and runbook','local history and configured origin inspected','evidence/task6/repository.txt; README.md; docs/runbook.md','Remote URL configured; no push or published-remote contents claimed.')
mark('FWX-EVID-006','production sandbox and tested QEMU service containment','current quota tests plus previous packet-capture/positive-control proof','evidence/task6/quotas.json; evidence/task3/egress.pcap; evidence/task3/capture-integration.json','Packet capture applies to tested probes, not universal future workloads.')
mark('FWX-EVID-007','fingerprint-only normal evidence','sentinels absent from stored scanner and integrated output','evidence/task6/redaction.log; evidence/task6/storage.log','Measured fixtures; universal redaction KPI remains FAIL.')
mark('FWX-GOV-001','docs/progress.md','dated previous/today/blockers entries','docs/progress.md','Local work log retained; not a substitute for human review.')
mark('FWX-DELIV-009','docs/final-writeup.md and task6-review.md','cross-check exact counts, trade-offs, bugs and limitations against evidence','evidence/task6/summary.json; docs/final-writeup.md','Final write-up explicitly states release is not accepted.')

mark('FWX-FUNC-001 FWX-DELIV-004','pipeline.py, tasks.py, API and dashboard','real controlled upload through all six stages; unregistered image remains partial','evidence/completion/pipeline-results.json; evidence/completion/controlled-report.json; evidence/completion/browser-results.json','Repeatable controlled vertical slice; real-image dynamic acceptance remains PENDING HUMAN REVIEW.')
mark('FWX-OBS-001','append-only audit role, tasks.py artifact hashes and persistence.py finding references','UPDATE/DELETE/TRUNCATE denied; input/stage/finding/output hash lifecycle checked','evidence/completion/audit-integrity.json; evidence/completion/storage-results.json','Immutable runtime audit, hashed output artifact references; privileged maintenance is separately audited.')
mark('FWX-OBS-002 FWX-DOD-008','observability.py, api.py, tasks.py, pipeline.py and telemetry view','11 linked spans; three failure cases; orphan recovery; SDK metrics; API/browser checks','evidence/completion/controlled-report.json; evidence/completion/lifecycle-failures.json; evidence/completion/recovery.json; evidence/completion/browser-results.json','Upload, queue wait, sandbox, six analysis stages plus pipeline parent, persistence. Failed processes retain controller telemetry; a killed process cannot export unfinished internal spans.')
mark('FWX-SAFE-006 FWX-DOD-006','output_policy.py, pipeline/API/controller boundaries; restricted legacy maintenance','adversarial keys/values/paths; four historical API surfaces; storage/audit/JSON/HTML sentinels','evidence/completion/output-boundary.log; evidence/completion/unit-tests.xml; evidence/completion/storage-results.json; evidence/completion/results.json','Normal diagnostics use reviewed typed metadata and salted pseudonyms. Legacy originals restricted to controller quarantine; immutable evidence validated, not rewritten. User-entered labels and restricted raw inputs are separate; universal KPI remains unverified.')
mark('FWX-TEST-001 FWX-EVID-009','unit and real integration suites','85 current unit tests; controlled lifecycle/output integration; prior unchanged component suites','evidence/completion/unit-tests.xml; evidence/completion/coverage.xml; evidence/completion/summary.json; evidence/task6/symbolic-results.json; evidence/task6/integration.json','32.81% whole-package unit coverage; external sandbox suites are not included in coverage. No invented threshold.')


# Controlled cross-architecture E2E adds evidence, not real-image acceptance.
for requirement_id in 'FWX-FUNC-001 FWX-STATIC-003 FWX-EMU-001 FWX-EMU-002 FWX-EMU-004 FWX-SYM-001 FWX-SYM-002 FWX-SAFE-003 FWX-SAFE-004 FWX-SAFE-006 FWX-API-005 FWX-API-006 FWX-OBS-002 FWX-DELIV-004 FWX-DOD-006 FWX-DOD-008'.split():
 impl,test,evidence,note=passes[requirement_id]
 passes[requirement_id]=(impl,test+'; five controlled architecture E2E uploads and actual dashboard exports',evidence+'; evidence/cross-e2e/summary.json; docs/cross-architecture-e2e.md',note+' Controlled x86_64/ARM32/ARM64/MIPS/MIPSEL full pipeline verified; real/vendor execution remains PENDING HUMAN REVIEW.')

reasons={
 'FWX-SAFE-009':'PENDING HUMAN REVIEW: mentor containment/quota sign-off absent; must precede untrusted execution.',
 'FWX-GOV-003':'BLOCKED: sensitive-code PR review absent; user has not authorized GitHub publication.',
 'FWX-GOV-004':'BLOCKED: mentor pairing has not been arranged/completed.',
 'FWX-GOV-002':'BLOCKED: human milestone/demo review has not been recorded.',
 'FWX-FUZZ-001':'DEFERRED Should per user instruction: service probes are not protocol fuzzers; unfinished optional prototype excluded.',
 'FWX-FUZZ-002':'DEFERRED Should per user instruction: minimized deterministic crash replay absent; no safety-policy block occurred.',
 'FWX-FUZZ-003':'DEFERRED Should per user instruction: fuzz-crash stack dedup absent.',
 'FWX-EMU-005':'DEFERRED Could: snapshot/restore not implemented.',
 'FWX-EMU-003':'PARTIAL Should: controlled ARM boot/stubs only; vendor service bring-up unverified.',
 'FWX-OBS-002':'INCOMPLETE: analysis spans exist; queue/persistence and all failure-stage telemetry do not.',
 'FWX-SAFE-006':'INCOMPLETE: historical static records and universal arbitrary output redaction unverified.',
 'FWX-KPI-005':'UNVERIFIED: fixture sentinel success does not prove universal 100% redaction.',
 'FWX-KPI-001':'6/6 current frozen corpus passes; standard corpus agreement/review remains pending.',
 'FWX-DOD-002':'6/6 current frozen corpus passes; standard corpus agreement/review remains pending.',
 'FWX-KPI-002':'PENDING HUMAN REVIEW: real representative static plus symbolic benchmark requires mentor-approved execution.',
 'FWX-EVID-008':'PENDING HUMAN REVIEW: real-image symbolic throughput evidence absent; static timing cannot substitute.',
 'FWX-DOD-007':'PENDING HUMAN REVIEW: representative-image basic-symbolic benchmark not authorized/completed.',
 'FWX-EVID-004':'PENDING HUMAN REVIEW: real-image taint/crash evidence absent; controlled fixture is not a substitute.',
 'FWX-EVID-005':'PARTIAL: controlled recording exists; required complete real-image dynamic demo remains gated.',
 'FWX-DOD-001':'PENDING HUMAN REVIEW: real-image static/scanner reports exist but dynamic path remains gated.',
 'FWX-DOD-009':'BLOCKED: independent new-engineer clean reproduction has not occurred.',
 'FWX-DELIV-002':'Runbook exists, but independent clean-machine full reproduction not verified.',
}
output=['# Final validation — NOT ACCEPTED','', 'Every canonical PRD requirement appears exactly once. PASS is evidence-bound to the stated scope; FAIL includes unmet, blocked, deferred or unverified obligations. The project must not be described as complete while Must requirements fail.','', 'Requirement | Implementation | Test | Evidence | Result | Notes','--- | --- | --- | --- | --- | ---']
counts={'PASS':0,'FAIL':0}
for id,section,requirement,impl,test,evidence,status in rows:
 if id in passes:impl,test,evidence,note=passes[id];result='PASS'
 else:result='FAIL';note=reasons.get(id,'Full acceptance evidence not established; prior scoped implementation/test results do not close this requirement. See known-limitations.md and task6-review.md.')
 counts[result]+=1
 output.append(' | '.join([id+' — '+requirement,impl,test,evidence,result,note]))
output+=['',f"Totals: {counts['PASS']} PASS; {counts['FAIL']} FAIL; 112 requirements. No sign-off or approval is inferred."]
(root/'docs/final-validation.md').write_text('\n'.join(output)+'\n');(root/'evidence/completion/validation-counts.json').write_text(json.dumps(counts,indent=2)+'\n');print(counts)
