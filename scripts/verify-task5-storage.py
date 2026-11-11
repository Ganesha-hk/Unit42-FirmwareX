"""Check the integrated output boundary against real PostgreSQL and storage."""
import hashlib,json
from pathlib import Path
from sqlalchemy import select
from firmwarex.database import factory
from firmwarex.models import Job,AuditEvent,FileEntry,BinaryAudit,Finding,FindingEvidence
from firmwarex.config import settings
cases=json.loads(Path('/evidence/pipeline-results.json').read_text());rows=[]
for case in cases:
 with factory()() as db:
  job=db.get(Job,case['job_id']);events=list(db.scalars(select(AuditEvent).where(AuditEvent.job_id==job.id)))
  result={'job':job.result,'audit':[e.details for e in events],'files':list(db.scalars(select(FileEntry.entry).where(FileEntry.firmware_id==job.firmware_id))),'binaries':list(db.scalars(select(BinaryAudit.audit).where(BinaryAudit.firmware_id==job.firmware_id))),'findings':list(db.scalars(select(Finding.record).where(Finding.firmware_id==job.firmware_id)))}
  result['evidence']=[db.get(FindingEvidence,f['evidence_ref']).artifact for f in result['findings']]
  encoded=json.dumps(result)+(settings().storage/'jobs'/job.id/'output/result.json').read_text()
  for forbidden in ['PipelineSecretSentinel123','PROPRIETARY-CONTENT-SENTINEL','proprietary-sentinel-private','UnitTestPassword123','SYNTHETIC-NOT-A-REAL-KEY']:assert forbidden not in encoded
  event_names=[e.event for e in events]
  assert {'uploaded','pipeline_started','findings_persisted','stage_finished','pipeline_finished'}<=set(event_names)
  assert event_names.count('stage_finished')==6
  finished=next(e for e in events if e.event=='pipeline_finished')
  artifact=settings().storage/'jobs'/job.id/'output/result.json'
  assert finished.details['artifact_sha256']==hashlib.sha256(artifact.read_bytes()).hexdigest()
  assert finished.details['artifact_ref']=='jobs/'+job.id+'/output/result.json'
  rows.append({'job_id':job.id,'persisted_findings':len(result['findings']),'audit_events':len(events),'plaintext_sentinels':0})
Path('/evidence/storage-results.json').write_text(json.dumps(rows,indent=2)+'\n');print('PASS: integrated storage, output and audit checks')
