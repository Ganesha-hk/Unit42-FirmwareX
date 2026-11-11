"""Verify actual persistence, output artifacts, schema, audit and sandbox cleanup."""
import hashlib,json
from pathlib import Path
import docker
from sqlalchemy import select
from firmwarex.database import factory
from firmwarex.models import Job,AuditEvent,FileEntry,BinaryAudit,Finding,FindingEvidence
from firmwarex.findings import validate
from firmwarex.config import settings
cases=json.loads(Path('/evidence/pipeline-results.json').read_text());client=docker.from_env();results=[]
for case in cases:
 with factory()() as db:
  job=db.get(Job,case['job_id']);events=list(db.scalars(select(AuditEvent).where(AuditEvent.job_id==job.id)))
  findings=list(db.scalars(select(Finding.record).where(Finding.firmware_id==job.firmware_id)))
  evidence={f['evidence_ref']:db.get(FindingEvidence,f['evidence_ref']).artifact for f in findings}
  stored={'result':job.result,'findings':findings,'evidence':evidence,'files':list(db.scalars(select(FileEntry.entry).where(FileEntry.firmware_id==job.firmware_id))),'binaries':list(db.scalars(select(BinaryAudit.audit).where(BinaryAudit.firmware_id==job.firmware_id))),'audit':[e.details for e in events]}
  artifact=settings().storage/'jobs'/job.id/'output/result.json';encoded=json.dumps(stored)+artifact.read_text()
  assert all(v not in encoded for v in ['PipelineSecretSentinel123','PROPRIETARY-CONTENT-SENTINEL','proprietary-sentinel-private','UnitTestPassword123','SYNTHETIC-NOT-A-REAL-KEY'])
  for finding in findings:validate(finding)
  finished=next(e for e in events if e.event=='pipeline_finished');assert finished.details['artifact_sha256']==hashlib.sha256(artifact.read_bytes()).hexdigest()
  assert {'uploaded','pipeline_started','findings_persisted','stage_finished','pipeline_finished'}<={e.event for e in events}
  assert len([e for e in events if e.event=='stage_finished'])==6
  assert not client.containers.list(all=True,filters={'label':'firmwarex.job_id='+job.id})
  results.append({'architecture':case['architecture'],'job_id':job.id,'persisted_findings':len(findings),'schema_valid':True,'normal_output_sentinels':0,'artifact_sha256':finished.details['artifact_sha256'],'cleanup_verified':True,'audit_verified':True,'status':job.status})
Path('/evidence/storage-results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results));client.close()
