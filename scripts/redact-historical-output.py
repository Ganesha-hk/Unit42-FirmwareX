"""Trusted local maintenance. Quarantine originals, sanitize normal legacy output.

Does not modify immutable audit history or user-entered provenance. Raw backups
are restricted to the private controller directory, never exposed by the API.
"""
import json,os,time
from pathlib import Path
from sqlalchemy import select,create_engine
from sqlalchemy.orm import sessionmaker
from firmwarex.persistence import safe_evidence
from firmwarex.database import factory
from firmwarex.models import Job,FileEntry,BinaryAudit,Finding,FindingEvidence,AuditEvent
from firmwarex.analysis.controller import salt_for_firmware
from firmwarex.output_policy import sanitize_output
from firmwarex.config import settings
os.umask(0o077);config=settings();archive=config.storage/'private'/'legacy-output'/str(time.time_ns());archive.mkdir(parents=True,mode=0o700)
counts={'database_records':0,'output_files':0};salts={}
def salt(fid):
 if fid not in salts:salts[fid]=salt_for_firmware(config,fid)
 return salts[fid]
def backup(name,value):
 path=archive/name;path.write_text(json.dumps(value));path.chmod(0o600)
maintenance=sessionmaker(create_engine(os.environ['FWX_MIGRATION_URL']))
with maintenance() as db:
 for model,column in [(FileEntry,'entry'),(BinaryAudit,'audit'),(Job,'result'),(Finding,'record')]:
  for row in db.scalars(select(model)):
   if isinstance(row,Job) and row.status in {'queued','running'}:raise RuntimeError('Wait for active jobs before maintenance')
   old=getattr(row,column);new=sanitize_output(old,salt(row.firmware_id))
   if old!=new:
    backup(f'{model.__tablename__}-{row.id}.json',old);setattr(row,column,new);counts['database_records']+=1
 # Evidence is immutable and already validated at its insertion boundary.
 # Verify all historical evidence; never rewrite content-addressed artifacts.
 for row in db.scalars(select(FindingEvidence)):
  try:safe_evidence(row.artifact)
  except ValueError:raise RuntimeError('Historical evidence requires restricted review') from None
 for job in db.scalars(select(Job)):
  path=config.storage/'jobs'/job.id/'output/result.json'
  if path.is_file() and not path.is_symlink():
   old=json.loads(path.read_text());new=sanitize_output(old,salt(job.firmware_id))
   if new!=old:
    backup(f'output-{job.id}.json',old);temp=path.with_suffix('.redacted');temp.write_text(json.dumps(new));temp.chmod(0o600);temp.replace(path);counts['output_files']+=1
 db.add(AuditEvent(job_id='00000000-0000-0000-0000-000000000000',event='historical_output_redacted',details=counts));db.commit()
print(json.dumps({'status':'complete',**counts,'originals':'restricted controller-only quarantine','immutable_audit':'unchanged'}))
