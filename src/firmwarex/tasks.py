from datetime import datetime,timedelta,timezone
import hashlib,json,os,time
from firmwarex.observability import Observer,merge_snapshots
from celery import Celery
from sqlalchemy import select
from firmwarex.config import settings
from firmwarex.database import factory
from firmwarex.models import Job,AuditEvent,FileEntry,BinaryAudit
from firmwarex.sandbox import launch,cleanup_job
from firmwarex.analysis.controller import salt_for_firmware
from firmwarex.persistence import persist
from firmwarex.output_policy import sanitize_output

app=Celery('firmwarex',broker=settings().redis_url)
app.conf.update(worker_concurrency=1,worker_prefetch_multiplier=1,task_acks_late=True,task_reject_on_worker_lost=True,task_serializer='json',accept_content=['json'])

@app.task(name='firmwarex.static',soft_time_limit=240,time_limit=270)
def analyze(job_id):
    config=settings()
    with factory()() as db:
        job=db.scalar(select(Job).where(Job.id==job_id).with_for_update())
        if not job or job.status!='queued':return
        previous=job.result or {};prior=previous.get('control_observability',{})
        observer=Observer(job_id,previous.get('trace_parent'))
        observer.interval('queue_wait',int(job.created_at.timestamp()*1e9),time.time_ns())
        job.status='running';job.stage='pipeline';firmware_id=job.firmware_id
        db.add(AuditEvent(job_id=job_id,event='pipeline_started',details={'firmware_id':firmware_id,'image':config.pipeline_image,'quotas':{'wall':config.job_wall_seconds,'cpu':config.job_cpu_seconds,'memory':config.job_memory_bytes}}));db.commit()
    try:
        with observer.stage('sandbox_execution') as span:
            folder=config.storage/'jobs'/job_id/'input'
            (folder/'context.json').write_text(json.dumps({'firmware_id':firmware_id,'job_id':job_id,'trace_parent':observer.carrier(span),'mentor_authorized_execution':config.mentor_authorized_execution}))
            salt=folder/'fingerprint-salt';salt.write_bytes(salt_for_firmware(config,firmware_id));salt.chmod(0o400);os.chown(salt,config.sandbox_uid,config.sandbox_gid)
            result,telemetry=launch(job_id,config.model_copy(update={'static_image':config.pipeline_image}),scope='pipeline')
            result=sanitize_output(result,salt.read_bytes())
            if result.get('error_code'):observer.fail(span)
    except Exception:
        result,telemetry={'error_code':'launcher_failed'},{}
    try:
        with observer.stage('persistence'):
            with factory()() as db:
                job=db.scalar(select(Job).where(Job.id==job_id).with_for_update())
                if job.status!='running':return
                if result.get('error_code'):
                    job.status='failed';job.error_code=result['error_code']
                else:
                    job.status=result['status']
                    db.add_all(FileEntry(firmware_id=job.firmware_id,entry=f) for f in result['files'])
                    db.add_all(BinaryAudit(firmware_id=job.firmware_id,audit=b) for b in result['binaries'])
                    persist(db,job_id,result)
                    for stage,outcome in result['stages'].items():db.add(AuditEvent(job_id=job_id,event='stage_finished',details={'stage':stage,'status':outcome['status']}))
                artifact=config.storage/'jobs'/job_id/'output/result.json'
                artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest() if artifact.is_file() else None
                job.stage='finished'
                job.result={k:v for k,v in result.items() if k not in {'files','binaries','findings','evidence'}};job.result['sandbox']=telemetry
                db.add(AuditEvent(job_id=job_id,event='pipeline_finished',details={'status':job.status,'error_code':job.error_code,'sandbox':telemetry,'finding_count':len(result.get('findings',[])),'artifact_sha256':artifact_sha256,'artifact_ref':'jobs/'+job_id+'/output/result.json' if artifact_sha256 else None}));db.commit()
    except Exception:
        # The transaction above rolls back atomically. Record a generic failure;
        # never leak invalid worker output or database exception text to clients.
        with factory()() as db:
            job=db.scalar(select(Job).where(Job.id==job_id).with_for_update())
            if job and job.status=='running':
                job.status='failed';job.stage='finished';job.error_code='result_persistence_failed'
                job.result={'error_code':'result_persistence_failed','sandbox':telemetry}
                db.add(AuditEvent(job_id=job_id,event='pipeline_finished',details={'status':'failed','error_code':'result_persistence_failed'}))
                db.commit()
    finally:
        try:
            with factory()() as db:
                job=db.get(Job,job_id)
                if job:
                    job.result={**(job.result or {}),'control_observability':merge_snapshots(prior,observer.snapshot())}
                    db.commit()
        finally:observer.close()

app.conf.beat_schedule={'recover-queued':{'task':'firmwarex.redispatch','schedule':10.0}}
@app.task(name='firmwarex.redispatch')
def redispatch():
    cutoff=datetime.now(timezone.utc)-timedelta(seconds=300)
    with factory()() as db:
        for job in db.scalars(select(Job).where(Job.status=='running',Job.updated_at<cutoff).with_for_update(skip_locked=True)):
            previous=job.result or {};observer=Observer(job.id,previous.get('trace_parent'))
            try:
                with observer.stage('abandoned_job_recovery'):
                    cleanup_job(job.id);job.status='failed';job.stage='finished';job.error_code='dispatcher_lost'
                job.result={**previous,'control_observability':merge_snapshots(previous.get('control_observability'),observer.snapshot())}
            finally:observer.close()
            db.add(AuditEvent(job_id=job.id,event='job_recovered',details={'status':'failed','error_code':'dispatcher_lost'}))
        db.commit()
    with factory()() as db:ids=db.scalars(select(Job.id).where(Job.status=='queued').limit(settings().max_pending_jobs)).all()
    for job_id in ids:analyze.apply_async(args=[job_id],retry=False)
