import json
from sqlalchemy import text
from firmwarex.database import factory
checks={}
with factory()() as db:
 for operation in ['UPDATE audit_events SET event=event','DELETE FROM audit_events','TRUNCATE audit_events']:
  try:
   db.execute(text(operation));db.rollback();checks[operation]=False
  except Exception:
   db.rollback();checks[operation]=True
 rows=db.execute(text('SELECT event,count(*) FROM audit_events GROUP BY event')).all()
 checks['lifecycle_events']=dict(rows)
assert all(checks[k] for k in checks if k!='lifecycle_events')
assert checks['lifecycle_events'].get('uploaded',0)>0
assert checks['lifecycle_events'].get('static_finished',0)>0
print(json.dumps(checks,indent=2))
