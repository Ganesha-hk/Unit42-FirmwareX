"""Migration roundtrip in a disposable database, never the application DB."""
import os,subprocess,uuid
from sqlalchemy import create_engine,text
from sqlalchemy.engine import make_url
name='fwx_migration_'+uuid.uuid4().hex
url=make_url(os.environ['FWX_MIGRATION_URL']);admin=create_engine(url, isolation_level='AUTOCOMMIT')
with admin.connect() as connection:connection.execute(text('CREATE DATABASE '+name))
try:
 env={**os.environ,'FWX_MIGRATION_URL':url.set(database=name).render_as_string(hide_password=False)}
 for args in [['upgrade','head'],['downgrade','0001'],['upgrade','head']]:
  subprocess.run(['alembic',*args],env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 engine=create_engine(url.set(database=name))
 with engine.connect() as connection:
  assert connection.execute(text('SELECT version_num FROM alembic_version')).scalar()=='0002'
  assert connection.execute(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name in ('findings','finding_evidence')")).scalar()==2
 engine.dispose()
 print('PASS: clean migration upgrade, downgrade to 0001 and re-upgrade; findings/evidence tables present')
finally:
 with admin.connect() as connection:connection.execute(text('DROP DATABASE '+name))
 admin.dispose()
