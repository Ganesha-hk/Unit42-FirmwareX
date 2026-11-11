import os
from alembic import context
from sqlalchemy import create_engine
from firmwarex.models import Base

engine = create_engine(os.environ["FWX_MIGRATION_URL"])
with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()
