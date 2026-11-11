"""Initial static pipeline and append-only audit."""
from alembic import op
revision = "0001"
down_revision = None

def upgrade():
    op.execute('\nCREATE TABLE audit_events (\n\tid SERIAL NOT NULL, \n\tjob_id VARCHAR(36) NOT NULL, \n\tevent VARCHAR(64) NOT NULL, \n\tdetails JSON NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id)\n)\n\n')
    op.execute('CREATE INDEX ix_audit_events_job_id ON audit_events (job_id)')
    op.execute('\nCREATE TABLE firmware (\n\tid VARCHAR(36) NOT NULL, \n\tsha256 VARCHAR(64) NOT NULL, \n\tsize BIGINT NOT NULL, \n\tprovenance JSON NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id)\n)\n\n')
    op.execute('CREATE INDEX ix_firmware_sha256 ON firmware (sha256)')
    op.execute('\nCREATE TABLE binary_audits (\n\tid SERIAL NOT NULL, \n\tfirmware_id VARCHAR(36) NOT NULL, \n\taudit JSON NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(firmware_id) REFERENCES firmware (id)\n)\n\n')
    op.execute('CREATE INDEX ix_binary_audits_firmware_id ON binary_audits (firmware_id)')
    op.execute('\nCREATE TABLE files (\n\tid SERIAL NOT NULL, \n\tfirmware_id VARCHAR(36) NOT NULL, \n\tentry JSON NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(firmware_id) REFERENCES firmware (id)\n)\n\n')
    op.execute('CREATE INDEX ix_files_firmware_id ON files (firmware_id)')
    op.execute('\nCREATE TABLE jobs (\n\tid VARCHAR(36) NOT NULL, \n\tfirmware_id VARCHAR(36) NOT NULL, \n\tstatus VARCHAR(32) NOT NULL, \n\tstage VARCHAR(32) NOT NULL, \n\terror_code VARCHAR(64), \n\tresult JSON, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(firmware_id) REFERENCES firmware (id)\n)\n\n')
    op.execute('CREATE INDEX ix_jobs_firmware_id ON jobs (firmware_id)')
    op.execute("""CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'audit events are append-only'; END $$""")
    op.execute("CREATE TRIGGER immutable_audit BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation()")
    op.execute("GRANT USAGE ON SCHEMA public TO fwxapp")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON firmware, jobs, files, binary_audits TO fwxapp")
    op.execute("GRANT SELECT, INSERT ON audit_events TO fwxapp")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fwxapp")

def downgrade():
    op.execute("DROP TRIGGER immutable_audit ON audit_events")
    op.execute("DROP FUNCTION reject_audit_mutation()")
    for table in ["binary_audits", "files", "jobs", "audit_events", "firmware"]:
        op.drop_table(table)
