"""Versioned normalized findings and redacted evidence only."""
from alembic import op
revision='0002'
down_revision='0001'

def upgrade():
    op.execute('CREATE TABLE findings (id VARCHAR(36) PRIMARY KEY, firmware_id VARCHAR(36) NOT NULL REFERENCES firmware(id), record JSON NOT NULL)')
    op.execute('CREATE INDEX ix_findings_firmware_id ON findings(firmware_id)')
    op.execute('CREATE TABLE finding_evidence (id VARCHAR(73) PRIMARY KEY, artifact JSON NOT NULL)')
    op.execute('GRANT SELECT,INSERT,UPDATE ON findings TO fwxapp')
    op.execute('GRANT SELECT,INSERT ON finding_evidence TO fwxapp')

def downgrade():
    op.drop_table('finding_evidence')
    op.drop_table('findings')
