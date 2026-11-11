"""Employee credentials and revocable browser sessions; preserve assessments."""
from alembic import op

revision = '0003'
down_revision = '0002'

def upgrade():
    op.execute('CREATE TABLE employees (employee_id VARCHAR(64) PRIMARY KEY, password_hash VARCHAR(256) NOT NULL, created_at TIMESTAMPTZ NOT NULL)')
    op.execute('CREATE TABLE employee_sessions (token_hash VARCHAR(64) PRIMARY KEY, employee_id VARCHAR(64) NOT NULL REFERENCES employees(employee_id), expires_at TIMESTAMPTZ NOT NULL)')
    op.create_index('ix_employee_sessions_employee_id', 'employee_sessions', ['employee_id'])
    op.create_index('ix_employee_sessions_expires_at', 'employee_sessions', ['expires_at'])
    op.execute('GRANT SELECT, INSERT, UPDATE ON employees TO fwxapp')
    op.execute('GRANT SELECT, INSERT, DELETE ON employee_sessions TO fwxapp')

def downgrade():
    op.drop_table('employee_sessions')
    op.drop_table('employees')
