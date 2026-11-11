import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, JSON, BigInteger
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

def now():
    return datetime.now(timezone.utc)

class Base(DeclarativeBase):
    pass

class Employee(Base):
    __tablename__ = 'employees'
    employee_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class EmployeeSession(Base):
    __tablename__ = 'employee_sessions'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    employee_id: Mapped[str] = mapped_column(ForeignKey('employees.employee_id'), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

class Firmware(Base):
    __tablename__ = "firmware"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size: Mapped[int] = mapped_column(BigInteger)
    provenance: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    firmware_id: Mapped[str] = mapped_column(ForeignKey("firmware.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    stage: Mapped[str] = mapped_column(String(32), default="static")
    error_code: Mapped[str | None] = mapped_column(String(64))
    result: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)

class FileEntry(Base):
    __tablename__ = "files"
    id: Mapped[int] = mapped_column(primary_key=True)
    firmware_id: Mapped[str] = mapped_column(ForeignKey("firmware.id"), index=True)
    entry: Mapped[dict] = mapped_column(JSON)

class BinaryAudit(Base):
    __tablename__ = "binary_audits"
    id: Mapped[int] = mapped_column(primary_key=True)
    firmware_id: Mapped[str] = mapped_column(ForeignKey("firmware.id"), index=True)
    audit: Mapped[dict] = mapped_column(JSON)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[str] = mapped_column(String(36), index=True)
    event: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Finding(Base):
    __tablename__ = 'findings'
    id: Mapped[str] = mapped_column(String(36),primary_key=True)
    firmware_id: Mapped[str] = mapped_column(ForeignKey('firmware.id'),index=True)
    record: Mapped[dict] = mapped_column(JSON)

class FindingEvidence(Base):
    __tablename__ = 'finding_evidence'
    id: Mapped[str] = mapped_column(String(73),primary_key=True)
    artifact: Mapped[dict] = mapped_column(JSON)
