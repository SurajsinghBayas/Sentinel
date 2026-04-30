"""
SQLAlchemy ORM Models — Neon PostgreSQL
Tables: users, log_sessions, threat_events, reports, audit_log
ANBU Sentinel
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String, Text, Float, Integer, Boolean, DateTime,
    ForeignKey, JSON, Enum as SAEnum, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.models.schemas import SeverityLevel, AttackType, LogFormat


def _now():
    return datetime.now(timezone.utc)


def _uuid():
    return str(uuid.uuid4())


# ── Users ─────────────────────────────────────────────────────────────────────

class UserDB(Base):
    __tablename__ = "users"

    id:              Mapped[str]  = mapped_column(String(36), primary_key=True, default=_uuid)
    name:            Mapped[str]  = mapped_column(String(100))
    email:           Mapped[str]  = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str]  = mapped_column(Text)
    role:            Mapped[str]  = mapped_column(String(50), default="analyst")
    avatar_initials: Mapped[Optional[str]] = mapped_column(String(4), nullable=True)
    is_active:       Mapped[bool] = mapped_column(Boolean, default=True)
    created_at:      Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_login:      Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # relationships
    sessions: Mapped[list["LogSessionDB"]] = relationship("LogSessionDB", back_populates="user", lazy="select")
    reports:  Mapped[list["ReportDB"]]     = relationship("ReportDB",     back_populates="analyst", lazy="select")


# ── Log Sessions ──────────────────────────────────────────────────────────────

class LogSessionDB(Base):
    __tablename__ = "log_sessions"

    id:           Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:      Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"))
    filename:     Mapped[str] = mapped_column(String(255))
    log_format:   Mapped[str] = mapped_column(String(50))
    total_lines:  Mapped[int] = mapped_column(Integer, default=0)
    parsed_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count:  Mapped[int] = mapped_column(Integer, default=0)
    threats_found:Mapped[int] = mapped_column(Integer, default=0)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    uploaded_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    user:    Mapped["UserDB"]          = relationship("UserDB",    back_populates="sessions")
    threats: Mapped[list["ThreatEventDB"]] = relationship("ThreatEventDB", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_sessions_user_id", "user_id"),)


# ── Threat Events ─────────────────────────────────────────────────────────────

class ThreatEventDB(Base):
    __tablename__ = "threat_events"

    id:            Mapped[str]   = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id:    Mapped[str]   = mapped_column(String(36), ForeignKey("log_sessions.id", ondelete="CASCADE"))
    timestamp:     Mapped[datetime] = mapped_column(DateTime(timezone=True))
    detected_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    attack_type:   Mapped[str]   = mapped_column(String(50))   # AttackType.value
    severity:      Mapped[str]   = mapped_column(String(20))   # SeverityLevel.value
    source_ip:     Mapped[str]   = mapped_column(String(45), index=True)
    target_path:   Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    confidence:    Mapped[float] = mapped_column(Float)
    rule_name:     Mapped[str]   = mapped_column(String(100))

    evidence:      Mapped[list]  = mapped_column(JSON, default=list)
    raw_entries:   Mapped[list]  = mapped_column(JSON, default=list)

    # AI narration fields
    ai_narration:      Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    attack_narrative:  Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    timeline_desc:     Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    risk_assessment:   Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    mitigation_steps:  Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    ioc_indicators:    Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    severity_justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_narrated:       Mapped[bool] = mapped_column(Boolean, default=False)

    # Status
    is_resolved:   Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at:   Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by:   Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    notes:         Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    session: Mapped["LogSessionDB"] = relationship("LogSessionDB", back_populates="threats")

    __table_args__ = (
        Index("ix_threats_session_id", "session_id"),
        Index("ix_threats_severity",   "severity"),
        Index("ix_threats_source_ip",  "source_ip"),
        Index("ix_threats_timestamp",  "timestamp"),
    )


# ── Reports ───────────────────────────────────────────────────────────────────

class ReportDB(Base):
    __tablename__ = "reports"

    id:               Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    analyst_id:       Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"))
    title:            Mapped[str] = mapped_column(String(255))
    classification:   Mapped[str] = mapped_column(String(50), default="CONFIDENTIAL")
    generated_at:     Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    session_id:       Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    summary_narration:  Mapped[str]  = mapped_column(Text)
    total_events:       Mapped[int]  = mapped_column(Integer, default=0)
    critical_count:     Mapped[int]  = mapped_column(Integer, default=0)
    high_count:         Mapped[int]  = mapped_column(Integer, default=0)
    medium_count:       Mapped[int]  = mapped_column(Integer, default=0)
    low_count:          Mapped[int]  = mapped_column(Integer, default=0)
    recommendations:    Mapped[list] = mapped_column(JSON, default=list)
    stats_snapshot:     Mapped[dict] = mapped_column(JSON, default=dict)

    # Stored PDF (base64 or S3 key — for future use)
    pdf_url:         Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    analyst: Mapped["UserDB"] = relationship("UserDB", back_populates="reports")


# ── Audit Log ─────────────────────────────────────────────────────────────────

class AuditLogDB(Base):
    __tablename__ = "audit_log"

    id:         Mapped[str]  = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:    Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    action:     Mapped[str]  = mapped_column(String(100))   # e.g. "upload_log", "narrate_threat"
    resource:   Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    detail:     Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (Index("ix_audit_user_id", "user_id"),)
