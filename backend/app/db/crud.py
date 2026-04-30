"""
CRUD helpers — async SQLAlchemy operations
ANBU Sentinel
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import UserDB, LogSessionDB, ThreatEventDB, ReportDB, AuditLogDB
from app.models.schemas import ThreatEvent, SeverityLevel


# ── Users ─────────────────────────────────────────────────────────────────────

async def get_user_by_email(db: AsyncSession, email: str) -> Optional[UserDB]:
    result = await db.execute(select(UserDB).where(UserDB.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: str) -> Optional[UserDB]:
    result = await db.execute(select(UserDB).where(UserDB.id == user_id))
    return result.scalar_one_or_none()


async def create_user(db: AsyncSession, name: str, email: str, hashed_password: str) -> UserDB:
    initials = "".join(w[0].upper() for w in name.split()[:2])
    user = UserDB(
        id=str(uuid.uuid4()),
        name=name,
        email=email,
        hashed_password=hashed_password,
        avatar_initials=initials,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def update_last_login(db: AsyncSession, user_id: str):
    user = await get_user_by_id(db, user_id)
    if user:
        user.last_login = datetime.now(timezone.utc)
        await db.commit()


# ── Log Sessions ──────────────────────────────────────────────────────────────

async def create_session(
    db: AsyncSession,
    session_id: str,
    user_id: str,
    filename: str,
    log_format: str,
    total_lines: int,
    parsed_count: int,
    error_count: int,
    threats_found: int,
    file_size_bytes: Optional[int] = None,
) -> LogSessionDB:
    session = LogSessionDB(
        id=session_id,
        user_id=user_id,
        filename=filename,
        log_format=log_format,
        total_lines=total_lines,
        parsed_count=parsed_count,
        error_count=error_count,
        threats_found=threats_found,
        file_size_bytes=file_size_bytes,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return session


async def get_sessions_by_user(db: AsyncSession, user_id: str) -> List[LogSessionDB]:
    result = await db.execute(
        select(LogSessionDB)
        .where(LogSessionDB.user_id == user_id)
        .order_by(desc(LogSessionDB.uploaded_at))
    )
    return list(result.scalars().all())


# ── Threat Events ─────────────────────────────────────────────────────────────

async def save_threat(db: AsyncSession, threat: ThreatEvent) -> ThreatEventDB:
    row = ThreatEventDB(
        id=threat.id,
        session_id=threat.session_id,
        timestamp=threat.timestamp,
        attack_type=threat.attack_type.value,
        severity=threat.severity.value,
        source_ip=threat.source_ip,
        target_path=threat.target_path,
        request_count=threat.request_count,
        confidence=threat.confidence,
        rule_name=threat.rule_name,
        evidence=threat.evidence,
        raw_entries=threat.raw_entries[:5],  # store up to 5 sample lines
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def update_threat_narration(db: AsyncSession, threat_id: str, narration: dict) -> Optional[ThreatEventDB]:
    result = await db.execute(select(ThreatEventDB).where(ThreatEventDB.id == threat_id))
    row = result.scalar_one_or_none()
    if not row:
        return None
    row.ai_narration        = narration.get("executive_summary")
    row.attack_narrative    = narration.get("attack_narrative")
    row.timeline_desc       = narration.get("timeline_description")
    row.risk_assessment     = narration.get("risk_assessment")
    row.mitigation_steps    = narration.get("mitigation_steps", [])
    row.ioc_indicators      = narration.get("ioc_indicators", [])
    row.severity_justification = narration.get("severity_justification")
    row.is_narrated         = True
    await db.commit()
    await db.refresh(row)
    return row


async def get_threats(
    db: AsyncSession,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    session_id: Optional[str] = None,
    limit: int = 100,
) -> List[ThreatEventDB]:
    q = select(ThreatEventDB)
    if severity:
        q = q.where(ThreatEventDB.severity == severity.upper())
    if attack_type:
        q = q.where(ThreatEventDB.attack_type == attack_type.upper())
    if session_id:
        q = q.where(ThreatEventDB.session_id == session_id)
    q = q.order_by(desc(ThreatEventDB.timestamp)).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


async def get_threat_by_id(db: AsyncSession, threat_id: str) -> Optional[ThreatEventDB]:
    result = await db.execute(select(ThreatEventDB).where(ThreatEventDB.id == threat_id))
    return result.scalar_one_or_none()


async def resolve_threat(db: AsyncSession, threat_id: str, resolved_by: str, notes: str = "") -> Optional[ThreatEventDB]:
    row = await get_threat_by_id(db, threat_id)
    if not row:
        return None
    row.is_resolved = True
    row.resolved_at = datetime.now(timezone.utc)
    row.resolved_by = resolved_by
    row.notes       = notes
    await db.commit()
    await db.refresh(row)
    return row


async def get_dashboard_counts(db: AsyncSession):
    """Return aggregated severity counts from DB."""
    counts = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        result = await db.execute(
            select(func.count()).where(ThreatEventDB.severity == sev)
        )
        counts[sev.lower()] = result.scalar() or 0
    total = await db.execute(select(func.count(ThreatEventDB.id)))
    counts["total"] = total.scalar() or 0
    return counts


async def get_all_threats_for_dashboard(db: AsyncSession, limit: int = 1000) -> List[ThreatEventDB]:
    """Fetch recent threats for chart building."""
    result = await db.execute(
        select(ThreatEventDB)
        .order_by(desc(ThreatEventDB.timestamp))
        .limit(limit)
    )
    return list(result.scalars().all())


async def get_total_logs_analyzed(db: AsyncSession) -> int:
    """Sum parsed_count across all log sessions."""
    result = await db.execute(select(func.sum(LogSessionDB.parsed_count)))
    return result.scalar() or 0


async def get_session_count(db: AsyncSession) -> int:
    result = await db.execute(select(func.count(LogSessionDB.id)))
    return result.scalar() or 0


# ── Reports ───────────────────────────────────────────────────────────────────

async def save_report(
    db: AsyncSession,
    analyst_id: str,
    title: str,
    classification: str,
    session_id: Optional[str],
    summary_narration: str,
    total_events: int,
    stats: dict,
    recommendations: List[str],
    severity_counts: dict,
) -> ReportDB:
    report = ReportDB(
        id=str(uuid.uuid4()),
        analyst_id=analyst_id,
        title=title,
        classification=classification,
        session_id=session_id,
        summary_narration=summary_narration,
        total_events=total_events,
        critical_count=severity_counts.get("CRITICAL", 0),
        high_count=severity_counts.get("HIGH", 0),
        medium_count=severity_counts.get("MEDIUM", 0),
        low_count=severity_counts.get("LOW", 0),
        recommendations=recommendations,
        stats_snapshot=stats,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


async def get_reports_by_user(db: AsyncSession, analyst_id: str) -> List[ReportDB]:
    result = await db.execute(
        select(ReportDB)
        .where(ReportDB.analyst_id == analyst_id)
        .order_by(desc(ReportDB.generated_at))
    )
    return list(result.scalars().all())


# ── Audit Log ─────────────────────────────────────────────────────────────────

async def log_action(
    db: AsyncSession,
    action: str,
    user_id: Optional[str] = None,
    resource: Optional[str] = None,
    detail: Optional[dict] = None,
    ip_address: Optional[str] = None,
):
    entry = AuditLogDB(
        id=str(uuid.uuid4()),
        user_id=user_id,
        action=action,
        resource=resource,
        detail=detail,
        ip_address=ip_address,
    )
    db.add(entry)
    await db.commit()
