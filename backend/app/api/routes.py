"""
Detections, Dashboard, Reports APIs
Now backed by Neon PostgreSQL
ANBU Sentinel
"""
import asyncio
import time
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.api.logs import DETECTIONS_STORE, SESSION_STORE
from app.models.schemas import SeverityLevel, DashboardStats, ReportRequest, ReportData
from app.core.narrator import generate_report_summary, generate_recommendations
from app.db.database import get_db
from app.db import crud
from app.db.models import LogSessionDB, ThreatEventDB

# ── Detections Router ────────────────────────────────────────────────────────
detections_router = APIRouter(prefix="/detections", tags=["Threat Detections"])

_START_TIME = time.time()


@detections_router.get("")
async def get_detections(
    severity: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch all detected threats from DB with optional filtering."""
    rows = await crud.get_threats(db, severity=severity, attack_type=attack_type,
                                  session_id=session_id, limit=limit)

    # Merge with in-memory (live session threats not yet committed)
    mem = list(DETECTIONS_STORE)
    db_ids = {r.id for r in rows}

    # Convert DB rows to dict
    result = []
    for r in rows:
        result.append({
            "id": r.id,
            "session_id": r.session_id,
            "timestamp": r.timestamp.isoformat(),
            "attack_type": r.attack_type,
            "severity": r.severity,
            "source_ip": r.source_ip,
            "target_path": r.target_path,
            "request_count": r.request_count,
            "confidence": r.confidence,
            "rule_name": r.rule_name,
            "evidence": r.evidence,
            "raw_entries": r.raw_entries,
            "ai_narration": r.ai_narration,
            "mitigation_steps": r.mitigation_steps,
            "is_narrated": r.is_narrated,
            "is_resolved": r.is_resolved,
        })

    # Append in-memory threats not yet in DB (e.g. from live stream)
    for t in mem:
        if t.id not in db_ids:
            if severity and t.severity.value != severity.upper():
                continue
            if attack_type and t.attack_type.value != attack_type.upper():
                continue
            result.append(t.model_dump())

    return {"total": len(result), "threats": result[:limit]}


@detections_router.get("/{threat_id}")
async def get_threat(
    threat_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    row = await crud.get_threat_by_id(db, threat_id)
    if row:
        return {
            "id": row.id, "session_id": row.session_id,
            "attack_type": row.attack_type, "severity": row.severity,
            "source_ip": row.source_ip, "confidence": row.confidence,
            "rule_name": row.rule_name, "evidence": row.evidence,
            "is_narrated": row.is_narrated, "is_resolved": row.is_resolved,
        }
    # fallback in-memory
    mem = next((t for t in DETECTIONS_STORE if t.id == threat_id), None)
    if mem:
        return mem.model_dump()
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Threat not found")


# ── Dashboard Router ─────────────────────────────────────────────────────────
dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@dashboard_router.get("/stats")
async def get_dashboard_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return aggregated stats — fully DB-backed so charts survive restarts."""

    # ── Pull from DB ─────────────────────────────────────────────────────
    db_counts    = await crud.get_dashboard_counts(db)
    threats      = await crud.get_all_threats_for_dashboard(db, limit=1000)
    logs_analyzed = await crud.get_total_logs_analyzed(db)
    session_count = await crud.get_session_count(db)

    # ── Merge with any in-memory threats not yet written to DB ───────────
    db_ids = {t.id for t in threats}
    for t in DETECTIONS_STORE:
        if t.id not in db_ids:
            # Convert pydantic model to a fake DB-like object for uniform access
            threats.append(t)  # ThreatEvent has same fields

    # ── Build chart data ─────────────────────────────────────────────────
    severity_counts    = Counter()
    attack_type_counts = Counter()
    ip_counts          = Counter()
    buckets: dict      = {}

    for t in threats:
        # Handle both ThreatEventDB (SQLAlchemy) and ThreatEvent (pydantic)
        sev = t.severity.value if hasattr(t.severity, 'value') else t.severity
        atk = t.attack_type.value if hasattr(t.attack_type, 'value') else t.attack_type
        ip  = t.source_ip or "unknown"

        severity_counts[sev]    += 1
        attack_type_counts[atk] += 1
        ip_counts[ip]           += 1

        ts = t.timestamp
        if ts and hasattr(ts, 'strftime'):
            if ts.tzinfo is None:
                from datetime import timezone as tz
                ts = ts.replace(tzinfo=tz.utc)
            hour_key = ts.strftime("%H:00")
            buckets[hour_key] = buckets.get(hour_key, 0) + (t.request_count or 1)

    requests_over_time = [
        {"time": k, "requests": v, "threats": 1}
        for k, v in sorted(buckets.items())
    ]

    # Recent threats (newest first, up to 5)
    recent_raw = sorted(threats, key=lambda x: x.timestamp or "", reverse=True)[:5]
    recent_threats = []
    for t in recent_raw:
        if hasattr(t, 'model_dump'):        # pydantic ThreatEvent
            recent_threats.append(t.model_dump())
        else:                                # SQLAlchemy row
            recent_threats.append({
                "id": t.id,
                "attack_type": t.attack_type.value if hasattr(t.attack_type, 'value') else t.attack_type,
                "severity":    t.severity.value    if hasattr(t.severity, 'value')    else t.severity,
                "source_ip":   t.source_ip,
                "confidence":  t.confidence,
                "timestamp":   t.timestamp.isoformat() if t.timestamp else None,
                "rule_name":   t.rule_name,
            })

    return {
        "total_logs_analyzed": logs_analyzed,
        "total_threats":       db_counts["total"] or len(threats),
        "critical_count":      db_counts.get("critical", severity_counts.get("CRITICAL", 0)),
        "high_count":          db_counts.get("high",     severity_counts.get("HIGH", 0)),
        "medium_count":        db_counts.get("medium",   severity_counts.get("MEDIUM", 0)),
        "low_count":           db_counts.get("low",      severity_counts.get("LOW", 0)),
        "top_attacking_ips":   [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(10)],
        "attack_type_breakdown": dict(attack_type_counts),
        "requests_over_time":  requests_over_time,
        "recent_threats":      recent_threats,
        "active_sessions":     session_count,
        "uptime_seconds":      time.time() - _START_TIME,
    }


# ── Reports Router ────────────────────────────────────────────────────────────
reports_router = APIRouter(prefix="/reports", tags=["Reports"])


@reports_router.post("/generate")
async def generate_report(
    body: ReportRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate and persist a report to DB."""
    # ── Read threats from DB (persistent across restarts) ──────────────────
    db_threats = await crud.get_threats(
        db,
        session_id=body.session_id,   # None = all sessions
        limit=500,
    )

    # Convert DB rows → plain dicts for the report
    threats_data = []
    for r in db_threats:
        threats_data.append({
            "id": r.id,
            "session_id": r.session_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "attack_type": r.attack_type,
            "severity": r.severity,
            "source_ip": r.source_ip,
            "target_path": r.target_path,
            "request_count": r.request_count,
            "confidence": r.confidence,
            "rule_name": r.rule_name,
            "evidence": r.evidence or [],
            "raw_entries": r.raw_entries or [],
            "ai_narration": r.ai_narration,
            "mitigation_steps": r.mitigation_steps,
            "is_narrated": r.is_narrated,
            "is_resolved": r.is_resolved,
        })

    # Also merge any in-memory threats from live stream (not yet in DB)
    db_ids = {r.id for r in db_threats}
    for t in DETECTIONS_STORE:
        if t.id not in db_ids:
            if body.session_id and t.session_id != body.session_id:
                continue
            threats_data.append(t.model_dump())

    severity_counts  = Counter(t["severity"] for t in threats_data)
    attack_counts    = Counter(t["attack_type"] for t in threats_data)
    ip_counts        = Counter(t["source_ip"] for t in threats_data)

    # Find session info
    session_info = SESSION_STORE.get(body.session_id, {}) if body.session_id else {}
    # Also try DB if not in memory
    if not session_info and body.session_id:
        rows = await crud.get_sessions_by_user(db, current_user["user_id"])
        match = next((r for r in rows if r.id == body.session_id), None)
        if match:
            session_info = {
                "filename": match.filename,
                "total_lines": match.total_lines,
            }

    filename    = session_info.get("filename", "All sessions")
    total_lines = session_info.get("total_lines", 0)

    stats_dict = {
        "total_threats": len(threats_data),
        "critical":  severity_counts.get("CRITICAL", 0),
        "high":      severity_counts.get("HIGH", 0),
        "medium":    severity_counts.get("MEDIUM", 0),
        "low":       severity_counts.get("LOW", 0),
        "attack_types": ", ".join(f"{k}: {v}" for k, v in attack_counts.most_common(5)) or "None detected",
        "top_ips":   ", ".join(f"{ip} ({c} threats)" for ip, c in ip_counts.most_common(5)) or "None",
        "time_range": f"Session: {filename}" if body.session_id else f"All sessions ({len(SESSION_STORE)} total)",
        "filename":   filename,
        "total_lines": total_lines,
    }

    # Run summary and recommendations in parallel via Nova
    summary, recommendations = await asyncio.gather(
        generate_report_summary(stats_dict),
        generate_recommendations(stats_dict),
    )

    # Persist report
    report_row = await crud.save_report(
        db,
        analyst_id=current_user["user_id"],
        title=body.title,
        classification=body.classification,
        session_id=body.session_id,
        summary_narration=summary,
        total_events=len(threats_data),
        stats=stats_dict,
        recommendations=recommendations,
        severity_counts=dict(severity_counts),
    )

    await crud.log_action(db, action="generate_report",
                          user_id=current_user["user_id"], resource=report_row.id)

    return {
        "report_id": report_row.id,
        "title": body.title,
        "classification": body.classification,
        "generated_at": report_row.generated_at.isoformat(),
        "analyst_name": current_user.get("name"),
        "summary_narration": summary,
        "total_events": len(threats_data),
        "threats": sorted(threats_data, key=lambda x: x.get("timestamp") or "", reverse=True),
        "stats": stats_dict,
        "recommendations": recommendations,
    }



@reports_router.get("/history")
async def get_report_history(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch all previously generated reports for the current user."""
    rows = await crud.get_reports_by_user(db, current_user["user_id"])
    return [
        {
            "id": r.id,
            "title": r.title,
            "classification": r.classification,
            "generated_at": r.generated_at.isoformat(),
            "total_events": r.total_events,
            "critical_count": r.critical_count,
            "high_count": r.high_count,
        }
        for r in rows
    ]
