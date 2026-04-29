"""
Detections, Dashboard, Reports APIs
ANBU Sentinel
"""
import time
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from app.core.security import get_current_user
from app.api.logs import DETECTIONS_STORE, SESSION_STORE
from app.models.schemas import SeverityLevel, DashboardStats, ReportRequest, ReportData
from app.core.narrator import generate_report_summary

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
):
    """Fetch all detected threats with optional filtering."""
    results = list(DETECTIONS_STORE)

    if severity:
        results = [t for t in results if t.severity.value == severity.upper()]
    if attack_type:
        results = [t for t in results if t.attack_type.value == attack_type.upper()]
    if session_id:
        results = [t for t in results if t.session_id == session_id]

    results = sorted(results, key=lambda t: t.timestamp, reverse=True)
    return {
        "total": len(results),
        "threats": [t.model_dump() for t in results[:limit]],
    }


@detections_router.get("/{threat_id}")
async def get_threat(threat_id: str, current_user: dict = Depends(get_current_user)):
    threat = next((t for t in DETECTIONS_STORE if t.id == threat_id), None)
    if not threat:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat.model_dump()


# ── Dashboard Router ─────────────────────────────────────────────────────────
dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@dashboard_router.get("/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Return aggregated stats for the dashboard overview."""
    threats = list(DETECTIONS_STORE)

    severity_counts = Counter(t.severity.value for t in threats)
    attack_type_counts = Counter(t.attack_type.value for t in threats)
    ip_counts = Counter(t.source_ip for t in threats)

    # Requests over time (last 24h buckets)
    now = datetime.now(timezone.utc)
    buckets: dict = {}
    for t in threats:
        ts = t.timestamp if t.timestamp.tzinfo else t.timestamp.replace(tzinfo=timezone.utc)
        hour_key = ts.strftime("%H:00")
        buckets[hour_key] = buckets.get(hour_key, 0) + (t.request_count or 1)

    requests_over_time = [
        {"time": k, "requests": v, "threats": 1}
        for k, v in sorted(buckets.items())
    ]

    return {
        "total_logs_analyzed": sum(s.get("parsed_count", 0) for s in SESSION_STORE.values()),
        "total_threats": len(threats),
        "critical_count": severity_counts.get("CRITICAL", 0),
        "high_count": severity_counts.get("HIGH", 0),
        "medium_count": severity_counts.get("MEDIUM", 0),
        "low_count": severity_counts.get("LOW", 0),
        "top_attacking_ips": [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(10)],
        "attack_type_breakdown": dict(attack_type_counts),
        "requests_over_time": requests_over_time,
        "recent_threats": [t.model_dump() for t in sorted(threats, key=lambda x: x.timestamp, reverse=True)[:5]],
        "active_sessions": len(SESSION_STORE),
        "uptime_seconds": time.time() - _START_TIME,
    }


# ── Reports Router ────────────────────────────────────────────────────────────
reports_router = APIRouter(prefix="/reports", tags=["Reports"])


@reports_router.post("/generate")
async def generate_report(
    body: ReportRequest,
    current_user: dict = Depends(get_current_user),
):
    """Generate report data (frontend renders as PDF via @react-pdf/renderer)."""
    threats = list(DETECTIONS_STORE)
    if body.session_id:
        threats = [t for t in threats if t.session_id == body.session_id]

    severity_counts = Counter(t.severity.value for t in threats)
    attack_type_counts = Counter(t.attack_type.value for t in threats)
    ip_counts = Counter(t.source_ip for t in threats)

    stats_dict = {
        "total_threats": len(threats),
        "critical": severity_counts.get("CRITICAL", 0),
        "high": severity_counts.get("HIGH", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
        "attack_types": ", ".join(f"{k}: {v}" for k, v in attack_type_counts.most_common(3)),
        "top_ips": ", ".join(f"{ip} ({count})" for ip, count in ip_counts.most_common(3)),
        "time_range": f"All sessions ({len(SESSION_STORE)} total)",
    }

    # Generate AI summary
    summary = await generate_report_summary(stats_dict)

    recommendations = [
        "Immediately block all CRITICAL severity source IPs at the firewall level",
        "Enable multi-factor authentication across all administrative accounts",
        "Deploy a Web Application Firewall (WAF) to filter SQLi and XSS patterns",
        "Implement rate limiting on authentication endpoints (max 5 attempts/minute)",
        "Review and patch all systems accessed by flagged source IPs",
        "Activate DDoS protection via CDN provider (Cloudflare/AWS Shield)",
        "Conduct a full audit of database access logs for potential data exposure",
        "Schedule a penetration test to assess current attack surface",
    ]

    return {
        "title": body.title,
        "classification": body.classification,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analyst_name": current_user.get("name"),
        "summary_narration": summary,
        "total_events": len(threats),
        "threats": [t.model_dump() for t in sorted(threats, key=lambda x: x.timestamp, reverse=True)],
        "stats": stats_dict,
        "recommendations": recommendations,
    }
