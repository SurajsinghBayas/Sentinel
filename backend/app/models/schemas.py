from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ── Enums ──────────────────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    NORMAL = "NORMAL"


class AttackType(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    DDOS = "DDOS"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    PORT_SCAN = "PORT_SCAN"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    ML_ANOMALY = "ML_ANOMALY"
    UNKNOWN = "UNKNOWN"


class LogFormat(str, Enum):
    APACHE = "apache"
    NGINX = "nginx"
    SYSLOG = "syslog"
    ZEEK_CSV = "zeek_csv"
    NGINX_ERROR = "nginx_error"
    AUTO = "auto"


# ── Auth Models ─────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str = "analyst"
    created_at: datetime
    avatar_initials: Optional[str] = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshRequest(BaseModel):
    refresh_token: str


# ── Log Models ──────────────────────────────────────────────────────────────

class LogEntry(BaseModel):
    id: str
    timestamp: datetime
    source_ip: str
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    bytes_sent: Optional[int] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    raw_line: str
    log_format: LogFormat
    session_id: str


class ParsedLogBatch(BaseModel):
    session_id: str
    total_lines: int
    parsed_count: int
    error_count: int
    entries: List[LogEntry]
    log_format: LogFormat


# ── Detection / Threat Models ───────────────────────────────────────────────

class ThreatEvent(BaseModel):
    id: str
    session_id: str
    timestamp: datetime
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    attack_type: AttackType
    severity: SeverityLevel
    source_ip: str
    target_path: Optional[str] = None
    request_count: Optional[int] = None
    confidence: float = Field(ge=0.0, le=1.0)
    rule_name: str
    evidence: List[str] = []
    raw_entries: List[str] = []
    ai_narration: Optional[str] = None
    mitigation_steps: Optional[List[str]] = None
    is_narrated: bool = False


class DetectionResult(BaseModel):
    session_id: str
    total_analyzed: int
    threats_found: int
    threats: List[ThreatEvent]
    anomaly_scores: Dict[str, float] = {}


# ── Dashboard Models ─────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_logs_analyzed: int
    total_threats: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    top_attacking_ips: List[Dict[str, Any]]
    attack_type_breakdown: Dict[str, int]
    requests_over_time: List[Dict[str, Any]]
    recent_threats: List[ThreatEvent]
    active_sessions: int
    uptime_seconds: float


# ── Report Models ─────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    session_id: Optional[str] = None  # None = all sessions
    title: str = "ANBU Sentinel Incident Report"
    classification: str = "CONFIDENTIAL"
    include_raw_logs: bool = False
    date_range_start: Optional[datetime] = None
    date_range_end: Optional[datetime] = None


class ReportData(BaseModel):
    title: str
    classification: str
    generated_at: datetime
    analyst_name: Optional[str] = None
    summary_narration: str
    total_events: int
    threats: List[ThreatEvent]
    stats: DashboardStats
    recommendations: List[str]


# ── WebSocket Message Models ─────────────────────────────────────────────────

class WSMessage(BaseModel):
    type: str  # "log_line" | "threat_detected" | "status" | "error"
    payload: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class NarrationChunk(BaseModel):
    threat_id: str
    chunk: str
    is_final: bool = False
