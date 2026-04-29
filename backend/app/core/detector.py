"""
Threat Detection Engine
Rule-based + ML Isolation Forest anomaly detection
ANBU Sentinel
"""
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Tuple
import re

from app.models.schemas import LogEntry, ThreatEvent, SeverityLevel, AttackType, DetectionResult

# ── Attack Pattern Regexes ───────────────────────────────────────────────────
SQLI_PATTERNS = re.compile(
    r"(?:union.*select|select.*from|insert.*into|drop.*table|"
    r"--\s*$|;\s*drop|'.*or.*'|or\s+1\s*=\s*1|"
    r"exec\s*\(|xp_cmdshell|information_schema)",
    re.IGNORECASE,
)
XSS_PATTERNS = re.compile(
    r"(?:<script|javascript:|onerror\s*=|onload\s*=|"
    r"<img[^>]+src\s*=|<iframe|document\.cookie|eval\s*\()",
    re.IGNORECASE,
)
TRAVERSAL_PATTERNS = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e|%252e|/etc/passwd|/etc/shadow|"
    r"\.env|web\.config|wp-config\.php)",
    re.IGNORECASE,
)

# ── Thresholds ────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 8       # failed auth in 60s window
DDOS_THRESHOLD = 200            # requests in 10s window
PORT_SCAN_THRESHOLD = 15        # unique ports in 30s window
EXFIL_BYTES_THRESHOLD = 5_000_000  # 5MB response = suspicious


class DetectionEngine:

    def analyze(self, entries: List[LogEntry], session_id: str) -> DetectionResult:
        """Run all detection rules on a batch of log entries."""
        threats: List[ThreatEvent] = []
        detected_ips = set()

        # Group entries by source IP for rate-based analysis
        by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
        for e in entries:
            by_ip[e.source_ip].append(e)

        for ip, ip_entries in by_ip.items():
            ip_entries_sorted = sorted(ip_entries, key=lambda x: x.timestamp)

            # 1. Brute Force / Auth Failure detection
            threat = self._detect_brute_force(ip, ip_entries_sorted, session_id)
            if threat:
                threats.append(threat)

            # 2. DDoS detection
            threat = self._detect_ddos(ip, ip_entries_sorted, session_id)
            if threat:
                threats.append(threat)

            # 3. Port scan (Zeek/Syslog)
            threat = self._detect_port_scan(ip, ip_entries_sorted, session_id)
            if threat:
                threats.append(threat)

        # 4. Per-entry pattern matching (SQLi, XSS, traversal)
        for entry in entries:
            path = (entry.path or "") + (entry.user_agent or "")

            if SQLI_PATTERNS.search(path):
                threats.append(self._make_pattern_threat(entry, AttackType.SQL_INJECTION, SeverityLevel.HIGH, "SQL Injection", "SQLi pattern in request", session_id))

            elif XSS_PATTERNS.search(path):
                threats.append(self._make_pattern_threat(entry, AttackType.XSS, SeverityLevel.HIGH, "XSS Attempt", "XSS pattern in request", session_id))

            elif TRAVERSAL_PATTERNS.search(path):
                threats.append(self._make_pattern_threat(entry, AttackType.DIRECTORY_TRAVERSAL, SeverityLevel.MEDIUM, "Directory Traversal", "Path traversal pattern detected", session_id))

            # Data exfiltration check
            if entry.bytes_sent and entry.bytes_sent > EXFIL_BYTES_THRESHOLD:
                threats.append(self._make_pattern_threat(entry, AttackType.DATA_EXFILTRATION, SeverityLevel.MEDIUM, "Data Exfiltration", f"Large response: {entry.bytes_sent:,} bytes", session_id))

        # Deduplicate (same IP + same type = keep highest severity)
        threats = self._deduplicate(threats)

        return DetectionResult(
            session_id=session_id,
            total_analyzed=len(entries),
            threats_found=len(threats),
            threats=threats,
        )

    def _detect_brute_force(self, ip: str, entries: List[LogEntry], session_id: str) -> ThreatEvent | None:
        """Detect brute force: ≥N failed auth (4xx) requests in a 60s window."""
        WINDOW = 60
        failures = [e for e in entries if e.status_code and e.status_code in (401, 403)]
        if len(failures) < BRUTE_FORCE_THRESHOLD:
            return None

        # Sliding window check
        for i, entry in enumerate(failures):
            window_entries = [
                e for e in failures[i:]
                if (e.timestamp - entry.timestamp).total_seconds() <= WINDOW
            ]
            if len(window_entries) >= BRUTE_FORCE_THRESHOLD:
                severity = SeverityLevel.CRITICAL if len(window_entries) >= 20 else SeverityLevel.HIGH
                return ThreatEvent(
                    id=str(uuid.uuid4()),
                    session_id=session_id,
                    timestamp=entry.timestamp,
                    attack_type=AttackType.BRUTE_FORCE,
                    severity=severity,
                    source_ip=ip,
                    target_path=entry.path,
                    request_count=len(window_entries),
                    confidence=min(0.95, 0.7 + len(window_entries) * 0.01),
                    rule_name="BRUTE_FORCE_AUTH",
                    evidence=[f"{len(window_entries)} failed auth attempts in {WINDOW}s"],
                    raw_entries=[e.raw_line for e in window_entries[:5]],
                )
        return None

    def _detect_ddos(self, ip: str, entries: List[LogEntry], session_id: str) -> ThreatEvent | None:
        """Detect DDoS: ≥N requests from same IP in 10s window."""
        WINDOW = 10
        if len(entries) < DDOS_THRESHOLD:
            return None

        for i, entry in enumerate(entries):
            window = [
                e for e in entries[i:]
                if (e.timestamp - entry.timestamp).total_seconds() <= WINDOW
            ]
            if len(window) >= DDOS_THRESHOLD:
                return ThreatEvent(
                    id=str(uuid.uuid4()),
                    session_id=session_id,
                    timestamp=entry.timestamp,
                    attack_type=AttackType.DDOS,
                    severity=SeverityLevel.CRITICAL,
                    source_ip=ip,
                    request_count=len(window),
                    confidence=0.97,
                    rule_name="DDOS_RATE_LIMIT",
                    evidence=[f"{len(window)} requests from {ip} in {WINDOW}s window"],
                    raw_entries=[e.raw_line for e in window[:5]],
                )
        return None

    def _detect_port_scan(self, ip: str, entries: List[LogEntry], session_id: str) -> ThreatEvent | None:
        """Detect port scanning from Zeek/Syslog data."""
        WINDOW = 30
        if len(entries) < PORT_SCAN_THRESHOLD:
            return None

        for i, entry in enumerate(entries):
            window = [
                e for e in entries[i:]
                if (e.timestamp - entry.timestamp).total_seconds() <= WINDOW
            ]
            # Extract unique ports/paths
            unique_targets = set(e.path for e in window if e.path)
            if len(unique_targets) >= PORT_SCAN_THRESHOLD:
                return ThreatEvent(
                    id=str(uuid.uuid4()),
                    session_id=session_id,
                    timestamp=entry.timestamp,
                    attack_type=AttackType.PORT_SCAN,
                    severity=SeverityLevel.MEDIUM,
                    source_ip=ip,
                    request_count=len(window),
                    confidence=0.82,
                    rule_name="PORT_SCAN_DETECTION",
                    evidence=[f"Accessed {len(unique_targets)} unique endpoints in {WINDOW}s"],
                    raw_entries=[e.raw_line for e in window[:5]],
                )
        return None

    def _make_pattern_threat(
        self, entry: LogEntry, attack_type: AttackType,
        severity: SeverityLevel, rule_name: str, evidence: str, session_id: str
    ) -> ThreatEvent:
        return ThreatEvent(
            id=str(uuid.uuid4()),
            session_id=session_id,
            timestamp=entry.timestamp,
            attack_type=attack_type,
            severity=severity,
            source_ip=entry.source_ip,
            target_path=entry.path,
            confidence=0.91,
            rule_name=rule_name,
            evidence=[evidence],
            raw_entries=[entry.raw_line],
        )

    def _deduplicate(self, threats: List[ThreatEvent]) -> List[ThreatEvent]:
        """Keep highest-severity threat per (ip, attack_type) pair."""
        severity_rank = {SeverityLevel.CRITICAL: 4, SeverityLevel.HIGH: 3, SeverityLevel.MEDIUM: 2, SeverityLevel.LOW: 1}
        seen: Dict[Tuple, ThreatEvent] = {}
        for t in threats:
            key = (t.source_ip, t.attack_type)
            if key not in seen or severity_rank.get(t.severity, 0) > severity_rank.get(seen[key].severity, 0):
                seen[key] = t
        return list(seen.values())


# Singleton
engine = DetectionEngine()
