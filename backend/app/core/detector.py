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

# ── Syslog / Auth pattern regexes ───────────────────────────────────────────
SSH_FAIL_PATTERN      = re.compile(r'Failed password for (invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)
SSH_ACCEPT_PATTERN    = re.compile(r'Accepted (password|publickey) for \S+ from (\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)
PRIV_ESC_PATTERN      = re.compile(r'(sudo.*command not allowed|authentication failure.*sudo|pam_tally2.*deny|pam_unix.*sudo.*failure)', re.IGNORECASE)
INVALID_USER_PATTERN  = re.compile(r'Invalid user \S+ from (\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)
ACCOUNT_LOCK_PATTERN  = re.compile(r'pam_tally.*tally\s+\d+.*deny|account.*locked|maximum authentication attempts exceeded', re.IGNORECASE)
UFW_BLOCK_PATTERN     = re.compile(r'\[UFW BLOCK\].*SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)', re.IGNORECASE)

# ── Thresholds ────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD  = 8        # failed auth in 60s window
DDOS_THRESHOLD         = 150      # requests in 10s window
PORT_SCAN_THRESHOLD    = 15       # unique ports in 30s window
EXFIL_BYTES_THRESHOLD  = 5_000_000  # 5MB response = suspicious
SSH_BRUTE_THRESHOLD    = 6        # SSH failed passwords per IP
INVALID_USER_THRESHOLD = 5        # invalid user attempts per IP


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

            # 1. Brute Force / Auth Failure (HTTP 401/403)
            threat = self._detect_brute_force(ip, ip_entries_sorted, session_id)
            if threat:
                threats.append(threat)

            # 2. SSH Brute Force (syslog Failed password messages)
            threat = self._detect_ssh_brute_force(ip, ip_entries_sorted, session_id)
            if threat:
                threats.append(threat)

            # 3. DDoS detection
            threat = self._detect_ddos(ip, ip_entries_sorted, session_id)
            if threat:
                threats.append(threat)

            # 4. Port scan (Zeek/Syslog UFW BLOCK patterns)
            threat = self._detect_port_scan(ip, ip_entries_sorted, session_id)
            if threat:
                threats.append(threat)

        # 5. Per-entry pattern matching (SQLi, XSS, traversal, syslog events)
        for entry in entries:
            path    = (entry.path or "")
            ua      = (entry.user_agent or "")
            raw     = (entry.raw_line or "")
            searchable = path + " " + ua

            if SQLI_PATTERNS.search(searchable):
                threats.append(self._make_pattern_threat(entry, AttackType.SQL_INJECTION, SeverityLevel.CRITICAL, "SQL_INJECTION", "SQLi pattern in request path/body", session_id))

            elif XSS_PATTERNS.search(searchable):
                threats.append(self._make_pattern_threat(entry, AttackType.XSS, SeverityLevel.HIGH, "XSS_ATTEMPT", "XSS pattern detected in request", session_id))

            elif TRAVERSAL_PATTERNS.search(searchable) or TRAVERSAL_PATTERNS.search(raw):
                threats.append(self._make_pattern_threat(entry, AttackType.DIRECTORY_TRAVERSAL, SeverityLevel.MEDIUM, "DIRECTORY_TRAVERSAL", "Path traversal pattern detected", session_id))

            # Privilege escalation (syslog)
            if PRIV_ESC_PATTERN.search(raw):
                threats.append(self._make_pattern_threat(entry, AttackType.PRIVILEGE_ESCALATION, SeverityLevel.CRITICAL, "PRIV_ESC_DETECTED", "Privilege escalation attempt via sudo/PAM", session_id))

            # Account lockout (syslog)
            elif ACCOUNT_LOCK_PATTERN.search(raw):
                threats.append(self._make_pattern_threat(entry, AttackType.BRUTE_FORCE, SeverityLevel.HIGH, "ACCOUNT_LOCKOUT", "Account lockout triggered by repeated failures", session_id))

            # UFW blocked port sweep — individual ports (low severity)
            ufw_m = UFW_BLOCK_PATTERN.search(raw)
            if ufw_m:
                threats.append(self._make_pattern_threat(entry, AttackType.PORT_SCAN, SeverityLevel.LOW, "UFW_BLOCK", f"UFW blocked connection to port {ufw_m.group(2)}", session_id))

            # Data exfiltration (large outbound bytes)
            if entry.bytes_sent and entry.bytes_sent > EXFIL_BYTES_THRESHOLD:
                threats.append(self._make_pattern_threat(entry, AttackType.DATA_EXFILTRATION, SeverityLevel.CRITICAL, "DATA_EXFIL", f"Suspiciously large response: {entry.bytes_sent:,} bytes", session_id))

        # Deduplicate (same IP + same type → keep highest severity)
        threats = self._deduplicate(threats)

        return DetectionResult(
            session_id=session_id,
            total_analyzed=len(entries),
            threats_found=len(threats),
            threats=threats,
        )

    def _detect_brute_force(self, ip: str, entries: List[LogEntry], session_id: str) -> ThreatEvent | None:
        """Detect HTTP brute force: ≥N failed auth (401/403) requests in 60s window."""
        WINDOW = 60
        failures = [e for e in entries if e.status_code and e.status_code in (401, 403)]
        if len(failures) < BRUTE_FORCE_THRESHOLD:
            return None
        for i, entry in enumerate(failures):
            window_entries = [e for e in failures[i:] if (e.timestamp - entry.timestamp).total_seconds() <= WINDOW]
            if len(window_entries) >= BRUTE_FORCE_THRESHOLD:
                severity = SeverityLevel.CRITICAL if len(window_entries) >= 20 else SeverityLevel.HIGH
                return ThreatEvent(
                    id=str(uuid.uuid4()), session_id=session_id,
                    timestamp=entry.timestamp, attack_type=AttackType.BRUTE_FORCE,
                    severity=severity, source_ip=ip, target_path=entry.path,
                    request_count=len(window_entries),
                    confidence=min(0.97, 0.7 + len(window_entries) * 0.01),
                    rule_name="HTTP_BRUTE_FORCE",
                    evidence=[f"{len(window_entries)} HTTP 401/403 responses from {ip} within {WINDOW}s"],
                    raw_entries=[e.raw_line for e in window_entries[:5]],
                )
        return None

    def _detect_ssh_brute_force(self, ip: str, entries: List[LogEntry], session_id: str) -> ThreatEvent | None:
        """Detect SSH brute force from syslog 'Failed password' messages."""
        ssh_fails = [e for e in entries if SSH_FAIL_PATTERN.search(e.raw_line or "")]
        if len(ssh_fails) < SSH_BRUTE_THRESHOLD:
            return None
        severity = SeverityLevel.CRITICAL if len(ssh_fails) >= 20 else SeverityLevel.HIGH
        first = ssh_fails[0]
        # Check for successful login — escalate severity
        success_logins = [e for e in entries if SSH_ACCEPT_PATTERN.search(e.raw_line or "")]
        if success_logins:
            severity = SeverityLevel.CRITICAL
        return ThreatEvent(
            id=str(uuid.uuid4()), session_id=session_id,
            timestamp=first.timestamp, attack_type=AttackType.BRUTE_FORCE,
            severity=severity, source_ip=ip,
            target_path="/ssh",
            request_count=len(ssh_fails),
            confidence=min(0.98, 0.75 + len(ssh_fails) * 0.01),
            rule_name="SSH_BRUTE_FORCE",
            evidence=[
                f"{len(ssh_fails)} SSH 'Failed password' attempts from {ip}",
                f"{len(success_logins)} successful logins detected" if success_logins else "No successful logins",
            ],
            raw_entries=[e.raw_line for e in ssh_fails[:5]],
        )

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
