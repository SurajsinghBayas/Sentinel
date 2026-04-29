"""
Multi-Format Log Parser
Supports: Apache/Nginx Combined, Syslog RFC 3164, Zeek CSV, Nginx Error
ANBU Sentinel
"""
import re
import csv
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from io import StringIO

from app.models.schemas import LogEntry, LogFormat, ParsedLogBatch


# ── Apache / Nginx Combined Log Format ──────────────────────────────────────
# 192.168.1.1 - - [29/Apr/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
APACHE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'           # IP
    r'\S+\s+\S+\s+'                                   # ident, auth
    r'\[(?P<time>[^\]]+)\]\s+'                        # timestamp
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+\S+"\s+' # method, path, protocol
    r'(?P<status>\d{3})\s+'                           # status code
    r'(?P<bytes>\d+|-)\s*'                            # bytes
    r'(?:"(?P<referrer>[^"]*)")?\s*'                  # referrer (optional)
    r'(?:"(?P<ua>[^"]*)")?'                           # user agent (optional)
)
APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


# ── Syslog RFC 3164 ──────────────────────────────────────────────────────────
# Apr 29 10:00:01 hostname sshd[1234]: Failed password for root from 192.168.1.105 port 22
SYSLOG_PATTERN = re.compile(
    r'(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>\S+):\s+(?P<msg>.+)'
)
SYSLOG_IP_PATTERN = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


# ── Nginx Error Log ──────────────────────────────────────────────────────────
# 2024/04/29 10:00:01 [error] 1234#0: *1 connect() failed (111: Connection refused)
NGINX_ERROR_PATTERN = re.compile(
    r'(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})\s+'
    r'(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+\S+:\s+\*?\d*\s*(?P<msg>.+)'
)


def _detect_format(content: str) -> LogFormat:
    """Auto-detect log format from the first non-empty line."""
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if APACHE_PATTERN.match(line):
            return LogFormat.APACHE
        if SYSLOG_PATTERN.match(line):
            return LogFormat.SYSLOG
        if NGINX_ERROR_PATTERN.match(line):
            return LogFormat.NGINX_ERROR
        if ',' in line and any(k in line.lower() for k in ['ts', 'uid', 'id.orig_h', 'proto']):
            return LogFormat.ZEEK_CSV
    return LogFormat.APACHE  # default fallback


def _parse_apache_line(line: str, session_id: str) -> Optional[LogEntry]:
    m = APACHE_PATTERN.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), APACHE_TIME_FMT)
    except ValueError:
        ts = datetime.now(timezone.utc)

    bytes_val = m.group("bytes")
    return LogEntry(
        id=str(uuid.uuid4()),
        timestamp=ts,
        source_ip=m.group("ip"),
        method=m.group("method"),
        path=m.group("path"),
        status_code=int(m.group("status")),
        bytes_sent=int(bytes_val) if bytes_val and bytes_val != '-' else None,
        user_agent=m.group("ua") or None,
        referrer=m.group("referrer") or None,
        raw_line=line.strip(),
        log_format=LogFormat.APACHE,
        session_id=session_id,
    )


def _parse_syslog_line(line: str, session_id: str) -> Optional[LogEntry]:
    m = SYSLOG_PATTERN.match(line.strip())
    if not m:
        return None

    month_map = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
                 "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
    try:
        month = month_map.get(m.group("month"), 1)
        day = int(m.group("day"))
        h, mi, s = map(int, m.group("time").split(":"))
        ts = datetime(datetime.now().year, month, day, h, mi, s, tzinfo=timezone.utc)
    except Exception:
        ts = datetime.now(timezone.utc)

    msg = m.group("msg")
    ip_match = SYSLOG_IP_PATTERN.search(msg)
    source_ip = ip_match.group(1) if ip_match else m.group("host")

    return LogEntry(
        id=str(uuid.uuid4()),
        timestamp=ts,
        source_ip=source_ip,
        method=None,
        path=msg[:200],
        status_code=None,
        raw_line=line.strip(),
        log_format=LogFormat.SYSLOG,
        session_id=session_id,
    )


def _parse_nginx_error_line(line: str, session_id: str) -> Optional[LogEntry]:
    m = NGINX_ERROR_PATTERN.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime(
            int(m.group("year")), int(m.group("month")), int(m.group("day")),
            int(m.group("hour")), int(m.group("min")), int(m.group("sec")),
            tzinfo=timezone.utc
        )
    except Exception:
        ts = datetime.now(timezone.utc)

    msg = m.group("msg")
    ip_match = SYSLOG_IP_PATTERN.search(msg)
    return LogEntry(
        id=str(uuid.uuid4()),
        timestamp=ts,
        source_ip=ip_match.group(1) if ip_match else "0.0.0.0",
        path=msg[:200],
        raw_line=line.strip(),
        log_format=LogFormat.NGINX_ERROR,
        session_id=session_id,
    )


def _parse_zeek_csv(content: str, session_id: str) -> List[LogEntry]:
    """Parse Zeek tab-separated or comma-separated connection log."""
    entries = []
    lines = [l for l in content.splitlines() if l and not l.startswith('#')]
    if not lines:
        return entries

    # Detect delimiter
    delimiter = '\t' if '\t' in lines[0] else ','
    reader = csv.DictReader(StringIO('\n'.join(lines)), delimiter=delimiter)

    for row in reader:
        try:
            ts_val = row.get('ts') or row.get('timestamp', '')
            try:
                ts = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
            except (ValueError, TypeError):
                ts = datetime.now(timezone.utc)

            source_ip = row.get('id.orig_h') or row.get('src_ip') or row.get('orig_h', '0.0.0.0')

            entries.append(LogEntry(
                id=str(uuid.uuid4()),
                timestamp=ts,
                source_ip=source_ip,
                method=row.get('proto') or row.get('service'),
                path=f"{row.get('id.resp_h', '')}:{row.get('id.resp_p', '')}",
                bytes_sent=int(float(row.get('resp_bytes', 0) or 0)),
                raw_line=str(row),
                log_format=LogFormat.ZEEK_CSV,
                session_id=session_id,
            ))
        except Exception:
            continue
    return entries


def parse_log_content(content: str, fmt: LogFormat = LogFormat.AUTO, session_id: str = "") -> ParsedLogBatch:
    """Parse raw log content into structured LogEntry objects."""
    if not session_id:
        session_id = str(uuid.uuid4())

    if fmt == LogFormat.AUTO:
        fmt = _detect_format(content)

    entries: List[LogEntry] = []
    errors = 0

    if fmt == LogFormat.ZEEK_CSV:
        entries = _parse_zeek_csv(content, session_id)
        total = len(content.splitlines())
    else:
        lines = content.splitlines()
        total = len(lines)
        for line in lines:
            if not line.strip():
                continue
            try:
                if fmt in (LogFormat.APACHE, LogFormat.NGINX):
                    entry = _parse_apache_line(line, session_id)
                elif fmt == LogFormat.SYSLOG:
                    entry = _parse_syslog_line(line, session_id)
                elif fmt == LogFormat.NGINX_ERROR:
                    entry = _parse_nginx_error_line(line, session_id)
                else:
                    entry = _parse_apache_line(line, session_id)

                if entry:
                    entries.append(entry)
                else:
                    errors += 1
            except Exception:
                errors += 1

    return ParsedLogBatch(
        session_id=session_id,
        total_lines=total,
        parsed_count=len(entries),
        error_count=errors,
        entries=entries,
        log_format=fmt,
    )
