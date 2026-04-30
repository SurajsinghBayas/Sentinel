"""
AWS Bedrock Narration Module
Amazon Nova Micro — AI-powered threat narration & report intelligence
ANBU Sentinel
"""
import json
import os
import asyncio
from typing import AsyncGenerator

import boto3
from botocore.config import Config
from dotenv import load_dotenv

from app.models.schemas import ThreatEvent, AttackType

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
AWS_REGION      = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-micro-v1:0")


# ── Client helpers ────────────────────────────────────────────────────────────

def _get_bedrock_client():
    """Return a Bedrock runtime client, or None if credentials are missing."""
    key    = os.getenv("AWS_ACCESS_KEY_ID", "")
    secret = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    if not key or not secret or not key.startswith("AKIA"):
        return None
    try:
        return boto3.client(
            service_name="bedrock-runtime",
            region_name=AWS_REGION,
            aws_access_key_id=key,
            aws_secret_access_key=secret,
            config=Config(read_timeout=60, connect_timeout=10, retries={"max_attempts": 2}),
        )
    except Exception:
        return None


def _build_body(prompt: str, max_tokens: int = 1500, temperature: float = 0.5) -> str:
    """Build the correct request payload for the configured model family."""
    model = BEDROCK_MODEL_ID.lower()
    if "nova" in model or model.startswith("amazon"):
        # Amazon Nova format
        return json.dumps({
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "inferenceConfig": {"maxTokens": max_tokens, "temperature": temperature},
        })
    # Anthropic Claude format (fallback)
    return json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    })


def _extract_text(response_body: dict) -> str:
    """Extract the text content from a Bedrock response, regardless of model family."""
    # Amazon Nova / Converse format
    try:
        return response_body["output"]["message"]["content"][0]["text"]
    except (KeyError, IndexError):
        pass
    # Anthropic Claude format
    try:
        return response_body["content"][0]["text"]
    except (KeyError, IndexError):
        pass
    return ""


async def _invoke(client, prompt: str, max_tokens: int, temperature: float) -> str:
    """Invoke Bedrock and return the response text. Raises on failure."""
    body = _build_body(prompt, max_tokens=max_tokens, temperature=temperature)
    response = await asyncio.to_thread(
        client.invoke_model,
        modelId=BEDROCK_MODEL_ID,
        body=body,
        contentType="application/json",
        accept="application/json",
    )
    raw = response["body"].read()
    return _extract_text(json.loads(raw))


# ── Prompts ───────────────────────────────────────────────────────────────────

_THREAT_PROMPT = """\
You are SENTINEL, an elite cybersecurity AI analyst. Analyze this threat event and produce a professional incident narration.

## Threat Details
- Attack Type: {attack_type}
- Severity: {severity}
- Source IP: {source_ip}
- Target: {target_path}
- Request Count: {request_count}
- Detection Confidence: {confidence:.0%}
- Rule Triggered: {rule_name}

## Evidence
{evidence}

## Sample Log Entries
{raw_entries}

Return ONLY valid JSON matching this schema exactly:
{{
  "executive_summary": "2-3 sentence plain-English summary",
  "attack_narrative": "Detailed technical paragraph on attack pattern, methodology, and intent",
  "timeline_description": "Brief timeline of how the attack unfolded",
  "risk_assessment": "Potential damage if the attack succeeds",
  "mitigation_steps": ["step1", "step2", "step3", "step4"],
  "ioc_indicators": ["indicator1", "indicator2"],
  "severity_justification": "Why this is classified as {severity}"
}}

Be precise, technical, and actionable.\
"""

_SUMMARY_PROMPT = """\
You are SENTINEL, an elite cybersecurity AI analyst writing an executive summary for a security incident report.

## Incident Data
- Log file: {filename}
- Total log lines parsed: {total_lines:,}
- Total threats detected: {total_threats}
- Severity: Critical={critical}, High={high}, Medium={medium}, Low={low}
- Attack vectors: {attack_types}
- Top attacking IPs: {top_ips}
- Scope: {time_range}

Write exactly 3 paragraphs:
1. What happened in THIS session — use the actual numbers, attack types, and IPs above.
2. Business impact and risk level based on the severity distribution.
3. Prioritised immediate actions specific to the threats found — name the attack types.

Under 350 words. Reference specific data. Never use placeholder language.\
"""

_RECOMMENDATIONS_PROMPT = """\
You are a senior cybersecurity analyst. Generate exactly 8 specific, actionable security recommendations for this incident.
Each recommendation MUST reference the actual attack types and/or IPs observed — never use generic advice.

## Incident Data
- File: {filename}
- Total threats: {total_threats} (Critical: {critical}, High: {high}, Medium: {medium}, Low: {low})
- Attack types observed: {attack_types}
- Top attacking IPs: {top_ips}

Return ONLY a JSON array of 8 strings. Each string is one complete recommendation.
Example: ["Block IP 1.2.3.4 at the perimeter firewall — responsible for directory traversal on /admin", "Deploy WAF rule ID #942100 to block SQLi payloads in POST body"]
No markdown, no explanation — just the JSON array.\
"""


# ── Fallbacks (data-driven, used only when Bedrock is unavailable) ────────────

_ATTACK_RECS: dict[str, list[str]] = {
    "BRUTE_FORCE":         [
        "Block all source IPs with >10 failed auth attempts at the perimeter firewall",
        "Enforce account lockout policy after 5 consecutive failed logins",
        "Enable MFA on all privileged and user accounts immediately",
        "Audit authentication logs for any successful logins from flagged IPs",
        "Implement CAPTCHA on all public-facing login forms",
    ],
    "SQL_INJECTION":       [
        "Deploy WAF rules to block SQLi payloads in query strings and POST bodies",
        "Parameterise all database queries and eliminate string concatenation",
        "Audit database access logs for anomalous SELECT/INSERT/DROP patterns",
        "Apply principle of least-privilege to all database service accounts",
        "Enable SQL query logging on all production databases",
    ],
    "XSS":                 [
        "Enforce strict Content-Security-Policy (CSP) headers on all responses",
        "Sanitise and HTML-encode all user-supplied output before rendering",
        "Implement input validation on every API endpoint and form field",
        "Run SAST scan on codebase for reflected and stored XSS vulnerabilities",
        "Enable browser XSS protection headers (X-XSS-Protection: 1; mode=block)",
    ],
    "DDOS":                [
        "Rate-limit and geo-block attacking IP ranges at CDN edge immediately",
        "Enable AWS Shield Advanced / Cloudflare Under Attack Mode",
        "Scale horizontally behind a load balancer and set auto-scaling thresholds",
        "Blackhole route the top attacking IP subnet at the upstream provider",
        "Implement SYN cookie protection at the network layer",
    ],
    "DIRECTORY_TRAVERSAL": [
        "Block all requests containing '../', '..\\\\', or encoded traversal sequences at WAF",
        "Enforce strict file-path whitelisting in application file-serving code",
        "Remove or password-protect all sensitive directories under the web root",
        "Apply chroot jails or sandboxing to file-serving application processes",
        "Audit web server configuration to disable directory listing",
    ],
    "COMMAND_INJECTION":   [
        "Disable shell execution functions (exec, system, popen) where not required",
        "Sanitise all user input passed to OS commands using strict allowlists",
        "Run application processes under least-privilege OS service accounts",
        "Deploy RASP (Runtime Application Self-Protection) to block injection at runtime",
        "Enable audit logging on all system command executions",
    ],
    "PORT_SCAN":           [
        "Block the scanning IP subnet at the network perimeter firewall",
        "Enable IDS/IPS signatures for reconnaissance and port-sweep patterns",
        "Review all externally exposed ports and close unnecessary services",
        "Deploy honeypot services to detect and alert on future scanning activity",
        "Enable connection rate limiting per source IP at the edge",
    ],
    "DEFAULT":             [
        "Immediately review all flagged IP addresses for further malicious activity",
        "Enable enhanced logging on targeted endpoints and services",
        "Perform a post-incident review and threat hunting session within 24 hours",
        "Update firewall and WAF rules based on observed attack patterns",
        "Notify security team and escalate to incident response procedures",
    ],
}


def _fallback_narration(threat: ThreatEvent) -> dict:
    """Data-driven fallback narration when Bedrock is unavailable."""
    attack  = threat.attack_type.value.replace("_", " ").title()
    sev     = threat.severity.value
    ip      = threat.source_ip
    path    = threat.target_path or "unknown endpoint"
    count   = threat.request_count or "multiple"
    conf    = threat.confidence
    ts      = threat.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if threat.timestamp else "unknown time"

    # Pick recs by attack type key
    rec_key = threat.attack_type.value if threat.attack_type.value in _ATTACK_RECS else "DEFAULT"
    recs    = [r.replace("{source_ip}", ip) for r in _ATTACK_RECS[rec_key][:4]]

    return {
        "executive_summary": (
            f"A {attack} attack was detected from {ip} targeting {path}. "
            f"The incident generated {count} suspicious requests and was flagged by the "
            f"{threat.rule_name} detection rule with {conf:.0%} confidence."
        ),
        "attack_narrative": (
            f"The {attack} originated from {ip} and targeted {path}. "
            f"ANBU Sentinel's rule engine classified this as {sev} severity based on behavioural "
            f"indicators including {'; '.join(threat.evidence[:3]) or 'pattern anomalies'}. "
            f"The attacker's approach suggests {'targeted exploitation' if sev in ('CRITICAL','HIGH') else 'opportunistic scanning'}."
        ),
        "timeline_description": f"Attack initiated at {ts} and detected in real-time by the rule engine.",
        "risk_assessment": (
            f"Severity is {sev}. "
            f"{'Immediate containment required — active exploitation risk.' if sev in ('CRITICAL','HIGH') else 'Monitor and remediate within standard SLA.'}"
        ),
        "mitigation_steps": recs,
        "ioc_indicators": [ip, path],
        "severity_justification": (
            f"Classified as {sev} based on {conf:.0%} detection confidence and "
            f"{count} observed request{'s' if count != 1 else ''} matching {threat.rule_name}."
        ),
    }


def _fallback_summary(stats: dict) -> str:
    """Data-driven fallback executive summary when Bedrock is unavailable."""
    total    = stats.get("total_threats", 0)
    critical = stats.get("critical", 0)
    high     = stats.get("high", 0)
    medium   = stats.get("medium", 0)
    low      = stats.get("low", 0)
    filename = stats.get("filename", "uploaded log file")
    attacks  = stats.get("attack_types", "multiple attack vectors")
    top_ips  = stats.get("top_ips", "unknown sources")
    lines    = stats.get("total_lines", 0)
    urgent   = "Immediate containment is required." if critical > 0 else "Standard remediation procedures apply."
    return (
        f"Analysis of '{filename}' ({lines:,} log lines) identified {total} security threats. "
        f"Severity distribution: {critical} CRITICAL, {high} HIGH, {medium} MEDIUM, {low} LOW. "
        f"Primary attack vectors: {attacks}. Top threat sources: {top_ips}.\n\n"
        f"The {critical} CRITICAL-severity event(s) indicate active, targeted exploitation rather than opportunistic scanning. "
        f"{urgent} The {high} HIGH-severity events suggest the attacker has completed reconnaissance and is escalating activity.\n\n"
        f"Prioritised response: isolate CRITICAL source IPs at the perimeter, enable enhanced endpoint logging, "
        f"review authentication records for successful compromise indicators, and engage the incident response team. "
        f"All {total} detected threats are catalogued in this report with full evidence chains."
    )


def _fallback_recommendations(stats: dict) -> list[str]:
    """Data-driven fallback recommendations based on observed attack types."""
    attacks  = stats.get("attack_types", "").upper()
    top_ips  = stats.get("top_ips", "unknown")
    critical = stats.get("critical", 0)

    recs: list[str] = []
    for key, items in _ATTACK_RECS.items():
        if key != "DEFAULT" and key in attacks:
            recs.extend(items)

    if not recs:
        recs = list(_ATTACK_RECS["DEFAULT"])

    if critical > 0:
        first_ip = top_ips.split(",")[0].strip()
        recs.insert(0, f"URGENT: Block all CRITICAL-severity source IPs at the perimeter firewall — starting with {first_ip}")

    # Deduplicate and cap
    seen: list[str] = []
    for r in recs:
        if r not in seen:
            seen.append(r)
    return seen[:8]


# ── Public API ────────────────────────────────────────────────────────────────

async def narrate_threat(threat: ThreatEvent) -> dict:
    """Generate AI narration for a single threat event via Nova, with fallback."""
    client = _get_bedrock_client()
    if not client:
        return _fallback_narration(threat)

    prompt = _THREAT_PROMPT.format(
        attack_type=threat.attack_type.value,
        severity=threat.severity.value,
        source_ip=threat.source_ip,
        target_path=threat.target_path or "N/A",
        request_count=threat.request_count or "N/A",
        confidence=threat.confidence,
        rule_name=threat.rule_name,
        evidence="\n".join(f"- {e}" for e in threat.evidence),
        raw_entries="\n".join(threat.raw_entries[:3]),
    )

    try:
        text = await _invoke(client, prompt, max_tokens=1200, temperature=0.4)
        start = text.find("{")
        end   = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
    except Exception as e:
        print(f"[Bedrock narrate_threat] {type(e).__name__}: {e}")

    return _fallback_narration(threat)


async def stream_narration(threat: ThreatEvent) -> AsyncGenerator[str, None]:
    """Stream narration word-by-word via Nova, with fallback."""
    client = _get_bedrock_client()

    if not client:
        fb = _fallback_narration(threat)
        for word in (fb["executive_summary"] + "\n\n" + fb["attack_narrative"]).split():
            yield word + " "
            await asyncio.sleep(0.03)
        return

    prompt = (
        f"Analyze this security threat and write a detailed narrative (plain text, no JSON):\n\n"
        f"Attack: {threat.attack_type.value} from {threat.source_ip}\n"
        f"Severity: {threat.severity.value}\n"
        f"Target: {threat.target_path or 'N/A'}\n"
        f"Evidence: {'; '.join(threat.evidence)}\n\n"
        f"Cover three sections:\n"
        f"1. What happened (technical detail)\n"
        f"2. Why it is dangerous (business impact)\n"
        f"3. What to do immediately (specific actions)"
    )

    try:
        text = await _invoke(client, prompt, max_tokens=700, temperature=0.5)
        for word in text.split():
            yield word + " "
            await asyncio.sleep(0.01)
        return
    except Exception as e:
        print(f"[Bedrock stream_narration] {type(e).__name__}: {e}")

    fb = _fallback_narration(threat)
    for word in fb["executive_summary"].split():
        yield word + " "
        await asyncio.sleep(0.02)


async def generate_report_summary(stats: dict) -> str:
    """Generate an AI executive summary for the incident report via Nova."""
    client = _get_bedrock_client()
    if not client:
        return _fallback_summary(stats)

    # Ensure all keys exist with safe defaults
    safe = {
        "filename":      stats.get("filename", "uploaded log"),
        "total_lines":   stats.get("total_lines", 0),
        "total_threats": stats.get("total_threats", 0),
        "critical":      stats.get("critical", 0),
        "high":          stats.get("high", 0),
        "medium":        stats.get("medium", 0),
        "low":           stats.get("low", 0),
        "attack_types":  stats.get("attack_types", "various"),
        "top_ips":       stats.get("top_ips", "unknown"),
        "time_range":    stats.get("time_range", "this session"),
    }

    prompt = _SUMMARY_PROMPT.format(**safe)

    try:
        return await _invoke(client, prompt, max_tokens=600, temperature=0.7)
    except Exception as e:
        print(f"[Bedrock report_summary] {type(e).__name__}: {e}")
        return _fallback_summary(stats)


async def generate_recommendations(stats: dict) -> list[str]:
    """Generate 8 AI-specific recommendations via Nova based on the actual threats."""
    client = _get_bedrock_client()
    if not client:
        return _fallback_recommendations(stats)

    safe = {
        "filename":      stats.get("filename", "uploaded log"),
        "total_threats": stats.get("total_threats", 0),
        "critical":      stats.get("critical", 0),
        "high":          stats.get("high", 0),
        "medium":        stats.get("medium", 0),
        "low":           stats.get("low", 0),
        "attack_types":  stats.get("attack_types", "various"),
        "top_ips":       stats.get("top_ips", "unknown"),
    }

    prompt = _RECOMMENDATIONS_PROMPT.format(**safe)

    try:
        text  = await _invoke(client, prompt, max_tokens=600, temperature=0.6)
        start = text.find("[")
        end   = text.rfind("]") + 1
        if start >= 0 and end > start:
            recs = json.loads(text[start:end])
            if isinstance(recs, list) and len(recs) > 0:
                return [str(r) for r in recs[:8]]
    except Exception as e:
        print(f"[Bedrock recommendations] {type(e).__name__}: {e}")

    return _fallback_recommendations(stats)
