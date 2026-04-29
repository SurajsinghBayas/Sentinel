"""
AWS Bedrock Narration Module
Uses Claude 3.5 Sonnet via Bedrock for AI-powered threat narration
ANBU Sentinel
"""
import json
import os
import asyncio
from typing import AsyncGenerator, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

from app.models.schemas import ThreatEvent, SeverityLevel, AttackType

load_dotenv()

# ── Bedrock Client Setup ─────────────────────────────────────────────────────
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")


def _get_bedrock_client():
    """Create a Bedrock runtime client with proper configuration."""
    try:
        return boto3.client(
            service_name="bedrock-runtime",
            region_name=AWS_REGION,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            config=Config(
                read_timeout=60,
                connect_timeout=10,
                retries={"max_attempts": 2},
            ),
        )
    except Exception:
        return None


# ── Prompt Templates ──────────────────────────────────────────────────────────

THREAT_NARRATION_PROMPT = """You are SENTINEL, an elite cybersecurity AI analyst. Analyze this threat event and provide a professional incident narration.

## Threat Details
- **Attack Type**: {attack_type}
- **Severity**: {severity}
- **Source IP**: {source_ip}
- **Target**: {target_path}
- **Request Count**: {request_count}
- **Confidence**: {confidence:.0%}
- **Rule Triggered**: {rule_name}

## Evidence
{evidence}

## Sample Log Entries
{raw_entries}

Provide your analysis in this exact JSON structure:
{{
  "executive_summary": "2-3 sentence plain-English summary of what happened",
  "attack_narrative": "Detailed paragraph explaining the attack pattern, methodology, and potential intent",
  "timeline_description": "Brief description of how the attack unfolded over time",
  "risk_assessment": "Assessment of the potential damage if this attack succeeded",
  "mitigation_steps": [
    "Specific actionable step 1",
    "Specific actionable step 2",
    "Specific actionable step 3",
    "Specific actionable step 4"
  ],
  "ioc_indicators": ["indicator1", "indicator2"],
  "severity_justification": "Why this was classified as {severity}"
}}

Be precise, technical, and actionable. Use cybersecurity terminology appropriately."""

REPORT_SUMMARY_PROMPT = """You are SENTINEL, an elite cybersecurity AI. Generate an executive summary for this incident report.

## Incident Statistics
- Total threats detected: {total_threats}
- Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}
- Top attack types: {attack_types}
- Most active attacker IPs: {top_ips}
- Analysis period: {time_range}

Write a professional 3-paragraph executive summary suitable for C-suite executives:
1. Paragraph 1: What happened (overview of the threat landscape)
2. Paragraph 2: Severity and business impact assessment  
3. Paragraph 3: Recommended immediate actions

Keep it under 300 words. Be direct and actionable."""


# ── Fallback Narration ────────────────────────────────────────────────────────

FALLBACK_TEMPLATES = {
    AttackType.BRUTE_FORCE: {
        "executive_summary": "A brute force authentication attack was detected from {source_ip}. The attacker made {request_count} rapid login attempts targeting the authentication endpoint.",
        "mitigation_steps": [
            "Immediately block IP {source_ip} at the firewall level",
            "Implement account lockout after 5 failed attempts",
            "Enable multi-factor authentication on all accounts",
            "Review authentication logs for any successful logins from this IP",
        ]
    },
    AttackType.SQL_INJECTION: {
        "executive_summary": "SQL Injection attack detected from {source_ip} targeting {target_path}. The attacker is attempting to manipulate database queries.",
        "mitigation_steps": [
            "Block IP {source_ip} immediately",
            "Review and sanitize all database query inputs",
            "Implement a Web Application Firewall (WAF)",
            "Audit database access logs for any successful injections",
        ]
    },
    AttackType.DDOS: {
        "executive_summary": "DDoS flood attack detected from {source_ip} with {request_count} requests. Service availability is at risk.",
        "mitigation_steps": [
            "Activate rate limiting for IP {source_ip}",
            "Enable CDN-level DDoS protection (Cloudflare, AWS Shield)",
            "Scale infrastructure horizontally if load persists",
            "Block ASN/subnet if attack continues",
        ]
    },
    AttackType.XSS: {
        "executive_summary": "Cross-Site Scripting (XSS) attempt detected from {source_ip}. Attacker is trying to inject malicious client-side scripts.",
        "mitigation_steps": [
            "Block IP {source_ip} at WAF level",
            "Implement strict Content Security Policy (CSP) headers",
            "Enable output encoding on all user-supplied content",
            "Audit all user input handling in the application",
        ]
    },
}


def _generate_fallback_narration(threat: ThreatEvent) -> dict:
    """Generate template-based narration when Bedrock is unavailable."""
    template = FALLBACK_TEMPLATES.get(threat.attack_type, {
        "executive_summary": f"{threat.attack_type.value} attack detected from {threat.source_ip}.",
        "mitigation_steps": [
            f"Block IP {threat.source_ip} at firewall",
            "Review related log entries",
            "Escalate to security team",
            "Document incident for compliance",
        ]
    })

    summary = template["executive_summary"].format(
        source_ip=threat.source_ip,
        request_count=threat.request_count or "N/A",
        target_path=threat.target_path or "unknown endpoint",
    )
    steps = [s.format(source_ip=threat.source_ip) for s in template["mitigation_steps"]]

    return {
        "executive_summary": summary,
        "attack_narrative": f"This {threat.attack_type.value.replace('_', ' ').lower()} was detected by the ANBU Sentinel rule engine with {threat.confidence:.0%} confidence. The attack originated from {threat.source_ip} and triggered the {threat.rule_name} detection rule.",
        "timeline_description": f"Attack began at {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} and was detected in real-time.",
        "risk_assessment": f"Severity assessed as {threat.severity.value}. Immediate containment recommended.",
        "mitigation_steps": steps,
        "ioc_indicators": [threat.source_ip, threat.target_path or ""],
        "severity_justification": f"Classified as {threat.severity.value} based on rule engine confidence of {threat.confidence:.0%}",
    }


# ── Main Narration Functions ──────────────────────────────────────────────────

async def narrate_threat(threat: ThreatEvent) -> dict:
    """Generate AI narration for a threat using Bedrock Claude or fallback."""
    client = _get_bedrock_client()
    if not client:
        return _generate_fallback_narration(threat)

    prompt = THREAT_NARRATION_PROMPT.format(
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
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1500,
            "temperature": 0.3,
            "messages": [{"role": "user", "content": prompt}],
        })

        response = await asyncio.to_thread(
            client.invoke_model,
            modelId=BEDROCK_MODEL_ID,
            body=body,
            contentType="application/json",
            accept="application/json",
        )

        response_body = json.loads(response["body"].read())
        content = response_body["content"][0]["text"]

        # Extract JSON from response
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(content[start:end])
        return _generate_fallback_narration(threat)

    except (ClientError, NoCredentialsError, json.JSONDecodeError, Exception):
        return _generate_fallback_narration(threat)


async def stream_narration(threat: ThreatEvent) -> AsyncGenerator[str, None]:
    """Stream narration tokens from Bedrock for real-time display."""
    client = _get_bedrock_client()
    if not client:
        # Stream fallback narration word by word
        narration = _generate_fallback_narration(threat)
        text = narration["executive_summary"] + "\n\n" + narration["attack_narrative"]
        for word in text.split():
            yield word + " "
            await asyncio.sleep(0.03)
        return

    prompt = f"""Analyze this security threat and provide a detailed narrative explanation in plain text (no JSON):

Attack: {threat.attack_type.value} from {threat.source_ip}
Severity: {threat.severity.value}
Evidence: {'; '.join(threat.evidence)}

Provide: 1) What happened 2) Why it's dangerous 3) What to do immediately"""

    try:
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 800,
            "temperature": 0.4,
            "messages": [{"role": "user", "content": prompt}],
        })

        response = await asyncio.to_thread(
            client.invoke_model_with_response_stream,
            modelId=BEDROCK_MODEL_ID,
            body=body,
            contentType="application/json",
            accept="application/json",
        )

        stream = response.get("body")
        if stream:
            for event in stream:
                chunk = event.get("chunk")
                if chunk:
                    chunk_data = json.loads(chunk.get("bytes", b"{}"))
                    if chunk_data.get("type") == "content_block_delta":
                        delta = chunk_data.get("delta", {})
                        if delta.get("type") == "text_delta":
                            yield delta.get("text", "")
    except Exception:
        narration = _generate_fallback_narration(threat)
        for word in narration["executive_summary"].split():
            yield word + " "
            await asyncio.sleep(0.02)


async def generate_report_summary(stats: dict) -> str:
    """Generate an executive summary paragraph for the incident report."""
    client = _get_bedrock_client()
    if not client:
        return (
            f"ANBU Sentinel detected {stats.get('total_threats', 0)} security threats during the analysis period. "
            f"Critical severity threats: {stats.get('critical', 0)}, High: {stats.get('high', 0)}. "
            "Immediate remediation actions are recommended for all critical and high severity incidents. "
            "This report provides detailed threat intelligence and actionable mitigation steps for your security team."
        )

    prompt = REPORT_SUMMARY_PROMPT.format(**stats)
    try:
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 500,
            "messages": [{"role": "user", "content": prompt}],
        })
        response = await asyncio.to_thread(
            client.invoke_model,
            modelId=BEDROCK_MODEL_ID,
            body=body,
            contentType="application/json",
            accept="application/json",
        )
        response_body = json.loads(response["body"].read())
        return response_body["content"][0]["text"]
    except Exception:
        return "Security analysis complete. See threat details below for full incident information."
