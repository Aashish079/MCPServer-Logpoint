"""Mock external integrations (threat intel, ticketing, email) for local testing.

These stand in for VirusTotal, AbuseIPDB, MISP, Jira, and SMTP until real
credentials are wired up. Swap the bodies for real HTTP calls without
changing the MCP tool signatures in mcp_server.py.
"""
import uuid
from typing import Any, Dict, List

JIRA_TICKETS: Dict[str, Dict[str, Any]] = {}
SENT_EMAILS: List[Dict[str, Any]] = []

KNOWN_BAD_IOCS = {"1.2.3.4", "evil.example.com", "44d88612fea8a8f36de82e1278abb02f"}


def lookup_virustotal(indicator: str) -> Dict[str, Any]:
    malicious = indicator in KNOWN_BAD_IOCS
    return {
        "indicator": indicator,
        "source": "virustotal",
        "malicious_votes": 42 if malicious else 0,
        "harmless_votes": 3 if malicious else 70,
        "reputation": "malicious" if malicious else "clean",
    }


def lookup_abuseipdb(ip: str) -> Dict[str, Any]:
    malicious = ip in KNOWN_BAD_IOCS
    return {
        "ip": ip,
        "source": "abuseipdb",
        "abuse_confidence_score": 95 if malicious else 0,
        "total_reports": 128 if malicious else 0,
        "reputation": "malicious" if malicious else "clean",
    }


def lookup_misp(indicator: str) -> Dict[str, Any]:
    malicious = indicator in KNOWN_BAD_IOCS
    return {
        "indicator": indicator,
        "source": "misp",
        "matched_events": ["APT29 phishing campaign"] if malicious else [],
        "reputation": "malicious" if malicious else "unknown",
    }


def create_jira_ticket(summary: str, description: str, severity: str, incident_id: str) -> Dict[str, Any]:
    key = f"SOC-{len(JIRA_TICKETS) + 1000}"
    ticket = {
        "key": key,
        "id": str(uuid.uuid4()),
        "summary": summary,
        "description": description,
        "severity": severity,
        "incident_id": incident_id,
        "url": f"https://jira.example.com/browse/{key}",
        "status": "Open",
    }
    JIRA_TICKETS[key] = ticket
    return ticket


def send_email(to: List[str], subject: str, body: str) -> Dict[str, Any]:
    message = {"to": to, "subject": subject, "body": body}
    SENT_EMAILS.append(message)
    return {"success": True, "message": f"Email sent to {', '.join(to)}"}
