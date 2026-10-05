import json

import httpx
import pytest

from logpoint_mcp.config import AbuseIPDBSettings, JiraSettings, MISPSettings, SMTPSettings, VirusTotalSettings
from logpoint_mcp.errors import IntegrationError
from logpoint_mcp.integrations import AbuseIPDBClient, EmailSender, JiraClient, MISPClient, VirusTotalClient
from logpoint_mcp.integrations.indicators import classify, refang
from logpoint_mcp.integrations.mitre import parse_bundle, search


class Recorder:
    def __init__(self, response: httpx.Response) -> None:
        self.response = response
        self.requests: list[httpx.Request] = []

    def client(self, base_url: str, **kwargs) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=base_url, transport=httpx.MockTransport(self), **kwargs)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response


@pytest.mark.parametrize(
    ("indicator", "kind"),
    [
        ("8.8.8.8", "ip"),
        ("2001:4860:4860::8888", "ip"),
        ("evil[.]example[.]com", "domain"),
        ("hxxps://evil.example.com/x", "url"),
        ("44d88612fea8a8f36de82e1278abb02f", "md5"),
        ("a" * 64, "sha256"),
    ],
)
def test_classify(indicator, kind):
    assert classify(indicator) == kind


def test_classify_rejects_garbage():
    with pytest.raises(ValueError):
        classify("not an indicator")


def test_refang():
    assert refang("hxxp://a[.]b[.]com") == "http://a.b.com"


async def test_virustotal_never_sends_private_ips():
    recorder = Recorder(httpx.Response(200, json={}))
    client = VirusTotalClient(VirusTotalSettings(api_key="k"), recorder.client("https://vt.test"))
    result = await client.lookup("10.1.2.3")
    assert result["skipped"] is True and recorder.requests == []


async def test_virustotal_domain_lookup():
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 4, "suspicious": 1, "harmless": 60},
                                    "reputation": -12, "registrar": "Reg"}}}
    recorder = Recorder(httpx.Response(200, json=body))
    client = VirusTotalClient(VirusTotalSettings(api_key="k"), recorder.client("https://vt.test"))
    result = await client.lookup("evil[.]example.com")
    assert recorder.requests[0].url.path == "/domains/evil.example.com"
    assert result["summary"] == "4 of 65 engines flag it as malicious, 1 as suspicious."
    assert result["registrar"] == "Reg"


async def test_virustotal_unknown_indicator():
    recorder = Recorder(httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
    client = VirusTotalClient(VirusTotalSettings(api_key="k"), recorder.client("https://vt.test"))
    assert (await client.lookup("a" * 64))["found"] is False


async def test_abuseipdb_check():
    body = {"data": {"abuseConfidenceScore": 97, "totalReports": 120, "countryCode": "XX"}}
    recorder = Recorder(httpx.Response(200, json=body))
    client = AbuseIPDBClient(AbuseIPDBSettings(api_key="k"), recorder.client("https://abuse.test"))
    result = await client.lookup("8.8.4.9")
    assert recorder.requests[0].url.params["ipAddress"] == "8.8.4.9"
    assert result["abuse_confidence_score"] == 97


async def test_abuseipdb_rejected_key_is_a_clear_error():
    recorder = Recorder(httpx.Response(401, json={}))
    client = AbuseIPDBClient(AbuseIPDBSettings(api_key="k"), recorder.client("https://abuse.test"))
    with pytest.raises(IntegrationError, match="rejected the API key"):
        await client.lookup("8.8.8.8")


async def test_misp_matches():
    body = {"response": {"Attribute": [
        {"event_id": "7", "category": "Network activity", "type": "ip-dst", "to_ids": True,
         "timestamp": "1790812800", "Event": {"info": "Campaign X"}, "Tag": [{"name": "tlp:amber"}]},
    ]}}
    recorder = Recorder(httpx.Response(200, json=body))
    client = MISPClient(MISPSettings(url="https://misp.test", api_key="k"), recorder.client("https://misp.test"))
    result = await client.lookup("8.8.8.8")
    assert json.loads(recorder.requests[0].content)["value"] == "8.8.8.8"
    assert result["matches"][0]["event_info"] == "Campaign X"
    assert result["summary"] == "1 matching attribute(s) in 1 MISP event(s)."


async def test_jira_create_issue():
    recorder = Recorder(httpx.Response(201, json={"id": "1", "key": "SOC-42"}))
    settings = JiraSettings(url="https://jira.test", email="bot@example.com", api_token="t", project_key="SOC")
    client = JiraClient(settings, recorder.client("https://jira.test"))
    result = await client.create_issue(summary="Brute force", description="Details", severity="high",
                                       incident_id="abc")
    fields = json.loads(recorder.requests[0].content)["fields"]
    assert fields["project"] == {"key": "SOC"} and "severity-high" in fields["labels"]
    assert result == {"key": "SOC-42", "url": "https://jira.test/browse/SOC-42"}


async def test_jira_validation_error():
    recorder = Recorder(httpx.Response(400, json={"errors": {"issuetype": "invalid"}}))
    settings = JiraSettings(url="https://jira.test", api_token="t", project_key="SOC")
    client = JiraClient(settings, recorder.client("https://jira.test"))
    with pytest.raises(IntegrationError, match="issuetype"):
        await client.create_issue(summary="s", description="d", severity="low", incident_id="x")


async def test_email_only_goes_to_allowlisted_recipients(monkeypatch):
    sender = EmailSender(SMTPSettings(host="smtp.test", from_address="soc-bot@example.com",
                                      allowed_recipients="@example.com,lead@partner.test",
                                      default_recipients="soc@example.com"))
    sent = []
    monkeypatch.setattr(sender, "_deliver", lambda message: sent.append(message))

    with pytest.raises(ValueError, match="not in SMTP_ALLOWED_RECIPIENTS"):
        await sender.send(subject="x", body="y", to=["attacker@evil.test"])
    assert sent == []

    result = await sender.send(subject="New\r\nBcc: x@evil.test", body="y")
    assert result["recipients"] == ["soc@example.com"]
    assert sent[0]["Subject"] == "New Bcc: x@evil.test"
    await sender.send(subject="x", body="y", to=["lead@partner.test"])
    assert len(sent) == 2


BUNDLE = {"objects": [
    {"type": "attack-pattern", "name": "Brute Force", "description": "Adversaries guess passwords (Citation: X).",
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1110", "url": "https://attack/T1110"}]},
    {"type": "attack-pattern", "name": "Password Spraying", "x_mitre_is_subtechnique": True,
     "description": "Use one password against many accounts.",
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1110.003"}]},
    {"type": "attack-pattern", "name": "Old", "revoked": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
    {"type": "malware", "name": "Not a technique"},
]}


def test_mitre_parse_and_search():
    techniques = parse_bundle(BUNDLE)
    assert [t.id for t in techniques] == ["T1110", "T1110.003"]
    assert techniques[0].tactics == ("Credential Access",)
    assert "Citation" not in techniques[0].description

    assert [t.id for t in search(techniques, "t1110")] == ["T1110", "T1110.003"]
    assert search(techniques, "password spraying")[0].id == "T1110.003"
    assert search(techniques, "ransomware") == []
