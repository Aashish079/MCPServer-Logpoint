"""Small local MITRE ATT&CK reference so the LLM can ground technique IDs
instead of inventing them. Not exhaustive - covers common Tier 1 SOC alert
categories. Swap for a full STIX bundle lookup if wider coverage is needed.
"""
from typing import Any, Dict, List

TECHNIQUES: List[Dict[str, str]] = [
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "keywords": "failed login,bruteforce,password spray"},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion, Persistence", "keywords": "valid account,successful login anomaly,impossible travel"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "keywords": "powershell,cmd,bash,script execution"},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "keywords": "c2,beacon,dns tunneling,http callback"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "keywords": "ransomware,file encryption,extortion"},
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "keywords": "phishing,malicious attachment,spearphishing"},
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "keywords": "port scan,network scan,service enumeration"},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "keywords": "exfiltration,data transfer,large upload"},
]


def lookup(query: str) -> List[Dict[str, str]]:
    query_lower = query.lower()
    matches = [
        technique
        for technique in TECHNIQUES
        if query_lower in technique["keywords"] or query_lower in technique["name"].lower()
    ]
    return matches or TECHNIQUES
