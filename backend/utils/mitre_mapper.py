"""Maps UNSW-NB15 attack categories to MITRE ATT&CK techniques.

This provides a deterministic mapping layer so every classified alert
gets tagged with relevant ATT&CK technique IDs before the RAG engine
does deeper investigation.
"""

# Mapping from UNSW-NB15 attack categories to likely MITRE ATT&CK techniques
ATTACK_TO_MITRE = {
    "Normal": [],
    "Analysis": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1135", "name": "Network Share Discovery", "tactic": "Discovery"},
        {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
    ],
    "Backdoor": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
        {"id": "T1543", "name": "Create or Modify System Process", "tactic": "Persistence"},
    ],
    "DoS": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
        {"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact"},
    ],
    "Exploits": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    ],
    "Fuzzers": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "Generic": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ],
    "Reconnaissance": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
        {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
        {"id": "T1590", "name": "Gather Victim Network Information", "tactic": "Reconnaissance"},
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],
    "Shellcode": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
        {"id": "T1620", "name": "Reflective Code Loading", "tactic": "Defense Evasion"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "Worms": [
        {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1080", "name": "Taint Shared Content", "tactic": "Lateral Movement"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    ],
}

# Mitigation recommendations per attack category
MITIGATIONS = {
    "Normal": [],
    "Analysis": [
        "Review and restrict network scanning from source IP",
        "Ensure network segmentation limits discovery scope",
        "Monitor for unauthorized service enumeration",
    ],
    "Backdoor": [
        "Isolate affected host immediately",
        "Scan for persistence mechanisms (scheduled tasks, services)",
        "Review outbound connections for C2 communication",
        "Check for unauthorized user accounts or SSH keys",
    ],
    "DoS": [
        "Enable rate limiting on affected services",
        "Activate DDoS mitigation (CDN/WAF rules)",
        "Block source IP at network perimeter",
        "Monitor for volumetric and application-layer patterns",
    ],
    "Exploits": [
        "Patch the targeted vulnerability immediately",
        "Check for signs of successful exploitation",
        "Review system logs for post-exploitation activity",
        "Consider isolating the affected system for forensics",
    ],
    "Fuzzers": [
        "Block source IP sending malformed input",
        "Review application input validation",
        "Check for successful exploitation among fuzzed requests",
        "Update WAF rules to catch common fuzzing patterns",
    ],
    "Generic": [
        "Investigate the full traffic capture for this session",
        "Check if data was exfiltrated via the communication channel",
        "Review DNS queries from the source IP for DGA patterns",
    ],
    "Reconnaissance": [
        "Block source IP at the firewall",
        "Audit exposed services and close unnecessary ports",
        "Review scan results to assess what was discovered",
        "Expect follow-up exploitation attempts",
    ],
    "Shellcode": [
        "Isolate the affected host immediately",
        "Capture memory dump for forensic analysis",
        "Check for process injection or code execution",
        "Scan for dropped payloads or additional malware",
    ],
    "Worms": [
        "Isolate affected network segment to prevent spread",
        "Identify the worm variant and propagation mechanism",
        "Scan all hosts in the subnet for infection",
        "Apply patches for the exploited vulnerability",
    ],
}


def map_attack_to_mitre(attack_category: str) -> list[dict]:
    """Map an attack category to MITRE ATT&CK techniques."""
    return ATTACK_TO_MITRE.get(attack_category, [])


def get_mitre_technique_ids(attack_category: str) -> list[str]:
    """Get just the technique IDs for an attack category."""
    return [t["id"] for t in map_attack_to_mitre(attack_category)]


def get_mitigations(attack_category: str) -> list[str]:
    """Get mitigation recommendations for an attack category."""
    return MITIGATIONS.get(attack_category, [])


def get_all_techniques() -> list[dict]:
    """Get all MITRE ATT&CK techniques in our mapping."""
    seen = set()
    techniques = []
    for techniques_list in ATTACK_TO_MITRE.values():
        for t in techniques_list:
            if t["id"] not in seen:
                seen.add(t["id"])
                techniques.append(t)
    return sorted(techniques, key=lambda t: t["id"])
