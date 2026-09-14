"""
Maps attack stages to MITRE ATT&CK techniques.
Think of this as a lookup dictionary.
"""

MITRE_MAP = {
    "Reconnaissance": {
        "technique_id": "T1595",
        "technique": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Attacker is scanning your network to find weak spots.",
        "risk": "LOW"
    },
    "Initial Access": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Attacker is trying to break into your network.",
        "risk": "MEDIUM"
    },
    "Execution": {
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Attacker is running malicious code on a system.",
        "risk": "HIGH"
    },
    "Persistence": {
        "technique_id": "T1053",
        "technique": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Attacker is making sure they can come back later.",
        "risk": "HIGH"
    },
    "Privilege Escalation": {
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Attacker is trying to get admin-level access.",
        "risk": "CRITICAL"
    },
    "Lateral Movement": {
        "technique_id": "T1021",
        "technique": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Attacker is moving to other computers in your network.",
        "risk": "CRITICAL"
    },
    "Exfiltration": {
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Attacker is stealing your data.",
        "risk": "CRITICAL"
    },
    "Benign": {
        "technique_id": "---",
        "technique": "Normal Traffic",
        "tactic": "None",
        "description": "This is normal traffic. Nothing to worry about.",
        "risk": "LOW"
    }
}

# The order attackers usually follow (like a video game level order)
ATTACK_CHAIN = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Lateral Movement",
    "Exfiltration"
]


def map_to_mitre(stage):
    """Give me a stage name, I'll give you the MITRE info."""
    return MITRE_MAP.get(stage, MITRE_MAP["Benign"])


def get_chain_index(stage):
    """What position is this stage in the kill chain?"""
    if stage in ATTACK_CHAIN:
        return ATTACK_CHAIN.index(stage)
    return -1