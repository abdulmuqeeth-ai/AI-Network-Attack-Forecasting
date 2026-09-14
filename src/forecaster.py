"""
Predicts the NEXT attack stage based on the current one.
Uses simple probability rules. Upgradeable to ML later.
"""

from src.mitre_mapper import ATTACK_CHAIN


TRANSITIONS = {
    "Benign": {"Reconnaissance": 0.6, "Initial Access": 0.3, "Benign": 0.1},
    "Reconnaissance": {"Initial Access": 0.75, "Reconnaissance": 0.15, "Execution": 0.10},
    "Initial Access": {"Execution": 0.70, "Persistence": 0.15, "Privilege Escalation": 0.15},
    "Execution": {"Persistence": 0.45, "Privilege Escalation": 0.40, "Lateral Movement": 0.15},
    "Persistence": {"Privilege Escalation": 0.55, "Lateral Movement": 0.35, "Exfiltration": 0.10},
    "Privilege Escalation": {"Lateral Movement": 0.60, "Exfiltration": 0.35, "Persistence": 0.05},
    "Lateral Movement": {"Exfiltration": 0.70, "Privilege Escalation": 0.20, "Lateral Movement": 0.10},
    "Exfiltration": {"Exfiltration": 0.60, "Benign": 0.40},
}


def forecast_next_stage(current_stage, threat_score=50):
    """Return the most likely next stage + confidence."""
    if current_stage not in TRANSITIONS:
        current_stage = "Benign"

    options = TRANSITIONS[current_stage]
    next_stage = max(options, key=options.get)
    base_conf = options[next_stage]

    confidence = min(0.99, base_conf * (0.7 + threat_score / 200))

    alternatives = sorted(options.items(), key=lambda x: -x[1])[1:3]

    return {
        "next_stage": next_stage,
        "confidence": round(confidence * 100, 1),
        "alternatives": alternatives
    }