"""
Looks at network flows and decides: is this Benign or an attack?
Uses simple rules for now. Later, we replace with ML.
"""

import numpy as np
import pandas as pd
from src.mitre_mapper import ATTACK_CHAIN


def detect_anomalies(df):
    """Go through each row and label it."""
    df = df.copy()

    HIGH_BYTES = 200000
    MED_BYTES = 20000
    HIGH_PACKETS = 500
    SCAN_PACKETS = 20

    stages = []

    for _, row in df.iterrows():
        sent = row.get("bytes_sent", 0)
        recv = row.get("bytes_recv", 0)
        pkts = row.get("packets", 0)
        dport = row.get("dst_port", 0)

        if sent > HIGH_BYTES:
            stages.append("Exfiltration")
        elif dport in (3389, 445) and pkts > HIGH_PACKETS:
            stages.append("Lateral Movement")
        elif sent > MED_BYTES and pkts > HIGH_PACKETS:
            stages.append("Privilege Escalation")
        elif pkts > HIGH_PACKETS:
            stages.append("Execution")
        elif sent > MED_BYTES:
            stages.append("Initial Access")
        elif pkts <= SCAN_PACKETS and recv < 1000:
            stages.append("Reconnaissance")
        else:
            stages.append("Benign")

    df["detected_stage"] = stages
    df["threat_score"] = df["detected_stage"].apply(_stage_score)

    return df


def _stage_score(stage):
    mapping = {
        "Benign": 5,
        "Reconnaissance": 25,
        "Initial Access": 45,
        "Execution": 65,
        "Persistence": 70,
        "Privilege Escalation": 80,
        "Lateral Movement": 88,
        "Exfiltration": 95,
    }
    return mapping.get(stage, 50)


def get_current_stage(df):
    """Return the most severe attack stage found."""
    if "detected_stage" not in df.columns or df.empty:
        return "Benign"

    attack_stages = [s for s in df["detected_stage"].unique()
                     if s in ATTACK_CHAIN]
    if not attack_stages:
        return "Benign"

    return max(attack_stages, key=lambda s: ATTACK_CHAIN.index(s))