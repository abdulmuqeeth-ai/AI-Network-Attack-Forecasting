"""
Cleans up network flow data before analysis.
"""

import pandas as pd
import numpy as np


FEATURE_COLS = [
    "bytes_sent", "bytes_recv", "packets",
    "duration_ms", "src_port", "dst_port"
]


def load_data(path_or_buffer):
    """Load a CSV file from disk or from a Streamlit upload."""
    df = pd.read_csv(path_or_buffer)
    df.columns = [c.strip().lower() for c in df.columns]
    return df


def extract_features(df):
    """Add useful numbers computed from existing ones."""
    df = df.copy()

    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df["bytes_ratio"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["bytes_total"] = df["bytes_sent"] + df["bytes_recv"]
    df["avg_packet_size"] = df["bytes_total"] / (df["packets"] + 1)
    df["packet_rate"] = df["packets"] / (df["duration_ms"] + 1)

    return df


def get_feature_matrix(df):
    """Return a numeric matrix for ML later."""
    cols = FEATURE_COLS + ["bytes_ratio", "bytes_total",
                           "avg_packet_size", "packet_rate"]
    return df[cols].values