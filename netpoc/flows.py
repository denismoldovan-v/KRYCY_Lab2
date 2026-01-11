import pandas as pd
from nfstream import NFStreamer


FLOW_COLS = [
    "id",
    "src_ip", "src_port",
    "dst_ip", "dst_port",
    "protocol",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",
    "duration_ms",
    "first_seen_ms",
    "last_seen_ms",
]


def pcap_to_flows_df(pcap_path: str) -> pd.DataFrame:
    streamer = NFStreamer(source=pcap_path, decode_tunnels=True, bpf_filter=None)

    rows = []
    for f in streamer:
        rows.append({
            "id": getattr(f, "id", None),
            "src_ip": getattr(f, "src_ip", None),
            "src_port": getattr(f, "src_port", None),
            "dst_ip": getattr(f, "dst_ip", None),
            "dst_port": getattr(f, "dst_port", None),
            "protocol": getattr(f, "protocol", None),

            "bidirectional_packets": getattr(f, "bidirectional_packets", 0),
            "bidirectional_bytes": getattr(f, "bidirectional_bytes", 0),

            "src2dst_packets": getattr(f, "src2dst_packets", 0),
            "src2dst_bytes": getattr(f, "src2dst_bytes", 0),

            "dst2src_packets": getattr(f, "dst2src_packets", 0),
            "dst2src_bytes": getattr(f, "dst2src_bytes", 0),

            "duration_ms": int(getattr(f, "bidirectional_duration_ms", 0) or 0),
            "first_seen_ms": int(getattr(f, "bidirectional_first_seen_ms", 0) or 0),
            "last_seen_ms": int(getattr(f, "bidirectional_last_seen_ms", 0) or 0),
        })

    df = pd.DataFrame(rows)
    for c in FLOW_COLS:
        if c not in df.columns:
            df[c] = None
    return df[FLOW_COLS]


def summary_pairs(df: pd.DataFrame) -> pd.DataFrame:
    grp = df.groupby(["src_ip", "dst_ip"], dropna=False).agg(
        flows=("id", "count"),
        packets=("bidirectional_packets", "sum"),
        bytes=("bidirectional_bytes", "sum"),
    ).reset_index().sort_values(["bytes"], ascending=False)
    return grp
