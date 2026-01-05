import pandas as pd


def rule_large_https_exfil(row):
    if row.get("dst_port") == 443 and (row.get("src2dst_bytes") or 0) > 1_000_000:
        return True, "Large src->dst bytes to 443"
    return False, None


def rule_many_flows_to_single_ip(row):
    # “prosta” heurystyka: dołożymy ją jako agregację w runnerze
    return False, None


RULES = [
    ("R001", "large_https_exfil", rule_large_https_exfil),
]


def run_python_rules(flows_df: pd.DataFrame):
    alerts = []
    for _, row in flows_df.iterrows():
        for rid, name, fn in RULES:
            ok, msg = fn(row)
            if ok:
                alerts.append({
                    "rule_id": rid,
                    "rule_name": name,
                    "type": "python",
                    "ts_ms": int(row.get("first_seen_ms") or 0),
                    "src_ip": row.get("src_ip"),
                    "dst_ip": row.get("dst_ip"),
                    "dst_port": row.get("dst_port"),
                    "details": msg,
                    "flow_id": row.get("id"),
                })

    # agregacja: dużo flow do jednego dst w krótkich czasach (użyteczne w raporcie)
    if "dst_ip" in flows_df.columns and len(flows_df) > 0:
        by_dst = flows_df.groupby("dst_ip").size().sort_values(ascending=False)
        for dst_ip, cnt in by_dst.head(10).items():
            if cnt >= 200:
                alerts.append({
                    "rule_id": "R010",
                    "rule_name": "burst_to_single_dst",
                    "type": "python",
                    "ts_ms": int(flows_df["first_seen_ms"].min() or 0),
                    "src_ip": None,
                    "dst_ip": dst_ip,
                    "dst_port": None,
                    "details": f"Many flows to single destination: {cnt}",
                    "flow_id": None,
                })

    return alerts
