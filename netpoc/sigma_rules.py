import os
import yaml
import pandas as pd


def load_sigma_rules(path_or_dir):
    if not path_or_dir:
        return []
    paths = []
    if os.path.isdir(path_or_dir):
        for name in os.listdir(path_or_dir):
            if name.endswith(".yml") or name.endswith(".yaml"):
                paths.append(os.path.join(path_or_dir, name))
    else:
        paths = [path_or_dir]

    rules = []
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            rules.append(yaml.safe_load(f))
    return rules


def _field_map():
    # Sigma często używa nazw “sieciowych” pod SIEM;
    # mapujemy je na nasze kolumny NFStream.
    return {
        "source.ip": "src_ip",
        "destination.ip": "dst_ip",
        "destination.port": "dst_port",
        "network.protocol": "protocol",
    }


def _match_selection(df: pd.DataFrame, sel: dict) -> pd.Series:
    m = pd.Series([True] * len(df), index=df.index)
    fmap = _field_map()

    for k, v in sel.items():
        col = fmap.get(k, k)
        if col not in df.columns:
            return pd.Series([False] * len(df), index=df.index)

        if isinstance(v, dict) and "contains" in v:
            needle = str(v["contains"])
            m = m & df[col].astype(str).str.contains(needle, na=False)
        elif isinstance(v, list):
            m = m & df[col].isin(v)
        else:
            m = m & (df[col] == v)
    return m


def run_sigma_rules(flows_df: pd.DataFrame, sigma_rules):
    alerts = []
    for rule in sigma_rules:
        title = rule.get("title", "sigma_rule")
        rid = rule.get("id", title)
        det = rule.get("detection", {})
        sel = det.get("selection", None)
        cond = det.get("condition", "selection")

        if not sel:
            continue
        if cond.strip() != "selection":
            continue

        mask = _match_selection(flows_df, sel)
        hits = flows_df[mask]

        for _, row in hits.iterrows():
            alerts.append({
                "rule_id": f"SIGMA:{rid}",
                "rule_name": title,
                "type": "sigma",
                "ts_ms": int(row.get("first_seen_ms") or 0),
                "src_ip": row.get("src_ip"),
                "dst_ip": row.get("dst_ip"),
                "dst_port": row.get("dst_port"),
                "details": rule.get("description", "Sigma match"),
                "flow_id": row.get("id"),
            })

    return alerts
