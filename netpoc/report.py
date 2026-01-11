import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from .report_latex import build_report_tex
from .flows import summary_pairs
from .report_map import build_map_optional


# ---------- Plots ----------

def _plot_top_flows_bytes(flows_df, out_png, top_n=10):
    if flows_df is None or len(flows_df) == 0:
        return None

    df = flows_df.copy()
    df["src2dst_bytes"] = pd.to_numeric(df["src2dst_bytes"], errors="coerce").fillna(0)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)

    top = df.sort_values("src2dst_bytes", ascending=False).head(top_n)
    if len(top) == 0:
        return None

    labels = [f"{r['src_ip']}→{r['dst_ip']}:{int(r['dst_port'])}" for _, r in top.iterrows()]
    values = top["src2dst_bytes"].values

    plt.figure(figsize=(10, 4))
    plt.barh(labels, values)
    plt.gca().invert_yaxis()
    plt.xlabel("src2dst_bytes")
    plt.title(f"Top {min(top_n, len(top))} flows by src→dst bytes")
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close()
    return out_png


def _plot_alerts_by_rule(alerts, out_png):
    if not alerts:
        return None

    # prefer rule_id, fallback to rule_name
    keys = [(a.get("rule_id") or a.get("rule_name") or "unknown") for a in alerts]
    counts = pd.Series(keys).value_counts()

    plt.figure(figsize=(6, 3))
    plt.bar(counts.index.astype(str), counts.values)
    plt.xlabel("Rule")
    plt.ylabel("Alerts")
    plt.title("Alerts by rule")
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close()
    return out_png


def _plot_flow_direction_bytes(flows_df, out_png, top_n=10):
    if flows_df is None or len(flows_df) == 0:
        return None

    df = flows_df.copy()
    df["src2dst_bytes"] = pd.to_numeric(df["src2dst_bytes"], errors="coerce").fillna(0)
    df["dst2src_bytes"] = pd.to_numeric(df["dst2src_bytes"], errors="coerce").fillna(0)
    df["bidirectional_bytes"] = pd.to_numeric(df["bidirectional_bytes"], errors="coerce").fillna(0)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)

    top = df.sort_values("bidirectional_bytes", ascending=False).head(top_n)
    if len(top) == 0:
        return None

    labels = [f"{r['src_ip']}→{r['dst_ip']}:{int(r['dst_port'])}" for _, r in top.iterrows()]
    y = np.arange(len(top))

    plt.figure(figsize=(10, 4))
    plt.barh(y, top["src2dst_bytes"].values, label="src→dst bytes")
    plt.barh(
        y,
        top["dst2src_bytes"].values,
        left=top["src2dst_bytes"].values,
        label="dst→src bytes",
    )
    plt.yticks(y, labels)
    plt.gca().invert_yaxis()
    plt.xlabel("Bytes")
    plt.title(f"Top {len(top)} flows: traffic direction split")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close()
    return out_png


def _plot_flows_scatter_over_time(flows_df, out_png):
    if flows_df is None or len(flows_df) == 0:
        return None

    df = flows_df.copy()
    df["first_seen_ms"] = pd.to_numeric(df["first_seen_ms"], errors="coerce").fillna(0).astype("int64")
    df["src2dst_bytes"] = pd.to_numeric(df["src2dst_bytes"], errors="coerce").fillna(0)
    df["bidirectional_bytes"] = pd.to_numeric(df["bidirectional_bytes"], errors="coerce").fillna(0)

    x = pd.to_datetime(df["first_seen_ms"], unit="ms", utc=True).dt.tz_convert(None)
    y = df["src2dst_bytes"].values

    size = df["bidirectional_bytes"].values
    size = (size / max(size.max(), 1)) * 600 + 80  # scale

    plt.figure(figsize=(10, 4))
    plt.scatter(x, y, s=size)
    plt.xlabel("First seen time")
    plt.ylabel("src→dst bytes")
    plt.title("Flows over time (bubble size = total bytes)")
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M:%S"))
    plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close()
    return out_png


def _plot_alerts_over_time(alerts, out_png):
    if not alerts:
        return None

    ts = [a.get("ts_ms") for a in alerts if a.get("ts_ms") is not None]
    if not ts:
        return None

    dt = pd.to_datetime(pd.Series(ts, dtype="int64"), unit="ms", utc=True).sort_values()
    span = dt.iloc[-1] - dt.iloc[0]

    if span <= pd.Timedelta(minutes=2):
        bin_size = "10s"
    elif span <= pd.Timedelta(hours=2):
        bin_size = "1min"
    elif span <= pd.Timedelta(days=2):
        bin_size = "1H"
    else:
        bin_size = "1D"

    counts = dt.dt.floor(bin_size).value_counts().sort_index()

    plt.figure(figsize=(10, 4))
    if len(counts) == 1:
        # jitter Y so points do not overlap visually
        x = dt.dt.tz_convert(None)
        y = np.arange(1, len(x) + 1) + np.linspace(-0.08, 0.08, len(x))
        plt.scatter(x, y, s=70)
        plt.xlabel("Time")
        plt.ylabel("Alert index")
        plt.title("Alerts timeline (each point = 1 alert)")
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M:%S"))
        plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.grid(True, alpha=0.3)
    else:
        x = counts.index.tz_convert(None)
        y = counts.values
        bin_seconds = pd.to_timedelta(bin_size).total_seconds()
        width = (bin_seconds / 86400.0) * 0.9
        plt.bar(x, y, width=width, align="center")
        plt.xlabel("Time")
        plt.ylabel("Alerts per bin")
        plt.title(f"Alerts over time (bin={bin_size})")
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M"))
        plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.grid(True, axis="y", alpha=0.3)

    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(out_png, dpi=180)
    plt.close()
    return out_png


# ---------- Report ----------

def build_report(out_dir, pcap_path, flows_df, python_alerts, sigma_alerts, ml_info, enrichment):
    os.makedirs(out_dir, exist_ok=True)

    all_alerts = (python_alerts or []) + (sigma_alerts or [])

    # Plots
    top_png = os.path.join(out_dir, "top_flows_bytes.png")
    byrule_png = os.path.join(out_dir, "alerts_by_rule.png")
    direction_png = os.path.join(out_dir, "flow_direction_bytes.png")
    scatter_png = os.path.join(out_dir, "flows_scatter_over_time.png")
    alerts_png = os.path.join(out_dir, "alerts_over_time.png")  # optional timeline

    _plot_top_flows_bytes(flows_df, top_png)
    _plot_alerts_by_rule(all_alerts, byrule_png)
    _plot_flow_direction_bytes(flows_df, direction_png, top_n=10)
    _plot_flows_scatter_over_time(flows_df, scatter_png)
    _plot_alerts_over_time(all_alerts, alerts_png)

    # Tables / exports
    pairs = summary_pairs(flows_df)

    flows_csv = os.path.join(out_dir, "flows.csv")
    flows_df.to_csv(flows_csv, index=False)

    pairs_csv = os.path.join(out_dir, "pairs_summary.csv")
    pairs.to_csv(pairs_csv, index=False)

    alerts_json = os.path.join(out_dir, "alerts.json")
    with open(alerts_json, "w", encoding="utf-8") as f:
        json.dump(all_alerts, f, indent=2, ensure_ascii=False)

    ml_csv = None
    if ml_info and ml_info.get("preds") is not None:
        ml_csv = os.path.join(out_dir, "ml_predictions.csv")
        ml_info["preds"].to_csv(ml_csv, index=False)

    map_html = build_map_optional(out_dir, all_alerts, enrichment)

    # Markdown report
    report_md = os.path.join(out_dir, "report.md")
    with open(report_md, "w", encoding="utf-8") as f:
        f.write("# Network PoC Report\n\n")
        f.write(f"PCAP: `{pcap_path}`\n\n")

        f.write("## A.1 — NFStream PCAP → flows\n")
        f.write(f"- Export: `{os.path.basename(flows_csv)}`\n")
        f.write(f"- Count flows: **{len(flows_df)}**\n\n")

        f.write("## A.2 — Summary stats (src_ip → dst_ip)\n")
        f.write(f"- Export: `{os.path.basename(pairs_csv)}`\n\n")
        f.write(pairs.head(15).to_markdown(index=False))
        f.write("\n\n")

        f.write("## V.0 — Top flows by bytes\n")
        if os.path.exists(top_png):
            f.write(f"![topflows]({os.path.basename(top_png)})\n\n")
            f.write("The plot highlights the most dominant flows by src→dst volume.\n\n")
        else:
            f.write("- (no top flows plot)\n\n")

        f.write("## V.1 — Alerts by rule\n")
        if os.path.exists(byrule_png):
            f.write(f"![byrule]({os.path.basename(byrule_png)})\n\n")
            f.write("This visualization summarizes how many alerts were produced by each detection rule.\n\n")
        else:
            f.write("- (no alerts-by-rule plot)\n\n")

        f.write("## V.2 — Direction split per flow\n")
        if os.path.exists(direction_png):
            f.write(f"![dir]({os.path.basename(direction_png)})\n\n")
            f.write("Direction split helps identify asymmetric flows (exfiltration-like patterns).\n\n")
        else:
            f.write("- (no direction split plot)\n\n")

        f.write("## V.3 — Flows over time (bubble plot)\n")
        if os.path.exists(scatter_png):
            f.write(f"![scatter]({os.path.basename(scatter_png)})\n\n")
        else:
            f.write("- (no flows scatter plot)\n\n")

        f.write("## V.9 — Alerts timeline (optional)\n")
        if os.path.exists(alerts_png):
            f.write(f"![alerts]({os.path.basename(alerts_png)})\n\n")
        else:
            f.write("- (no alerts timeline plot)\n\n")

        f.write("## D.1 — Detection as Code (Python rules)\n")
        f.write(f"- Alerts: **{len(python_alerts or [])}**\n\n")

        f.write("## D.2 — Sigma rules\n")
        f.write(f"- Alerts: **{len(sigma_alerts or [])}**\n\n")

        f.write("## ML.1/ML.2 — ML classification + metrics\n")
        if ml_csv:
            f.write(f"- Predictions: `{os.path.basename(ml_csv)}`\n")
        if ml_info and ml_info.get("eval"):
            f.write("\nMetrics:\n\n")
            f.write(pd.DataFrame([ml_info["eval"]]).to_markdown(index=False))
            f.write("\n\n")
        else:
            f.write("- (no train csv provided, baseline model used)\n\n")

        f.write("## E.1 — Enrichment (geo/IP)\n")
        f.write(f"- Enriched IPs: **{len(enrichment or {})}**\n\n")

        if map_html:
            f.write("## V.10 — Map (optional)\n")
            f.write(f"- Map: `{os.path.basename(map_html)}`\n\n")

        f.write("## Raw outputs\n")
        f.write(f"- `{os.path.basename(alerts_json)}`\n")
        f.write(f"- `{os.path.basename(flows_csv)}`\n")
        f.write(f"- `{os.path.basename(pairs_csv)}`\n")

    report_tex = build_report_tex(out_dir=out_dir, pcap_path=pcap_path)
    return {"report_md": report_md, "map_html": map_html, "report_tex": report_tex}
