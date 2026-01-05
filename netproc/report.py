import os
import json
import pandas as pd
import matplotlib.pyplot as plt

from .flows import summary_pairs
from .utils import ms_to_dt
from .report_map import build_map_optional


def _plot_alerts_over_time(alerts, out_png):
    if not alerts:
        return None

    ts = [a.get("ts_ms", 0) for a in alerts if a.get("ts_ms")]
    if not ts:
        return None

    # bin: 1 minuta
    s = pd.Series(ts).astype(int)
    minute = (s // 60000) * 60000
    counts = minute.value_counts().sort_index()

    x = [ms_to_dt(v) for v in counts.index]
    y = counts.values

    plt.figure()
    plt.bar(x, y)
    plt.xticks(rotation=30, ha="right")
    plt.title("Alerts over time (per minute)")
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()
    return out_png


def build_report(out_dir, pcap_path, flows_df, python_alerts, sigma_alerts, ml_info, enrichment):
    os.makedirs(out_dir, exist_ok=True)

    pairs = summary_pairs(flows_df)

    all_alerts = python_alerts + sigma_alerts
    alerts_png = os.path.join(out_dir, "alerts_over_time.png")
    _plot_alerts_over_time(all_alerts, alerts_png)

    flows_csv = os.path.join(out_dir, "flows.csv")
    flows_df.to_csv(flows_csv, index=False)

    pairs_csv = os.path.join(out_dir, "pairs_summary.csv")
    pairs.to_csv(pairs_csv, index=False)

    alerts_json = os.path.join(out_dir, "alerts.json")
    with open(alerts_json, "w", encoding="utf-8") as f:
        json.dump(all_alerts, f, indent=2, ensure_ascii=False)

    ml_csv = None
    if ml_info.get("preds") is not None:
        ml_csv = os.path.join(out_dir, "ml_predictions.csv")
        ml_info["preds"].to_csv(ml_csv, index=False)

    map_html = build_map_optional(out_dir, all_alerts, enrichment)

    report_md = os.path.join(out_dir, "report.md")
    with open(report_md, "w", encoding="utf-8") as f:
        f.write(f"# Network PoC Report\n\n")
        f.write(f"PCAP: `{pcap_path}`\n\n")

        f.write("## A.1 — NFStream PCAP → flows\n")
        f.write(f"- Export: `{os.path.basename(flows_csv)}`\n")
        f.write(f"- Count flows: **{len(flows_df)}**\n\n")

        f.write("## A.2 — Summary stats (src_ip → dst_ip)\n")
        f.write(f"- Export: `{os.path.basename(pairs_csv)}`\n\n")
        f.write(pairs.head(15).to_markdown(index=False))
        f.write("\n\n")

        f.write("## D.1 — Detection as Code (Python rules)\n")
        f.write(f"- Alerts: **{len(python_alerts)}**\n\n")

        f.write("## D.2 — Sigma rules\n")
        f.write(f"- Alerts: **{len(sigma_alerts)}**\n\n")

        f.write("## V.1 — Alerts over time\n")
        if os.path.exists(alerts_png):
            f.write(f"![alerts]({os.path.basename(alerts_png)})\n\n")
        else:
            f.write("- (no alerts plot)\n\n")

        f.write("## ML.1/ML.2 — ML classification + metrics\n")
        if ml_csv:
            f.write(f"- Predictions: `{os.path.basename(ml_csv)}`\n")
        if ml_info.get("eval"):
            f.write("\nMetrics:\n\n")
            f.write(pd.DataFrame([ml_info["eval"]]).to_markdown(index=False))
            f.write("\n\n")
        else:
            f.write("- (no train csv provided, baseline model used)\n\n")

        f.write("## E.1 — Enrichment (geo/IP)\n")
        f.write(f"- Enriched IPs: **{len(enrichment or {})}**\n\n")

        if map_html:
            f.write("## V.2 — Map (optional)\n")
            f.write(f"- Map: `{os.path.basename(map_html)}`\n\n")

        f.write("## Raw outputs\n")
        f.write(f"- `{os.path.basename(alerts_json)}`\n")
        f.write(f"- `{os.path.basename(flows_csv)}`\n")
        f.write(f"- `{os.path.basename(pairs_csv)}`\n")

    return {"report_md": report_md, "map_html": map_html}
