import os
import click

from .flows import pcap_to_flows_df
from .detection_rules import run_python_rules
from .sigma_rules import load_sigma_rules, run_sigma_rules
from .ml import train_or_load_model, predict_with_model, evaluate_model
from .enrich import enrich_suspicious_ips
from .report import build_report


@click.group()
def cli():
    pass


@cli.command()
@click.option("--pcap", required=True, type=click.Path(exists=True))
@click.option("--out", default="out", show_default=True)
@click.option("--sigma", default=None, help="Folder or YAML file with Sigma rules")
@click.option("--model", default="out/model.joblib", show_default=True)
@click.option("--train-csv", default=None, help="CSV with labeled flows to train ML (optional)")
@click.option("--no-ml", is_flag=True, default=False)
@click.option("--no-enrich", is_flag=True, default=False)
def analyze(pcap, out, sigma, model, train_csv, no_ml, no_enrich):
    os.makedirs(out, exist_ok=True)

    flows_df = pcap_to_flows_df(pcap)
    py_alerts = run_python_rules(flows_df)

    sigma_rules = load_sigma_rules(sigma) if sigma else []
    sigma_alerts = run_sigma_rules(flows_df, sigma_rules) if sigma_rules else []

    ml_info = {}
    if not no_ml:
        model_obj, model_meta = train_or_load_model(model_path=model, train_csv=train_csv)
        preds = predict_with_model(model_obj, flows_df, model_meta)
        ml_info["preds"] = preds
        if train_csv:
            ml_info["eval"] = evaluate_model(model_obj, train_csv, model_meta)

    all_alerts = py_alerts + sigma_alerts

    enrich = {}
    if not no_enrich:
        enrich = enrich_suspicious_ips(all_alerts)

    report_paths = build_report(
        out_dir=out,
        pcap_path=pcap,
        flows_df=flows_df,
        python_alerts=py_alerts,
        sigma_alerts=sigma_alerts,
        ml_info=ml_info,
        enrichment=enrich,
    )

    click.echo(f"OK. Report: {report_paths['report_md']}")
    if report_paths.get("map_html"):
        click.echo(f"Map: {report_paths['map_html']}")


@cli.command()
@click.option("--pcap", required=True, type=click.Path(exists=True))
@click.option("--csv-out", required=True, type=click.Path())
def export_csv(pcap, csv_out):
    df = pcap_to_flows_df(pcap)
    df.to_csv(csv_out, index=False)
    click.echo(f"Saved: {csv_out}")


@cli.command()
@click.option("--train-csv", required=True, type=click.Path(exists=True))
@click.option("--model-out", default="out/model.joblib", show_default=True)
def train(train_csv, model_out):
    model_obj, meta = train_or_load_model(model_path=model_out, train_csv=train_csv, force_train=True)
    click.echo(f"Trained. Model: {model_out}")
    click.echo(f"Features: {meta['features']}")
