## Setup

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## Analyze

python app.py analyze --pcap sample.pcap --out out --sigma rules

## Export flows to CSV

python app.py export-csv --pcap sample.pcap --csv-out flows.csv

## Train model (optional)

# CSV must include column: label (0/1)
python app.py train --train-csv labeled_flows.csv --model-out out/model.joblib
