![Python checks](https://github.com/leakquicked/netflow-inspector/actions/workflows/python-checks.yml/badge.svg)

# Netflow Inspector

A small offline analyzer for CSV or JSON Lines flow exports. It aggregates protocols, bytes, packets and top source/destination IPs.

## Input schema
CSV headers or JSONL keys:
- `src_ip`
- `dst_ip`
- `protocol`
- `bytes` (optional; defaults to 0)
- `packets` (optional; defaults to 0)

## Run
Python 3.10+, standard library only.

```bash
python netflow_inspector.py sample_flows.csv
python netflow_inspector.py sample_flows.csv --top 5 --output summary.json
python -m unittest discover -s tests -v
```

## Safety and limitations
Analyze only flow data from networks you own or are authorized to monitor. This tool performs no packet capture, scanning or network connections. Aggregates are descriptive and do not establish whether traffic is malicious. Flow exports may contain sensitive network metadata; do not publish real operational logs.
