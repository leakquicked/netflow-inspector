#!/usr/bin/env python3
"""Netflow Inspector: summarize authorized network-flow CSV or JSONL exports."""
import argparse, csv, json
from collections import Counter
from pathlib import Path

def load_rows(path):
    path=Path(path)
    if path.suffix.lower()==".csv":
        with path.open(newline="",encoding="utf-8") as f: return list(csv.DictReader(f))
    rows=[]
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip(): rows.append(json.loads(line))
    return rows

def inspect(rows, top=10):
    protocols=Counter(); sources=Counter(); destinations=Counter(); total_bytes=0; total_packets=0
    for row in rows:
        proto=str(row.get("protocol","unknown")).lower()
        protocols[proto]+=1
        src=str(row.get("src_ip","unknown")); dst=str(row.get("dst_ip","unknown"))
        sources[src]+=1; destinations[dst]+=1
        total_bytes+=int(row.get("bytes",0) or 0); total_packets+=int(row.get("packets",0) or 0)
    return {"flows":len(rows),"total_bytes":total_bytes,"total_packets":total_packets,
      "protocols":dict(protocols),"top_sources":sources.most_common(top),
      "top_destinations":destinations.most_common(top),
      "note":"Descriptive aggregation only; this report does not identify malicious activity by itself."}

def main():
    p=argparse.ArgumentParser(description="Summarize flow records from an authorized CSV or JSONL export.")
    p.add_argument("file",type=Path); p.add_argument("--top",type=int,default=10)
    p.add_argument("--output",type=Path); a=p.parse_args()
    if a.top<1: p.error("--top must be positive")
    try: report=inspect(load_rows(a.file),a.top)
    except (OSError,ValueError,json.JSONDecodeError) as e: p.error(str(e))
    text=json.dumps(report,indent=2,ensure_ascii=False)
    if a.output: a.output.write_text(text+"\n",encoding="utf-8")
    print(text)
if __name__=="__main__": main()
