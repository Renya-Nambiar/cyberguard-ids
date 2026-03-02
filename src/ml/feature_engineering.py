import time
import pandas as pd

def aggregate_flows_cicids(packets, capture_started_ts=None):
    """
    Aggregate raw packets into CICIDS-style flow features.
    Produces per-flow rows keyed by (src_ip, dst_ip, proto, sport, dport).
    """
    if capture_started_ts is None:
        capture_started_ts = time.time()

    flows = {}
    for pkt in packets:
        try:
            pkt_len = len(pkt)
            src_ip = getattr(pkt, "src", None)
            dst_ip = getattr(pkt, "dst", None)
            proto = getattr(pkt, "proto", None)
            sport = getattr(pkt, "sport", None)
            dport = getattr(pkt, "dport", None)
            flags = getattr(pkt, "flags", 0)

            if not src_ip or not dst_ip:
                continue

            key = (src_ip, dst_ip, proto or 0, sport or 0, dport or 0)
            if key not in flows:
                flows[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "proto": proto or 0,
                    "sport": sport or 0,
                    "dport": dport or 0,
                    "Total Fwd Packets": 0,
                    "Total Backward Packets": 0,
                    "Total Length of Fwd Packets": 0,
                    "Total Length of Bwd Packets": 0,
                    "_fwd_lengths": [],
                    "_bwd_lengths": [],
                    "_pkt_count": 0,
                    "_first_ts": time.time(),
                    "flags": flags,
                }

            rec = flows[key]
            if sport:
                rec["Total Fwd Packets"] += 1
                rec["Total Length of Fwd Packets"] += pkt_len
                rec["_fwd_lengths"].append(pkt_len)
            if dport:
                rec["Total Backward Packets"] += 1
                rec["Total Length of Bwd Packets"] += pkt_len
                rec["_bwd_lengths"].append(pkt_len)

            rec["_pkt_count"] += 1
            rec["flags"] = flags
        except Exception:
            continue

    rows = []
    now = time.time()
    for rec in flows.values():
        fwd_mean = sum(rec["_fwd_lengths"]) / len(rec["_fwd_lengths"]) if rec["_fwd_lengths"] else 0
        bwd_mean = sum(rec["_bwd_lengths"]) / len(rec["_bwd_lengths"]) if rec["_bwd_lengths"] else 0
        total_bytes = rec["Total Length of Fwd Packets"] + rec["Total Length of Bwd Packets"]
        flow_duration = max(now - rec["_first_ts"], 0.001)
        rows.append({
            "src_ip": rec["src_ip"],
            "dst_ip": rec["dst_ip"],
            "proto": rec["proto"],
            "sport": rec["sport"],
            "dport": rec["dport"],
            "flags": rec["flags"],
            "Flow Duration": flow_duration,
            "Total Fwd Packets": rec["Total Fwd Packets"],
            "Total Backward Packets": rec["Total Backward Packets"],
            "Total Length of Fwd Packets": rec["Total Length of Fwd Packets"],
            "Total Length of Bwd Packets": rec["Total Length of Bwd Packets"],
            "Fwd Packet Length Mean": fwd_mean,
            "Bwd Packet Length Mean": bwd_mean,
            "Flow Bytes/s": total_bytes / flow_duration,
            "Flow Packets/s": rec["_pkt_count"] / flow_duration,
        })
    return pd.DataFrame(rows)
