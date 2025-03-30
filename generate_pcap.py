#!/usr/bin/env python3

from scapy.all import Ether, IP, TCP, wrpcap, rdpcap
import random, time
from collections import defaultdict
import pandas as pd
from sklearn.tree import DecisionTreeClassifier, export_graphviz
import joblib

NUM_FLOWS = 50
PCAP_FILE = "pcap/flows.pcap"
MODEL_FILE = "output/dt_model.pkl"
DOT_FILE = "output/tree.dot"

packets = []
flow_id_to_label = {}

base_time = time.time()

for flow_id in range(NUM_FLOWS):
    # Create unique 5-tuple
    src_ip = f"10.0.{flow_id // 5}.{flow_id % 5 + 1}"
    dst_ip = f"10.1.{flow_id // 5}.{flow_id % 5 + 1}"
    sport = 10000 + flow_id
    dport = 20000 + flow_id

    # Flow-level label
    label = random.choice([0, 1])
    flow_id_to_label[(src_ip, dst_ip, sport, dport)] = label

    # Packet characteristics
    pkt_count = random.randint(10, 30)
    iat = random.uniform(0.001, 0.01)  # inter-arrival time
    base_seq = 1000
    ack = 1
    now = base_time + flow_id

    # SYN
    pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S", seq=base_seq)
    pkt.time = now
    packets.append(pkt)
    base_seq += 1
    now += iat

    # Payload
    for i in range(pkt_count - 2):
        payload_len = random.randint(20, 200)
        payload = ("X" * payload_len).encode()
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", seq=base_seq, ack=ack)/payload
        pkt.time = now
        packets.append(pkt)
        base_seq += len(payload)
        now += iat + random.uniform(0, 0.005)

    # FIN
    pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="FA", seq=base_seq, ack=ack)
    pkt.time = now
    packets.append(pkt)

wrpcap(PCAP_FILE, packets)
print(f"[+] PCAP written to: {PCAP_FILE}")

# --- Feature extraction ---
flows = defaultdict(list)

for pkt in rdpcap(PCAP_FILE):
    if IP in pkt and TCP in pkt:
        key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        flows[key].append(pkt)

features = []

for key, pkts in flows.items():
    sizes = [len(p) for p in pkts]
    times = sorted([p.time for p in pkts])
    flow_duration = times[-1] - times[0] if len(times) > 1 else 0
    avg_iat = sum(t2 - t1 for t1, t2 in zip(times, times[1:])) / (len(times) - 1) if len(times) > 1 else 0

    features.append({
        "pkt_count": len(pkts),
        "byte_count": sum(sizes),
        "avg_pkt_size": sum(sizes) / len(sizes),
        "duration": flow_duration,
        "avg_iat": avg_iat,
        "label": flow_id_to_label.get(key, 0)
    })

df = pd.DataFrame(features)
print(f"\n[+] Extracted features for {len(df)} flows")
print(df)

labels = df.pop("label")

# --- Train and export model ---
clf = DecisionTreeClassifier(max_depth=6, random_state=42)
clf.fit(df, labels)
joblib.dump(clf, MODEL_FILE)
print(f"[+] Model saved to: {MODEL_FILE}")

with open(DOT_FILE, "w") as f:
    export_graphviz(clf, out_file=f, feature_names=df.columns, class_names=["0", "1"], filled=True)
print(f"[+] DOT file saved to: {DOT_FILE}")
