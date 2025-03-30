#!/usr/bin/env python3

import json
import os
import joblib
import numpy as np
from sklearn.tree import _tree
from itertools import product

# === Config ===
TOPO_JSON_PATH = "topo/linear,2.json"
OUTPUT_JSON_PATH = TOPO_JSON_PATH
GRPC_PORT = "50001"
FEATURES = ["pkt_count", "byte_count", "avg_pkt_size", "duration", "avg_iat"]
MAX_COMBINATIONS = 10  # Limit rule generation to this

# Binning resolution
BINS = {
    "pkt_count": 5,
    "byte_count": 200,
    "avg_pkt_size": 10,
    "duration": 0.05,
    "avg_iat": 0.005
}

def bin_value(value, bin_size):
    return round((value // bin_size) * bin_size, 4) if isinstance(bin_size, float) else int((value // bin_size) * bin_size)

def extract_simple_rules(clf):
    tree = clf.tree_
    rules = []

    def recurse(node, conditions):
        if tree.feature[node] != _tree.TREE_UNDEFINED:
            name = FEATURES[tree.feature[node]]
            threshold = tree.threshold[node]
            recurse(tree.children_left[node], conditions + [(name, "<=", threshold)])
            recurse(tree.children_right[node], conditions + [(name, ">", threshold)])
        else:
            pred = int(np.argmax(tree.value[node][0]))
            rules.append({"conditions": conditions, "result": pred})

    recurse(0, [])
    return rules

def generate_exact_matches(rules, max_combinations):
    exact_rules = []
    for rule in rules:
        bins_per_feature = {}
        for fname, op, threshold in rule["conditions"]:
            bin_size = BINS[fname]
            if op == "<=":
                vals = [bin_value(v, bin_size) for v in np.linspace(0, threshold, num=2)]
            else:
                vals = [bin_value(v, bin_size) for v in np.linspace(threshold + bin_size, threshold + 2 * bin_size, num=2)]
            bins_per_feature[fname] = list(set(vals))

        # Cartesian product
        combos = list(product(*bins_per_feature.values()))
        keys = list(bins_per_feature.keys())

        for combo in combos:
            match = dict(zip(keys, combo))
            match["result"] = rule["result"]
            exact_rules.append(match)
            if len(exact_rules) >= max_combinations:
                return exact_rules
    return exact_rules

# === Main ===
clf = joblib.load("output/dt_model.pkl")
raw_rules = extract_simple_rules(clf)
exact_rules = generate_exact_matches(raw_rules, MAX_COMBINATIONS)

# Load or create topo JSON
if os.path.exists(TOPO_JSON_PATH):
    with open(TOPO_JSON_PATH) as f:
        topo = json.load(f)
else:
    topo = {
        "switch": {
            GRPC_PORT: {
                "mcast": {"id": 1, "ports": [1, 2]},
                "vlan_id_to_ports": {"100": [1], "200": [2]}
            }
        },
        "host": {
            "h1s1": {"vlan": 100},
            "h2s1": {"vlan": 200}
        },
        "decision_tree_rules": {}
    }

topo["decision_tree_rules"][GRPC_PORT] = exact_rules

# Save
os.makedirs(os.path.dirname(OUTPUT_JSON_PATH), exist_ok=True)
with open(OUTPUT_JSON_PATH, "w") as f:
    json.dump(topo, f, indent=2)

print(f"[✓] Inserted {len(exact_rules)} simplified demo rules into {OUTPUT_JSON_PATH}")
