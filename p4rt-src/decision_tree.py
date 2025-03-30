#!/usr/bin/env python3

import argparse
import json
import contextlib
import p4runtime_sh.shell as p4sh

CFG_DIR = "cfg"
BRIDGE_ID = 1

# Fields expected in the rules
MATCH_FIELDS = [
               #"pkt_count", 
                "byte_count", 
                "avg_pkt_size", 
                # "duration", 
                "avg_iat"]

# Float fields that need to be scaled to int for exact match
FLOAT_SCALES = {
    "avg_iat": 1000,    # 0.005 → 5
    "duration": 1000    # 0.02 → 20
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decision Tree Controller')
    parser.add_argument('--grpc-port', required=True, help='GRPC Port (e.g., 50001)')
    parser.add_argument('--topo-config', required=True, help='Path to topology config (e.g., topo/2.json)')
    args = parser.parse_args()

    grpc_port = args.grpc_port
    switch_name = f"decision_tree-{grpc_port}"

    # Load decision tree rules from topo
    with open(args.topo_config, 'r') as f:
        topo = json.load(f)

    rules = topo.get("decision_tree_rules", {}).get(grpc_port, [])
    if not rules:
        print(f"[!] No decision tree rules found in topo config for port {grpc_port}")
        exit(1)

    # Setup P4Runtime shell
    p4sh.setup(
        device_id=BRIDGE_ID,
        grpc_addr=f"127.0.0.1:{grpc_port}",
        election_id=(0, 1),
        config=p4sh.FwdPipeConfig(
            f"{CFG_DIR}/{switch_name}-p4info.txt",
            f"{CFG_DIR}/{switch_name}.json"
        )
    )

    print(f"[✓] Connected to {switch_name} (gRPC {grpc_port})")
    print(f"[+] Installing {len(rules)} decision tree rules...\n")

    for rule in rules:
        try:
            table_entry = p4sh.TableEntry("MyIngress.classifier")(action="MyIngress.write_result")

            for field in MATCH_FIELDS:
                print(f"Field: {field}")
                val = rule.get(field, 0)  # Use 0 if not present in rule
                if field in FLOAT_SCALES:
                    val = int(val * FLOAT_SCALES[field])
                    print(f"  Scaled: {val}")
                table_entry.match[f"meta.{field}"] = str(val)


            table_entry.match["hdr.tcp.flags"] = "0x01"  # Match on FIN
            table_entry.action["result"] = str(rule["result"])
            table_entry.insert()

            cond = " AND ".join([f"{k}={rule[k]}" for k in rule if k != "result"])
            print(f"[✓] Rule installed: if {cond} AND FIN → result = {rule['result']}")

        except Exception as e:
            print(f"[✗] Failed to insert rule {rule}: {e}\n")

    print("\n[✓] Controller running. Press Ctrl+C to exit.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[!] Controller shutting down.")
        p4sh.teardown()
