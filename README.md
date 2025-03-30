# GSOC qual task: P4 + Mininet Docker Environment

## Overview

This repository demonstrates how **machine learning models**, specifically **decision trees**, can be compiled into data plane rules for deployment on **P4-programmable switches**.

### Components

- **Mininet**  
  A lightweight network emulator used to create virtual network topologies consisting of hosts, switches, and controllers. It allows fast prototyping and testing of P4 programs in a controlled environment.

- **P4 (Programming Protocol-Independent Packet Processors)**  
  A domain-specific language designed to describe how packets are processed on programmable switches. It enables full control over parsing, matching, and action execution on packet headers.

- **P4Runtime (P4RT)**  
  An API that provides a control plane interface to P4-programmable switches. It allows the controller to dynamically install, modify, and delete table entries on the switch at runtime.

### What This Repo Does

1. **Generates synthetic packet flows** using Scapy.
2. **Extracts flow-level features** such as:
   - Packet count  
   - Byte count  
   - Average packet size  
   - Flow duration  
   - Average inter-arrival time (IAT)
3. **Trains a Decision Tree (DT)** classifier on the extracted flow features.
4. **Converts the DT logic into exact-match rules** that can be understood by a P4 switch.
5. **Installs the rules via P4Runtime** onto the switch, allowing in-network ML-based classification with explainable rules.
---

## Step 1: Clone this repository to your host machine (laptop, desktop)

Start by cloning the official P4 tutorials repo:
```bash
$ git clone 
```
---

## Step 2: Generate Packet Flows
Run the packet generator to create a `.pcap` file with synthetic traffic consisting of multiple 5-tuple TCP flows. This file will also generate a decision tree for you in the `output` directory.

```bash
$ python3 generate_pcap.py
```
---
## Step 3: Generate Controller Rules
Use the decision tree to generate rules for the controller. 

```bash
$ python3 dt_rule_gen.py
```
---

## Step 4: Run Mininet with Stratum
Use `make` to launch the Mininet + Stratum container in another terminal:
```bash
$ make mininet
```
Once started, you will see the mininet> prompt. This indicates that your virtual network is ready and running, and you can now issue commands through this prompt.
Let's try listing the hosts and switches in this network and their connectivity. Enter ...
```bash
$ mininet> net
```
Output:
```bash
mininet> net
h1 h1-eth0:s1-eth1
h2 h2-eth0:s1-eth2
s1 lo:  s1-eth1:h1-eth0 s1-eth2:h2-eth0
```

This shows three nodes in this network: `h1`, `h2`, and `s1`. For `h1` and `h2`, their `eth0` interface is connected to switch `s1` `eth1` and `eth2` interfaces, respecitvely.

**Note:** Visit http://mininet.org/walkthrough/ to learn more about Mininet and the various commands you can run inside it.


## Step 5: Run the starter code
Open another shell and run the starter code:
```bash
$ make controller name=decision-tree grpc_port=50001 topo=linear,2
```
This will:
- Read topo/linear,2.json for decision tree rules

- Connect to the P4 switch on gRPC port 50001

- Insert table entries into MyIngress.classifier for flows that match the decision tree logic

## Your task: Flow Classification and Digest Reporting in P4

1. **Modify the P4 Program**
   - Use registers to track flow-level features such as:
     - `pkt_count`
     - `byte_count`
     - `avg_pkt_size`
     - `duration`
     - `avg_iat`
   - Extract flow identifiers from 5-tuple (src IP, dst IP, src port, dst port, protocol).
   - Use `register.read()` and `register.write()` to maintain per-flow state across packets.

2. **Use Classifier Table**
   - Define a `classifier` table that matches on the flow features.
   - Implement actions like `write_result(result)` that store the classification output in metadata.

3. **Send Digest to Control Plane**
   - After classification (e.g., on FIN flag), trigger a digest message.
   - Include in the digest: 5-tuple fields and the `result`.

4. **Implement Python Receiver**
   - Write a Python script using `p4runtime-sh` or `p4runtime API` to:
     - Listen for incoming digest messages.
     - Extract and print the flow's 5-tuple and classification result.

5. **Run and Demo**
   - Generate PCAP using `generate_pcap.py`.
   - Extract features and rules with `dt_rule_gen.py`.
   - Install rules using `make controller name=decision-tree`.
   - Send packets using `send.py`.
   - Observe classification results in the Python receiver.



You now have an interpretable decision tree model compiled into P4 match-action rules,
deployed directly on a P4-enabled switch using Mininet + P4Runtime.
