#!/usr/bin/env python3

from scapy.all import *
import argparse
import time

def send_pcap(pcap_file, iface="h1-eth0", delay=0):
    print(f"Sending packets from {pcap_file} on interface {iface}...\n")
    packets = rdpcap(pcap_file)

    for i, pkt in enumerate(packets):
        sendp(pkt, iface=iface, verbose=False)
        print(f"Sent packet #{i + 1}\n")
        if delay > 0:
            time.sleep(delay)

    print(f"Done! {len(packets)} packets sent.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay packets from a PCAP file.")
    parser.add_argument("--pcap", default="network_trace.pcap", required=True, help="Path to .pcap file")
    # parser.add_argument("--iface", default="eth0", help="Interface to send on (default: eth0)")
    # parser.add_argument("--delay", type=float, default=0, help="Delay between packets in seconds")
    args = parser.parse_args()

    send_pcap(args.pcap)
