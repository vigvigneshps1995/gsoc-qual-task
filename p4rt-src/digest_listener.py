#!/usr/bin/env python3

import argparse
import json
import contextlib
import p4runtime_sh.shell as p4sh
from p4.v1.p4runtime_pb2 import Update
import ipaddress

DIGEST_NAME="digest_msg"
CFG_DIR = "cfg"
BRIDGE_ID = 1


def get_addr(data):
    if (len(data) == 4):
        return str(ipaddress.IPv4Address(data))
    else:
       return ""

def get_int(data):
    return int.from_bytes(data, byteorder='big')

def get_proto(data):
    proto = int.from_bytes(data, byteorder='big')
    switch = {
        6:  "TCP",
        17: "UDP"
    }
    return switch.get(proto, "UNKNOWN")

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Decision Tree Controller')
    parser.add_argument('--grpc-port', required=True, help='GRPC Port (e.g., 50001)')
    args = parser.parse_args()
    
    grpc_port = args.grpc_port
    switch_name = f"decision_tree-{grpc_port}"
    
    # Setup P4Runtime shell
    p4sh.setup(
        device_id=BRIDGE_ID,
        grpc_addr=f"127.0.0.1:{grpc_port}",
        election_id=(0, 2),
        config=p4sh.FwdPipeConfig(
            f"{CFG_DIR}/{switch_name}-p4info.txt",
            f"{CFG_DIR}/{switch_name}.json"
        )
    )

    digest_id = p4sh.DigestEntry(DIGEST_NAME).digest_id

    update = Update()
    update.type = p4sh.p4runtime_pb2.Update.INSERT
    digest_entry = update.entity.digest_entry
    digest_entry.digest_id = digest_id
    digest_entry.config.max_timeout_ns = 0
    digest_entry.config.max_list_size = 1
    digest_entry.config.ack_timeout_ns = 0 

    p4sh.client.write_update(update)

    try:
        while True:
            msg = p4sh.client.get_stream_packet("digest")
            if not msg is None:
                members = msg.digest.data[0].struct.members
                src_addr = get_addr(members[0].bitstring)
                dst_addr = get_addr(members[1].bitstring)
                src_port = get_int(members[2].bitstring)
                dst_port = get_int(members[3].bitstring)
                proto = get_proto(members[4].bitstring)
                result = get_int(members[5].bitstring)
                #print("src_add: %s, dst_addr: %s, src_port: %d, dst_port: %d, proto: %s -> result: %d" % (src_addr, dst_addr, src_port, dst_port, proto, result))


                pkts = get_int(members[6].bitstring)
                _bytes = get_int(members[7].bitstring)
                pkt_size = get_int(members[8].bitstring)
                duration = get_int(members[9].bitstring)
                iat = get_int(members[10].bitstring)
                flow_id = get_int(members[11].bitstring)
                print("flow-id:%d,  pkts: %d, bytes: %d, pkt_size: %d, duration: %d, IAT: %d" % (flow_id, pkts, _bytes, pkt_size, duration, iat))
    except KeyboardInterrupt:
        print("Exiting...")
        p4sh.teardown()
