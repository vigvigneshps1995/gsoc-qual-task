// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define KEY_SIZE 32
#define NUM_REGISTERS 1024
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TCP_FIN_MASK = 0x01;
const bit<8> TCP_SYN_MASK = 0x02;
    

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    bit<32> pkt_count;
    bit<32> byte_count;
    bit<32> avg_pkt_size;
    bit<32> duration;
    bit<32> avg_iat;
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<10> flow_id;
    bit<8>  result;
    bit<1>  apply_classifier;
}

struct digest_msg {
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8>  protocol;
    bit<8>  result;
    bit<32> pkt_count;
    bit<32> byte_count;
    bit<32> avg_pkt_size;
    bit<32> duration;
    bit<32> avg_iat;
    bit<10> flow_id;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // register definition
    register<bit<32>>(NUM_REGISTERS) pkt_count;
    register<bit<32>>(NUM_REGISTERS) byte_count;
    register<bit<32>>(NUM_REGISTERS) avg_pkt_size;
    register<bit<48>>(NUM_REGISTERS) avg_iat;

    register<bit<48>>(NUM_REGISTERS) first_pkt_ts;
    register<bit<48>>(NUM_REGISTERS) prev_pkt_ts;

    action compute_flow_id() {
        bit<32> hash_out;
        hash(hash_out,
            HashAlgorithm.crc32,
            (bit<32>)0x0,
            {
                meta.src_addr,
                meta.dst_addr,
                (bit<32>)meta.src_port,
                (bit<32>)meta.dst_port,
                (bit<32>)hdr.ipv4.protocol
            },
            (bit<32>)0xFFFFFFFF);

        // use only 10 LSB bits
        meta.flow_id = hash_out[9:0];
    }

    action store_pkts_and_bytes_count() {
        pkt_count.read(meta.pkt_count, (bit<32>)meta.flow_id);
        byte_count.read(meta.byte_count, (bit<32>)meta.flow_id);
        
        meta.pkt_count = meta.pkt_count + 1;
        meta.byte_count = meta.byte_count + standard_metadata.packet_length;
        //meta.avg_pkt_size = meta.byte_count / meta.pkt_count;

        pkt_count.write((bit<32>)meta.flow_id, meta.pkt_count);
        byte_count.write((bit<32>)meta.flow_id, meta.byte_count);
    }

    action compute_avg_pkt_size() {
        avg_pkt_size.read(meta.avg_pkt_size, (bit<32>)meta.flow_id);
        meta.avg_pkt_size = (meta.avg_pkt_size  >> 4) + standard_metadata.packet_length;

        avg_pkt_size.write((bit<32>)meta.flow_id, meta.avg_pkt_size);
    }

    action store_first_pkt_ts() {
        first_pkt_ts.write((bit<32>)meta.flow_id, standard_metadata.ingress_global_timestamp);
        prev_pkt_ts.write((bit<32>)meta.flow_id, standard_metadata.ingress_global_timestamp);
    }
    
    action compute_flow_duration() {
        bit<48> pkt_ts; 
        bit<48> duration;
        first_pkt_ts.read(pkt_ts, (bit<32>)meta.flow_id);
        duration = (standard_metadata.ingress_global_timestamp - pkt_ts) >> 20;        // convert to milliseconds

        meta.duration = (bit<32>)duration;
    }
    
    action compute_iat() {
        bit<48> prev_ts;
        bit<48> iat;
        avg_iat.read(iat, (bit<32>)meta.flow_id);
        prev_pkt_ts.read(prev_ts, (bit<32>)meta.flow_id);
        iat = (iat >> 4) + ((standard_metadata.ingress_global_timestamp - prev_ts) >> 2);

        meta.avg_iat = iat[31:0];                                                    // take only LSB bits
        avg_iat.write((bit<32>)meta.flow_id, iat);
        prev_pkt_ts.write((bit<32>)meta.flow_id, standard_metadata.ingress_global_timestamp);
    }

    action write_result(bit<8> result) {
        meta.result = result;
    }

    table classifier {
        key = {
            // meta.pkt_count: exact;
            meta.byte_count: exact;
            meta.avg_pkt_size: exact;
            // meta.duration: exact;
            meta.avg_iat: exact;
        }
        actions = {
            write_result;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action send_digest_msg() {
        digest_msg msg;
        msg.src_addr = meta.src_addr;
        msg.dst_addr = meta.dst_addr;
        msg.src_port = meta.src_port;
        msg.dst_port = meta.dst_port;
        msg.protocol = hdr.ipv4.protocol;
        msg.result = meta.result;

        msg.pkt_count =  meta.pkt_count;
        msg.byte_count = meta.byte_count;
        msg.avg_pkt_size = meta.avg_pkt_size;
        msg.duration = meta.duration;
        msg.avg_iat = meta.avg_iat;
        msg.flow_id = meta.flow_id;

        digest<digest_msg>(1, msg);
    }

    apply {

        if (hdr.ipv4.isValid()) {

            meta.src_addr = hdr.ipv4.srcAddr;
            meta.dst_addr = hdr.ipv4.dstAddr;

            // process TCP 
            if (hdr.tcp.isValid()) {

                meta.src_port = hdr.tcp.srcPort;
                meta.dst_port = hdr.tcp.dstPort;
                
                compute_flow_id();

                store_pkts_and_bytes_count();

                compute_avg_pkt_size();

                if ((hdr.tcp.flags & TCP_SYN_MASK) == 1) {           // first packet 
                    store_first_pkt_ts();
                } else if ((hdr.tcp.flags & TCP_FIN_MASK) == 1) {    // last packet
                    compute_flow_duration();
                    compute_iat();
                    meta.apply_classifier = 1;
                } else {                                             // all other packets
                    compute_iat();
                }
            }

            // process UDP
            if (hdr.udp.isValid()) {

                meta.src_port = hdr.udp.srcPort;
                meta.dst_port = hdr.udp.dstPort;
                
                compute_flow_id();
                
                store_pkts_and_bytes_count();
                
                compute_avg_pkt_size();

                if (meta.pkt_count == 1) {                            // first packet 
                    store_first_pkt_ts();
                } else {                                              // all other packets

                    // since there is no way to know the last packet in udp flows
                    // update flow features for all intermediate packets and run 
                    // classifier for all packets. However, a sampling based
                    // approch can also be implemented here.

                    compute_flow_duration();
                    compute_iat();
                    meta.apply_classifier = 1;
                }
            }
        }

        if (meta.apply_classifier == 1) {
            classifier.apply();
            send_digest_msg();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
