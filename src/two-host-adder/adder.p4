/* -*- P4_16 -*- */
/*
 * Define the headers the program will recognize
 */
#include <core.p4>
#include <v1model.p4>

/*
        1               2               3               4
+---------------+---------------+---------------+---------------+
                          dst_addr<48>                          |
+---------------+---------------+---------------+---------------+
|                         src_addr<48>                          |
+---------------+---------------+---------------+---------------+
|           ether_type          |                               |
+---------------+---------------+---------------+---------------+   


+---------------+---------------+---------------+---------------+                               
|   version     |       ihl     |    diffserv   |   totalLen    |
+---------------+---------------+---------------+---------------+
|        identification         | flags<3>|      fragOffset<13> |
+---------------+---------------+---------------+---------------+
|       ttl     |   protocol    |           hdrChecksum         |
+---------------+---------------+---------------+---------------+
|                            srcAddr                            |
+---------------+---------------+---------------+---------------+
|                            dstAddr                            |
+---------------+---------------+---------------+---------------+


+---------------+---------------+---------------+---------------+   
|            Src_port           |            Dst_port           |
+---------------+---------------+---------------+---------------+
|           Length              |             Checksum          |
+---------------+---------------+---------------+---------------+
|      'A'      |      'D'      | VERSION_MAJOR | VERSION_MINOR |
+---------------+---------------+---------------+---------------+
|    SEQ_NUM    |   IS_RESULT   |                               |
+---------------------------------------------------------------+
|                              NUM                              |
+---------------------------------------------------------------+
*/
//UDP+IP+ETHENET header
/*
 * Standard Ethernet header
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}
//const type
const bit<16>  TYPE_ADDER   = 1234;
const bit<16>  TYPE_IPV4    = 0x0800;
const bit<16>  TYPE_ARP     = 0x0806;
const bit<8>  TYPE_UDP      = 0x11;
/*
 * This is a custom protocol header for the calculator. We'll use
 * etherType 0x1234 for it (see parser)
 */
const bit<8>  ADDER_A             = 0x41;
const bit<8>  ADDER_D             = 0x44;
const bit<8>  ADDER_VERSION_MAJOR = 0x00;
const bit<8>  ADDER_VERSION_MINOR = 0x01;

// the address of hosts
const bit<48> HOST_1_ADDR         = 0x080000000101;
const bit<48> HOST_2_ADDR         = 0x080000000102;
const bit<48> DST_MAC             = 0x080000000103;
const bit<32> DST_IP              = 0xa0000103;
const bit<9>  HOST_1_PORT         = 1;
const bit<9>  HOST_2_PORT         = 2;
const bit<9>  DST_PORT            = 3;

// buffer size
const bit<32> BUFFER_SIZE         = 256;



header adder_t {
    bit<8>  a;
    bit<8>  d;
    bit<8>  ver_maj;
    bit<8>  ver_min;
    bit<8>  seq_num;
    bit<8>  is_result;
    bit<32> num;
}

/*
 * All headers, used in the program needs to be assembled into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    adder_t      adder;
}

/*
 * All metadata, globally used in the program, also  needs to be assembled
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */

struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        /*packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ADDER_ETYPE : check_adder;
            default     : accept;
        }*/
        transition parse_ethernet;
    }
    state parse_ethernet{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4     : parse_ipv4;
            default       : accept;
        }
    }
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP  : parse_udp;
            default   : accept;
        }
    }
    state parse_udp{
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            TYPE_ADDER : check_adder;
            default    : accept;
        }
    }
    state check_adder {
        transition select(packet.lookahead<adder_t>().a,
        packet.lookahead<adder_t>().d,
        packet.lookahead<adder_t>().ver_maj,
        packet.lookahead<adder_t>().ver_min) {
            (ADDER_A, ADDER_D, ADDER_VERSION_MAJOR, ADDER_VERSION_MINOR) : parse_adder;
            default                                                      : accept;
        }
    }

    state parse_adder {
        packet.extract(hdr.adder);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(BUFFER_SIZE) num_buffer;
    register<bit<1>> (BUFFER_SIZE) num_buffer_valid;
    register<bit<9>> (BUFFER_SIZE) num_buffer_author;

    action save_result(bit<32> result, bit<8> seq_num) {
        // save the result in header
        hdr.adder.num = result;
        hdr.adder.seq_num = seq_num;
    }
    action save_num(bit<32> index, bit<32> num, bit<9> author) {
        num_buffer.write(index, num);
        num_buffer_valid.write(index, 1);
        num_buffer_author.write(index, author);
    }
    action delete_num(bit<32> index) {
        num_buffer.write(index, 0);
        num_buffer_valid.write(index, 0);
        num_buffer_author.write(index, 0);
    }

    action drop() {
        // drop the packet
        mark_to_drop(standard_metadata);
    }

    /*action send_ack(bit<9> port, bit<8> is_result) {
        // send the ack back
        // hdr.adder.num = num; (remain the same)
        // hdr.adder.seq_num = seq_num; (remain the same)
        hdr.adder.is_result = is_result;
        bit<48> tmp = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp;
        hdr.ethernet.etherType = ADDER_ETYPE;
        standard_metadata.egress_spec = port;
    }*/

    action send_result(bit<9> port) {
        // forward the packet to the destination
        hdr.ethernet.dstAddr = DST_MAC;
        standard_metadata.egress_spec = port;
    }
    action multicast() {
        standard_metadata.mcast_grp = 1;
    }
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
    }
    table ipv4_lookup{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
           ipv4_forward;
           drop;
           multicast;
        }
        size = 1024;
        default_action = multicast;
    }
    apply {
        if (hdr.adder.isValid()) {
            if(standard_metadata.ingress_port==3){
                multicast();
            }
            else{

            // read the number from the register
            bit<32> num;
            bit<1>  valid;
            bit<9>  author;
            bit<32> index;
            bit<32> base = 0;
            bit<9>  srcPort = standard_metadata.ingress_port;
            hash(index, HashAlgorithm.crc32, base, {hdr.adder.seq_num}, BUFFER_SIZE - 1);
            num_buffer.read(num, index);
            num_buffer_valid.read(valid, index);
            num_buffer_author.read(author, index);

            // based on valid, determine what to do:
            // 1. if valid == 0, then the register is empty, so we need to
            //    buffer the number and wait for the next packet
            // 2. if valid == 1, then the register is full, so we can
            //    proceed with the calculation
            // the register is empty
            if (valid == 0) { 
                // save the number in the register
                save_num(index, hdr.adder.num, srcPort);
                //send_ack(srcPort, 0);
            }
            else if (valid == 0) { 
                // save the number in the register
                save_num(index, hdr.adder.num, srcPort);
                //send_ack(srcPort, 0);
            }
            // the register is occupied by another host
            else if (valid == 1 && srcPort != author) { 
                // calculate the result
                bit<32> result = num + hdr.adder.num;
                // save the result in header
                save_result(result, hdr.adder.seq_num);
                // clear the register
                delete_num(index);
                send_result(DST_PORT);
            }
            else { // the register is occupied by the same host
                // drop the packet
                drop();
            }
            }
        } 
        else {
            ipv4_lookup.apply();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action revise_dstIP(){
        if(standard_metadata.egress_port==1){
            hdr.ipv4.dstAddr = 0x0a000101;
        }
        else if(standard_metadata.egress_port==2){
            hdr.ipv4.dstAddr = 0x0a000102;
        }
        else if(standard_metadata.egress_port==3){
            hdr.ipv4.dstAddr = 0x0a000103;
        }
    }
    apply {
        if (standard_metadata.egress_port == standard_metadata.ingress_port) drop();
        else revise_dstIP();
    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.adder);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
