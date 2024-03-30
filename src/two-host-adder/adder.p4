/* -*- P4_16 -*- */
/*
 * Define the headers the program will recognize
 */
#include <core.p4>
#include <v1model.p4>
//const type
const bit<16>  TYPE_ADDER   = 1234;
const bit<16>  TYPE_IPV4    = 0x0800;
const bit<16>  TYPE_ARP     = 0x0806;
const bit<8>   TYPE_TCP     = 0x06;
const bit<8>   TYPE_UDP     = 0x11;
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

/*
        1               2               3               4
Ethernet header
+---------------+---------------+---------------+---------------+
|                         dst_addr<48>                          |
+---------------+---------------+---------------+---------------+
|                         src_addr<48>                          |
+---------------+---------------+---------------+---------------+
|           ether_type          |                               |
+---------------+---------------+---------------+---------------+   

IP header
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

TCP header
+---------------+---------------+---------------+---------------+   
|            Src_port           |            Dst_port           |
+---------------+---------------+---------------+---------------+
|                            seq_num                            |
+---------------+---------------+---------------+---------------+
|                            ack_num                            |
+---------------+---------------+---------------+---------------+
|dt_of<4>|re<3>|   ctl_fl<9>    |          window_size<16>      |
+---------------+---------------+---------------+---------------+
|            Checksum           |           ugrent_num          |
+---------------+---------------+---------------+---------------+
|                            options                            |   
+---------------+---------------+---------------+---------------+

Adder header
+---------------+---------------+---------------+---------------+
|      'A'      |      'D'      | VERSION_MAJOR | VERSION_MINOR |
+---------------+---------------+---------------+---------------+
|    SEQ_NUM    |   IS_RESULT   |                               |
+---------------------------------------------------------------+
|                              NUM                              |
+---------------------------------------------------------------+
*/
//TCPP+IP+ETHENET header
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
header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seq_num;
    bit<32> ack_num;
    bit<4>  data_offset;
    bit<3>  reserved;
    bit<9>  ctl_flag;
    bit<16> window_size;
    bit<16> checksum;
    bit<16> urgent_num;
}
//tcp option type
//kind = 0 end of option list
header Tcp_option_end_h { 
    bit<8> kind;
}
//kind = 1 no operation
header Tcp_option_nop_h {  
    bit<8> kind;
}
//kind = 2 max segment size
header Tcp_option_ss_h {
    bit<8>  kind;
    bit<8>  length;
    bit<16> max_segment_size;
}
//kind = 3 shift count
header Tcp_option_s_h {
    bit<8>  kind;
    bit<8>  length;
    bit<8>  shift_count;
}
//kind = 4  sack permitted
header Tcp_option_sp_h {
    bit<8> kind;
    bit<8> length;
}
//kind = 5 sack
header Tcp_option_sack_h {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}
//kind = 8 timestamp
header Tcp_option_ts_h {
    bit<8> kind;
    bit<8> length;
    bit<32> ts_val;
    bit<32> ts_ecr;
}
header_union Tcp_option_h {
    Tcp_option_end_h  end;
    Tcp_option_nop_h  nop;
    Tcp_option_ss_h   ss;
    Tcp_option_s_h    s;
    Tcp_option_sp_h   sp;
    Tcp_option_sack_h sack;
    Tcp_option_ts_h   ts;
}

// Defines a stack of 10 tcp options
typedef Tcp_option_h[10] Tcp_option_stack;

header Tcp_option_padding_h {
    varbit<256> padding;
}

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
    //udp_t        udp;
    tcp_t        tcp;
    Tcp_option_stack tcp_options_vec;
    Tcp_option_padding_h tcp_options_padding;
    adder_t      adder;
}
error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

struct Tcp_option_sack_top
{
    bit<8> kind;
    bit<8> length;
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
parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         out Tcp_option_stack vec,
                         out Tcp_option_padding_h padding)
{
    bit<7> tcp_hdr_bytes_left;
    
    state start {
        // RFC 793 - the Data Offset field is the length of the TCP
        // header in units of 32-bit words.  It must be at least 5 for
        // the minimum length TCP header, and since it is 4 bits in
        // size, can be at most 15, for a maximum TCP header length of
        // 15*4 = 60 bytes.
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        // always true here: 0 <= tcp_hdr_bytes_left <= 40
        transition next_option;
    }
    state next_option {
        transition select(tcp_hdr_bytes_left) {
            0 : accept;  // no TCP header bytes left
            default : next_option_part2;
        }
    }
    state next_option_part2 {
        // precondition: tcp_hdr_bytes_left >= 1
        transition select(b.lookahead<bit<8>>()) {
            0: parse_tcp_option_end;  // end
            1: parse_tcp_option_nop;  //no operation
            2: parse_tcp_option_ss;   // max segment size
            3: parse_tcp_option_s;    // window scale(shift)
            4: parse_tcp_option_sp;   //sack permitted
            5: parse_tcp_option_sack; //sack
            8: parse_tcp_option_ts;   //timestamp
        }
    }
    state parse_tcp_option_end {
        b.extract(vec.next.end);
        // TBD: This code is an example demonstrating why it would be
        // useful to have sizeof(vec.next.end) instead of having to
        // put in a hard-coded length for each TCP option.
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition consume_remaining_tcp_hdr_and_accept;
    }
    state parse_tcp_option_nop { 
        b.extract(vec.next.nop);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition next_option;
    }
    state parse_tcp_option_ss {
        verify(tcp_hdr_bytes_left >= 4, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 4;
        b.extract(vec.next.ss);
        transition next_option;
    }
    state parse_tcp_option_s {
        verify(tcp_hdr_bytes_left >= 3, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 3;
        b.extract(vec.next.s);
        transition next_option;
    }
    state parse_tcp_option_sp {
        verify(tcp_hdr_bytes_left >= 2, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 2;
        b.extract(vec.next.sp);
        transition next_option;
    }
    state parse_tcp_option_sack {
        bit<8> n_sack_bytes = b.lookahead<Tcp_option_sack_top>().length;
        // I do not have global knowledge of all TCP SACK
        // implementations, but from reading the RFC, it appears that
        // the only SACK option lengths that are legal are 2+8*n for
        // n=1, 2, 3, or 4, so set an error if anything else is seen.
        verify(n_sack_bytes == 10 || n_sack_bytes == 18 ||
               n_sack_bytes == 26 || n_sack_bytes == 34,
               error.TcpBadSackOptionLength);
        verify(tcp_hdr_bytes_left >= (bit<7>) n_sack_bytes,
               error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - (bit<7>) n_sack_bytes;
        b.extract(vec.next.sack, (bit<32>) (8 * n_sack_bytes - 16));
        transition next_option;
    }
    state parse_tcp_option_ts {
        verify(tcp_hdr_bytes_left >= 10, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 10;
        b.extract(vec.next.ts);
        transition next_option;
    }
    state consume_remaining_tcp_hdr_and_accept {
        // A more picky sub-parser implementation would verify that
        // all of the remaining bytes are 0, as specified in RFC 793,
        // setting an error and rejecting if not.  This one skips past
        // the rest of the TCP header without checking this.

        // tcp_hdr_bytes_left might be as large as 40, so multiplying
        // it by 8 it may be up to 320, which requires 9 bits to avoid
        // losing any information.
        b.extract(padding, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
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
            //TYPE_UDP  : parse_udp;
            TYPE_TCP  : parse_tcp;
            default   : accept;
        }
    }
    // state parse_udp{
    //     packet.extract(hdr.udp);
    //     transition select(hdr.udp.dstPort) {
    //         TYPE_ADDER : check_adder;
    //         default    : accept;
    //     }
    // }
    state parse_tcp{
        packet.extract(hdr.tcp);
        Tcp_option_parser.apply(packet, hdr.tcp.data_offset,
                                hdr.tcp_options_vec, hdr.tcp_options_padding);
        transition check_adder;
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
            }
            // the register is occupied by another host
            else if (valid == 1 && srcPort != author) { 
                // calculate the result
                bit<32> result = num + hdr.adder.num;
                // save the result in header and clear the register
                save_result(result, hdr.adder.seq_num);
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
            //hdr.ipv4.srcAddr = 0x0a000101;
        }
    }
    apply {
        if (standard_metadata.egress_port == standard_metadata.ingress_port) drop();
        if(hdr.adder.isValid()){
            revise_dstIP();
        }
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
        //packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options_vec);
        packet.emit(hdr.tcp_options_padding);
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
