#pragma once

#include "types.h"
#include "type_conversion.h"
#include <stdio.h>

typedef struct ipv4_packet {
    u8 version_ihl;
    u8 dscp_ecn;
    u8 total_length[2];
    u8 identification[2];
    u8 flags_fragment_offset[2];
    u8 time_to_live;
    u8 protocol;
    u8 header_checksum[2];
    u8 src_ip_address[4];
    u8 dst_ip_address[4];
    u8 options[0]; // if ihl > 5
} ipv4_packet;

#define IPV4_PROTOCOL_ICMP 1
#define IPV4_PROTOCOL_IGMP 2
#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17
#define IPV4_PROTOCOL_ENCAP 41
#define IPV4_PROTOCOL_OSPF 89
#define IPV4_PROTOCOL_SCTP 132

#define IPV4_ADDRESS_STRING_LEN 15

inline void ipv4_address_to_string(u8 const (*p)[4], char* buf, size_t buflen) {
    snprintf(buf, buflen, "%hhu.%hhu.%hhu.%hhu", (*p)[0], (*p)[1], (*p)[2], (*p)[4]);
}

inline u8 ipv4_packet_ihl(ipv4_packet const* p) {
    return p->version_ihl & 0xf;
}

void ipv4_packet_print(ipv4_packet const* p);

