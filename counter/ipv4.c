#include "ipv4.h"
#include <stdio.h>

void ipv4_packet_print(ipv4_packet const* p) {
    char src[IPV4_ADDRESS_STRING_LEN];
    char dst[IPV4_ADDRESS_STRING_LEN];
    ipv4_address_to_string(&p->src_ip_address, src, sizeof(src));
    ipv4_address_to_string(&p->dst_ip_address, dst, sizeof(dst));

    printf("IPv4: ihl=%hhu, total_len=%hu, protocol=%hhX, src=%s, dst=%s",
            ipv4_packet_ihl(p), u8s_to_u16(&p->total_length),
            p->protocol, src, dst);
}

