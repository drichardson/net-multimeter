#pragma once

typedef struct udp_packet {
    u8 src_port[2];
    u8 dst_port[2];
    u8 length[2];
    u8 checksum[2];
} udp_packet;

inline void udp_packet_print(udp_packet const* udp) {
    printf("UDP: src_port=%hu, dst_port=%hu", u8s_to_u16(&udp->src_port),
            u8s_to_u16(&udp->dst_port));
}


