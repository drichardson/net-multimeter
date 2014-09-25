#pragma once

typedef struct tcp_packet {
    u8 src_port[2];
    u8 dst_port[2];
    u8 sequence_number[4];
    u8 acknowledgement_number[4];
    u8 data_offset_reserved_flag1;
    u8 flag2_thru_9;
    u8 window_size[2];
    u8 checksum[2];
    u8 urgent_pointer[2];
    u8 options[0]; // if data offset > 5
} tcp_packet;

inline void tcp_packet_print(tcp_packet const* tcp) {
    printf("TCP: src_port=%hu, dst_port=%hu", u8s_to_u16(&tcp->src_port),
            u8s_to_u16(&tcp->dst_port));
}


