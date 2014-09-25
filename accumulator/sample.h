#pragma

#include "types.h"
#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "udp.h"

typedef struct sample {
    ethernet_frame ethernet;
    union {
        struct {
            ipv4_packet packet;
            union {
                tcp_packet tcp;
                udp_packet udp;
            };
        } ipv4;
    };
} sample;

#if 0
typedef struct sample {
    struct timeval timestamp;
    u16 frame_size;
    u8 mac_dst[6];
    u8 mac_src[6];
    u16 ethertype;
    union {
        struct {
            u8 src[4];
            u8 dst[4];
            u16 total_length;
            u8 protocol;
        } ipv4;
        struct {
            u8 src[16];
            u8 dst[16];
            u16 payload_length;
            u8 next_header;
        } ipv6;
    };

    union {
        struct {
            u8 src[2];
            u8 dst[2];
            u8 data_offset;
        } tcp;
        struct {
            u8 src[2];
            u8 dst[2];
            u8 length[2];
        } udp;
    };
} sample;
#endif

