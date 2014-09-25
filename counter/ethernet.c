#include "ethernet.h"

#include "mac.h"

void
ethernet_frame_print(ethernet_frame const* e) {
    char src[MAC_ADDRESS_STRING_LEN];
    char dst[MAC_ADDRESS_STRING_LEN];
    mac_address_to_string(&e->src_mac_address, src, sizeof(src));
    mac_address_to_string(&e->dst_mac_address, dst, sizeof(dst));
    printf("Ethernet: src_mac=%s, dst_mac=%s, ethertype=0x%hu",
            src, dst, ethernet_frame_ethertype(e));
}

