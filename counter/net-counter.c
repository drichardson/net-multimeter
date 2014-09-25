// pcap was complaining until I defined _BSD_SOURCE. _GNU_SOURCE also seems to work.
#define _BSD_SOURCE

#include "compare.h"
#include "debug.h"
#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "udp.h"
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void
die(char const* msg) {
    fputs(msg, stderr);
    exit(1);
}

static void
print_captured_data(u8 const* data, int data_len) {
    if (data_len < sizeof(ethernet_frame)) {
        printf("ppf: didn't capture enough to parse ethernet frame. len=%d\n", data_len);
        return;
    }

    ethernet_frame const* e = (ethernet_frame*)data;
    putchar('\t'); ethernet_frame_print(e); putchar('\n');

    u16 const ethertype = ethernet_frame_ethertype(e);

    if (ethertype == ETHERTYPE_IPV4) {
        if (data_len < sizeof(ethernet_frame) + sizeof(ipv4_packet)) {
            printf("ppf: didn't capture enough to parse IPv4 header. len=%d\n", data_len);
            return;
        }
        // IPv4
        ipv4_packet const* ip4 = (ipv4_packet*)(data + sizeof(ethernet_frame));
        putchar('\t'); ipv4_packet_print(ip4); putchar('\n');
        
        u8 const* payload = (((u8*)ip4)+ipv4_packet_ihl(ip4)*4);
        putchar('\t');

        switch(ip4->protocol) {
        case IPV4_PROTOCOL_ICMP:
            printf("ICMP");
            break;
        case IPV4_PROTOCOL_IGMP:
            printf("IGMP");
            break;
        case IPV4_PROTOCOL_TCP:
            tcp_packet_print((tcp_packet*)payload);
            break;
        case IPV4_PROTOCOL_UDP: 
            udp_packet_print((udp_packet*)payload);
            break;
        case IPV4_PROTOCOL_ENCAP:
            printf("ENCAP");
            break;
        case IPV4_PROTOCOL_SCTP:
            printf("SCTP");
            break;
        default:
            printf("Unknown IP protocol %hhu", ip4->protocol);
            break;
        }
        putchar('\n');
    } else if (ethertype == ETHERTYPE_IPV6) {
        // IPv6
        printf("\tIPv6\n");
    } else if (ethertype == ETHERTYPE_ARP) {
        printf("\tARP\n");
    } else {
        printf("\tUnhandled ethertype: %0xX\n", ethertype);
    }
}

int main(int argc, char const** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int rc;
    char const* source = "eth0";

    printf("libpcap version: %s\n", pcap_lib_version());

    //
    // Create new pcap
    //
    printf("Using source %s\n", source);
    pcap_t* pc = pcap_create(source, errbuf);
    if (pc == NULL) {
        fprintf(stderr, "pcap_create failed on source %s. %s\n", source, errbuf);
        exit(1);
    }   

    //
    // Configure pcap options
    //
    rc = pcap_set_snaplen(pc, 100);
    if (rc != 0) die("pcap_set_snaplen failed");
    rc = pcap_set_promisc(pc, 0);
    if (rc != 0) die("pcap_set_promisc failed");
    // 1Gbit/1s * 1s/1000ms = 1Mbit/1ms. Therefore, on a 1Gbps network, each ms
    // of read delay can fill up 1Mbit of buffer which is
    // 1Mbit*(1byte/8bit)=125k bytes per ms.
    int const read_timeout_ms = 1000;
    rc = pcap_set_timeout(pc, read_timeout_ms);
    if (rc != 0) die("pcap_set_timeout failed");
    rc = pcap_set_buffer_size(pc, 125000 * read_timeout_ms);
    if (rc != 0) die("pcap_set_buffer_size failed");

    //
    // Start capturing
    //
    rc = pcap_activate(pc);
    if (rc != 0) {
        fprintf(stderr, "pcap_activate returned %d. %s\n", rc, pcap_geterr(pc));
        exit(1);
    }

    puts("Capture source activated");
    struct pcap_pkthdr* hdr = NULL;
    const u_char* data = NULL;
    unsigned long counter = 0;
    while(1) {
        rc = pcap_next_ex(pc, &hdr, &data);
        switch(rc) {
        case 1: // packet read
            ++counter;
            printf("packet %lu: caplen=%d, len=%d data=", counter, hdr->caplen, hdr->len);
            print_hex_dump(data, min_int(hdr->caplen, 20));
            puts("...");
            print_captured_data(data, hdr->caplen);
            break;
        case 0: // timeout expired
            break;
        case -1: // error occurred while reading packet
            fprintf(stderr, "Error occurred while reading packet. %s", pcap_geterr(pc));
            exit(1);
            break;
        case -2: // no more packets in savefile. 
            // Since we're live capturing from device, shouldn't hit this.
            puts("No more packets in savefile.");
            break;
        default:
            fprintf(stderr, "Unexpected pcap_next_ex return value %d\n", rc);
            exit(1);
            break;
        }
    } 

    pcap_close(pc);
    return 0;
}
