#include "compare.h"
#include "debug.h"
#include "ethernet.h"
#include "ipv4.h"
#include "likely.h"
#include "tcp.h"
#include "transact_file.h"
#include "udp.h"
#include <errno.h>
#include <limits.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct app_state {
} app_state;

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

static bool
process_pcap_file(app_state* state, char const* filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pc = pcap_open_offline(filename, errbuf);
    if (pc == NULL) {
        fprintf(stderr, "pcap_open_offline failed. %s\n", errbuf);
        return false;
    }
    bool result = false;
    struct pcap_pkthdr* hdr = NULL;
    const u_char* data = NULL;
    unsigned long counter = 0;
    while(1) {
        int rc = pcap_next_ex(pc, &hdr, &data);
        switch(rc) {
        case 1: // packet read
            ++counter;
            printf("packet %lu: caplen=%d, len=%d data=", counter, hdr->caplen, hdr->len);
            print_hex_dump(data, min_int(hdr->caplen, 20));
            puts("...");
            print_captured_data(data, hdr->caplen);
            break;
        case 0: // timeout expired
            // probably shouldn't get this when reading from a file.
            fprintf(stderr, "Unexpected timeout returned from pcap_next_ex\n");
            break;
        case -1: // error occurred while reading packet
            fprintf(stderr, "Error occurred while reading packet. %s", pcap_geterr(pc));
            break;
        case -2: // no more packets in savefile. 
            puts("No more packets in savefile.");
            result = true;
            goto end_loop;
        default:
            fprintf(stderr, "Unexpected pcap_next_ex return value %d\n", rc);
            goto end_loop;
        }
    } 
end_loop:
    pcap_close(pc);
    return result;
}

static void
publish_json(app_state const* state, char const* json_path) {
    transact_file tf;
    if (!transact_file_open(&tf, json_path)) {
        fprintf(stderr, "transact_file_open failed opening %s. %s", json_path, strerror(errno));
        return;
    }

    static int count = 0;
    fprintf(tf.fp, "{%d}", ++count);

    if(!transact_file_close(&tf, true)) {
        fprintf(stderr, "transact_file_open failed to commit and close %s. %s", json_path, strerror(errno));
    } else {
        printf("published to %s\n", json_path);
    }
}

static int
main_loop(char const* capture_path, char const* publish_path) {

    int result = 1;

    // watch for new files in capture path, and process them when they're closed.

    int inote_fd = inotify_init1(IN_CLOEXEC);
    if (inote_fd == -1) {
        perror("inotify_init1 failed");
        return 1;
    }

    int watch1 = inotify_add_watch(inote_fd, capture_path, IN_CLOSE_WRITE);
    if (watch1 == -1) {
        perror("inotify_add_watch failed");
        close(inote_fd);
        return 1;
    }

    // declaration of buf from man (2) inotify
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    app_state state;
    memset(&state, 0, sizeof state);

    while(1) {
        ssize_t len = read(inote_fd, buf, sizeof(buf));
        if (len < 0) {
            perror("read failed.");
            if (errno != EAGAIN && errno != EINTR) {
                fprintf(stderr, "Non-recoverable read failure. %d\n", errno);
                goto end;
            }
        }

        struct inotify_event const* event = NULL;

        for(char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
            event = (struct inotify_event*)ptr;

            if (unlikely(event->wd != watch1)) {
                // should not happen
                fprintf(stderr, "Unexpected wd %d\n", event->wd);
                goto end;
            }

            if (unlikely(!(event->mask & IN_CLOSE_WRITE))) {
                fprintf(stderr, "Unexpected event mask: 0x%X\n", event->mask);
                // this could happen if someone removes the directory we're watching.
                // in that case exit.
                goto end;
            }

            if (unlikely(event->len == 0)) {
                // should not happen.
                fprintf(stderr, "Unexpected event->len == 0\n");
                goto end;
            }

            char pcap_file[PATH_MAX];
            snprintf(pcap_file, sizeof pcap_file, "%s/%s", capture_path, event->name);

            process_pcap_file(&state, pcap_file);
            publish_json(&state, publish_path);
        }
    }

end:
    close(inote_fd);

    return result;
}

int main(int argc, char const** argv) {
    if (argc != 3) {
        fprintf(stderr, "Missing required arguments.\nUsage: accumulator <capture_path> <publish_path>\n");
        exit(1);
    }

    char const* capture_path = argv[1];
    char const* publish_path = argv[2];
    return main_loop(capture_path, publish_path);
}

