#include "compare.h"
#include "debug.h"
#include "ethernet.h"
#include "ipv4.h"
#include "likely.h"
#include "tcp.h"
#include "transact_file.h"
#include "udp.h"
#include <errno.h>
#include <inttypes.h>
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

// TODO: May be fast on 32-bit devices to have a 32-bit version of these fields which
// are used while processing a single pcap file which are then added at the end to
// the 64-bit version of them.

typedef struct {
    u64 packets;
    u64 payload_data; 
    u64 total_data;
} protocol_counts;

typedef struct {
    u64 errors;
    protocol_counts ethernet;

    // protocols transported by ethernet
    struct {
        protocol_counts ipv4;
        protocol_counts ipv6;
        protocol_counts arp;
        protocol_counts other;
    } over_ethernet;

    // protocols transported by ipv4 and ipv6
    struct {
        protocol_counts icmpv4;
        protocol_counts icmpv6;
        protocol_counts tcp;
        protocol_counts udp;
        protocol_counts other;
    } over_ip;
} aggregate_counts;

typedef struct {
    aggregate_counts aggregates;
} app_state;

static void inline
protocol_count_add_packet(protocol_counts* pc, u64 const payload_data, u64 const total_data) {
    ++pc->packets;
    pc->payload_data += payload_data;
    pc->total_data += total_data;
}

static void
ethernet_packet_process(app_state* state, u8 const* data, int data_len /* captured data */, int total_data_len) {
    if (data_len < sizeof(ethernet_frame)) {
        fprintf(stderr, "ppf: didn't capture enough to parse ethernet frame. len=%d\n", data_len);
        return;
    }

    ethernet_frame const* e = (ethernet_frame*)data;

    protocol_count_add_packet(&state->aggregates.ethernet,
            total_data_len - sizeof(ethernet_frame),
            total_data_len);

    u16 const ethertype = ethernet_frame_ethertype(e);

    if (ethertype == ETHERTYPE_IPV4) {
        if (data_len < sizeof(ethernet_frame) + sizeof(ipv4_packet)) {
            fprintf(stderr, "ppf: didn't capture enough to parse IPv4 header. len=%d\n", data_len);
            return;
        }
        // IPv4
        ipv4_packet const* ip4 = (ipv4_packet*)(data + sizeof(ethernet_frame));
        
        u32 const ip_payload_len = ipv4_packet_ihl(ip4)*4;
        // u8 const* ip_payload = (((u8*)ip4)+ip_payload_len);

        protocol_count_add_packet(&state->aggregates.over_ethernet.ipv4,
                ip_payload_len,
                total_data_len - (sizeof(ethernet_frame) + sizeof(ipv4_packet))
                );

        switch(ip4->protocol) {
        case IPV4_PROTOCOL_ICMP:
            protocol_count_add_packet(&state->aggregates.over_ip.icmpv4, 0, 0);
            break;
        case IPV4_PROTOCOL_TCP:
            protocol_count_add_packet(&state->aggregates.over_ip.tcp, 0, 0);
            break;
        case IPV4_PROTOCOL_UDP: 
            protocol_count_add_packet(&state->aggregates.over_ip.udp, 0, 0);
            break;
        case IPV4_PROTOCOL_IGMP:
        case IPV4_PROTOCOL_ENCAP:
        case IPV4_PROTOCOL_SCTP:
        default:
            protocol_count_add_packet(&state->aggregates.over_ip.other, 0, 0);
            break;
        }
    } else if (ethertype == ETHERTYPE_IPV6) {
        protocol_count_add_packet(&state->aggregates.over_ethernet.ipv6, 0, 0);
    } else if (ethertype == ETHERTYPE_ARP) {
        protocol_count_add_packet(&state->aggregates.over_ethernet.arp, 0, 0);
    } else {
        protocol_count_add_packet(&state->aggregates.over_ethernet.other, 0, 0);
    }
}

static void 
process_pcap_file(app_state* state, char const* filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pc = pcap_open_offline(filename, errbuf);
    if (pc == NULL) {
        fprintf(stderr, "pcap_open_offline failed. %s\n", errbuf);
        return;
    }
    struct pcap_pkthdr* hdr = NULL;
    const u_char* data = NULL;
    while(1) {
        int rc = pcap_next_ex(pc, &hdr, &data);
        switch(rc) {
        case 1: // packet read
            ethernet_packet_process(state, data, hdr->caplen, hdr->len);
            break;
        case 0: // timeout expired
            // probably shouldn't get this when reading from a file.
            fprintf(stderr, "Unexpected timeout returned from pcap_next_ex\n");
            break;
        case -1: // error occurred while reading packet
            fprintf(stderr, "Error occurred while reading packet. %s", pcap_geterr(pc));
            ++state->aggregates.errors;
            break;
        case -2: // no more packets in savefile. 
            goto end_loop;
        default:
            fprintf(stderr, "Unexpected pcap_next_ex return value %d\n", rc);
            goto end_loop;
        }
    } 
end_loop:
    pcap_close(pc);
}


static void publish_protocol_counts_named(FILE* fp,
        char const* name,
        protocol_counts const* pc) {
    fprintf(fp,
            "\"%s\":{\"packets\":%" PRIu64
            ", \"payload_data\":%" PRIu64
            ", \"total_data\":%" PRIu64 "}",
            name, pc->packets, pc->payload_data, pc->total_data);
}

static void
publish_json_fp(app_state const* state, FILE* fp) {
#define put(x) fputs(x, fp)
#define sep() fputs(",\n", fp)
#define key(n) put("\"" n "\":")
    put("{");
    publish_protocol_counts_named(fp, "ethernet", &state->aggregates.ethernet);
    sep();
    key("over_ethernet");
    {
        put("{");
        publish_protocol_counts_named(fp, "ipv4", &state->aggregates.over_ethernet.ipv4);
        sep();
        publish_protocol_counts_named(fp, "ipv6", &state->aggregates.over_ethernet.ipv6);
        sep();
        publish_protocol_counts_named(fp, "arp", &state->aggregates.over_ethernet.arp);
        sep();
        publish_protocol_counts_named(fp, "other", &state->aggregates.over_ethernet.other);
        put("}");
    }
    sep();
    key("over_ip");
    {
        put("{");
        publish_protocol_counts_named(fp, "tcp", &state->aggregates.over_ip.tcp);
        sep();
        publish_protocol_counts_named(fp, "udp", &state->aggregates.over_ip.udp);
        sep();
        publish_protocol_counts_named(fp, "icmpv4", &state->aggregates.over_ip.icmpv4);
        sep();
        publish_protocol_counts_named(fp, "icmpv6", &state->aggregates.over_ip.icmpv6);
        sep();
        publish_protocol_counts_named(fp, "other", &state->aggregates.over_ip.other);
        put("}");
    }
    put("}");
}

static void
publish_json(app_state const* state, char const* json_path) {
    transact_file tf;
    if (!transact_file_open(&tf, json_path)) {
        fprintf(stderr, "transact_file_open failed opening %s. %s", json_path, strerror(errno));
        return;
    }

    publish_json_fp(state, tf.fp);

    if(!transact_file_close(&tf, true)) {
        fprintf(stderr, "transact_file_open failed to commit and close %s. %s", json_path, strerror(errno));
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

