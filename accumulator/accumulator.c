#include "compare.h"
#include "debug.h"
#include "ethernet.h"
#include "ipv4.h"
#include "likely.h"
#include "tcp.h"
#include "transact_file.h"
#include "udp.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pcap/pcap.h>
#include <search.h>
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
    // constraint 1: low_address <= high_address
    // constraint 2: low_address must immediately preceed high_address in memory.
    u8 low_address[4];
    u8 high_address[4];
    protocol_counts low_originated;
    protocol_counts high_originated;
} ipv4_counter_pair;

static int ipv4_counter_pair_compare(void const* n1, void const* n2) {
    ipv4_counter_pair const* p1 = n1;
    ipv4_counter_pair const* p2 = n2;

    _Static_assert(offsetof(ipv4_counter_pair, high_address)
            - offsetof(ipv4_counter_pair, low_address)
            == sizeof(p1->low_address),
            "high_address doesn't immediately follow low_address in structure layout");

    return memcmp(p1->low_address, p2->low_address,
            sizeof(p1->low_address)+sizeof(p1->high_address));
}

typedef struct {
    aggregate_counts aggregates;
    void* ipv4_counter_pairs;
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
        
        u32 const ip_header_len = ipv4_packet_ihl(ip4)*4;
        u32 const ip_total_len = u8s_to_u16(&ip4->total_length);
        u32 const ip_payload_len = ip_total_len - ip_header_len;
        // u8 const* ip_payload = (((u8*)ip4)+ip_payload_len);

        protocol_count_add_packet(&state->aggregates.over_ethernet.ipv4,
                ip_payload_len,
                ip_total_len);

        // Update the per-IPv4 address counters.
        ipv4_counter_pair* new_pair = calloc(sizeof(ipv4_counter_pair), 1);
        enum originator { o_src_low, o_src_high } originator;
        if (memcmp(ip4->src_ip_address, ip4->dst_ip_address, 4) <= 0) {
            memcpy(new_pair->low_address, ip4->src_ip_address, 4);
            memcpy(new_pair->high_address, ip4->dst_ip_address, 4);
            originator = o_src_low;
        } else {
            memcpy(new_pair->low_address, ip4->dst_ip_address, 4);
            memcpy(new_pair->high_address, ip4->src_ip_address, 4);
            originator = o_src_high;
        }

        ipv4_counter_pair** ppair = tsearch(new_pair, &state->ipv4_counter_pairs, ipv4_counter_pair_compare);
        ipv4_counter_pair *pair = *ppair;
        if (pair != new_pair) {
            // TODO: reuse instead of constantly mallocing and freeing just because the address exists
            // already.
            free(new_pair);
        }
        assert(pair);
        protocol_counts* originator_counts = originator == o_src_low ? &pair->low_originated : &pair->high_originated;

        protocol_count_add_packet(originator_counts, ip_payload_len, ip_total_len);

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

_Thread_local bool tl_publish_first;
_Thread_local FILE* tl_publish_fp;

#define put(x) fputs(x, tl_publish_fp)
#define sep() fputs(",\n", tl_publish_fp)
#define key(n) put("\"" n "\":")
#define quote(s) { put("\""); put(s); put("\""); }

static void
ipv4_counter_pair_json_publish_action(const void *nodep,
        const VISIT which,
        const int depth) {

    if (which != postorder && which != leaf) {
        return;
    }

    ipv4_counter_pair const* const* ppair = nodep;
    ipv4_counter_pair const* pair = *ppair;
    {
        if (tl_publish_first) {
            tl_publish_first = false;
        } else {
            sep();
        }
        put("{\n");
        char s[16];
        ipv4_address_to_string(&pair->low_address, s, sizeof s);
        key("low-address"); quote(s);
        sep();
        ipv4_address_to_string(&pair->high_address, s, sizeof s);
        key("high-address"); quote(s);
        sep();
        publish_protocol_counts_named(tl_publish_fp, "low-counts", &pair->low_originated);
        sep();
        publish_protocol_counts_named(tl_publish_fp, "high-counts", &pair->low_originated);
        put("}");
    }
}

static void
publish_json_fp(app_state const* state, FILE* fp) {
    tl_publish_fp = fp;
    put("{\n");
    publish_protocol_counts_named(fp, "ethernet", &state->aggregates.ethernet);
    sep();
    key("over_ethernet");
    {
        put("{\n");
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
        put("{\n");
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
    sep();
    key("over_ip_by_address_pair");
    {
        put("[\n");
        tl_publish_first = true;
        twalk(state->ipv4_counter_pairs, ipv4_counter_pair_json_publish_action);
        put("\n]");
    }
    put("}");

    tl_publish_fp = NULL;
}

static void
publish_json(app_state const* state, char const* json_path) {
    transact_file tf;
    if (!transact_file_open(&tf, json_path)) {
        fprintf(stderr, "transact_file_open failed opening %s. %s\n", json_path, strerror(errno));
        return;
    }

    publish_json_fp(state, tf.fp);

    if(!transact_file_close(&tf, true)) {
        fprintf(stderr, "transact_file_open failed to commit and close %s. %s\n", json_path, strerror(errno));
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

