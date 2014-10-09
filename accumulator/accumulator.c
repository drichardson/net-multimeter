#include "compare.h"
#include "debug.h"
#include "ethernet.h"
#include "ipv4.h"
#include "likely.h"
#include "mac.h"
#include "mkdirp.h"
#include "tcp.h"
#include "transact_file.h"
#include "udp.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
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

static void inline
protocol_count_add_packet(protocol_counts* pc, u64 const payload_data, u64 const total_data) {
    ++pc->packets;
    pc->payload_data += payload_data;
    pc->total_data += total_data;
}

typedef struct {
    u64 errors;

    // protocols transported by ethernet
    protocol_counts ipv4;
    protocol_counts ipv6;
    protocol_counts arp;
    protocol_counts other_over_ethernet;

    // protocols transported by ipv4 and ipv6
    protocol_counts icmpv4;
    protocol_counts icmpv6;
    protocol_counts tcp;
    protocol_counts udp;
    protocol_counts other_over_ip;

} aggregate_counts;

#define define_address_pair_counter_struct(name, addrlen)  \
typedef struct { \
    u8 low_address[addrlen]; \
    u8 high_address[addrlen]; \
    protocol_counts low_originated; \
    protocol_counts high_originated; \
} name;

// create a tsearch compatible compare function named <type>_compare
// subject to constraints on address pair nodes (low first, then high)
#define make_counter_pair_compare(type) \
static int type ## _compare (void const* n1, void const* n2) { \
    type const* p1 = n1; \
    type const* p2 = n2; \
    return memcmp(p1->low_address, p2->low_address, \
            sizeof(p1->low_address)+sizeof(p1->high_address)); \
}

enum originator { o_src_low, o_src_high };

#define make_counter_pair_alloc(type, addrlen) \
static type * type ## _alloc (u8 const (*src)[addrlen], u8 const (*dst)[addrlen], enum originator * originator_out) { \
    type * new_pair = calloc(sizeof(type), 1); \
    if (memcmp(*src, *dst, addrlen) <= 0) { \
        memcpy(new_pair->low_address, src, addrlen); \
        memcpy(new_pair->high_address, dst, addrlen); \
        *originator_out = o_src_low; \
    } else { \
        memcpy(new_pair->low_address, dst, addrlen); \
        memcpy(new_pair->high_address, src, addrlen); \
        *originator_out = o_src_high; \
    } \
    return new_pair; \
}

#define make_address_pair_add_packet(type, addrlen) \
static void type ## _add_packet(void** root, u8 const (*src)[addrlen], u8 const (*dst)[addrlen], u64 payload_len, u64 total_len) { \
    enum originator originator; \
    type* new_pair = type ## _alloc(src, dst, &originator); \
    /* TODO: Unbounded memory growth. Prune the tree using LRU. */ \
    type ** ppair = tsearch(new_pair, root, type ## _compare); \
    type *pair = *ppair; \
    if (pair != new_pair) { \
        /* TODO: reuse instead of constantly mallocing and freeing just because the address exists
         already. */ \
        free(new_pair); \
    } \
    assert(pair); \
    protocol_counts* originator_counts = originator == o_src_low ? &pair->low_originated : &pair->high_originated; \
    protocol_count_add_packet(originator_counts, payload_len, total_len); \
}

_Thread_local bool tl_publish_first;
_Thread_local FILE* tl_publish_fp;

#define put(x) fputs(x, tl_publish_fp)
#define sep() fputs(",\n", tl_publish_fp)
#define key(n) put("\"" n "\":")
#define quote(s) { put("\""); put(s); put("\""); }

static void
publish_protocol_counts_named(
        FILE* fp,
        char const* name,
        protocol_counts const* pc) {
    fprintf(fp,
            "\"%s\":{\"packets\":%" PRIu64
            ", \"payload_data\":%" PRIu64
            ", \"total_data\":%" PRIu64 "}",
            name, pc->packets, pc->payload_data, pc->total_data);
}

#define make_address_pair_json_publish_action(type, addrlen, addr_to_string_conv) \
static void \
type ## _json_publish_action(const void *nodep, \
        const VISIT which, \
        const int depth) { \
\
    if (which != postorder && which != leaf) { \
        return; \
    } \
\
    type const* const* ppair = nodep; \
    type const* pair = *ppair; \
    { \
        if (tl_publish_first) { \
            tl_publish_first = false; \
        } else { \
            sep(); \
        } \
        put("{\n"); \
        char s[100]; \
        addr_to_string_conv(&pair->low_address, s, sizeof s); \
        key("low-address"); quote(s); \
        sep(); \
        addr_to_string_conv(&pair->high_address, s, sizeof s); \
        key("high-address"); quote(s); \
        sep(); \
        publish_protocol_counts_named(tl_publish_fp, "low-counts", &pair->low_originated); \
        sep(); \
        publish_protocol_counts_named(tl_publish_fp, "high-counts", &pair->low_originated); \
        put("}"); \
    } \
} \

#define define_address_pair_counter(name, addrlen, addr_to_string_conv) \
    define_address_pair_counter_struct(name, addrlen) \
    make_counter_pair_compare(name) \
    make_counter_pair_alloc(name, addrlen) \
    make_address_pair_add_packet(name, addrlen) \
    make_address_pair_json_publish_action(name, addr, addr_to_string_conv)



define_address_pair_counter(ipv4_counter_pair, 4, ipv4_address_to_string);
define_address_pair_counter(ethernet_counter_pair, 6, mac_address_to_string);

typedef struct {
    aggregate_counts aggregates;
    void* ethernet_counter_pairs;
    void* ipv4_counter_pairs;

    // caches
    struct dirent *dent_cache;
} app_state;

static void
ethernet_packet_process(app_state* state, u8 const* data, int data_len /* captured data */, int total_data_len) {
    if (data_len < sizeof(ethernet_frame)) {
        ++state->aggregates.errors;
        fprintf(stderr, "ppf: didn't capture enough to parse ethernet frame. len=%d\n", data_len);
        return;
    }

    ethernet_frame const* e = (ethernet_frame*)data;
    u64 const ethernet_payload_len = total_data_len - sizeof(ethernet_frame);

    ethernet_counter_pair_add_packet(
            &state->ethernet_counter_pairs,
            &e->src_mac_address,
            &e->dst_mac_address,
            ethernet_payload_len,
            total_data_len);

    u16 const ethertype = ethernet_frame_ethertype(e);

    if (ethertype == ETHERTYPE_IPV4) {
        if (data_len < sizeof(ethernet_frame) + sizeof(ipv4_packet)) {
            ++state->aggregates.errors;
            fprintf(stderr, "ppf: didn't capture enough to parse IPv4 header. len=%d\n", data_len);
            return;
        }
        // IPv4
        ipv4_packet const* ip4 = (ipv4_packet*)(data + sizeof(ethernet_frame));
        
        u32 const ip_header_len = ipv4_packet_ihl(ip4)*4;
        u32 const ip_total_len = u8s_to_u16(&ip4->total_length);
        u32 const ip_payload_len = ip_total_len - ip_header_len;
        // u8 const* ip_payload = (((u8*)ip4)+ip_payload_len);

        protocol_count_add_packet(&state->aggregates.ipv4,
                ip_payload_len,
                ip_total_len);

        ipv4_counter_pair_add_packet(
                &state->ipv4_counter_pairs,
                &ip4->src_ip_address,
                &ip4->dst_ip_address, 
                ip_payload_len,
                ip_total_len);

        switch(ip4->protocol) {
        case IPV4_PROTOCOL_ICMP:
            protocol_count_add_packet(&state->aggregates.icmpv4, 0, 0);
            break;
        case IPV4_PROTOCOL_TCP:
            protocol_count_add_packet(&state->aggregates.tcp, 0, 0);
            break;
        case IPV4_PROTOCOL_UDP: 
            protocol_count_add_packet(&state->aggregates.udp, 0, 0);
            break;
        case IPV4_PROTOCOL_IGMP:
        case IPV4_PROTOCOL_ENCAP:
        case IPV4_PROTOCOL_SCTP:
        default:
            protocol_count_add_packet(&state->aggregates.other_over_ip, 0, 0);
            break;
        }
    } else if (ethertype == ETHERTYPE_IPV6) {
        protocol_count_add_packet(&state->aggregates.ipv6, 0, 0);
    } else if (ethertype == ETHERTYPE_ARP) {
        protocol_count_add_packet(&state->aggregates.arp, 0, 0);
    } else {
        protocol_count_add_packet(&state->aggregates.other_over_ethernet, 0, 0);
    }
}

static bool
process_pcap(app_state* state, pcap_t* pc) {
    bool result = false;
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
            result = true;
            goto end_loop;
        default:
            fprintf(stderr, "Unexpected pcap_next_ex return value %d\n", rc);
            goto end_loop;
        }
    } 
end_loop:
    return result;
}

#define publish_aggregate_counts_with_key(field, key) \
    publish_protocol_counts_named(tl_publish_fp, key, &state->aggregates.field)

#define publish_aggregate_counts(field) \
    publish_aggregate_counts_with_key(field, #field)

static void
publish_json_fp(app_state const* state, FILE* fp) {
    tl_publish_fp = fp;
    put("{\n");
    key("accumulator_errors"); fprintf(fp, "%" PRIu64, state->aggregates.errors);
    sep();
    key("ethernet_by_type");
    {
        put("{\n");
        publish_aggregate_counts(ipv4);
        sep();
        publish_aggregate_counts(ipv6);
        sep();
        publish_aggregate_counts(arp);
        sep();
        publish_aggregate_counts_with_key(other_over_ethernet, "other");
        put("},\n");
    }
    key("ip_by_type");
    {
        put("{\n");
        publish_aggregate_counts(tcp);
        sep();
        publish_aggregate_counts(udp);
        sep();
        publish_aggregate_counts(icmpv4);
        sep();
        publish_aggregate_counts(icmpv6);
        sep();
        publish_aggregate_counts_with_key(other_over_ip, "other");
        put("}\n,");
    }
    key("ip_by_address_pair");
    {
        put("[\n");
        tl_publish_first = true;
        twalk(state->ipv4_counter_pairs, ipv4_counter_pair_json_publish_action);
        put("\n],\n");
    }
    key("ethernet_by_address_pair");
    {
        put("[\n");
        tl_publish_first = true;
        twalk(state->ethernet_counter_pairs, ethernet_counter_pair_json_publish_action);
        put("\n]");
    }
    put("}");

    tl_publish_fp = NULL;
}

static bool
publish_json(app_state const* state, char const* json_path) {
    transact_file tf;
    if (!transact_file_open(&tf, json_path)) {
        fprintf(stderr, "transact_file_open failed opening %s. %s\n", json_path, strerror(errno));
        return false;
    }

    publish_json_fp(state, tf.fp);

    if(!transact_file_close(&tf, true)) {
        fprintf(stderr, "transact_file_open failed to commit and close %s. %s\n", json_path, strerror(errno));
        return false;
    }

    return true;
}

static bool
process_files_in_dir(app_state* state, char const* dirpath) {
    DIR* dp = opendir(dirpath);
    if (dp == NULL) {
        perror("Couldn't open process directory");
        return false;
    }

    int dir_fd = dirfd(dp);
    if (dir_fd == -1) {
        closedir(dp);
        perror("Couldn't get descriptor for directory.");
        return false;
    }

    if (state->dent_cache == NULL) {
        int name_max = pathconf(dirpath, _PC_NAME_MAX);
        errno = 0; // clear, so we can tell if pathconf == -1 means unlimited or erro
        if (name_max == -1) {
            if (errno) {
                perror("pathconf failed");
            } else {
                // no limit. This is kind of weird for a file system, so print a warning message.
                name_max = 4000;
                fprintf(stderr, "WARNING: file system says it has no limit on \
                        names. I need a limit so using %d\n", name_max); }
        }
        int len = offsetof(struct dirent, d_name) + name_max + 1;
        state->dent_cache = malloc(len);
    }

    bool result = false;

    struct dirent* ent;
    int rd_rc;
    while((rd_rc = readdir_r(dp, state->dent_cache, &ent)) == 0) {
        if (ent == NULL) {
            // end of stream reached
            result = true;
            break;
        }
        if (unlikely(ent->d_type == DT_UNKNOWN)) {
            fprintf(stderr, "File system doesn't support d_type. Aborting.");
            break;
        }
        if (ent->d_type == DT_DIR) {
            continue;
        }
        if (strstr(ent->d_name, "pcap") == NULL) {
            // safety check. Skip any files that don't have pcap in the name
            fprintf(stderr, "WARNING: skipping file that doesn't look like I'm \
                    supposed to delete '%s'.\n", ent->d_name); continue;
        }
        printf("Processing %s\n", ent->d_name);
        int pcap_fd = openat(dir_fd, ent->d_name, O_RDONLY | O_CLOEXEC);

        // After possible openat succeeds, unlink the file before doing
        // anything else.  This prevents us from stuck in a loop because of a
        // file we choke on time and time again.
        int rc = unlinkat(dir_fd, ent->d_name, 0);
        if (rc == -1) {
            if (pcap_fd != -1) {
                close(pcap_fd);
            }
            fprintf(stderr, "Error unlinking %s. %s\n", ent->d_name, strerror(errno));
            break;
        }

        if (pcap_fd == -1) {
            fprintf(stderr, "Error opening file %s. %s\n", ent->d_name, strerror(errno));
            break;
        }
        FILE* fp = fdopen(pcap_fd, "r");
        if (fp == NULL) {
            close(pcap_fd);
            fprintf(stderr, "Error opening file pointer for %s. %s\n", ent->d_name, strerror(errno));
            break;
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pc = pcap_fopen_offline(fp, errbuf);
        if (pc == NULL) {
            fclose(fp);
            fprintf(stderr, "pcap_fopen_offline failed for %s. %s\n", ent->d_name, errbuf);
            break;
        }

        bool ok = process_pcap(state, pc);
        pcap_close(pc); // also closes fp

        if (!ok) {
            break;
        }
    }

    if (rd_rc != 0) {
        fprintf(stderr, "readdir_r returned error %d: %s\n", rd_rc, strerror(rd_rc));
        result = false;
    }

    int rc = closedir(dp);
    if (rc == -1) {
        perror("Couldn't close process directory.");
        result = false;
    }

    return result;
}

static bool
mkdirparts(char const* path, mode_t mode) {
    char* path_copy = strdup(path);
    char* dir = dirname(path_copy);
    int rc = mkdirp(dir, mode);
    int e = errno;
    free(path_copy);
    errno = e;
    return rc == 0;
}

static int
main_loop(char const* process_path, char const* publish_path) {

    int result = 1;
 
    // watch for new files in capture path, and process them when they're closed.

    int inote_fd = inotify_init1(IN_CLOEXEC);
    if (inote_fd == -1) {
        perror("inotify_init1 failed");
        return 1;
    }

    int watch1 = inotify_add_watch(inote_fd, process_path, IN_MOVED_TO);
    if (watch1 == -1) {
        fprintf(stderr, "inotify_add_watch failed on %s. %s\n", process_path, strerror(errno));
        close(inote_fd);
        return 1;
    }

    // declaration of buf from man (2) inotify
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    app_state state;
    memset(&state, 0, sizeof state);

    while(1) {
        bool ok = process_files_in_dir(&state, process_path);
        if (!ok) {
            goto end;
        }
        ok = publish_json(&state, publish_path);
        if (!ok) {
            goto end;
        }

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

            if (unlikely(!(event->mask & IN_MOVED_TO))) {
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
        }
    }

end:
    close(inote_fd);

    return result;
}

int main(int argc, char const** argv) {
    if (argc != 3) {
        fprintf(stderr, "Missing required arguments.\nUsage: accumulator <process_path> <publish_path>\n");
        exit(1);
    }

    char const* process_path = argv[1];
    char const* publish_path = argv[2];

    // This process is responsible for creating the publish path, but not the process path.
    // The idea being that if you are creating a file, you're responsible for making sure
    // the output folder exists. If you're reading a file, someone else is responsible for
    // creating the directories.
    bool ok = mkdirparts(publish_path, 0755);
    if (!ok) {
        perror("Couldn't create publish path");
        return 1;
    }

    return main_loop(process_path, publish_path);
}

