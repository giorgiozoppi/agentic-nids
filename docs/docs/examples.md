---
sidebar_position: 6
---

# Complete Examples

This section provides complete, working examples that demonstrate various nDPI integration patterns.

## Simple Packet Reader

A basic example that reads packets from a PCAP file and performs protocol detection:

```c
/*
 * simple_reader.c - Basic nDPI packet reader example
 */
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct simple_flow {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;

    struct ndpi_flow_struct* ndpi_flow;
    struct ndpi_proto detected_protocol;
    uint32_t packets;
    uint8_t detection_completed;
};

// Global variables
struct ndpi_detection_module_struct* ndpi_mod = NULL;
struct simple_flow flows[1000];  // Simple array for demo
int flow_count = 0;

// Find or create flow
struct simple_flow* get_flow(uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint8_t protocol) {
    // Try to find existing flow
    for (int i = 0; i < flow_count; i++) {
        struct simple_flow* f = &flows[i];
        if ((f->src_ip == src_ip && f->dst_ip == dst_ip &&
             f->src_port == src_port && f->dst_port == dst_port &&
             f->protocol == protocol) ||
            (f->src_ip == dst_ip && f->dst_ip == src_ip &&
             f->src_port == dst_port && f->dst_port == src_port &&
             f->protocol == protocol)) {
            return f;
        }
    }

    // Create new flow
    if (flow_count >= 1000) return NULL;

    struct simple_flow* f = &flows[flow_count++];
    memset(f, 0, sizeof(struct simple_flow));

    f->src_ip = src_ip;
    f->dst_ip = dst_ip;
    f->src_port = src_port;
    f->dst_port = dst_port;
    f->protocol = protocol;

    f->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (!f->ndpi_flow) return NULL;
    memset(f->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    return f;
}

// Packet processing callback
void packet_handler(u_char* user, const struct pcap_pkthdr* header,
                   const u_char* packet) {
    const struct ndpi_ethhdr* ethernet = (struct ndpi_ethhdr*)packet;
    const struct ndpi_iphdr* ip;
    const struct ndpi_tcphdr* tcp;
    const struct ndpi_udphdr* udp;

    uint16_t type = ntohs(ethernet->h_proto);
    if (type != 0x0800) return;  // Only IPv4

    ip = (struct ndpi_iphdr*)(packet + sizeof(struct ndpi_ethhdr));
    if (ip->version != 4) return;

    uint32_t src_ip = ntohl(ip->saddr);
    uint32_t dst_ip = ntohl(ip->daddr);
    uint16_t src_port = 0, dst_port = 0;

    // Extract ports for TCP/UDP
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct ndpi_tcphdr*)((uint8_t*)ip + (ip->ihl * 4));
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct ndpi_udphdr*)((uint8_t*)ip + (ip->ihl * 4));
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }

    // Get flow
    struct simple_flow* flow = get_flow(src_ip, dst_ip, src_port, dst_port, ip->protocol);
    if (!flow) return;

    // Process with nDPI
    uint64_t timestamp = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000;
    uint16_t ip_size = ntohs(ip->tot_len);

    flow->detected_protocol = ndpi_detection_process_packet(
        ndpi_mod, flow->ndpi_flow, (uint8_t*)ip, ip_size, timestamp, NULL);

    flow->packets++;

    // Check if protocol detected
    if (!flow->detection_completed && ndpi_is_protocol_detected(flow->detected_protocol)) {
        flow->detection_completed = 1;

        printf("Flow %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u detected as %s | %s\n",
            (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
            (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
            (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
            (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, dst_port,
            ndpi_get_proto_name(ndpi_mod, flow->detected_protocol.proto.master_protocol),
            ndpi_get_proto_name(ndpi_mod, flow->detected_protocol.proto.app_protocol));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    // Initialize nDPI
    ndpi_mod = ndpi_init_detection_module(NULL);
    if (!ndpi_mod) {
        fprintf(stderr, "Failed to initialize nDPI\n");
        return 1;
    }

    if (ndpi_finalize_initialization(ndpi_mod) != 0) {
        fprintf(stderr, "Failed to finalize nDPI initialization\n");
        return 1;
    }

    printf("nDPI %s initialized\n", ndpi_revision());

    // Open PCAP file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        fprintf(stderr, "Failed to open PCAP file: %s\n", errbuf);
        return 1;
    }

    // Process packets
    printf("Processing packets...\n");
    pcap_loop(handle, -1, packet_handler, NULL);

    // Print summary
    printf("\nSummary:\n");
    printf("Total flows: %d\n", flow_count);
    int detected = 0;
    for (int i = 0; i < flow_count; i++) {
        if (flows[i].detection_completed) detected++;
    }
    printf("Detected protocols: %d/%d flows\n", detected, flow_count);

    // Cleanup
    for (int i = 0; i < flow_count; i++) {
        if (flows[i].ndpi_flow) {
            ndpi_flow_free(flows[i].ndpi_flow);
        }
    }

    pcap_close(handle);
    ndpi_exit_detection_module(ndpi_mod);

    return 0;
}
```

### Compilation and Usage

```bash
# Compile
gcc -o simple_reader simple_reader.c -lndpi -lpcap

# Run with a PCAP file
./simple_reader sample.pcap
```

## Multi-threaded Network Monitor

A more advanced example using multiple threads for high-throughput packet processing:

```c
/*
 * mt_monitor.c - Multi-threaded network monitor with nDPI
 */
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <uthash.h>

#define MAX_THREADS 4
#define MAX_FLOWS_PER_THREAD 10000
#define FLOW_TIMEOUT_MS 300000  // 5 minutes

struct flow_info {
    uint64_t flow_key;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;

    struct ndpi_flow_struct* ndpi_flow;
    struct ndpi_proto detected_protocol;

    uint64_t first_seen, last_seen;
    uint32_t packets, bytes;
    uint8_t detection_completed;

    UT_hash_handle hh;
};

struct thread_context {
    int thread_id;
    pthread_t thread;
    pcap_t* pcap_handle;

    struct ndpi_detection_module_struct* ndpi_mod;
    struct flow_info* flows;

    uint64_t packets_processed;
    uint64_t flows_created;
    uint64_t flows_detected;

    volatile int should_stop;
};

static struct thread_context threads[MAX_THREADS];
static volatile int global_stop = 0;

// Generate flow key for hash table
uint64_t generate_flow_key(uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t protocol) {
    uint64_t key = 0;

    // Normalize flow direction
    if (src_ip > dst_ip || (src_ip == dst_ip && src_port > dst_port)) {
        key = ((uint64_t)dst_ip << 32) | src_ip;
        key ^= ((uint64_t)dst_port << 16) | src_port;
    } else {
        key = ((uint64_t)src_ip << 32) | dst_ip;
        key ^= ((uint64_t)src_port << 16) | dst_port;
    }

    key ^= protocol;
    return key;
}

// Find or create flow
struct flow_info* get_or_create_flow(struct thread_context* ctx,
                                   uint32_t src_ip, uint32_t dst_ip,
                                   uint16_t src_port, uint16_t dst_port,
                                   uint8_t protocol, uint64_t timestamp) {
    uint64_t key = generate_flow_key(src_ip, dst_ip, src_port, dst_port, protocol);
    struct flow_info* flow;

    // Try to find existing flow
    HASH_FIND_INT64(ctx->flows, &key, flow);
    if (flow) {
        return flow;
    }

    // Check flow limit
    if (HASH_COUNT(ctx->flows) >= MAX_FLOWS_PER_THREAD) {
        return NULL;
    }

    // Create new flow
    flow = malloc(sizeof(struct flow_info));
    if (!flow) return NULL;

    memset(flow, 0, sizeof(struct flow_info));
    flow->flow_key = key;
    flow->src_ip = src_ip;
    flow->dst_ip = dst_ip;
    flow->src_port = src_port;
    flow->dst_port = dst_port;
    flow->protocol = protocol;
    flow->first_seen = timestamp;
    flow->last_seen = timestamp;

    // Allocate nDPI flow
    flow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (!flow->ndpi_flow) {
        free(flow);
        return NULL;
    }
    memset(flow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    // Add to hash table
    HASH_ADD_INT64(ctx->flows, flow_key, flow);
    ctx->flows_created++;

    return flow;
}

// Cleanup expired flows
void cleanup_expired_flows(struct thread_context* ctx, uint64_t current_time) {
    struct flow_info* flow, *tmp;
    uint64_t timeout_threshold = current_time - FLOW_TIMEOUT_MS;

    HASH_ITER(hh, ctx->flows, flow, tmp) {
        if (flow->last_seen < timeout_threshold) {
            printf("[Thread %d] Removing expired flow\n", ctx->thread_id);

            HASH_DEL(ctx->flows, flow);
            if (flow->ndpi_flow) {
                ndpi_flow_free(flow->ndpi_flow);
            }
            free(flow);
        }
    }
}

// Packet processing
void process_packet(struct thread_context* ctx, const struct pcap_pkthdr* header,
                   const u_char* packet) {
    const struct ndpi_ethhdr* ethernet = (struct ndpi_ethhdr*)packet;
    const struct ndpi_iphdr* ip;

    uint16_t type = ntohs(ethernet->h_proto);
    if (type != 0x0800) return;  // Only IPv4

    ip = (struct ndpi_iphdr*)(packet + sizeof(struct ndpi_ethhdr));
    if (ip->version != 4) return;

    // Extract flow information
    uint32_t src_ip = ntohl(ip->saddr);
    uint32_t dst_ip = ntohl(ip->daddr);
    uint16_t src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        const struct ndpi_tcphdr* tcp = (struct ndpi_tcphdr*)((uint8_t*)ip + (ip->ihl * 4));
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        const struct ndpi_udphdr* udp = (struct ndpi_udphdr*)((uint8_t*)ip + (ip->ihl * 4));
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }

    uint64_t timestamp = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000;

    // Get or create flow
    struct flow_info* flow = get_or_create_flow(ctx, src_ip, dst_ip,
                                              src_port, dst_port,
                                              ip->protocol, timestamp);
    if (!flow) return;

    // Update flow statistics
    flow->last_seen = timestamp;
    flow->packets++;
    flow->bytes += header->len;
    ctx->packets_processed++;

    // Process with nDPI
    if (!flow->detection_completed) {
        uint16_t ip_size = ntohs(ip->tot_len);

        flow->detected_protocol = ndpi_detection_process_packet(
            ctx->ndpi_mod, flow->ndpi_flow, (uint8_t*)ip, ip_size, timestamp, NULL);

        if (ndpi_is_protocol_detected(flow->detected_protocol)) {
            flow->detection_completed = 1;
            ctx->flows_detected++;

            printf("[Thread %d] Protocol detected: %s | %s\n",
                ctx->thread_id,
                ndpi_get_proto_name(ctx->ndpi_mod, flow->detected_protocol.proto.master_protocol),
                ndpi_get_proto_name(ctx->ndpi_mod, flow->detected_protocol.proto.app_protocol));
        }
    }

    // Periodic cleanup
    static uint64_t last_cleanup = 0;
    if (timestamp - last_cleanup > 30000) {  // Every 30 seconds
        cleanup_expired_flows(ctx, timestamp);
        last_cleanup = timestamp;
    }
}

// Worker thread function
void* worker_thread(void* arg) {
    struct thread_context* ctx = (struct thread_context*)arg;

    printf("Thread %d starting\n", ctx->thread_id);

    while (!ctx->should_stop && !global_stop) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int result = pcap_next_ex(ctx->pcap_handle, &header, &packet);
        if (result == 1) {
            process_packet(ctx, header, packet);
        } else if (result == 0) {
            usleep(1000);  // No packet available, sleep briefly
        } else {
            break;  // Error or end of file
        }
    }

    printf("Thread %d stopping\n", ctx->thread_id);
    return NULL;
}

// Signal handler
void signal_handler(int sig) {
    printf("Received signal %d, stopping...\n", sig);
    global_stop = 1;
}

// Initialize thread context
int init_thread_context(struct thread_context* ctx, int thread_id,
                       const char* interface) {
    ctx->thread_id = thread_id;
    ctx->should_stop = 0;
    ctx->flows = NULL;

    // Initialize nDPI
    ctx->ndpi_mod = ndpi_init_detection_module(NULL);
    if (!ctx->ndpi_mod) {
        return -1;
    }

    if (ndpi_finalize_initialization(ctx->ndpi_mod) != 0) {
        ndpi_exit_detection_module(ctx->ndpi_mod);
        return -1;
    }

    // Open PCAP handle
    char errbuf[PCAP_ERRBUF_SIZE];
    ctx->pcap_handle = pcap_open_live(interface, 65535, 1, 100, errbuf);
    if (!ctx->pcap_handle) {
        fprintf(stderr, "Failed to open interface %s: %s\n", interface, errbuf);
        ndpi_exit_detection_module(ctx->ndpi_mod);
        return -1;
    }

    return 0;
}

// Cleanup thread context
void cleanup_thread_context(struct thread_context* ctx) {
    // Stop thread
    ctx->should_stop = 1;
    if (ctx->thread) {
        pthread_join(ctx->thread, NULL);
    }

    // Cleanup flows
    struct flow_info* flow, *tmp;
    HASH_ITER(hh, ctx->flows, flow, tmp) {
        HASH_DEL(ctx->flows, flow);
        if (flow->ndpi_flow) {
            ndpi_flow_free(flow->ndpi_flow);
        }
        free(flow);
    }

    // Cleanup resources
    if (ctx->pcap_handle) {
        pcap_close(ctx->pcap_handle);
    }

    if (ctx->ndpi_mod) {
        ndpi_exit_detection_module(ctx->ndpi_mod);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char* interface = argv[1];

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Multi-threaded nDPI monitor starting on %s\n", interface);
    printf("Using %d threads\n", MAX_THREADS);

    // Initialize threads
    for (int i = 0; i < MAX_THREADS; i++) {
        if (init_thread_context(&threads[i], i, interface) != 0) {
            fprintf(stderr, "Failed to initialize thread %d\n", i);
            return 1;
        }

        if (pthread_create(&threads[i].thread, NULL, worker_thread, &threads[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            return 1;
        }
    }

    // Statistics reporting loop
    while (!global_stop) {
        sleep(10);  // Report every 10 seconds

        uint64_t total_packets = 0, total_flows = 0, total_detected = 0;

        for (int i = 0; i < MAX_THREADS; i++) {
            total_packets += threads[i].packets_processed;
            total_flows += threads[i].flows_created;
            total_detected += threads[i].flows_detected;
        }

        printf("Stats: %llu packets, %llu flows, %llu detected\n",
               total_packets, total_flows, total_detected);
    }

    // Cleanup
    printf("Shutting down threads...\n");
    for (int i = 0; i < MAX_THREADS; i++) {
        cleanup_thread_context(&threads[i]);
    }

    printf("Shutdown complete\n");
    return 0;
}
```

### Compilation and Usage

```bash
# Compile with threading support
gcc -o mt_monitor mt_monitor.c -lndpi -lpcap -lpthread

# Run on network interface
sudo ./mt_monitor eth0
```

## Live Traffic Analysis with Risk Detection

An example that combines real-time traffic analysis with security risk detection:

```c
/*
 * risk_analyzer.c - Real-time traffic analysis with risk detection
 */
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

struct risk_flow {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;

    struct ndpi_flow_struct* ndpi_flow;
    struct ndpi_proto detected_protocol;

    ndpi_risk_enum risks;
    uint8_t risk_score;
    char risk_description[512];

    uint64_t first_seen, last_seen;
    uint32_t packets, bytes;
    uint8_t detection_completed;
    uint8_t risks_analyzed;
};

struct risk_stats {
    uint64_t total_flows;
    uint64_t flows_with_risks;
    uint64_t high_risk_flows;
    uint64_t critical_alerts;

    // Risk type counters
    uint64_t malicious_ja3_count;
    uint64_t sql_injection_count;
    uint64_t xss_attempt_count;
    uint64_t weak_crypto_count;
    uint64_t suspicious_entropy_count;
};

static struct ndpi_detection_module_struct* ndpi_mod = NULL;
static struct risk_stats stats;
static FILE* risk_log = NULL;

// Calculate risk score
uint8_t calculate_risk_score(ndpi_risk_enum risks) {
    uint8_t score = 0;

    // Critical risks (score += 30)
    if (risks & (NDPI_MALICIOUS_JA3 | NDPI_MALICIOUS_SHA1_CERTIFICATE |
                 NDPI_URL_POSSIBLE_RCE_INJECTION)) {
        score += 30;
    }

    // High risks (score += 20)
    if (risks & (NDPI_URL_POSSIBLE_SQL_INJECTION | NDPI_CLEAR_TEXT_CREDENTIALS |
                 NDPI_TLS_WEAK_CIPHER | NDPI_URL_POSSIBLE_XSS)) {
        score += 20;
    }

    // Medium risks (score += 15)
    if (risks & (NDPI_HTTP_SUSPICIOUS_HEADER | NDPI_SUSPICIOUS_ENTROPY |
                 NDPI_TLS_OBSOLETE_VERSION | NDPI_HTTP_SUSPICIOUS_URL)) {
        score += 15;
    }

    // Low risks (score += 10)
    if (risks & (NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT |
                 NDPI_DESKTOP_OR_FILE_SHARING_SESSION |
                 NDPI_UNIDIRECTIONAL_TRAFFIC)) {
        score += 10;
    }

    return (score > 100) ? 100 : score;
}

// Format risk description
void format_risk_description(ndpi_risk_enum risks, char* buffer, size_t buffer_size) {
    buffer[0] = '\0';

    if (risks & NDPI_MALICIOUS_JA3) {
        strncat(buffer, "Malicious JA3 fingerprint; ", buffer_size - strlen(buffer) - 1);
    }
    if (risks & NDPI_URL_POSSIBLE_SQL_INJECTION) {
        strncat(buffer, "SQL injection attempt; ", buffer_size - strlen(buffer) - 1);
    }
    if (risks & NDPI_URL_POSSIBLE_XSS) {
        strncat(buffer, "XSS attempt; ", buffer_size - strlen(buffer) - 1);
    }
    if (risks & NDPI_CLEAR_TEXT_CREDENTIALS) {
        strncat(buffer, "Clear text credentials; ", buffer_size - strlen(buffer) - 1);
    }
    if (risks & NDPI_TLS_WEAK_CIPHER) {
        strncat(buffer, "Weak TLS cipher; ", buffer_size - strlen(buffer) - 1);
    }
    if (risks & NDPI_SUSPICIOUS_ENTROPY) {
        strncat(buffer, "Suspicious entropy; ", buffer_size - strlen(buffer) - 1);
    }
    if (risks & NDPI_HTTP_SUSPICIOUS_HEADER) {
        strncat(buffer, "Suspicious HTTP header; ", buffer_size - strlen(buffer) - 1);
    }

    // Remove trailing semicolon and space
    size_t len = strlen(buffer);
    if (len > 2) {
        buffer[len - 2] = '\0';
    }
}

// Log risk alert
void log_risk_alert(struct risk_flow* flow) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // Log to file
    if (risk_log) {
        fprintf(risk_log, "[%s] RISK ALERT - Score: %d/100\n", timestamp, flow->risk_score);
        fprintf(risk_log, "  Flow: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%s)\n",
            (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
            (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF, flow->src_port,
            (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
            (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF, flow->dst_port,
            ndpi_get_proto_name(ndpi_mod, flow->detected_protocol.proto.app_protocol));
        fprintf(risk_log, "  Risks: %s\n", flow->risk_description);
        fprintf(risk_log, "  Packets: %u, Bytes: %u\n\n", flow->packets, flow->bytes);
        fflush(risk_log);
    }

    // Log to syslog for critical alerts
    if (flow->risk_score >= 70) {
        syslog(LOG_ALERT, "nDPI Critical Risk Alert: Score %d/100, Flow %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, Risks: %s",
            flow->risk_score,
            (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
            (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF, flow->src_port,
            (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
            (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF, flow->dst_port,
            flow->risk_description);

        stats.critical_alerts++;
    }

    // Console output for high-risk flows
    if (flow->risk_score >= 50) {
        printf("⚠️  HIGH RISK FLOW (Score: %d/100)\n", flow->risk_score);
        printf("   %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
            (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
            (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF, flow->src_port,
            (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
            (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF, flow->dst_port);
        printf("   Protocol: %s\n",
            ndpi_get_proto_name(ndpi_mod, flow->detected_protocol.proto.app_protocol));
        printf("   Risks: %s\n\n", flow->risk_description);

        stats.high_risk_flows++;
    }
}

// Analyze flow risks
void analyze_flow_risks(struct risk_flow* flow) {
    if (flow->risks_analyzed || !flow->detection_completed) {
        return;
    }

    // Get flow risks
    flow->risks = ndpi_get_flow_risk(flow->ndpi_flow);

    if (flow->risks != NDPI_NO_RISK) {
        stats.flows_with_risks++;

        // Calculate risk score
        flow->risk_score = calculate_risk_score(flow->risks);

        // Format description
        format_risk_description(flow->risks, flow->risk_description,
                              sizeof(flow->risk_description));

        // Update specific risk counters
        if (flow->risks & NDPI_MALICIOUS_JA3) stats.malicious_ja3_count++;
        if (flow->risks & NDPI_URL_POSSIBLE_SQL_INJECTION) stats.sql_injection_count++;
        if (flow->risks & NDPI_URL_POSSIBLE_XSS) stats.xss_attempt_count++;
        if (flow->risks & NDPI_TLS_WEAK_CIPHER) stats.weak_crypto_count++;
        if (flow->risks & NDPI_SUSPICIOUS_ENTROPY) stats.suspicious_entropy_count++;

        // Log alert
        log_risk_alert(flow);

        flow->risks_analyzed = 1;
    }
}

// Packet processing callback
void packet_handler(u_char* user, const struct pcap_pkthdr* header,
                   const u_char* packet) {
    static struct risk_flow flows[10000];
    static int flow_count = 0;

    const struct ndpi_ethhdr* ethernet = (struct ndpi_ethhdr*)packet;
    const struct ndpi_iphdr* ip;

    uint16_t type = ntohs(ethernet->h_proto);
    if (type != 0x0800) return;  // Only IPv4

    ip = (struct ndpi_iphdr*)(packet + sizeof(struct ndpi_ethhdr));
    if (ip->version != 4) return;

    // Extract flow information
    uint32_t src_ip = ntohl(ip->saddr);
    uint32_t dst_ip = ntohl(ip->daddr);
    uint16_t src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        const struct ndpi_tcphdr* tcp = (struct ndpi_tcphdr*)((uint8_t*)ip + (ip->ihl * 4));
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        const struct ndpi_udphdr* udp = (struct ndpi_udphdr*)((uint8_t*)ip + (ip->ihl * 4));
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }

    // Find or create flow (simplified)
    struct risk_flow* flow = NULL;
    for (int i = 0; i < flow_count; i++) {
        struct risk_flow* f = &flows[i];
        if ((f->src_ip == src_ip && f->dst_ip == dst_ip &&
             f->src_port == src_port && f->dst_port == dst_port &&
             f->protocol == ip->protocol) ||
            (f->src_ip == dst_ip && f->dst_ip == src_ip &&
             f->src_port == dst_port && f->dst_port == src_port &&
             f->protocol == ip->protocol)) {
            flow = f;
            break;
        }
    }

    if (!flow && flow_count < 10000) {
        flow = &flows[flow_count++];
        memset(flow, 0, sizeof(struct risk_flow));

        flow->src_ip = src_ip;
        flow->dst_ip = dst_ip;
        flow->src_port = src_port;
        flow->dst_port = dst_port;
        flow->protocol = ip->protocol;

        flow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
        if (!flow->ndpi_flow) return;
        memset(flow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

        flow->first_seen = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000;
        stats.total_flows++;
    }

    if (!flow) return;

    // Update flow statistics
    flow->last_seen = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000;
    flow->packets++;
    flow->bytes += header->len;

    // Process with nDPI
    if (!flow->detection_completed) {
        uint16_t ip_size = ntohs(ip->tot_len);

        flow->detected_protocol = ndpi_detection_process_packet(
            ndpi_mod, flow->ndpi_flow, (uint8_t*)ip, ip_size,
            flow->last_seen, NULL);

        if (ndpi_is_protocol_detected(flow->detected_protocol)) {
            flow->detection_completed = 1;

            printf("✓ Protocol detected: %s | %s\n",
                ndpi_get_proto_name(ndpi_mod, flow->detected_protocol.proto.master_protocol),
                ndpi_get_proto_name(ndpi_mod, flow->detected_protocol.proto.app_protocol));
        }
    }

    // Analyze risks
    analyze_flow_risks(flow);
}

// Print statistics
void print_statistics() {
    printf("\n=== nDPI Risk Analysis Statistics ===\n");
    printf("Total flows analyzed: %llu\n", stats.total_flows);
    printf("Flows with risks: %llu (%.2f%%)\n",
           stats.flows_with_risks,
           stats.total_flows > 0 ? (double)stats.flows_with_risks / stats.total_flows * 100 : 0);
    printf("High-risk flows: %llu\n", stats.high_risk_flows);
    printf("Critical alerts: %llu\n", stats.critical_alerts);
    printf("\nRisk Type Breakdown:\n");
    printf("  Malicious JA3: %llu\n", stats.malicious_ja3_count);
    printf("  SQL Injection: %llu\n", stats.sql_injection_count);
    printf("  XSS Attempts: %llu\n", stats.xss_attempt_count);
    printf("  Weak Crypto: %llu\n", stats.weak_crypto_count);
    printf("  Suspicious Entropy: %llu\n", stats.suspicious_entropy_count);
    printf("=====================================\n\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <interface_or_pcap_file>\n", argv[0]);
        return 1;
    }

    const char* source = argv[1];

    // Initialize nDPI
    ndpi_mod = ndpi_init_detection_module(NULL);
    if (!ndpi_mod) {
        fprintf(stderr, "Failed to initialize nDPI\n");
        return 1;
    }

    if (ndpi_finalize_initialization(ndpi_mod) != 0) {
        fprintf(stderr, "Failed to finalize nDPI initialization\n");
        return 1;
    }

    // Open risk log file
    risk_log = fopen("ndpi_risks.log", "a");
    if (!risk_log) {
        fprintf(stderr, "Warning: Could not open risk log file\n");
    }

    // Open syslog
    openlog("ndpi_risk_analyzer", LOG_PID, LOG_DAEMON);

    printf("nDPI Risk Analyzer %s starting\n", ndpi_revision());
    printf("Analyzing traffic from: %s\n", source);
    printf("Risk alerts will be logged to: ndpi_risks.log\n\n");

    // Open PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Try to open as live interface first, then as file
    handle = pcap_open_live(source, 65535, 1, 100, errbuf);
    if (!handle) {
        handle = pcap_open_offline(source, errbuf);
        if (!handle) {
            fprintf(stderr, "Failed to open %s: %s\n", source, errbuf);
            return 1;
        }
    }

    // Process packets
    signal(SIGINT, SIG_DFL);  // Allow Ctrl+C to interrupt

    printf("Starting packet analysis... (Press Ctrl+C to stop)\n\n");

    // Statistics reporting loop
    time_t last_stats = time(NULL);

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (1) {
        int result = pcap_next_ex(handle, &header, &packet);
        if (result == 1) {
            packet_handler(NULL, header, packet);

            // Print stats every 30 seconds
            time_t now = time(NULL);
            if (now - last_stats >= 30) {
                print_statistics();
                last_stats = now;
            }
        } else if (result == 0) {
            usleep(10000);  // No packet available
        } else {
            break;  // Error or end of file
        }
    }

    // Final statistics
    print_statistics();

    // Cleanup
    pcap_close(handle);
    ndpi_exit_detection_module(ndpi_mod);

    if (risk_log) {
        fclose(risk_log);
    }

    closelog();

    return 0;
}
```

### Compilation and Usage

```bash
# Compile with required libraries
gcc -o risk_analyzer risk_analyzer.c -lndpi -lpcap

# Run on live interface
sudo ./risk_analyzer eth0

# Or analyze PCAP file
./risk_analyzer capture.pcap
```

## Building and Running Examples

### Makefile for Examples

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LIBS = -lndpi -lpcap -lpthread
INCLUDES = -I/usr/local/include

TARGETS = simple_reader mt_monitor risk_analyzer

all: $(TARGETS)

simple_reader: simple_reader.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

mt_monitor: mt_monitor.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

risk_analyzer: risk_analyzer.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGETS)

install: all
	cp $(TARGETS) /usr/local/bin/

.PHONY: all clean install
```

### Usage Examples

```bash
# Build all examples
make

# Simple packet reader
./simple_reader sample.pcap

# Multi-threaded monitor (requires root for live capture)
sudo ./mt_monitor eth0

# Risk analyzer
sudo ./risk_analyzer eth0
# or
./risk_analyzer malicious_traffic.pcap
```

## Next Steps

These examples provide a solid foundation for building nDPI-based applications. You can extend them by:

- Adding database integration for flow storage
- Implementing web dashboards for real-time monitoring
- Creating custom protocol detection rules
- Integrating with SIEM systems
- Adding machine learning for anomaly detection

Continue with:
- [API Reference](./api-reference)