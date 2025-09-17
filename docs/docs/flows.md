---
sidebar_position: 4
---

# Flow Management

This guide explains how to manage network flows in nDPI for effective protocol detection and analysis.

## Understanding Flows

A **flow** in nDPI represents a sequence of packets between two endpoints. Flows are bidirectional and identified by:

- Source and destination IP addresses
- Source and destination ports
- Protocol (TCP/UDP/ICMP)

## Flow Lifecycle

### 1. Flow Creation

```c
struct flow_info {
    // Network identifiers
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;

    // nDPI specific
    struct ndpi_flow_struct* ndpi_flow;
    struct ndpi_proto detected_protocol;
    struct ndpi_proto guessed_protocol;

    // Flow metadata
    uint64_t first_seen, last_seen;
    uint64_t packets_processed;
    uint64_t bytes_processed;
    uint8_t detection_completed;
    uint8_t flow_finished;
};

struct flow_info* create_flow(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t protocol
) {
    struct flow_info* flow = malloc(sizeof(struct flow_info));
    if (!flow) return NULL;

    memset(flow, 0, sizeof(struct flow_info));

    // Set network identifiers
    flow->src_ip = src_ip;
    flow->dst_ip = dst_ip;
    flow->src_port = src_port;
    flow->dst_port = dst_port;
    flow->protocol = protocol;

    // Allocate nDPI flow structure
    flow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (!flow->ndpi_flow) {
        free(flow);
        return NULL;
    }
    memset(flow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    return flow;
}
```

### 2. Flow Hash Table Management

```c
#include <uthash.h>

struct flow_entry {
    uint64_t flow_key;           // Hash key
    struct flow_info* flow;      // Flow data
    UT_hash_handle hh;          // Hash table handle
};

struct flow_manager {
    struct flow_entry* active_flows;  // Hash table of active flows
    uint32_t max_flows;
    uint32_t current_flows;
    uint64_t total_flows;
};

// Generate flow key
uint64_t generate_flow_key(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t protocol
) {
    uint64_t key = 0;

    // Ensure bidirectional flow matching
    if (src_ip > dst_ip || (src_ip == dst_ip && src_port > dst_port)) {
        // Swap src and dst
        key = ((uint64_t)dst_ip << 32) | src_ip;
        key ^= ((uint64_t)dst_port << 16) | src_port;
    } else {
        key = ((uint64_t)src_ip << 32) | dst_ip;
        key ^= ((uint64_t)src_port << 16) | dst_port;
    }

    key ^= protocol;
    return key;
}

// Find existing flow
struct flow_info* find_flow(
    struct flow_manager* manager,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t protocol
) {
    uint64_t key = generate_flow_key(src_ip, dst_ip, src_port, dst_port, protocol);
    struct flow_entry* entry;

    HASH_FIND_INT64(manager->active_flows, &key, entry);
    return entry ? entry->flow : NULL;
}

// Add new flow
int add_flow(struct flow_manager* manager, struct flow_info* flow) {
    if (manager->current_flows >= manager->max_flows) {
        return -1;  // Flow table full
    }

    struct flow_entry* entry = malloc(sizeof(struct flow_entry));
    if (!entry) return -1;

    entry->flow_key = generate_flow_key(
        flow->src_ip, flow->dst_ip,
        flow->src_port, flow->dst_port,
        flow->protocol
    );
    entry->flow = flow;

    HASH_ADD_INT64(manager->active_flows, flow_key, entry);
    manager->current_flows++;
    manager->total_flows++;

    return 0;
}
```

### 3. Packet Processing Per Flow

```c
void process_packet_for_flow(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct flow_info* flow,
    const uint8_t* ip_packet,
    uint16_t packet_len,
    uint64_t timestamp
) {
    // Update flow timestamps
    if (flow->first_seen == 0) {
        flow->first_seen = timestamp;
    }
    flow->last_seen = timestamp;
    flow->packets_processed++;
    flow->bytes_processed += packet_len;

    // Process with nDPI if detection not completed
    if (!flow->detection_completed &&
        flow->ndpi_flow->num_processed_pkts < 255) {

        flow->detected_protocol = ndpi_detection_process_packet(
            ndpi_mod,
            flow->ndpi_flow,
            ip_packet,
            packet_len,
            timestamp,
            NULL
        );

        // Check if protocol detected
        if (ndpi_is_protocol_detected(flow->detected_protocol)) {
            flow->detection_completed = 1;

            printf("Flow %u:%u -> %u:%u detected as %s | %s\n",
                ntohl(flow->src_ip), flow->src_port,
                ntohl(flow->dst_ip), flow->dst_port,
                ndpi_get_proto_name(ndpi_mod, flow->detected_protocol.proto.master_protocol),
                ndpi_get_proto_name(ndpi_mod, flow->detected_protocol.proto.app_protocol)
            );
        }

        // Last chance detection
        else if (flow->ndpi_flow->num_processed_pkts == 254) {
            uint8_t was_guessed = 0;
            flow->guessed_protocol = ndpi_detection_giveup(
                ndpi_mod, flow->ndpi_flow, &was_guessed
            );

            if (was_guessed) {
                printf("Flow %u:%u -> %u:%u guessed as %s\n",
                    ntohl(flow->src_ip), flow->src_port,
                    ntohl(flow->dst_ip), flow->dst_port,
                    ndpi_get_proto_name(ndpi_mod, flow->guessed_protocol.proto.app_protocol)
                );
            }
            flow->detection_completed = 1;
        }
    }
}
```

## Advanced Flow Features

### Flow Information Extraction

```c
void extract_flow_info(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct flow_info* flow
) {
    if (!flow->detection_completed) return;

    // Get additional flow information
    const char* flow_info = ndpi_get_flow_info(flow->ndpi_flow, &flow->detected_protocol);
    if (flow_info) {
        printf("Flow info: %s\n", flow_info);
    }

    // TLS specific information
    if (flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_TLS ||
        flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_TLS) {

        if (flow->ndpi_flow->host_server_name[0] != '\0') {
            printf("TLS SNI: %s\n", flow->ndpi_flow->host_server_name);
        }

        if (flow->ndpi_flow->protos.tls_quic.server_names) {
            printf("TLS Server Names: %s\n", flow->ndpi_flow->protos.tls_quic.server_names);
        }

        if (flow->ndpi_flow->protos.tls_quic.issuerDN) {
            printf("TLS Issuer: %s\n", flow->ndpi_flow->protos.tls_quic.issuerDN);
        }
    }

    // HTTP specific information
    if (flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_HTTP) {
        if (flow->ndpi_flow->host_server_name[0] != '\0') {
            printf("HTTP Host: %s\n", flow->ndpi_flow->host_server_name);
        }
    }
}
```

### Flow Serialization

```c
void serialize_flow_to_json(struct flow_info* flow, FILE* output) {
    fprintf(output, "{\n");
    fprintf(output, "  \"src_ip\": \"%u.%u.%u.%u\",\n",
        (ntohl(flow->src_ip) >> 24) & 0xFF,
        (ntohl(flow->src_ip) >> 16) & 0xFF,
        (ntohl(flow->src_ip) >> 8) & 0xFF,
        ntohl(flow->src_ip) & 0xFF
    );
    fprintf(output, "  \"dst_ip\": \"%u.%u.%u.%u\",\n",
        (ntohl(flow->dst_ip) >> 24) & 0xFF,
        (ntohl(flow->dst_ip) >> 16) & 0xFF,
        (ntohl(flow->dst_ip) >> 8) & 0xFF,
        ntohl(flow->dst_ip) & 0xFF
    );
    fprintf(output, "  \"src_port\": %u,\n", flow->src_port);
    fprintf(output, "  \"dst_port\": %u,\n", flow->dst_port);
    fprintf(output, "  \"protocol\": %u,\n", flow->protocol);
    fprintf(output, "  \"packets\": %llu,\n", flow->packets_processed);
    fprintf(output, "  \"bytes\": %llu,\n", flow->bytes_processed);
    fprintf(output, "  \"first_seen\": %llu,\n", flow->first_seen);
    fprintf(output, "  \"last_seen\": %llu,\n", flow->last_seen);

    if (flow->detection_completed) {
        fprintf(output, "  \"detected_protocol\": \"%s\",\n",
            ndpi_get_proto_name(NULL, flow->detected_protocol.proto.app_protocol));
        fprintf(output, "  \"master_protocol\": \"%s\",\n",
            ndpi_get_proto_name(NULL, flow->detected_protocol.proto.master_protocol));
        fprintf(output, "  \"category\": \"%s\"\n",
            ndpi_category_get_name(NULL, flow->detected_protocol.category));
    }

    fprintf(output, "}\n");
}
```

## Flow Timeout and Cleanup

### Timeout Management

```c
#define FLOW_TIMEOUT_SECONDS 300  // 5 minutes
#define FLOW_CLEANUP_INTERVAL 30  // 30 seconds

void cleanup_expired_flows(
    struct flow_manager* manager,
    uint64_t current_time
) {
    struct flow_entry* entry, *tmp;
    uint64_t timeout_threshold = current_time - (FLOW_TIMEOUT_SECONDS * 1000);

    HASH_ITER(hh, manager->active_flows, entry, tmp) {
        struct flow_info* flow = entry->flow;

        // Check for timeout or TCP FIN
        if (flow->last_seen < timeout_threshold || flow->flow_finished) {

            // Print final flow stats
            printf("Closing flow %u:%u -> %u:%u (%llu packets, %llu bytes)\n",
                ntohl(flow->src_ip), flow->src_port,
                ntohl(flow->dst_ip), flow->dst_port,
                flow->packets_processed, flow->bytes_processed
            );

            // Remove from hash table
            HASH_DEL(manager->active_flows, entry);
            manager->current_flows--;

            // Free memory
            if (flow->ndpi_flow) {
                ndpi_flow_free(flow->ndpi_flow);
            }
            free(flow);
            free(entry);
        }
    }
}
```

### TCP Connection State Tracking

```c
void update_tcp_state(struct flow_info* flow, const struct ndpi_tcphdr* tcp) {
    // Track TCP flags
    if (tcp->fin) {
        flow->flow_finished = 1;
        printf("TCP FIN detected for flow\n");
    }

    if (tcp->rst) {
        flow->flow_finished = 1;
        printf("TCP RST detected for flow\n");
    }

    // Update connection state based on flags
    if (tcp->syn && !tcp->ack) {
        printf("TCP SYN - new connection\n");
    } else if (tcp->syn && tcp->ack) {
        printf("TCP SYN-ACK - connection establishing\n");
    } else if (tcp->ack) {
        printf("TCP ACK - data transfer\n");
    }
}
```

## Complete Flow Manager Example

```c
#include <ndpi_api.h>
#include <uthash.h>
#include <time.h>

struct complete_flow_manager {
    struct ndpi_detection_module_struct* ndpi_mod;
    struct flow_entry* active_flows;
    uint32_t max_flows;
    uint32_t current_flows;
    uint64_t total_flows;
    uint64_t last_cleanup_time;
};

struct complete_flow_manager* init_flow_manager(uint32_t max_flows) {
    struct complete_flow_manager* manager = malloc(sizeof(struct complete_flow_manager));
    if (!manager) return NULL;

    memset(manager, 0, sizeof(struct complete_flow_manager));

    // Initialize nDPI
    manager->ndpi_mod = ndpi_init_detection_module(NULL);
    if (!manager->ndpi_mod) {
        free(manager);
        return NULL;
    }

    if (ndpi_finalize_initialization(manager->ndpi_mod) != 0) {
        ndpi_exit_detection_module(manager->ndpi_mod);
        free(manager);
        return NULL;
    }

    manager->max_flows = max_flows;
    manager->last_cleanup_time = time(NULL) * 1000;

    return manager;
}

void process_packet(
    struct complete_flow_manager* manager,
    const uint8_t* packet,
    uint16_t packet_len,
    uint64_t timestamp
) {
    // Extract flow identifiers from packet
    // (This would include IP/TCP/UDP header parsing)

    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;

    // ... packet parsing code ...

    // Find or create flow
    struct flow_info* flow = find_flow(manager, src_ip, dst_ip, src_port, dst_port, protocol);
    if (!flow) {
        flow = create_flow(src_ip, dst_ip, src_port, dst_port, protocol);
        if (flow && add_flow(manager, flow) != 0) {
            // Flow table full, handle appropriately
            free_flow(flow);
            return;
        }
    }

    if (flow) {
        process_packet_for_flow(manager->ndpi_mod, flow, packet, packet_len, timestamp);
    }

    // Periodic cleanup
    if (timestamp - manager->last_cleanup_time > (FLOW_CLEANUP_INTERVAL * 1000)) {
        cleanup_expired_flows(manager, timestamp);
        manager->last_cleanup_time = timestamp;
    }
}

void free_flow_manager(struct complete_flow_manager* manager) {
    if (!manager) return;

    // Free all flows
    struct flow_entry* entry, *tmp;
    HASH_ITER(hh, manager->active_flows, entry, tmp) {
        HASH_DEL(manager->active_flows, entry);
        if (entry->flow) {
            if (entry->flow->ndpi_flow) {
                ndpi_flow_free(entry->flow->ndpi_flow);
            }
            free(entry->flow);
        }
        free(entry);
    }

    // Free nDPI
    if (manager->ndpi_mod) {
        ndpi_exit_detection_module(manager->ndpi_mod);
    }

    free(manager);
}
```

## Best Practices

### Flow Management Tips

1. **Memory Management**: Always free flows properly to avoid leaks
2. **Timeout Values**: Adjust timeouts based on your network characteristics
3. **Hash Table Size**: Size hash table appropriately for expected flow count
4. **Bidirectional Matching**: Ensure flows are matched bidirectionally
5. **Performance**: Consider flow caching for high-throughput scenarios

### Common Pitfalls

- **Memory Leaks**: Not freeing flow structures
- **Hash Collisions**: Poor flow key generation
- **Timeouts**: Inappropriate timeout values
- **Thread Safety**: Synchronization in multi-threaded environments
- **Packet Ordering**: Out-of-order packet handling

## Next Steps

- [Learn about risk detection](./risks)
- [Check out complete examples](./examples)
- [See API reference](./api-reference)