---
sidebar_position: 3
---

# Basic Integration

This guide shows how to integrate nDPI into your application for basic protocol detection.

## Simple Integration Example

Here's a minimal example showing how to use nDPI:

```c
#include <ndpi_api.h>
#include <ndpi_typedefs.h>
#include <ndpi_main.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Initialize nDPI detection module
    struct ndpi_detection_module_struct* ndpi_mod = ndpi_init_detection_module(NULL);
    if (!ndpi_mod) {
        fprintf(stderr, "Failed to initialize nDPI\n");
        return 1;
    }

    // Finalize initialization
    if (ndpi_finalize_initialization(ndpi_mod) != 0) {
        fprintf(stderr, "Failed to finalize nDPI initialization\n");
        ndpi_exit_detection_module(ndpi_mod);
        return 1;
    }

    printf("nDPI v%s initialized successfully!\n", ndpi_revision());
    printf("API version: %u\n", ndpi_get_api_version());

    // Cleanup
    ndpi_exit_detection_module(ndpi_mod);
    return 0;
}
```

## Initialization Steps

### 1. Create Detection Module

```c
struct ndpi_detection_module_struct* ndpi_mod;

// Basic initialization
ndpi_mod = ndpi_init_detection_module(NULL);

// With custom configuration
NDPI_PROTOCOL_BITMASK all_protocols;
NDPI_BITMASK_SET_ALL(all_protocols);
ndpi_mod = ndpi_init_detection_module(&all_protocols);
```

### 2. Configure Protocol Detection

```c
// Enable all protocols (default)
NDPI_PROTOCOL_BITMASK all_protocols;
NDPI_BITMASK_SET_ALL(all_protocols);
ndpi_set_protocol_detection_bitmask2(ndpi_mod, &all_protocols);

// Enable specific protocols only
NDPI_PROTOCOL_BITMASK custom_protocols;
NDPI_BITMASK_RESET(custom_protocols);
NDPI_BITMASK_ADD(custom_protocols, NDPI_PROTOCOL_HTTP);
NDPI_BITMASK_ADD(custom_protocols, NDPI_PROTOCOL_HTTPS);
NDPI_BITMASK_ADD(custom_protocols, NDPI_PROTOCOL_DNS);
ndpi_set_protocol_detection_bitmask2(ndpi_mod, &custom_protocols);
```

### 3. Finalize Initialization

```c
// This step is required before processing packets
if (ndpi_finalize_initialization(ndpi_mod) != 0) {
    fprintf(stderr, "Failed to finalize nDPI\n");
    return -1;
}
```

## Flow Management

### Creating a Flow

```c
// Allocate flow structure
struct ndpi_flow_struct* flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
if (!flow) {
    fprintf(stderr, "Failed to allocate flow\n");
    return NULL;
}
memset(flow, 0, SIZEOF_FLOW_STRUCT);
```

### Flow Information Structure

```c
struct flow_info {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;

    struct ndpi_flow_struct* ndpi_flow;
    struct ndpi_proto detected_protocol;

    uint32_t packets_processed;
    uint64_t first_seen, last_seen;
    uint8_t detection_completed;
};
```

## Packet Processing

### Basic Packet Analysis

```c
struct ndpi_proto process_packet(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow,
    const uint8_t* packet,
    uint16_t packet_len,
    uint64_t timestamp
) {
    return ndpi_detection_process_packet(
        ndpi_mod,
        flow,
        packet,
        packet_len,
        timestamp,
        NULL  // src (optional)
    );
}
```

### Complete Processing Example

```c
void analyze_packet(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct flow_info* flow_info,
    const uint8_t* ip_packet,
    uint16_t ip_len,
    uint64_t timestamp
) {
    // Process packet with nDPI
    flow_info->detected_protocol = ndpi_detection_process_packet(
        ndpi_mod,
        flow_info->ndpi_flow,
        ip_packet,
        ip_len,
        timestamp,
        NULL
    );

    flow_info->packets_processed++;
    flow_info->last_seen = timestamp;

    if (flow_info->first_seen == 0) {
        flow_info->first_seen = timestamp;
    }

    // Check if protocol is detected
    if (ndpi_is_protocol_detected(flow_info->detected_protocol) &&
        !flow_info->detection_completed) {

        flow_info->detection_completed = 1;

        printf("Protocol detected: %s | %s\n",
            ndpi_get_proto_name(ndpi_mod, flow_info->detected_protocol.proto.master_protocol),
            ndpi_get_proto_name(ndpi_mod, flow_info->detected_protocol.proto.app_protocol)
        );

        printf("Category: %s\n",
            ndpi_category_get_name(ndpi_mod, flow_info->detected_protocol.category)
        );
    }
}
```

## Working with Network Layers

### Extracting L4 Information

```c
int extract_l4_info(
    const uint8_t* ip_packet,
    uint16_t ip_len,
    const uint8_t** l4_ptr,
    uint16_t* l4_len,
    uint8_t* l4_protocol
) {
    return ndpi_detection_get_l4(
        ip_packet,
        ip_len,
        l4_ptr,
        l4_len,
        l4_protocol,
        NDPI_DETECTION_ONLY_IPV4 | NDPI_DETECTION_ONLY_IPV6
    );
}
```

### Handling IPv4 and IPv6

```c
void process_ip_packet(
    const uint8_t* packet,
    uint16_t packet_len,
    struct flow_info* flow
) {
    const struct ndpi_iphdr* ipv4 = (struct ndpi_iphdr*)packet;
    const struct ndpi_ipv6hdr* ipv6 = (struct ndpi_ipv6hdr*)packet;

    if (ipv4->version == 4) {
        flow->src_ip = ipv4->saddr;
        flow->dst_ip = ipv4->daddr;
        flow->protocol = ipv4->protocol;
    } else if (ipv4->version == 6) {
        // Handle IPv6
        memcpy(&flow->src_ip, &ipv6->ip6_src, 16);
        memcpy(&flow->dst_ip, &ipv6->ip6_dst, 16);
        flow->protocol = ipv6->ip6_nxt;
    }
}
```

## Error Handling

### Common Error Checks

```c
// Check initialization
if (!ndpi_mod) {
    fprintf(stderr, "nDPI initialization failed\n");
    return -1;
}

// Check flow allocation
if (!flow) {
    fprintf(stderr, "Flow allocation failed\n");
    return -1;
}

// Check packet processing
if (packet_len < sizeof(struct ndpi_iphdr)) {
    fprintf(stderr, "Packet too small\n");
    return -1;
}
```

### Memory Management

```c
void cleanup_flow(struct flow_info* flow_info) {
    if (flow_info && flow_info->ndpi_flow) {
        ndpi_flow_free(flow_info->ndpi_flow);
        flow_info->ndpi_flow = NULL;
    }
    if (flow_info) {
        free(flow_info);
    }
}

void cleanup_ndpi(struct ndpi_detection_module_struct* ndpi_mod) {
    if (ndpi_mod) {
        ndpi_exit_detection_module(ndpi_mod);
    }
}
```

## Complete Minimal Example

```c
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct simple_flow {
    struct ndpi_flow_struct* ndpi_flow;
    struct ndpi_proto result;
    uint32_t packets;
};

int main() {
    // Initialize nDPI
    struct ndpi_detection_module_struct* ndpi_mod = ndpi_init_detection_module(NULL);
    if (!ndpi_mod) {
        return 1;
    }

    if (ndpi_finalize_initialization(ndpi_mod) != 0) {
        ndpi_exit_detection_module(ndpi_mod);
        return 1;
    }

    // Create a flow
    struct simple_flow flow;
    flow.ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (!flow.ndpi_flow) {
        ndpi_exit_detection_module(ndpi_mod);
        return 1;
    }
    memset(flow.ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    flow.packets = 0;

    // Example: Process a dummy packet (normally you'd get this from pcap/socket)
    uint8_t dummy_packet[] = { /* your packet data */ };
    uint64_t timestamp = time(NULL) * 1000; // milliseconds

    // Process packet
    flow.result = ndpi_detection_process_packet(
        ndpi_mod,
        flow.ndpi_flow,
        dummy_packet,
        sizeof(dummy_packet),
        timestamp,
        NULL
    );

    flow.packets++;

    // Check result
    if (ndpi_is_protocol_detected(flow.result)) {
        printf("Detected: %s\n",
            ndpi_get_proto_name(ndpi_mod, flow.result.proto.app_protocol));
    } else {
        printf("Protocol not yet detected (%d packets processed)\n", flow.packets);
    }

    // Cleanup
    ndpi_flow_free(flow.ndpi_flow);
    ndpi_exit_detection_module(ndpi_mod);

    return 0;
}
```

## Compilation

To compile your nDPI application:

```bash
# Basic compilation
gcc -o my_app main.c -lndpi

# With pkg-config
gcc -o my_app main.c $(pkg-config --cflags --libs libndpi)

# Static linking
gcc -o my_app main.c -I/usr/local/include -L/usr/local/lib -lndpi -lm -lpthread

# Debug build
gcc -g -O0 -o my_app main.c -lndpi -DDEBUG
```

## Next Steps

Now that you understand basic integration:

- [Learn about flow management](./flows)
- [Explore risk detection](./risks)
- [See complete examples](./examples)