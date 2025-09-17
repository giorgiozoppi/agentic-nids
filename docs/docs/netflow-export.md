# nDPI to NetFlow Export

This guide explains how to convert nDPI flows to standard NetFlow v9 format for compatibility with network monitoring tools and SIEM systems.

## Overview

Converting nDPI flows to NetFlow format enables integration with existing network monitoring infrastructure while preserving the enhanced protocol detection capabilities of nDPI.

## NetFlow v9 Specification

Based on [RFC 3954](https://datatracker.ietf.org/doc/html/rfc3954), NetFlow v9 uses a template-based approach for flexible field definitions.

### Packet Structure

```
NetFlow v9 Export Packet:
├── Packet Header (20 bytes)
├── Template FlowSet (variable)
└── Data FlowSet(s) (variable)
```

### Key Components

1. **Export Packet Header**
   - Version (2 bytes) = 9
   - Count (2 bytes) - Number of FlowSets
   - System Uptime (4 bytes)
   - Unix Timestamp (4 bytes)
   - Sequence Number (4 bytes)
   - Source ID (4 bytes)

2. **Template FlowSet**
   - Defines structure of flow records
   - Template ID (≥ 256)
   - Field specifications

3. **Data FlowSet**
   - Contains actual flow data
   - References Template ID

## nDPI to NetFlow Field Mapping

### Core NetFlow Fields

| NetFlow Field Type | nDPI Source | Description |
|--------------------|-------------|-------------|
| 1 (IN_BYTES) | flow->bytes[0] + flow->bytes[1] | Total bytes |
| 2 (IN_PKTS) | flow->packets[0] + flow->packets[1] | Total packets |
| 4 (PROTOCOL) | flow->protocol | IP protocol |
| 7 (L4_SRC_PORT) | flow->src_port | Source port |
| 8 (IPV4_SRC_ADDR) | flow->src_ip | Source IP |
| 11 (L4_DST_PORT) | flow->dst_port | Destination port |
| 12 (IPV4_DST_ADDR) | flow->dst_ip | Destination IP |
| 21 (LAST_SWITCHED) | flow->last_seen | Flow end time |
| 22 (FIRST_SWITCHED) | flow->first_seen | Flow start time |

### nDPI Extended Fields

| Custom Field ID | nDPI Source | Description |
|-----------------|-------------|-------------|
| 32768 | flow->detected_protocol | nDPI protocol ID |
| 32769 | flow->master_protocol | nDPI master protocol |
| 32770 | flow->category | Application category |
| 32771 | flow->risk | Risk score |
| 32772 | flow->confidence | Detection confidence |

## Implementation

### Data Structures

```cpp
#include <stdint.h>
#include <netinet/in.h>

// NetFlow v9 Packet Header
struct netflow_v9_header {
    uint16_t version;        // 9
    uint16_t count;          // Number of FlowSets
    uint32_t sys_uptime;     // System uptime in ms
    uint32_t unix_secs;      // Unix timestamp
    uint32_t sequence;       // Sequence number
    uint32_t source_id;      // Source ID
} __attribute__((packed));

// Template Record
struct template_field {
    uint16_t field_type;
    uint16_t field_length;
} __attribute__((packed));

struct template_record {
    uint16_t template_id;
    uint16_t field_count;
    struct template_field fields[];
} __attribute__((packed));

// FlowSet Header
struct flowset_header {
    uint16_t flowset_id;
    uint16_t length;
} __attribute__((packed));

// nDPI Flow Data Record (based on template)
struct ndpi_netflow_record {
    uint64_t in_bytes;       // Total bytes
    uint64_t in_pkts;        // Total packets
    uint8_t protocol;        // IP protocol
    uint16_t src_port;       // Source port
    uint32_t src_addr;       // Source IP
    uint16_t dst_port;       // Destination port
    uint32_t dst_addr;       // Destination IP
    uint32_t first_switched; // Flow start
    uint32_t last_switched;  // Flow end
    uint16_t ndpi_protocol;  // nDPI protocol ID
    uint16_t ndpi_master;    // nDPI master protocol
    uint8_t ndpi_category;   // Application category
    uint8_t ndpi_risk;       // Risk score
    uint8_t ndpi_confidence; // Detection confidence
} __attribute__((packed));
```

### Template Definition

```cpp
#define TEMPLATE_ID 256
#define NDPI_NETFLOW_TEMPLATE_FIELD_COUNT 13

struct template_field ndpi_template_fields[] = {
    {1, 8},     // IN_BYTES (8 bytes)
    {2, 8},     // IN_PKTS (8 bytes)
    {4, 1},     // PROTOCOL (1 byte)
    {7, 2},     // L4_SRC_PORT (2 bytes)
    {8, 4},     // IPV4_SRC_ADDR (4 bytes)
    {11, 2},    // L4_DST_PORT (2 bytes)
    {12, 4},    // IPV4_DST_ADDR (4 bytes)
    {21, 4},    // LAST_SWITCHED (4 bytes)
    {22, 4},    // FIRST_SWITCHED (4 bytes)
    {32768, 2}, // NDPI_PROTOCOL (2 bytes)
    {32769, 2}, // NDPI_MASTER (2 bytes)
    {32770, 1}, // NDPI_CATEGORY (1 byte)
    {32771, 1}, // NDPI_RISK (1 byte)
    {32772, 1}  // NDPI_CONFIDENCE (1 byte)
};

void create_ndpi_template(uint8_t *buffer, size_t *offset) {
    struct flowset_header *flowset = (struct flowset_header *)(buffer + *offset);
    flowset->flowset_id = htons(0); // Template FlowSet ID

    *offset += sizeof(struct flowset_header);

    struct template_record *template = (struct template_record *)(buffer + *offset);
    template->template_id = htons(TEMPLATE_ID);
    template->field_count = htons(NDPI_NETFLOW_TEMPLATE_FIELD_COUNT);

    *offset += sizeof(struct template_record);

    // Copy template fields
    memcpy(buffer + *offset, ndpi_template_fields,
           sizeof(ndpi_template_fields));
    *offset += sizeof(ndpi_template_fields);

    // Set FlowSet length
    flowset->length = htons(*offset - ((uint8_t*)flowset - buffer));

    // Pad to 4-byte boundary
    while (*offset % 4 != 0) {
        buffer[(*offset)++] = 0;
    }
}
```

### Flow Conversion

```cpp
void convert_ndpi_flow_to_netflow(struct ndpi_flow_info *ndpi_flow,
                                  struct ndpi_netflow_record *netflow_record) {
    // Basic flow statistics
    netflow_record->in_bytes = htonll(ndpi_flow->bytes[0] + ndpi_flow->bytes[1]);
    netflow_record->in_pkts = htonll(ndpi_flow->packets[0] + ndpi_flow->packets[1]);
    netflow_record->protocol = ndpi_flow->protocol;

    // Network addresses and ports
    netflow_record->src_addr = htonl(ndpi_flow->src_ip);
    netflow_record->dst_addr = htonl(ndpi_flow->dst_ip);
    netflow_record->src_port = htons(ndpi_flow->src_port);
    netflow_record->dst_port = htons(ndpi_flow->dst_port);

    // Timing information
    netflow_record->first_switched = htonl(ndpi_flow->first_seen);
    netflow_record->last_switched = htonl(ndpi_flow->last_seen);

    // nDPI-specific information
    netflow_record->ndpi_protocol = htons(ndpi_flow->detected_protocol);
    netflow_record->ndpi_master = htons(ndpi_flow->master_protocol);
    netflow_record->ndpi_category = ndpi_flow->category;
    netflow_record->ndpi_risk = ndpi_risk_score(ndpi_flow);
    netflow_record->ndpi_confidence = ndpi_flow->confidence;
}
```

### Export Function

```cpp
#include <sys/socket.h>
#include <arpa/inet.h>

struct netflow_exporter {
    int socket_fd;
    struct sockaddr_in collector_addr;
    uint32_t sequence_number;
    uint32_t source_id;
    time_t last_template_sent;
};

int export_ndpi_flows_as_netflow(struct netflow_exporter *exporter,
                                 struct ndpi_flow_info *flows,
                                 size_t flow_count) {
    uint8_t packet_buffer[1500]; // MTU-sized buffer
    size_t offset = 0;
    time_t current_time = time(NULL);

    // Create packet header
    struct netflow_v9_header *header = (struct netflow_v9_header *)packet_buffer;
    header->version = htons(9);
    header->sys_uptime = htonl(get_system_uptime_ms());
    header->unix_secs = htonl(current_time);
    header->sequence = htonl(exporter->sequence_number);
    header->source_id = htonl(exporter->source_id);

    offset = sizeof(struct netflow_v9_header);

    // Send template every 30 minutes or if this is the first export
    if (current_time - exporter->last_template_sent > 1800 ||
        exporter->last_template_sent == 0) {
        create_ndpi_template(packet_buffer, &offset);
        exporter->last_template_sent = current_time;
        header->count = htons(1); // Template FlowSet
    }

    // Create data FlowSet
    struct flowset_header *data_flowset =
        (struct flowset_header *)(packet_buffer + offset);
    data_flowset->flowset_id = htons(TEMPLATE_ID);

    size_t data_start = offset + sizeof(struct flowset_header);
    offset = data_start;

    size_t records_exported = 0;
    for (size_t i = 0; i < flow_count; i++) {
        // Check if we have space for another record
        if (offset + sizeof(struct ndpi_netflow_record) > sizeof(packet_buffer)) {
            break;
        }

        struct ndpi_netflow_record *record =
            (struct ndpi_netflow_record *)(packet_buffer + offset);

        convert_ndpi_flow_to_netflow(&flows[i], record);
        offset += sizeof(struct ndpi_netflow_record);
        records_exported++;
    }

    // Set data FlowSet length
    data_flowset->length = htons(offset - data_start + sizeof(struct flowset_header));

    // Pad to 4-byte boundary
    while (offset % 4 != 0) {
        packet_buffer[offset++] = 0;
    }

    // Update header count
    header->count = htons(ntohs(header->count) + 1); // Add data FlowSet

    // Send packet
    int result = sendto(exporter->socket_fd, packet_buffer, offset, 0,
                       (struct sockaddr *)&exporter->collector_addr,
                       sizeof(exporter->collector_addr));

    if (result > 0) {
        exporter->sequence_number += records_exported;
    }

    return records_exported;
}
```

### Initialization

```cpp
int init_netflow_exporter(struct netflow_exporter *exporter,
                         const char *collector_ip,
                         uint16_t collector_port,
                         uint32_t source_id) {
    // Create UDP socket
    exporter->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (exporter->socket_fd < 0) {
        return -1;
    }

    // Configure collector address
    memset(&exporter->collector_addr, 0, sizeof(exporter->collector_addr));
    exporter->collector_addr.sin_family = AF_INET;
    exporter->collector_addr.sin_port = htons(collector_port);

    if (inet_pton(AF_INET, collector_ip, &exporter->collector_addr.sin_addr) <= 0) {
        close(exporter->socket_fd);
        return -1;
    }

    // Initialize state
    exporter->sequence_number = 0;
    exporter->source_id = source_id;
    exporter->last_template_sent = 0;

    return 0;
}

void cleanup_netflow_exporter(struct netflow_exporter *exporter) {
    if (exporter->socket_fd >= 0) {
        close(exporter->socket_fd);
        exporter->socket_fd = -1;
    }
}
```

## Usage Example

```cpp
#include "ndpi_api.h"
#include "netflow_export.h"

int main() {
    // Initialize nDPI detection module
    struct ndpi_detection_module_struct *ndpi_struct = ndpi_init_detection_module();

    // Initialize NetFlow exporter
    struct netflow_exporter exporter;
    if (init_netflow_exporter(&exporter, "192.168.1.100", 2055, 1) < 0) {
        fprintf(stderr, "Failed to initialize NetFlow exporter\n");
        return 1;
    }

    // Process flows and export
    struct ndpi_flow_info flows[100];
    size_t flow_count = 0;

    // ... populate flows from network traffic ...

    // Export flows as NetFlow
    int exported = export_ndpi_flows_as_netflow(&exporter, flows, flow_count);
    printf("Exported %d flows as NetFlow records\n", exported);

    // Cleanup
    cleanup_netflow_exporter(&exporter);
    ndpi_exit_detection_module(ndpi_struct);

    return 0;
}
```

## Best Practices

### Performance Optimization

1. **Batch Export**: Accumulate multiple flows before exporting
2. **Template Caching**: Send templates periodically, not with every packet
3. **Buffer Management**: Use appropriate buffer sizes for network conditions
4. **Error Handling**: Implement retry logic for failed exports

### Security Considerations

1. **Field Sanitization**: Validate all field values before export
2. **Rate Limiting**: Prevent export flooding
3. **Authentication**: Use secure channels where required
4. **Privacy**: Consider IP address anonymization for compliance

### Monitoring

```cpp
struct netflow_stats {
    uint64_t packets_sent;
    uint64_t flows_exported;
    uint64_t export_errors;
    uint64_t template_updates;
};

void log_export_stats(struct netflow_stats *stats) {
    printf("NetFlow Export Statistics:\n");
    printf("  Packets Sent: %lu\n", stats->packets_sent);
    printf("  Flows Exported: %lu\n", stats->flows_exported);
    printf("  Export Errors: %lu\n", stats->export_errors);
    printf("  Template Updates: %lu\n", stats->template_updates);
}
```

## Integration with Network Tools

### Collector Configuration

Popular NetFlow collectors that support nDPI extended fields:

- **nfcapd**: Configure with custom template support
- **Elastic Stack**: Use Logstash NetFlow input plugin
- **PRTG**: Enable NetFlow v9 monitoring
- **SolarWinds**: Configure custom NetFlow templates

### Example nfcapd Configuration

```bash
# Start nfcapd with custom field support
nfcapd -w -D -p 2055 -l /var/cache/nfcapd -T all
```

## Next Steps

- See [XGBoost Integration](./xgboost-integration.md) for machine learning capabilities
- Check [Examples](./examples.md) for complete implementation samples
- Review [API Reference](./api-reference.md) for detailed function documentation