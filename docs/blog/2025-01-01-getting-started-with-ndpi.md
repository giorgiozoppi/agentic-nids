---
slug: getting-started-with-ndpi
title: Getting Started with nDPI for Network Analysis
authors: [slorber]
tags: [ndpi, network-analysis, deep-packet-inspection, tutorial]
---

# Getting Started with nDPI for Network Analysis

nDPI (Network Deep Packet Inspection) is a powerful open-source library for analyzing network traffic and detecting protocols in real-time. Whether you're building a network monitoring tool, implementing security analysis, or conducting research, nDPI provides the foundation you need.

<!-- truncate -->

## Why Choose nDPI?

nDPI stands out in the network analysis space for several reasons:

- **Comprehensive Protocol Support**: Detects 400+ protocols including modern applications
- **Security-Focused**: Built-in risk assessment and threat detection
- **High Performance**: Optimized for high-throughput environments
- **Open Source**: LGPL v3 license with active community support
- **Production Ready**: Used by ntopng, pfSense, and other commercial products

## Quick Start Example

Here's a simple example that shows how easy it is to get started with nDPI:

```c
#include <ndpi_api.h>
#include <stdio.h>

int main() {
    // Initialize nDPI
    struct ndpi_detection_module_struct* ndpi_mod = ndpi_init_detection_module(NULL);
    if (!ndpi_mod) {
        printf("Failed to initialize nDPI\n");
        return 1;
    }

    // Finalize initialization
    ndpi_finalize_initialization(ndpi_mod);

    printf("nDPI %s initialized successfully!\n", ndpi_revision());
    printf("Ready to analyze network traffic\n");

    // Cleanup
    ndpi_exit_detection_module(ndpi_mod);
    return 0;
}
```

Compile and run:
```bash
gcc -o ndpi_hello hello.c -lndpi
./ndpi_hello
```

## Real-World Application: PCAP Analysis

Let's look at a practical example that analyzes a PCAP file:

```c
#include <ndpi_api.h>
#include <pcap.h>

void analyze_pcap(const char* filename) {
    // Initialize nDPI
    struct ndpi_detection_module_struct* ndpi_mod = ndpi_init_detection_module(NULL);
    ndpi_finalize_initialization(ndpi_mod);

    // Open PCAP file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        printf("Error opening PCAP: %s\n", errbuf);
        return;
    }

    printf("Analyzing %s...\n", filename);

    struct pcap_pkthdr* header;
    const u_char* packet;
    int packet_count = 0;

    // Process packets
    while (pcap_next_ex(handle, &header, &packet) == 1) {
        packet_count++;

        // Here you would extract flow information and call
        // ndpi_detection_process_packet() for each flow

        if (packet_count % 1000 == 0) {
            printf("Processed %d packets...\n", packet_count);
        }
    }

    printf("Analysis complete: %d packets processed\n", packet_count);

    pcap_close(handle);
    ndpi_exit_detection_module(ndpi_mod);
}
```

## Key Concepts to Master

### 1. Flow-Based Analysis
nDPI works with **flows** - sequences of packets between two endpoints. Understanding flow lifecycle is crucial:

- **Flow Creation**: When the first packet of a new connection is seen
- **Protocol Detection**: Analyzing multiple packets to identify the protocol
- **Flow Termination**: When connection ends or times out

### 2. Risk Assessment
Modern network analysis isn't just about protocol detection - it's about security:

```c
// Check for security risks
ndpi_risk_enum risks = ndpi_get_flow_risk(flow);
if (risks != NDPI_NO_RISK) {
    if (ndpi_isset_risk(flow, NDPI_MALICIOUS_JA3)) {
        printf("⚠️ Malicious TLS fingerprint detected!\n");
    }
    if (ndpi_isset_risk(flow, NDPI_URL_POSSIBLE_SQL_INJECTION)) {
        printf("⚠️ Possible SQL injection attempt!\n");
    }
}
```

### 3. Protocol Categories
nDPI doesn't just tell you "this is HTTP" - it provides rich context:

```c
struct ndpi_proto result = ndpi_detection_process_packet(/* ... */);
if (ndpi_is_protocol_detected(result)) {
    printf("Protocol: %s\n",
           ndpi_get_proto_name(ndpi_mod, result.proto.app_protocol));
    printf("Category: %s\n",
           ndpi_category_get_name(ndpi_mod, result.category));
}
```

## Building Your First Network Monitor

Here's the structure for a basic network monitoring application:

1. **Initialize nDPI** - Set up the detection engine
2. **Capture Packets** - Use libpcap or raw sockets
3. **Manage Flows** - Track connections and their state
4. **Analyze Protocols** - Feed packets to nDPI for analysis
5. **Handle Results** - Process detection results and risks
6. **Report/Store** - Output results to logs, databases, or dashboards

## Performance Considerations

When building production systems with nDPI:

- **Memory Management**: Properly free flows and detection modules
- **Flow Timeouts**: Implement flow cleanup to prevent memory leaks
- **Threading**: Use multiple threads for high-throughput scenarios
- **Packet Sampling**: Consider sampling for very high-speed networks

## Next Steps

Ready to dive deeper? Here are some paths to explore:

1. **[Complete Examples](/docs/examples)** - See full working applications
2. **[Flow Management](/docs/flows)** - Master flow lifecycle and optimization
3. **[Risk Detection](/docs/risks)** - Implement security analysis
4. **[API Reference](/docs/api-reference)** - Comprehensive function documentation

## Community and Support

- **Source Code**: [GitHub Repository](https://github.com/ntop/nDPI)
- **Documentation**: [Official nDPI Docs](https://www.ntop.org/guides/nDPI/)
- **Mailing List**: Join the ntop community discussions
- **Commercial Support**: Available through ntop

## Conclusion

nDPI opens up a world of possibilities for network analysis. Whether you're building security tools, network monitors, or research applications, its combination of protocol detection and security analysis makes it an invaluable tool.

Start with the simple examples in this documentation, then gradually work your way up to more complex scenarios. The nDPI community is here to help along the way!

Happy packet hunting! 🔍📊