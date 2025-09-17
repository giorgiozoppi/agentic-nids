---
sidebar_position: 1
---

# nDPI Introduction

nDPI is an open source deep packet inspection (DPI) library based on the OpenDPI and PACE technology by ipoque GmbH. It provides comprehensive protocol detection and network traffic analysis capabilities.

## What is nDPI?

nDPI is designed to detect and classify network protocols in real-time, providing insights into network traffic patterns, security risks, and application behavior. It can identify over 400+ protocols and applications.

## Key Features

### Protocol Detection
- **Deep Packet Inspection**: Analyzes packet payloads to identify protocols
- **Flow-based Analysis**: Tracks complete network flows
- **Real-time Processing**: Suitable for live traffic analysis
- **Multi-layer Detection**: Supports L3-L7 protocol identification

### Security Analysis
- **Risk Assessment**: Identifies potential security threats
- **Flow Risks**: Detects suspicious patterns and behaviors
- **Entropy Analysis**: Identifies encrypted or obfuscated traffic
- **Certificate Validation**: TLS/SSL security analysis

### Performance
- **High Throughput**: Optimized for high-speed networks
- **Low Memory Footprint**: Efficient memory management
- **Multi-threading Support**: Parallel processing capabilities
- **Scalable Architecture**: Suitable for enterprise deployments

## Supported Protocols

nDPI supports detection of:

- **Web Protocols**: HTTP, HTTPS, HTTP/2, HTTP/3, WebSocket
- **Email**: SMTP, POP3, IMAP
- **File Sharing**: BitTorrent, eMule, FTP, SFTP
- **Messaging**: WhatsApp, Telegram, Signal, Skype
- **Streaming**: Netflix, YouTube, Spotify, Twitch
- **Gaming**: Steam, Xbox Live, PlayStation Network
- **VPN/Tunneling**: OpenVPN, IPSec, WireGuard, Tor
- **Enterprise**: RDP, VNC, TeamViewer, Citrix
- **IoT Protocols**: MQTT, CoAP, Modbus
- **And many more...

## Architecture Overview

nDPI consists of several key components:

1. **Detection Engine**: Core protocol detection logic
2. **Flow Manager**: Tracks and manages network flows
3. **Risk Engine**: Identifies security threats and anomalies
4. **Protocol Plugins**: Modular protocol dissectors
5. **API Layer**: C/C++ APIs for integration

## Use Cases

- **Network Monitoring**: Real-time traffic analysis
- **Security Analysis**: Threat detection and prevention
- **Quality of Service**: Bandwidth management and optimization
- **Compliance**: Regulatory compliance monitoring
- **Research**: Network behavior analysis

## Getting Started

Ready to start using nDPI? Check out our guides:

- [Building nDPI](./building)
- [Basic Integration](./basic-integration)
- [API Reference](./api-reference)
- [Examples](./examples)

## License

nDPI is released under the GNU Lesser General Public License (LGPL) v3.0.
