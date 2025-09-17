---
sidebar_position: 5
---

# Flow Risks and Security Analysis

nDPI provides comprehensive security risk assessment capabilities to identify potential threats and anomalies in network traffic.

## Understanding Flow Risks

Flow risks in nDPI are security concerns detected during protocol analysis. These risks are represented as a bitmap where each bit corresponds to a specific risk type.

### Risk Categories

Based on the official nDPI documentation, risks fall into several categories:

#### Web Application Security
- **XSS (Cross-Site Scripting)**: Potential XSS attacks detected
- **SQL Injection**: SQL injection attempts identified
- **RCE (Remote Code Execution)**: Remote code execution patterns
- **Suspicious URLs**: Malicious or suspicious URL patterns
- **HTTP Header Anomalies**: Unusual HTTP headers

#### Protocol Security
- **Weak Encryption**: Obsolete or weak cryptographic algorithms
- **Certificate Issues**: Invalid or suspicious TLS certificates
- **Protocol Violations**: Non-standard protocol usage
- **Clear Text Credentials**: Unencrypted credential transmission

#### Network Behavior
- **Port Scanning**: Systematic port probing attempts
- **Unidirectional Traffic**: Suspicious one-way communication
- **Periodic Flows**: Regular, automated traffic patterns
- **Binary Data Transfer**: Potential malware/executable transfers

## Working with Risks

### Basic Risk Detection

```c
#include <ndpi_api.h>

void check_flow_risks(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow
) {
    // Get current risk bitmap
    ndpi_risk_enum risks = ndpi_get_flow_risk(flow);

    if (risks != NDPI_NO_RISK) {
        printf("Security risks detected:\n");

        // Check specific risks
        if (ndpi_isset_risk(flow, NDPI_MALICIOUS_JA3)) {
            printf("  - Malicious JA3 fingerprint detected\n");
        }

        if (ndpi_isset_risk(flow, NDPI_SUSPICIOUS_ENTROPY)) {
            printf("  - Suspicious entropy in payload\n");
        }

        if (ndpi_isset_risk(flow, NDPI_CLEAR_TEXT_CREDENTIALS)) {
            printf("  - Clear text credentials detected\n");
        }

        if (ndpi_isset_risk(flow, NDPI_HTTP_SUSPICIOUS_HEADER)) {
            printf("  - Suspicious HTTP header\n");
        }
    }
}
```

### Risk Enumeration

```c
// Common risk types (from nDPI source)
typedef enum {
    NDPI_NO_RISK = 0,
    NDPI_URL_POSSIBLE_XSS,
    NDPI_URL_POSSIBLE_SQL_INJECTION,
    NDPI_URL_POSSIBLE_RCE_INJECTION,
    NDPI_BINARY_APPLICATION_TRANSFER,
    NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,
    NDPI_TLS_SELFSIGNED_CERTIFICATE,
    NDPI_TLS_OBSOLETE_VERSION,
    NDPI_TLS_WEAK_CIPHER,
    NDPI_TLS_CERTIFICATE_EXPIRED,
    NDPI_TLS_CERTIFICATE_MISMATCH,
    NDPI_HTTP_SUSPICIOUS_HEADER,
    NDPI_HTTP_SUSPICIOUS_URL,
    NDPI_HTTP_SUSPICIOUS_USER_AGENT,
    NDPI_SUSPICIOUS_ENTROPY,
    NDPI_MALICIOUS_JA3,
    NDPI_MALICIOUS_JA4,
    NDPI_MALICIOUS_SHA1_CERTIFICATE,
    NDPI_DESKTOP_OR_FILE_SHARING_SESSION,
    NDPI_CLEAR_TEXT_CREDENTIALS,
    NDPI_DNS_SUSPICIOUS_TRAFFIC,
    NDPI_UNIDIRECTIONAL_TRAFFIC,
    NDPI_TCP_ISSUES,
    NDPI_FULLY_ENCRYPTED_FLOW,
    // ... more risks
} ndpi_risk_enum;
```

### Advanced Risk Analysis

```c
struct risk_info {
    ndpi_risk_enum risk_bitmap;
    char risk_message[512];
    uint8_t risk_score;        // 0-100
    uint32_t risk_count;
    time_t first_risk_time;
    time_t last_risk_time;
};

void analyze_flow_risks(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow,
    struct risk_info* risk_info
) {
    // Get current risks
    risk_info->risk_bitmap = ndpi_get_flow_risk(flow);

    if (risk_info->risk_bitmap == NDPI_NO_RISK) {
        return;
    }

    // Iterate through all possible risks
    for (int i = 0; i < NDPI_MAX_RISK; i++) {
        if (ndpi_isset_risk(flow, (ndpi_risk_enum)(1 << i))) {
            risk_info->risk_count++;

            // Get risk description
            const char* risk_name = ndpi_risk2str((ndpi_risk_enum)(1 << i));
            if (risk_name) {
                strncat(risk_info->risk_message, risk_name,
                       sizeof(risk_info->risk_message) - strlen(risk_info->risk_message) - 1);
                strncat(risk_info->risk_message, "; ",
                       sizeof(risk_info->risk_message) - strlen(risk_info->risk_message) - 1);
            }

            // Calculate risk score (example scoring)
            switch ((ndpi_risk_enum)(1 << i)) {
                case NDPI_MALICIOUS_JA3:
                case NDPI_MALICIOUS_SHA1_CERTIFICATE:
                    risk_info->risk_score += 30;
                    break;
                case NDPI_URL_POSSIBLE_RCE_INJECTION:
                case NDPI_URL_POSSIBLE_SQL_INJECTION:
                    risk_info->risk_score += 25;
                    break;
                case NDPI_CLEAR_TEXT_CREDENTIALS:
                case NDPI_TLS_WEAK_CIPHER:
                    risk_info->risk_score += 20;
                    break;
                case NDPI_SUSPICIOUS_ENTROPY:
                case NDPI_HTTP_SUSPICIOUS_HEADER:
                    risk_info->risk_score += 15;
                    break;
                default:
                    risk_info->risk_score += 10;
                    break;
            }
        }
    }

    // Cap risk score at 100
    if (risk_info->risk_score > 100) {
        risk_info->risk_score = 100;
    }

    // Update timestamps
    time_t now = time(NULL);
    if (risk_info->first_risk_time == 0) {
        risk_info->first_risk_time = now;
    }
    risk_info->last_risk_time = now;
}
```

## Entropy Analysis

### Understanding Entropy

nDPI calculates entropy to identify encrypted, compressed, or random data:

```c
void analyze_payload_entropy(
    const uint8_t* payload,
    uint16_t payload_len,
    struct ndpi_flow_struct* flow
) {
    if (payload_len < 64) return;  // Skip small payloads

    // Calculate entropy
    float entropy = ndpi_entropy(payload, payload_len);

    // Interpret entropy values
    if (NDPI_ENTROPY_ENCRYPTED_OR_RANDOM(entropy)) {
        printf("Highly encrypted/random data (entropy: %.3f)\n", entropy);
        // This might indicate tunneling, encryption, or malware
    } else if (NDPI_ENTROPY_EXECUTABLE_ENCRYPTED(entropy)) {
        printf("Encrypted executable data (entropy: %.3f)\n", entropy);
        // Possible packed malware or encrypted binaries
    } else if (NDPI_ENTROPY_EXECUTABLE_PACKED(entropy)) {
        printf("Packed executable data (entropy: %.3f)\n", entropy);
        // Compressed or packed executables
    } else if (NDPI_ENTROPY_EXECUTABLE(entropy)) {
        printf("Executable data (entropy: %.3f)\n", entropy);
        // Regular executable files
    } else if (NDPI_ENTROPY_PLAINTEXT(entropy)) {
        printf("Plain text data (entropy: %.3f)\n", entropy);
        // Human-readable text
    }

    // Convert entropy to risk assessment
    char entropy_str[32];
    ndpi_entropy2str(entropy, entropy_str, sizeof(entropy_str));
    printf("Entropy classification: %s\n", entropy_str);
}
```

### Custom Entropy Thresholds

```c
#define CUSTOM_ENTROPY_THRESHOLD_LOW    3.0f
#define CUSTOM_ENTROPY_THRESHOLD_MEDIUM 5.0f
#define CUSTOM_ENTROPY_THRESHOLD_HIGH   7.0f

typedef enum {
    ENTROPY_LEVEL_LOW = 0,
    ENTROPY_LEVEL_MEDIUM,
    ENTROPY_LEVEL_HIGH,
    ENTROPY_LEVEL_VERY_HIGH
} entropy_level_t;

entropy_level_t classify_entropy(float entropy) {
    if (entropy < CUSTOM_ENTROPY_THRESHOLD_LOW) {
        return ENTROPY_LEVEL_LOW;
    } else if (entropy < CUSTOM_ENTROPY_THRESHOLD_MEDIUM) {
        return ENTROPY_LEVEL_MEDIUM;
    } else if (entropy < CUSTOM_ENTROPY_THRESHOLD_HIGH) {
        return ENTROPY_LEVEL_HIGH;
    } else {
        return ENTROPY_LEVEL_VERY_HIGH;
    }
}
```

## TLS/SSL Security Analysis

### Certificate Analysis

```c
void analyze_tls_security(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow
) {
    if (flow->detected_l7_protocol.proto.app_protocol != NDPI_PROTOCOL_TLS &&
        flow->detected_l7_protocol.proto.master_protocol != NDPI_PROTOCOL_TLS) {
        return;
    }

    // Check TLS version
    if (flow->protos.tls_quic.ssl_version < 0x0302) {  // TLS 1.1 or older
        printf("WARNING: Obsolete TLS version detected\n");
        ndpi_set_risk(ndpi_mod, flow, NDPI_TLS_OBSOLETE_VERSION,
                     "TLS version < 1.2");
    }

    // Check cipher suites
    if (flow->protos.tls_quic.server_cipher != 0) {
        // Check for weak ciphers (example)
        uint16_t cipher = flow->protos.tls_quic.server_cipher;
        if (is_weak_cipher(cipher)) {
            printf("WARNING: Weak cipher suite detected: 0x%04x\n", cipher);
            ndpi_set_risk(ndpi_mod, flow, NDPI_TLS_WEAK_CIPHER,
                         "Weak cipher suite");
        }
    }

    // Check certificate information
    if (flow->protos.tls_quic.issuerDN) {
        printf("Certificate Issuer: %s\n", flow->protos.tls_quic.issuerDN);
    }

    if (flow->protos.tls_quic.subjectDN) {
        printf("Certificate Subject: %s\n", flow->protos.tls_quic.subjectDN);
    }

    // Check SNI vs certificate mismatch
    if (flow->host_server_name[0] != '\0' &&
        flow->protos.tls_quic.server_names) {
        if (strcmp(flow->host_server_name, flow->protos.tls_quic.server_names) != 0) {
            printf("WARNING: SNI/Certificate name mismatch\n");
            ndpi_set_risk(ndpi_mod, flow, NDPI_TLS_CERTIFICATE_MISMATCH,
                         "SNI mismatch");
        }
    }
}

int is_weak_cipher(uint16_t cipher) {
    // Examples of weak ciphers (this is simplified)
    switch (cipher) {
        case 0x0004:  // TLS_RSA_WITH_RC4_128_MD5
        case 0x0005:  // TLS_RSA_WITH_RC4_128_SHA
        case 0x000A:  // TLS_RSA_WITH_3DES_EDE_CBC_SHA
            return 1;
        default:
            return 0;
    }
}
```

## HTTP Security Analysis

### Malicious Content Detection

```c
void analyze_http_security(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow,
    const char* http_url,
    const char* user_agent
) {
    if (!http_url || !user_agent) return;

    // Check for suspicious URL patterns
    if (check_suspicious_url(http_url)) {
        printf("WARNING: Suspicious URL detected: %s\n", http_url);
        ndpi_set_risk(ndpi_mod, flow, NDPI_HTTP_SUSPICIOUS_URL,
                     "Suspicious URL pattern");
    }

    // Check for XSS attempts
    if (strstr(http_url, "<script>") || strstr(http_url, "javascript:") ||
        strstr(http_url, "onerror=") || strstr(http_url, "onload=")) {
        printf("WARNING: Possible XSS attempt in URL\n");
        ndpi_set_risk(ndpi_mod, flow, NDPI_URL_POSSIBLE_XSS,
                     "XSS pattern in URL");
    }

    // Check for SQL injection
    if (strstr(http_url, "UNION SELECT") || strstr(http_url, "'; DROP") ||
        strstr(http_url, "OR 1=1") || strstr(http_url, "' OR '1'='1")) {
        printf("WARNING: Possible SQL injection attempt\n");
        ndpi_set_risk(ndpi_mod, flow, NDPI_URL_POSSIBLE_SQL_INJECTION,
                     "SQL injection pattern");
    }

    // Check User-Agent
    if (check_suspicious_user_agent(user_agent)) {
        printf("WARNING: Suspicious User-Agent: %s\n", user_agent);
        ndpi_set_risk(ndpi_mod, flow, NDPI_HTTP_SUSPICIOUS_USER_AGENT,
                     "Suspicious User-Agent");
    }
}

int check_suspicious_url(const char* url) {
    // Simple pattern matching (enhance as needed)
    const char* suspicious_patterns[] = {
        "/admin/",
        "/wp-admin/",
        "/phpMyAdmin/",
        "/.env",
        "/config.php",
        "cmd.exe",
        "powershell",
        NULL
    };

    for (int i = 0; suspicious_patterns[i]; i++) {
        if (strstr(url, suspicious_patterns[i])) {
            return 1;
        }
    }
    return 0;
}

int check_suspicious_user_agent(const char* user_agent) {
    // Check for automated tools, scanners, etc.
    const char* suspicious_agents[] = {
        "Nmap",
        "Sqlmap",
        "Nikto",
        "Burp",
        "OWASP",
        "curl/",
        "wget/",
        "python-requests",
        NULL
    };

    for (int i = 0; suspicious_agents[i]; i++) {
        if (strstr(user_agent, suspicious_agents[i])) {
            return 1;
        }
    }
    return 0;
}
```

## Risk Reporting and Alerting

### Real-time Risk Alerting

```c
struct risk_alert {
    time_t timestamp;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;
    ndpi_risk_enum risks;
    uint8_t severity;  // 1-5 scale
    char description[256];
};

void generate_risk_alert(
    struct ndpi_flow_struct* flow,
    struct risk_alert* alert
) {
    alert->timestamp = time(NULL);
    alert->risks = ndpi_get_flow_risk(flow);

    // Calculate severity based on risk types
    alert->severity = calculate_risk_severity(alert->risks);

    // Generate human-readable description
    format_risk_description(alert->risks, alert->description,
                           sizeof(alert->description));

    // Log high-severity alerts immediately
    if (alert->severity >= 4) {
        log_critical_alert(alert);
    }

    // Send to SIEM/monitoring system
    send_to_siem(alert);
}

uint8_t calculate_risk_severity(ndpi_risk_enum risks) {
    uint8_t severity = 1;

    // High-severity risks
    if (risks & (NDPI_MALICIOUS_JA3 | NDPI_MALICIOUS_SHA1_CERTIFICATE |
                 NDPI_URL_POSSIBLE_RCE_INJECTION)) {
        severity = 5;
    }
    // Medium-high severity
    else if (risks & (NDPI_URL_POSSIBLE_SQL_INJECTION | NDPI_CLEAR_TEXT_CREDENTIALS |
                     NDPI_TLS_WEAK_CIPHER)) {
        severity = 4;
    }
    // Medium severity
    else if (risks & (NDPI_HTTP_SUSPICIOUS_HEADER | NDPI_SUSPICIOUS_ENTROPY |
                     NDPI_TLS_OBSOLETE_VERSION)) {
        severity = 3;
    }
    // Low-medium severity
    else if (risks & (NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT |
                     NDPI_DESKTOP_OR_FILE_SHARING_SESSION)) {
        severity = 2;
    }

    return severity;
}
```

### Risk Statistics and Reporting

```c
struct risk_statistics {
    uint64_t total_flows_analyzed;
    uint64_t flows_with_risks;
    uint64_t risk_counts[NDPI_MAX_RISK];
    time_t stats_start_time;
    time_t stats_last_update;
};

void update_risk_statistics(
    struct risk_statistics* stats,
    ndpi_risk_enum flow_risks
) {
    stats->total_flows_analyzed++;

    if (flow_risks != NDPI_NO_RISK) {
        stats->flows_with_risks++;

        // Count individual risks
        for (int i = 0; i < NDPI_MAX_RISK; i++) {
            if (flow_risks & (1 << i)) {
                stats->risk_counts[i]++;
            }
        }
    }

    stats->stats_last_update = time(NULL);
}

void print_risk_report(struct risk_statistics* stats) {
    printf("\n=== nDPI Risk Analysis Report ===\n");
    printf("Analysis Period: %ld - %ld\n",
           stats->stats_start_time, stats->stats_last_update);
    printf("Total Flows Analyzed: %llu\n", stats->total_flows_analyzed);
    printf("Flows with Risks: %llu (%.2f%%)\n",
           stats->flows_with_risks,
           (double)stats->flows_with_risks / stats->total_flows_analyzed * 100);

    printf("\nTop Risk Types:\n");
    // Sort and display top risks
    for (int i = 0; i < NDPI_MAX_RISK; i++) {
        if (stats->risk_counts[i] > 0) {
            printf("  %s: %llu occurrences\n",
                   ndpi_risk2str((ndpi_risk_enum)(1 << i)),
                   stats->risk_counts[i]);
        }
    }
}
```

## Integration with Security Tools

### SIEM Integration Example

```c
void send_risk_to_siem(
    struct risk_alert* alert,
    const char* siem_endpoint
) {
    // Example: Send JSON alert to SIEM
    cJSON* json = cJSON_CreateObject();

    cJSON_AddStringToObject(json, "event_type", "ndpi_risk_alert");
    cJSON_AddNumberToObject(json, "timestamp", alert->timestamp);
    cJSON_AddStringToObject(json, "src_ip", inet_ntoa(*(struct in_addr*)&alert->src_ip));
    cJSON_AddStringToObject(json, "dst_ip", inet_ntoa(*(struct in_addr*)&alert->dst_ip));
    cJSON_AddNumberToObject(json, "src_port", alert->src_port);
    cJSON_AddNumberToObject(json, "dst_port", alert->dst_port);
    cJSON_AddNumberToObject(json, "severity", alert->severity);
    cJSON_AddStringToObject(json, "description", alert->description);

    char* json_string = cJSON_Print(json);

    // Send to SIEM (HTTP POST, syslog, etc.)
    send_http_post(siem_endpoint, json_string);

    free(json_string);
    cJSON_Delete(json);
}
```

## Next Steps

- [Learn about API reference](./api-reference)
- [Check complete examples](./examples)