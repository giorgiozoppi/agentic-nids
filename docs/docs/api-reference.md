---
sidebar_position: 7
---

# API Reference

This section provides comprehensive documentation of the nDPI API functions and data structures.

## Core Initialization Functions

### ndpi_init_detection_module()

Initializes the nDPI detection module.

```c
struct ndpi_detection_module_struct* ndpi_init_detection_module(
    NDPI_PROTOCOL_BITMASK* detection_bitmask
);
```

**Parameters:**
- `detection_bitmask`: Protocol detection bitmask. Use `NULL` to enable all protocols.

**Returns:**
- Pointer to initialized detection module on success
- `NULL` on failure

**Example:**
```c
// Enable all protocols
struct ndpi_detection_module_struct* ndpi_mod = ndpi_init_detection_module(NULL);

// Enable specific protocols only
NDPI_PROTOCOL_BITMASK custom_protocols;
NDPI_BITMASK_RESET(custom_protocols);
NDPI_BITMASK_ADD(custom_protocols, NDPI_PROTOCOL_HTTP);
NDPI_BITMASK_ADD(custom_protocols, NDPI_PROTOCOL_HTTPS);
struct ndpi_detection_module_struct* ndpi_mod = ndpi_init_detection_module(&custom_protocols);
```

### ndpi_finalize_initialization()

Finalizes the initialization process. Must be called after `ndpi_init_detection_module()`.

```c
int ndpi_finalize_initialization(struct ndpi_detection_module_struct* ndpi_mod);
```

**Parameters:**
- `ndpi_mod`: Pointer to the detection module

**Returns:**
- `0` on success
- Non-zero on failure

### ndpi_exit_detection_module()

Cleans up and frees the detection module.

```c
void ndpi_exit_detection_module(struct ndpi_detection_module_struct* ndpi_mod);
```

**Parameters:**
- `ndpi_mod`: Pointer to the detection module to free

## Flow Management Functions

### ndpi_flow_malloc()

Allocates memory for a flow structure.

```c
void* ndpi_flow_malloc(size_t size);
```

**Parameters:**
- `size`: Size to allocate (use `SIZEOF_FLOW_STRUCT`)

**Returns:**
- Pointer to allocated memory on success
- `NULL` on failure

### ndpi_flow_free()

Frees flow structure memory.

```c
void ndpi_flow_free(void* ptr);
```

**Parameters:**
- `ptr`: Pointer to memory to free

### ndpi_detection_process_packet()

Processes a packet for protocol detection.

```c
struct ndpi_proto ndpi_detection_process_packet(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow,
    const unsigned char* packet,
    const unsigned short packetlen,
    const u_int64_t current_tick_ms,
    struct ndpi_id_struct* src,
    struct ndpi_id_struct* dst
);
```

**Parameters:**
- `ndpi_mod`: Detection module
- `flow`: Flow structure
- `packet`: Packet data (IP header onwards)
- `packetlen`: Packet length
- `current_tick_ms`: Current timestamp in milliseconds
- `src`: Source endpoint info (optional, can be `NULL`)
- `dst`: Destination endpoint info (optional, can be `NULL`)

**Returns:**
- `ndpi_proto` structure containing detection results

## Protocol Detection Functions

### ndpi_is_protocol_detected()

Checks if a protocol has been detected for a flow.

```c
int ndpi_is_protocol_detected(struct ndpi_proto protocol);
```

**Parameters:**
- `protocol`: Protocol structure returned by detection

**Returns:**
- Non-zero if protocol is detected
- `0` if not detected

### ndpi_detection_giveup()

Forces detection completion and returns best guess.

```c
struct ndpi_proto ndpi_detection_giveup(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow,
    u_int8_t* protocol_was_guessed
);
```

**Parameters:**
- `ndpi_mod`: Detection module
- `flow`: Flow structure
- `protocol_was_guessed`: Output parameter indicating if result is a guess

**Returns:**
- `ndpi_proto` structure with best guess

### ndpi_get_proto_name()

Gets the name of a protocol.

```c
char* ndpi_get_proto_name(
    struct ndpi_detection_module_struct* ndpi_mod,
    u_int16_t proto_id
);
```

**Parameters:**
- `ndpi_mod`: Detection module
- `proto_id`: Protocol ID

**Returns:**
- Protocol name string

### ndpi_category_get_name()

Gets the name of a protocol category.

```c
const char* ndpi_category_get_name(
    struct ndpi_detection_module_struct* ndpi_mod,
    ndpi_protocol_category_t category
);
```

**Parameters:**
- `ndpi_mod`: Detection module
- `category`: Category enum

**Returns:**
- Category name string

## Layer 4 Detection Functions

### ndpi_detection_get_l4()

Extracts Layer 4 information from an IP packet.

```c
u_int8_t ndpi_detection_get_l4(
    const u_int8_t* l3,
    u_int16_t l3_len,
    const u_int8_t** l4_return,
    u_int16_t* l4_len_return,
    u_int8_t* l4_protocol_return,
    u_int32_t flags
);
```

**Parameters:**
- `l3`: IP packet data
- `l3_len`: IP packet length
- `l4_return`: Output pointer to L4 data
- `l4_len_return`: Output L4 data length
- `l4_protocol_return`: Output L4 protocol
- `flags`: Detection flags (`NDPI_DETECTION_ONLY_IPV4`, `NDPI_DETECTION_ONLY_IPV6`)

**Returns:**
- `0` on success
- Non-zero on failure

## Risk and Security Functions

### ndpi_get_flow_risk()

Gets the risk bitmap for a flow.

```c
ndpi_risk_enum ndpi_get_flow_risk(struct ndpi_flow_struct* flow);
```

**Parameters:**
- `flow`: Flow structure

**Returns:**
- Risk bitmap enum

### ndpi_isset_risk()

Checks if a specific risk is set for a flow.

```c
int ndpi_isset_risk(struct ndpi_flow_struct* flow, ndpi_risk_enum risk);
```

**Parameters:**
- `flow`: Flow structure
- `risk`: Risk to check

**Returns:**
- Non-zero if risk is set
- `0` if risk is not set

### ndpi_set_risk()

Sets a risk for a flow.

```c
void ndpi_set_risk(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow,
    ndpi_risk_enum risk,
    char* risk_message
);
```

**Parameters:**
- `ndpi_mod`: Detection module
- `flow`: Flow structure
- `risk`: Risk to set
- `risk_message`: Optional risk message

### ndpi_unset_risk()

Unsets a risk for a flow.

```c
void ndpi_unset_risk(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow,
    ndpi_risk_enum risk
);
```

**Parameters:**
- `ndpi_mod`: Detection module
- `flow`: Flow structure
- `risk`: Risk to unset

### ndpi_entropy()

Calculates entropy of a data buffer.

```c
float ndpi_entropy(u_int8_t const * const buf, size_t len);
```

**Parameters:**
- `buf`: Data buffer
- `len`: Buffer length

**Returns:**
- Entropy value (0.0 to 8.0)

### ndpi_entropy2str()

Converts entropy value to string description.

```c
char* ndpi_entropy2str(float entropy, char* buf, size_t len);
```

**Parameters:**
- `entropy`: Entropy value
- `buf`: Output buffer
- `len`: Buffer length

**Returns:**
- Pointer to buffer

## Flow Information Functions

### ndpi_get_flow_info()

Gets additional flow information as a string.

```c
const char* ndpi_get_flow_info(
    struct ndpi_flow_struct* flow,
    struct ndpi_proto* detected_protocol
);
```

**Parameters:**
- `flow`: Flow structure
- `detected_protocol`: Detected protocol

**Returns:**
- Flow information string or `NULL`

### ndpi_dpi2json()

Serializes flow information to JSON.

```c
char* ndpi_dpi2json(
    struct ndpi_detection_module_struct* ndpi_mod,
    struct ndpi_flow_struct* flow,
    struct ndpi_proto* detected_protocol
);
```

**Parameters:**
- `ndpi_mod`: Detection module
- `flow`: Flow structure
- `detected_protocol`: Detected protocol

**Returns:**
- JSON string (must be freed with `ndpi_free()`)

## Utility Functions

### ndpi_revision()

Gets the nDPI version string.

```c
char* ndpi_revision(void);
```

**Returns:**
- Version string

### ndpi_get_api_version()

Gets the nDPI API version number.

```c
u_int32_t ndpi_get_api_version(void);
```

**Returns:**
- API version number

### ndpi_malloc()

nDPI memory allocation function.

```c
void* ndpi_malloc(size_t size);
```

**Parameters:**
- `size`: Size to allocate

**Returns:**
- Pointer to allocated memory

### ndpi_calloc()

nDPI memory allocation function (zero-initialized).

```c
void* ndpi_calloc(size_t count, size_t size);
```

**Parameters:**
- `count`: Number of elements
- `size`: Size of each element

**Returns:**
- Pointer to allocated memory

### ndpi_free()

nDPI memory deallocation function.

```c
void ndpi_free(void* ptr);
```

**Parameters:**
- `ptr`: Pointer to memory to free

## Hash and Flow Key Functions

### ndpi_flowv4_flow_hash()

Generates hash for IPv4 flow.

```c
int ndpi_flowv4_flow_hash(
    u_int8_t l4_proto,
    u_int32_t src_ip,
    u_int32_t dst_ip,
    u_int16_t src_port,
    u_int16_t dst_port,
    u_int8_t icmp_type,
    u_int8_t icmp_code,
    u_int8_t* hash_buf,
    u_int8_t hash_buf_len
);
```

**Parameters:**
- `l4_proto`: Layer 4 protocol
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `src_port`: Source port
- `dst_port`: Destination port
- `icmp_type`: ICMP type (if applicable)
- `icmp_code`: ICMP code (if applicable)
- `hash_buf`: Output buffer for hash
- `hash_buf_len`: Buffer length

**Returns:**
- `0` on success, non-zero on failure

### ndpi_flowv6_flow_hash()

Generates hash for IPv6 flow.

```c
int ndpi_flowv6_flow_hash(
    u_int8_t l4_proto,
    struct ndpi_in6_addr* src_ip,
    struct ndpi_in6_addr* dst_ip,
    u_int16_t src_port,
    u_int16_t dst_port,
    u_int8_t icmp_type,
    u_int8_t icmp_code,
    u_int8_t* hash_buf,
    u_int8_t hash_buf_len
);
```

**Parameters:**
- Similar to IPv4 version but with IPv6 addresses

**Returns:**
- `0` on success, non-zero on failure

## Data Structures

### struct ndpi_proto

Protocol detection result structure.

```c
struct ndpi_proto {
    ndpi_protocol proto;
    ndpi_protocol_category_t category;
};

typedef struct ndpi_protocol {
    u_int16_t master_protocol;
    u_int16_t app_protocol;
    ndpi_protocol_category_t category;
} ndpi_protocol;
```

### struct ndpi_flow_struct

Flow state structure (opaque to users). Key fields accessible:

```c
struct ndpi_flow_struct {
    u_int8_t num_processed_pkts;
    u_int8_t max_extra_packets_to_check;
    u_int8_t num_extra_packets_checked;

    char host_server_name[256];

    union {
        struct {
            // TLS/QUIC specific fields
            u_int16_t ssl_version;
            char* server_names;
            char* issuerDN;
            char* subjectDN;
            // ... more fields
        } tls_quic;
        // Other protocol-specific unions
    } protos;
};
```

### Risk Enumerations

```c
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
    NDPI_MAX_RISK
} ndpi_risk_enum;
```

### Protocol Categories

```c
typedef enum {
    NDPI_PROTOCOL_CATEGORY_UNSPECIFIED = 0,
    NDPI_PROTOCOL_CATEGORY_MEDIA,
    NDPI_PROTOCOL_CATEGORY_VPN,
    NDPI_PROTOCOL_CATEGORY_EMAIL,
    NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
    NDPI_PROTOCOL_CATEGORY_WEB,
    NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
    NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
    NDPI_PROTOCOL_CATEGORY_GAME,
    NDPI_PROTOCOL_CATEGORY_CHAT,
    NDPI_PROTOCOL_CATEGORY_VOIP,
    NDPI_PROTOCOL_CATEGORY_DATABASE,
    NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
    NDPI_PROTOCOL_CATEGORY_CLOUD,
    NDPI_PROTOCOL_CATEGORY_NETWORK,
    NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
    NDPI_PROTOCOL_CATEGORY_RPC,
    NDPI_PROTOCOL_CATEGORY_STREAMING,
    NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
    NDPI_PROTOCOL_CATEGORY_SW_UPDATE,
    // ... more categories
} ndpi_protocol_category_t;
```

## Constants and Macros

### Size Constants

```c
#define SIZEOF_FLOW_STRUCT          sizeof(struct ndpi_flow_struct)
#define NDPI_MAX_SUPPORTED_PROTOCOLS 512
#define NDPI_MAX_HOSTNAME_LEN       256
```

### Risk Macros

```c
#define NDPI_ENTROPY_PLAINTEXT(entropy)           (entropy < 4.941f)
#define NDPI_ENTROPY_EXECUTABLE(entropy)          (entropy >= 4.941f)
#define NDPI_ENTROPY_EXECUTABLE_PACKED(entropy)   (entropy >= 6.677f)
#define NDPI_ENTROPY_EXECUTABLE_ENCRYPTED(entropy) (entropy >= 7.174f)
#define NDPI_ENTROPY_ENCRYPTED_OR_RANDOM(entropy) (entropy >= 7.312f)
```

### Protocol Bitmask Macros

```c
#define NDPI_BITMASK_SET_ALL(a)           memset(&a, 0xFF, sizeof(NDPI_PROTOCOL_BITMASK))
#define NDPI_BITMASK_RESET(a)             memset(&a, 0, sizeof(NDPI_PROTOCOL_BITMASK))
#define NDPI_BITMASK_ADD(a, b)            NDPI_ADD_PROTOCOL_TO_BITMASK(a, b)
#define NDPI_BITMASK_DEL(a, b)            NDPI_DEL_PROTOCOL_FROM_BITMASK(a, b)
#define NDPI_BITMASK_IS_SET(a, b)         NDPI_ISSET_PROTOCOL_BITMASK(a, b)
```

## Error Codes

Common return values and error conditions:

- `0`: Success
- `-1`: Generic error
- `NDPI_PROTOCOL_UNKNOWN`: Protocol not detected
- `NDPI_NO_RISK`: No security risks detected

## Thread Safety

nDPI is generally thread-safe with these considerations:

- Each thread should have its own detection module instance
- Flow structures should not be shared between threads
- Global protocol configuration is read-only after initialization

## Memory Management Best Practices

1. Always call `ndpi_exit_detection_module()` to free the detection module
2. Use `ndpi_flow_free()` to free flow structures allocated with `ndpi_flow_malloc()`
3. Free JSON strings returned by `ndpi_dpi2json()` using `ndpi_free()`
4. Set pointers to `NULL` after freeing to avoid double-free errors

## Next Steps

- [Complete Examples](./examples)
- [Building nDPI](./building)
- [Flow Management](./flows)