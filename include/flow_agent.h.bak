/*
 * flow_agent.hpp
 *
 * Modern C++ header for network flow monitoring agent
 */

#pragma once

#include <memory>
#include <string>
#include <chrono>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <array>
#include <vector>
#include <cstdint>

// Forward declarations for external libraries
struct pcap;
typedef struct pcap pcap_t;
struct pcap_pkthdr;
struct ndpi_detection_module_struct;
namespace rocksdb {
    class DB;
    class Options;
    class WriteOptions;
    class ReadOptions;
}

/**
 * Network flow key using 5-tuple
 */
struct FlowKey {
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t protocol{0};
    
    bool operator==(const FlowKey& other) const noexcept;
    bool operator<(const FlowKey& other) const noexcept;
};

/**
 * Hash function for FlowKey using SipHash
 */
struct FlowKeyHasher {
    explicit FlowKeyHasher(const std::array<uint8_t, 16>& key);
    std::size_t operator()(const FlowKey& key) const noexcept;
    
private:
    std::array<uint8_t, 16> sip_key_;
};

/**
 * Complete flow record with all NetFlow v5 fields
 */
struct FlowRecord {
    FlowKey key;
    uint64_t bytes{0};
    uint64_t packets{0};
    uint16_t ndpi_protocol{0};
    uint8_t tcp_flags{0};
    uint8_t tos{0};
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    uint32_t src_as{0};
    uint32_t dst_as{0};
    uint8_t src_mask{0};
    uint8_t dst_mask{0};
    uint16_t input_snmp{0};
    uint16_t output_snmp{0};
    
    // Serialization for RocksDB
    std::string serialize() const;
    static FlowRecord deserialize(const std::string& data);
    
    // Check if flow should expire
    bool should_expire(std::chrono::seconds idle_timeout, 
                      std::chrono::seconds active_timeout,
                      std::chrono::system_clock::time_point now) const;
};

/**
 * NetFlow v5 packet structures
 */
#pragma pack(push, 1)
struct NetFlowV5Header {
    uint16_t version{5};
    uint16_t count{0};
    uint32_t sys_uptime{0};
    uint32_t unix_secs{0};
    uint32_t unix_nsecs{0};
    uint32_t flow_sequence{0};
    uint8_t engine_type{1};
    uint8_t engine_id{1};
    uint16_t sampling_interval{0};
};

struct NetFlowV5Record {
    uint32_t src_addr{0};
    uint32_t dst_addr{0};
    uint32_t nexthop{0};
    uint16_t input{0};
    uint16_t output{0};
    uint32_t d_pkts{0};
    uint32_t d_octets{0};
    uint32_t first{0};
    uint32_t last{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t pad1{0};
    uint8_t tcp_flags{0};
    uint8_t prot{0};
    uint8_t tos{0};
    uint16_t src_as{0};
    uint16_t dst_as{0};
    uint8_t src_mask{0};
    uint8_t dst_mask{0};
    uint16_t pad2{0};
};
#pragma pack(pop)

/**
 * Configuration structure
 */
struct FlowAgentConfig {
    std::string interface;
    std::string rocksdb_path;
    std::string collector_ip{"127.0.0.1"};
    int collector_port{2055};
    std::chrono::seconds idle_timeout{300};
    std::chrono::seconds active_timeout{1800};
    std::chrono::seconds scan_interval{5};
    size_t max_flows_per_packet{30};
    size_t max_pending_flows{10000};
};

/**
 * Statistics structure
 */
struct FlowStatistics {
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> flows_created{0};
    std::atomic<uint64_t> flows_updated{0};
    std::atomic<uint64_t> flows_exported{0};
    std::atomic<uint64_t> flows_expired{0};
    std::atomic<uint64_t> netflow_packets_sent{0};
    std::atomic<uint32_t> netflow_sequence{0};
    std::atomic<size_t> active_flows{0};
    std::atomic<size_t> pending_flows{0};
};

/**
 * Main Flow Agent class
 */
class FlowAgent {
public:
    explicit FlowAgent(const FlowAgentConfig& config);
    ~FlowAgent();
    
    // Non-copyable, non-movable
    FlowAgent(const FlowAgent&) = delete;
    FlowAgent& operator=(const FlowAgent&) = delete;
    FlowAgent(FlowAgent&&) = delete;
    FlowAgent& operator=(FlowAgent&&) = delete;
    
    void initialize();
    void run();
    void stop();
    
    void print_statistics() const;
    FlowStatistics get_statistics() const;
    
    // For testing
    void process_packet(const uint8_t* packet, size_t length, 
                       std::chrono::system_clock::time_point timestamp);
    bool get_flow(const FlowKey& key, FlowRecord& record) const;

private:
    // Configuration and state
    FlowAgentConfig config_;
    std::atomic<bool> running_{false};
    FlowStatistics stats_;
    
    // Crypto key for SipHash
    std::array<uint8_t, 16> sip_key_;
    std::unique_ptr<FlowKeyHasher> hasher_;
    
    // External library handles
    pcap_t* pcap_handle_{nullptr};
    struct ndpi_detection_module_struct* ndpi_struct_{nullptr};
    
    // RocksDB
    std::unique_ptr<rocksdb::DB> db_;
    std::unique_ptr<rocksdb::Options> db_options_;
    std::unique_ptr<rocksdb::WriteOptions> write_options_;
    std::unique_ptr<rocksdb::ReadOptions> read_options_;
    
    // Networking
    int netflow_socket_{-1};
    struct sockaddr_in collector_addr_{};
    
    // Threading and synchronization
    std::thread export_thread_;
    std::thread expiration_thread_;
    std::mutex flow_mutex_;
    std::condition_variable flow_condition_;
    std::queue<FlowRecord> pending_flows_;
    
    // Private methods
    void init_crypto();
    void init_ndpi();
    void init_rocksdb();
    void init_pcap();
    void init_netflow_socket();
    
    void packet_capture_loop();
    void export_loop();
    void expiration_loop();
    
    FlowKey extract_flow_key(const uint8_t* packet, size_t length) const;
    uint8_t extract_tcp_flags(const uint8_t* packet, size_t length, 
                             const FlowKey& key) const;
    uint8_t extract_tos(const uint8_t* packet) const;
    uint16_t classify_with_ndpi(const uint8_t* packet, size_t length) const;
    
    void update_or_create_flow(const FlowKey& key, size_t packet_size,
                              uint8_t tcp_flags, uint8_t tos, uint16_t protocol,
                              std::chrono::system_clock::time_point timestamp);
    
    bool store_flow(const FlowKey& key, const FlowRecord& record);
    bool load_flow(const FlowKey& key, FlowRecord& record) const;
    bool delete_flow(const FlowKey& key);
    
    void add_to_export_queue(const FlowRecord& record);
    void export_flows_batch(const std::vector<FlowRecord>& flows);
    void scan_expired_flows();
    
    std::vector<uint8_t> create_netflow_packet(const std::vector<FlowRecord>& flows) const;
    void send_netflow_packet(const std::vector<uint8_t>& packet);
    
    // Utility methods
    std::string flow_key_to_string(const FlowKey& key) const;
    uint32_t time_point_to_unix(std::chrono::system_clock::time_point tp) const;
    void generate_random_key();
    
    // Error handling
    void handle_pcap_error(const std::string& operation, int result) const;
    void handle_rocksdb_error(const std::string& operation, const std::string& error) const;
};

/**
 * Exception classes
 */
class FlowAgentException : public std::exception {
public:
    explicit FlowAgentException(const std::string& message) : message_(message) {}
    const char* what() const noexcept override { return message_.c_str(); }
private:
    std::string message_;
};

class InitializationException : public FlowAgentException {
public:
    explicit InitializationException(const std::string& message) 
        : FlowAgentException("Initialization failed: " + message) {}
};

class NetworkException : public FlowAgentException {
public:
    explicit NetworkException(const std::string& message)
        : FlowAgentException("Network error: " + message) {}
};

class DatabaseException : public FlowAgentException {
public:
    explicit DatabaseException(const std::string& message)
        : FlowAgentException("Database error: " + message) {}
};
