/*
 * flow_agent_impl.cpp
 *
 * Implementation of the FlowAgent class
 */

#include "flow_agent.h"
#include <pcap/pcap.h>
#include <ndpi_api.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

// SipHash implementation
namespace {
    inline uint64_t rotl(uint64_t x, int b) {
        return (x << b) | (x >> (64 - b));
    }

    uint64_t siphash24(const uint8_t* in, size_t inlen, const std::array<uint8_t, 16>& key) {
        uint64_t k0, k1;
        std::memcpy(&k0, key.data(), 8);
        std::memcpy(&k1, key.data() + 8, 8);

        uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
        uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
        uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
        uint64_t v3 = 0x7465646279746573ULL ^ k1;

        const uint8_t* end = in + inlen - (inlen % 8);
        const int left = inlen & 7;
        uint64_t m = 0;

        for (const uint8_t* p = in; p != end; p += 8) {
            std::memcpy(&m, p, 8);
            v3 ^= m;
            
            // SIPROUND x2
            for (int i = 0; i < 2; ++i) {
                v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
                v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
                v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
                v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
            }
            v0 ^= m;
        }

        // Build last block
        uint64_t last = static_cast<uint64_t>(inlen) << 56;
        switch (left) {
            case 7: last |= static_cast<uint64_t>(end[6]) << 48; [[fallthrough]];
            case 6: last |= static_cast<uint64_t>(end[5]) << 40; [[fallthrough]];
            case 5: last |= static_cast<uint64_t>(end[4]) << 32; [[fallthrough]];
            case 4: last |= static_cast<uint64_t>(end[3]) << 24; [[fallthrough]];
            case 3: last |= static_cast<uint64_t>(end[2]) << 16; [[fallthrough]];
            case 2: last |= static_cast<uint64_t>(end[1]) << 8; [[fallthrough]];
            case 1: last |= static_cast<uint64_t>(end[0]); break;
            case 0: break;
        }

        v3 ^= last;
        for (int i = 0; i < 2; ++i) {
            v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
            v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
            v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
            v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
        }
        v0 ^= last;

        v2 ^= 0xff;
        for (int i = 0; i < 4; ++i) {
            v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
            v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
            v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
            v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
        }

        return v0 ^ v1 ^ v2 ^ v3;
    }
}

// FlowKey implementation
bool FlowKey::operator==(const FlowKey& other) const noexcept {
    return src_ip == other.src_ip && dst_ip == other.dst_ip &&
           src_port == other.src_port && dst_port == other.dst_port &&
           protocol == other.protocol;
}

bool FlowKey::operator<(const FlowKey& other) const noexcept {
    if (src_ip != other.src_ip) return src_ip < other.src_ip;
    if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
    if (src_port != other.src_port) return src_port < other.src_port;
    if (dst_port != other.dst_port) return dst_port < other.dst_port;
    return protocol < other.protocol;
}

// FlowKeyHasher implementation
FlowKeyHasher::FlowKeyHasher(const std::array<uint8_t, 16>& key) : sip_key_(key) {}

std::size_t FlowKeyHasher::operator()(const FlowKey& key) const noexcept {
    uint8_t buffer[13];
    std::memcpy(buffer, &key.src_ip, 4);
    std::memcpy(buffer + 4, &key.dst_ip, 4);
    std::memcpy(buffer + 8, &key.src_port, 2);
    std::memcpy(buffer + 10, &key.dst_port, 2);
    std::memcpy(buffer + 12, &key.protocol, 1);
    
    return static_cast<std::size_t>(siphash24(buffer, sizeof(buffer), sip_key_));
}

// FlowRecord implementation
std::string FlowRecord::serialize() const {
    std::ostringstream oss;
    oss.write(reinterpret_cast<const char*>(&key), sizeof(key));
    oss.write(reinterpret_cast<const char*>(&bytes), sizeof(bytes));
    oss.write(reinterpret_cast<const char*>(&packets), sizeof(packets));
    oss.write(reinterpret_cast<const char*>(&ndpi_protocol), sizeof(ndpi_protocol));
    oss.write(reinterpret_cast<const char*>(&tcp_flags), sizeof(tcp_flags));
    oss.write(reinterpret_cast<const char*>(&tos), sizeof(tos));
    
    auto first_time = std::chrono::duration_cast<std::chrono::seconds>(
        first_seen.time_since_epoch()).count();
    auto last_time = std::chrono::duration_cast<std::chrono::seconds>(
        last_seen.time_since_epoch()).count();
    
    oss.write(reinterpret_cast<const char*>(&first_time), sizeof(first_time));
    oss.write(reinterpret_cast<const char*>(&last_time), sizeof(last_time));
    oss.write(reinterpret_cast<const char*>(&src_as), sizeof(src_as));
    oss.write(reinterpret_cast<const char*>(&dst_as), sizeof(dst_as));
    oss.write(reinterpret_cast<const char*>(&src_mask), sizeof(src_mask));
    oss.write(reinterpret_cast<const char*>(&dst_mask), sizeof(dst_mask));
    oss.write(reinterpret_cast<const char*>(&input_snmp), sizeof(input_snmp));
    oss.write(reinterpret_cast<const char*>(&output_snmp), sizeof(output_snmp));
    
    return oss.str();
}

FlowRecord FlowRecord::deserialize(const std::string& data) {
    FlowRecord record;
    std::istringstream iss(data);
    
    iss.read(reinterpret_cast<char*>(&record.key), sizeof(record.key));
    iss.read(reinterpret_cast<char*>(&record.bytes), sizeof(record.bytes));
    iss.read(reinterpret_cast<char*>(&record.packets), sizeof(record.packets));
    iss.read(reinterpret_cast<char*>(&record.ndpi_protocol), sizeof(record.ndpi_protocol));
    iss.read(reinterpret_cast<char*>(&record.tcp_flags), sizeof(record.tcp_flags));
    iss.read(reinterpret_cast<char*>(&record.tos), sizeof(record.tos));
    
    int64_t first_time, last_time;
    iss.read(reinterpret_cast<char*>(&first_time), sizeof(first_time));
    iss.read(reinterpret_cast<char*>(&last_time), sizeof(last_time));
    
    record.first_seen = std::chrono::system_clock::from_time_t(first_time);
    record.last_seen = std::chrono::system_clock::from_time_t(last_time);
    
    iss.read(reinterpret_cast<char*>(&record.src_as), sizeof(record.src_as));
    iss.read(reinterpret_cast<char*>(&record.dst_as), sizeof(record.dst_as));
    iss.read(reinterpret_cast<char*>(&record.src_mask), sizeof(record.src_mask));
    iss.read(reinterpret_cast<char*>(&record.dst_mask), sizeof(record.dst_mask));
    iss.read(reinterpret_cast<char*>(&record.input_snmp), sizeof(record.input_snmp));
    iss.read(reinterpret_cast<char*>(&record.output_snmp), sizeof(record.output_snmp));
    
    return record;
}

bool FlowRecord::should_expire(std::chrono::seconds idle_timeout,
                              std::chrono::seconds active_timeout,
                              std::chrono::system_clock::time_point now) const {
    auto idle_duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_seen);
    auto active_duration = std::chrono::duration_cast<std::chrono::seconds>(now - first_seen);
    
    return idle_duration > idle_timeout || active_duration > active_timeout;
}

// FlowAgent implementation
FlowAgent::FlowAgent(const FlowAgentConfig& config) : config_(config) {
    generate_random_key();
    hasher_ = std::make_unique<FlowKeyHasher>(sip_key_);
}

FlowAgent::~FlowAgent() {
    stop();
    
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
    }
    
    if (ndpi_struct_) {
        ndpi_exit_detection_module(ndpi_struct_);
    }
    
    if (netflow_socket_ >= 0) {
        close(netflow_socket_);
    }
}

void FlowAgent::initialize() {
    try {
        init_ndpi();
        init_rocksdb();
        init_pcap();
        init_netflow_socket();
    } catch (const std::exception& e) {
        throw InitializationException(e.what());
    }
}

void FlowAgent::run() {
    if (running_.exchange(true)) {
        throw FlowAgentException("Agent is already running");
    }
    
    try {
        // Start worker threads
        export_thread_ = std::thread(&FlowAgent::export_loop, this);
        expiration_thread_ = std::thread(&FlowAgent::expiration_loop, this);
        
        // Main packet capture loop
        packet_capture_loop();
        
        // Wait for threads to finish
        if (export_thread_.joinable()) {
            export_thread_.join();
        }
        if (expiration_thread_.joinable()) {
            expiration_thread_.join();
        }
        
    } catch (const std::exception& e) {
        running_ = false;
        throw;
    }
}

void FlowAgent::stop() {
    if (running_.exchange(false)) {
        flow_condition_.notify_all();
        
        // Break out of pcap loop
        if (pcap_handle_) {
            pcap_breakloop(pcap_handle_);
        }
    }
}

void FlowAgent::print_statistics() const {
    auto stats = get_statistics();
    
    std::cout << "\n=== Flow Agent Statistics ===" << std::endl;
    std::cout << "Packets processed: " << stats.packets_processed << std::endl;
    std::cout << "Flows created: " << stats.flows_created << std::endl;
    std::cout << "Flows updated: " << stats.flows_updated << std::endl;
    std::cout << "Flows exported: " << stats.flows_exported << std::endl;
    std::cout << "Flows expired: " << stats.flows_expired << std::endl;
    std::cout << "NetFlow packets sent: " << stats.netflow_packets_sent << std::endl;
    std::cout << "Active flows: " << stats.active_flows << std::endl;
    std::cout << "Pending flows: " << stats.pending_flows << std::endl;
    std::cout << "NetFlow sequence: " << stats.netflow_sequence << std::endl;
    std::cout << "=============================" << std::endl;
}

FlowStatistics FlowAgent::get_statistics() const {
    return stats_;
}

void FlowAgent::process_packet(const uint8_t* packet, size_t length,
                              std::chrono::system_clock::time_point timestamp) {
    if (length < 34) return; // Minimum Ethernet + IP header size
    
    stats_.packets_processed++;
    
    try {
        FlowKey key = extract_flow_key(packet, length);
        if (key.protocol == 0) return; // Invalid packet
        
        uint8_t tcp_flags = extract_tcp_flags(packet, length, key);
        uint8_t tos = extract_tos(packet);
        uint16_t ndpi_protocol = classify_with_ndpi(packet, length);
        
        update_or_create_flow(key, length, tcp_flags, tos, ndpi_protocol, timestamp);
        
    } catch (const std::exception& e) {
        // Log error but continue processing
        std::cerr << "Error processing packet: " << e.what() << std::endl;
    }
}

bool FlowAgent::get_flow(const FlowKey& key, FlowRecord& record) const {
    return load_flow(key, record);
}

// Private method implementations
void FlowAgent::init_ndpi() {
    ndpi_struct_ = ndpi_init_detection_module(ndpi_no_prefs);
    if (!ndpi_struct_) {
        throw InitializationException("Failed to initialize nDPI");
    }
}

void FlowAgent::init_rocksdb() {
    db_options_ = std::make_unique<rocksdb::Options>();
    db_options_->create_if_missing = true;
    db_options_->compression = rocksdb::kLZ4Compression;
    db_options_->write_buffer_size = 64 * 1024 * 1024; // 64MB
    db_options_->max_write_buffer_number = 3;
    db_options_->target_file_size_base = 64 * 1024 * 1024;
    
    write_options_ = std::make_unique<rocksdb::WriteOptions>();
    read_options_ = std::make_unique<rocksdb::ReadOptions>();
    
    rocksdb::DB* db_raw;
    rocksdb::Status status = rocksdb::DB::Open(*db_options_, config_.rocksdb_path, &db_raw);
    
    if (!status.ok()) {
        throw DatabaseException("Failed to open RocksDB: " + status.ToString());
    }
    
    db_.reset(db_raw);
}

void FlowAgent::init_pcap() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_ = pcap_open_live(config_.interface.c_str(), 65535, 1, 1000, errbuf);
    
    if (!pcap_handle_) {
        throw NetworkException("Failed to open interface " + config_.interface + ": " + errbuf);
    }
    
    // Set non-blocking mode for better control
    if (pcap_setnonblock(pcap_handle_, 1, errbuf) == -1) {
        throw NetworkException("Failed to set non-blocking mode: " + std::string(errbuf));
    }
}

void FlowAgent::init_netflow_socket() {
    netflow_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (netflow_socket_ < 0) {
        throw NetworkException("Failed to create NetFlow socket: " + std::string(std::strerror(errno)));
    }
    
    std::memset(&collector_addr_, 0, sizeof(collector_addr_));
    collector_addr_.sin_family = AF_INET;
    collector_addr_.sin_port = htons(config_.collector_port);
    
    if (inet_aton(config_.collector_ip.c_str(), &collector_addr_.sin_addr) == 0) {
        throw NetworkException("Invalid collector IP address: " + config_.collector_ip);
    }
}

void FlowAgent::packet_capture_loop() {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int result;
    
    while (running_) {
        result = pcap_next_ex(pcap_handle_, &header, &packet);
        
        if (result == 1) {
            // Packet captured successfully
            auto timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                           std::chrono::microseconds(header->ts.tv_usec);
            process_packet(packet, header->caplen, timestamp);
            
        } else if (result == 0) {
            // Timeout - continue
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            
        } else if (result == -1) {
            // Error
            if (running_) {
                handle_pcap_error("pcap_next_ex", result);
            }
            break;
            
        } else if (result == -2) {
            // End of capture file or pcap_breakloop called
            break;
        }
    }
}

void FlowAgent::export_loop() {
    std::vector<FlowRecord> batch;
    batch.reserve(config_.max_flows_per_packet);
    
    while (running_ || !pending_flows_.empty()) {
        std::unique_lock<std::mutex> lock(flow_mutex_);
        
        // Wait for flows to export or timeout
        flow_condition_.wait_for(lock, std::chrono::milliseconds(100), [this] {
            return !pending_flows_.empty() || !running_;
        });
        
        // Collect batch of flows
        batch.clear();
        while (!pending_flows_.empty() && batch.size() < config_.max_flows_per_packet) {
            batch.push_back(std::move(pending_flows_.front()));
            pending_flows_.pop();
        }
        
        stats_.pending_flows = pending_flows_.size();
        lock.unlock();
        
        // Export batch if we have flows
        if (!batch.empty()) {
            export_flows_batch(batch);
        }
    }
}

void FlowAgent::expiration_loop() {
    while (running_) {
        scan_expired_flows();
        std::this_thread::sleep_for(config_.scan_interval);
    }
    
    // Final scan before exit
    scan_expired_flows();
}

FlowKey FlowAgent::extract_flow_key(const uint8_t* packet, size_t length) const {
    FlowKey key{};
    
    if (length < 34) return key; // Too short
    
    // Skip Ethernet header (14 bytes)
    const uint8_t* ip_header = packet + 14;
    
    // Check for IPv4
    if ((ip_header[0] >> 4) != 4) return key;
    
    uint8_t ihl = (ip_header[0] & 0x0f) * 4;
    if (ihl < 20 || length < 14 + ihl) return key;
    
    key.protocol = ip_header[9];
    std::memcpy(&key.src_ip, ip_header + 12, 4);
    std::memcpy(&key.dst_ip, ip_header + 16, 4);
    
    // Extract ports for TCP/UDP
    if ((key.protocol == IPPROTO_TCP || key.protocol == IPPROTO_UDP) && 
        length >= 14 + ihl + 4) {
        const uint8_t* l4_header = ip_header + ihl;
        std::memcpy(&key.src_port, l4_header, 2);
        std::memcpy(&key.dst_port, l4_header + 2, 2);
        key.src_port = ntohs(key.src_port);
        key.dst_port = ntohs(key.dst_port);
    }
    
    return key;
}

uint8_t FlowAgent::extract_tcp_flags(const uint8_t* packet, size_t length, 
                                    const FlowKey& key) const {
    if (key.protocol != IPPROTO_TCP || length < 34) return 0;
    
    const uint8_t* ip_header = packet + 14;
    uint8_t ihl = (ip_header[0] & 0x0f) * 4;
    
    if (length < 14 + ihl + 14) return 0; // Minimum TCP header
    
    const uint8_t* tcp_header = ip_header + ihl;
    return tcp_header[13]; // TCP flags byte
}

uint8_t FlowAgent::extract_tos(const uint8_t* packet) const {
    if (packet && (packet[14] >> 4) == 4) {
        return packet[15]; // ToS/DSCP field in IP header
    }
    return 0;
}

uint16_t FlowAgent::classify_with_ndpi(const uint8_t* packet, size_t length) const {
    if (!ndpi_struct_ || length == 0) return 0;
    
    // Simplified nDPI classification - in production you'd need flow state
    struct ndpi_proto result = ndpi_detection_process_packet(
        ndpi_struct_, const_cast<uint8_t*>(packet), length, 0, nullptr);
    
    return result.app_protocol;
}

void FlowAgent::update_or_create_flow(const FlowKey& key, size_t packet_size,
                                     uint8_t tcp_flags, uint8_t tos, uint16_t protocol,
                                     std::chrono::system_clock::time_point timestamp) {
    FlowRecord record;
    bool is_new_flow = !load_flow(key, record);
    
    if (is_new_flow) {
        // Create new flow
        record.key = key;
        record.bytes = packet_size;
        record.packets = 1;
        record.ndpi_protocol = protocol;
        record.tcp_flags = tcp_flags;
        record.tos = tos;
        record.first_seen = timestamp;
        record.last_seen = timestamp;
        
        stats_.flows_created++;
        stats_.active_flows++;
        
    } else {
        // Update existing flow
        record.bytes += packet_size;
        record.packets++;
        record.tcp_flags |= tcp_flags; // Accumulate TCP flags
        record.last_seen = timestamp;
        
        // Update protocol if we have better information
        if (record.ndpi_protocol == 0 && protocol != 0) {
            record.ndpi_protocol = protocol;
        }
        
        stats_.flows_updated++;
    }
    
    store_flow(key, record);
}

bool FlowAgent::store_flow(const FlowKey& key, const FlowRecord& record) {
    try {
        std::string key_str = flow_key_to_string(key);
        std::string value = record.serialize();
        
        rocksdb::Status status = db_->Put(*write_options_, key_str, value);
        
        if (!status.ok()) {
            handle_rocksdb_error("Put", status.ToString());
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error storing flow: " << e.what() << std::endl;
        return false;
    }
}

bool FlowAgent::load_flow(const FlowKey& key, FlowRecord& record) const {
    try {
        std::string key_str = flow_key_to_string(key);
        std::string value;
        
        rocksdb::Status status = db_->Get(*read_options_, key_str, &value);
        
        if (status.IsNotFound()) {
            return false;
        }
        
        if (!status.ok()) {
            handle_rocksdb_error("Get", status.ToString());
            return false;
        }
        
        record = FlowRecord::deserialize(value);
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error loading flow: " << e.what() << std::endl;
        return false;
    }
}

bool FlowAgent::delete_flow(const FlowKey& key) {
    try {
        std::string key_str = flow_key_to_string(key);
        rocksdb::Status status = db_->Delete(*write_options_, key_str);
        
        if (!status.ok() && !status.IsNotFound()) {
            handle_rocksdb_error("Delete", status.ToString());
            return false;
        }
        
        stats_.active_flows--;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error deleting flow: " << e.what() << std::endl;
        return false;
    }
}

void FlowAgent::add_to_export_queue(const FlowRecord& record) {
    std::lock_guard<std::mutex> lock(flow_mutex_);
    
    if (pending_flows_.size() >= config_.max_pending_flows) {
        // Drop oldest flow to prevent memory exhaustion
        pending_flows_.pop();
    }
    
    pending_flows_.push(record);
    stats_.pending_flows = pending_flows_.size();
    flow_condition_.notify_one();
}

void FlowAgent::export_flows_batch(const std::vector<FlowRecord>& flows) {
    if (flows.empty()) return;
    
    try {
        std::vector<uint8_t> packet = create_netflow_packet(flows);
        send_netflow_packet(packet);
        
        stats_.flows_exported += flows.size();
        stats_.netflow_packets_sent++;
        
    } catch (const std::exception& e) {
        std::cerr << "Error exporting flows: " << e.what() << std::endl;
    }
}

void FlowAgent::scan_expired_flows() {
    auto now = std::chrono::system_clock::now();
    std::vector<FlowKey> expired_keys;
    
    try {
        std::unique_ptr<rocksdb::Iterator> it(db_->NewIterator(*read_options_));
        
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            FlowRecord record = FlowRecord::deserialize(it->value().ToString());
            
            if (record.should_expire(config_.idle_timeout, config_.active_timeout, now)) {
                expired_keys.push_back(record.key);
                add_to_export_queue(record);
            }
        }
        
        if (!it->status().ok()) {
            handle_rocksdb_error("Iterator", it->status().ToString());
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error scanning for expired flows: " << e.what() << std::endl;
        return;
    }
    
    // Delete expired flows
    for (const auto& key : expired_keys) {
        delete_flow(key);
        stats_.flows_expired++;
    }
}

std::vector<uint8_t> FlowAgent::create_netflow_packet(const std::vector<FlowRecord>& flows) const {
    if (flows.size() > config_.max_flows_per_packet) {
        throw std::runtime_error("Too many flows for single NetFlow packet");
    }
    
    NetFlowV5Header header{};
    header.version = htons(5);
    header.count = htons(static_cast<uint16_t>(flows.size()));
    header.sys_uptime = 0;
    header.unix_secs = htonl(time_point_to_unix(std::chrono::system_clock::now()));
    header.unix_nsecs = 0;
    header.flow_sequence = htonl(stats_.netflow_sequence.fetch_add(flows.size()));
    header.engine_type = 1;
    header.engine_id = 1;
    header.sampling_interval = 0;
    
    std::vector<uint8_t> packet;
    packet.reserve(sizeof(NetFlowV5Header) + flows.size() * sizeof(NetFlowV5Record));
    
    // Add header
    const uint8_t* header_ptr = reinterpret_cast<const uint8_t*>(&header);
    packet.insert(packet.end(), header_ptr, header_ptr + sizeof(header));
    
    // Add flow records
    for (const auto& flow : flows) {
        NetFlowV5Record record{};
        record.src_addr = flow.key.src_ip;
        record.dst_addr = flow.key.dst_ip;
        record.nexthop = 0;
        record.input = htons(flow.input_snmp);
        record.output = htons(flow.output_snmp);
        record.d_pkts = htonl(static_cast<uint32_t>(std::min(flow.packets, 
                                                            static_cast<uint64_t>(UINT32_MAX))));
        record.d_octets = htonl(static_cast<uint32_t>(std::min(flow.bytes, 
                                                              static_cast<uint64_t>(UINT32_MAX))));
        record.first = htonl(time_point_to_unix(flow.first_seen));
        record.last = htonl(time_point_to_unix(flow.last_seen));
        record.src_port = htons(flow.key.src_port);
        record.dst_port = htons(flow.key.dst_port);
        record.pad1 = 0;
        record.tcp_flags = flow.tcp_flags;
        record.prot = flow.key.protocol;
        record.tos = flow.tos;
        record.src_as = htons(static_cast<uint16_t>(flow.src_as));
        record.dst_as = htons(static_cast<uint16_t>(flow.dst_as));
        record.src_mask = flow.src_mask;
        record.dst_mask = flow.dst_mask;
        record.pad2 = 0;
        
        const uint8_t* record_ptr = reinterpret_cast<const uint8_t*>(&record);
        packet.insert(packet.end(), record_ptr, record_ptr + sizeof(record));
    }
    
    return packet;
}

void FlowAgent::send_netflow_packet(const std::vector<uint8_t>& packet) {
    ssize_t sent = sendto(netflow_socket_, packet.data(), packet.size(), 0,
                         reinterpret_cast<const sockaddr*>(&collector_addr_),
                         sizeof(collector_addr_));
    
    if (sent < 0) {
        throw NetworkException("Failed to send NetFlow packet: " + std::string(std::strerror(errno)));
    }
    
    if (static_cast<size_t>(sent) != packet.size()) {
        throw NetworkException("Partial NetFlow packet sent");
    }
}

std::string FlowAgent::flow_key_to_string(const FlowKey& key) const {
    uint64_t hash = (*hasher_)(key);
    return std::string(reinterpret_cast<const char*>(&hash), sizeof(hash));
}

uint32_t FlowAgent::time_point_to_unix(std::chrono::system_clock::time_point tp) const {
    return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        tp.time_since_epoch()).count());
}

void FlowAgent::generate_random_key() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint8_t> dis;
    
    for (auto& byte : sip_key_) {
        byte = dis(gen);
    }
}

void FlowAgent::handle_pcap_error(const std::string& operation, int result) const {
    std::string error_msg = operation + " failed";
    if (pcap_handle_) {
        error_msg += ": " + std::string(pcap_geterr(pcap_handle_));
    }
    throw NetworkException(error_msg);
}

void FlowAgent::handle_rocksdb_error(const std::string& operation, const std::string& error) const {
    throw DatabaseException(operation + " failed: " + error);
}
