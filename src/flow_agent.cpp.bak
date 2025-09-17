/*
 * flow_agent.cpp
 *
 * Modern C++ network flow monitoring agent with:
 *  - Modern C++17 features and RAII
 *  - vcpkg dependency management
 *  - Object-oriented design with proper separation of concerns
 *  - Thread-safe flow aggregation
 *  - Comprehensive error handling
 *  - Unit testable architecture
 */

#include "flow_agent.hpp"
#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>

// Global agent instance for signal handling
std::unique_ptr<FlowAgent> g_agent;

void signal_handler(int signum) {
    if (g_agent) {
        switch (signum) {
            case SIGINT:
            case SIGTERM:
                std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
                g_agent->stop();
                break;
            case SIGUSR1:
                g_agent->print_statistics();
                break;
        }
    }
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 4) {
            std::cerr << "Usage: " << argv[0] 
                      << " <interface> <rocksdb_path> <collector_ip:port> [idle_timeout] [active_timeout]" 
                      << std::endl;
            std::cerr << "  Send SIGUSR1 to display statistics" << std::endl;
            return 1;
        }

        FlowAgentConfig config;
        config.interface = argv[1];
        config.rocksdb_path = argv[2];
        
        // Parse collector address
        std::string collector_addr = argv[3];
        auto colon_pos = collector_addr.find(':');
        if (colon_pos != std::string::npos) {
            config.collector_ip = collector_addr.substr(0, colon_pos);
            config.collector_port = std::stoi(collector_addr.substr(colon_pos + 1));
        } else {
            config.collector_ip = collector_addr;
            config.collector_port = 2055;
        }

        if (argc >= 5) config.idle_timeout = std::chrono::seconds(std::stoi(argv[4]));
        if (argc >= 6) config.active_timeout = std::chrono::seconds(std::stoi(argv[5]));

        std::cout << "Flow Agent starting..." << std::endl;
        std::cout << "Interface: " << config.interface << std::endl;
        std::cout << "RocksDB path: " << config.rocksdb_path << std::endl;
        std::cout << "Collector: " << config.collector_ip << ":" << config.collector_port << std::endl;
        std::cout << "Idle timeout: " << config.idle_timeout.count() << " seconds" << std::endl;
        std::cout << "Active timeout: " << config.active_timeout.count() << " seconds" << std::endl;

        // Create and initialize agent
        g_agent = std::make_unique<FlowAgent>(config);
        
        // Setup signal handlers
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        std::signal(SIGUSR1, signal_handler);
        
        // Initialize and run
        g_agent->initialize();
        g_agent->run();
        
        std::cout << "Flow agent shutdown complete." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
