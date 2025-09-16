cmake_minimum_required(VERSION 3.20)

# Set vcpkg toolchain before project() if not already set
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

project(ndpi-flow-agent
    VERSION 1.0.0
    DESCRIPTION "High-performance network flow monitoring agent"
    LANGUAGES CXX C
)

# C++ standard and features
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build configuration
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Compiler-specific options
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -Wconversion -Wsign-conversion
        -Wnull-dereference -Wdouble-promotion
        -Wformat=2 -Wformat-security
        -Wcast-align -Wcast-qual
        -Wshadow
    )
    
    # Debug flags
    add_compile_options($<$<CONFIG:Debug>:-g3 -O0 -DDEBUG -fsanitize=address -fsanitize=undefined>)
    add_link_options($<$<CONFIG:Debug>:-fsanitize=address -fsanitize=undefined>)
    
    # Release flags
    add_compile_options($<$<CONFIG:Release>:-O3 -DNDEBUG -flto>)
    add_link_options($<$<CONFIG:Release>:-flto>)
    
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(/W4 /permissive-)
    add_compile_options($<$<CONFIG:Debug>:/Od /Zi>)
    add_compile_options($<$<CONFIG:Release>:/O2 /GL>)
    add_link_options($<$<CONFIG:Release>:/LTCG>)
endif()

# Find packages
find_package(Threads REQUIRED)
find_package(RocksDB CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)

# Platform-specific packages
if(WIN32)
    find_package(winpcap CONFIG REQUIRED)
    set(PCAP_LIBRARY winpcap::winpcap)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBPCAP REQUIRED IMPORTED_TARGET libpcap)
    set(PCAP_LIBRARY PkgConfig::LIBPCAP)
endif()

# Optional features
option(ENABLE_TESTS "Build unit tests" ON)
option(ENABLE_BENCHMARKS "Build performance benchmarks" OFF)
option(ENABLE_NATS "Enable NATS messaging support" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)

# nDPI - typically needs manual installation or custom find module
find_path(NDPI_INCLUDE_DIR 
    NAMES ndpi_api.h
    PATHS
        /usr/include/ndpi
        /usr/local/include/ndpi
        /opt/ndpi/include
        ${NDPI_ROOT}/include
    PATH_SUFFIXES ndpi
)

find_library(NDPI_LIBRARY
    NAMES ndpi
    PATHS
        /usr/lib
        /usr/local/lib
        /opt/ndpi/lib
        ${NDPI_ROOT}/lib
    PATH_SUFFIXES x86_64-linux-gnu
)

if(NOT NDPI_INCLUDE_DIR OR NOT NDPI_LIBRARY)
    message(WARNING "nDPI not found. You may need to install it manually or set NDPI_ROOT")
    set(NDPI_FOUND FALSE)
else()
    set(NDPI_FOUND TRUE)
    message(STATUS "Found nDPI: ${NDPI_LIBRARY}")
endif()

# Create interface library for nDPI
if(NDPI_FOUND)
    add_library(ndpi INTERFACE)
    target_include_directories(ndpi INTERFACE ${NDPI_INCLUDE_DIR})
    target_link_libraries(ndpi INTERFACE ${NDPI_LIBRARY})
endif()

# Main executable
add_executable(ndpi-flow-agent
    src/main.cpp
    src/flow_agent.cpp
    src/siphash.cpp
    src/packet_parser.cpp
    src/netflow_exporter.cpp
    src/flow_database.cpp
)

target_include_directories(ndpi-flow-agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(ndpi-flow-agent PRIVATE
    Threads::Threads
    RocksDB::rocksdb
    fmt::fmt
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    CLI11::CLI11
    ${PCAP_LIBRARY}
)

if(NDPI_FOUND)
    target_link_libraries(ndpi-flow-agent PRIVATE ndpi)
    target_compile_definitions(ndpi-flow-agent PRIVATE HAVE_NDPI)
endif()

# Optional NATS support
if(ENABLE_NATS)
    find_package(nats-c CONFIG REQUIRED)
    target_link_libraries(ndpi-flow-agent PRIVATE nats-c::nats)
    target_compile_definitions(ndpi-flow-agent PRIVATE ENABLE_NATS)
endif()

# Unit tests
if(ENABLE_TESTS)
    find_package(GTest CONFIG REQUIRED)
    enable_testing()
    
    add_executable(unit-tests
        tests/test_main.cpp
        tests/test_flow_key.cpp
        tests/test_flow_record.cpp
        tests/test_siphash.cpp
        tests/test_packet_parser.cpp
        tests/test_netflow_exporter.cpp
        tests/test_flow_database.cpp
        tests/test_flow_agent.cpp
        # Source files needed for testing
        src/flow_agent.cpp
        src/siphash.cpp
        src/packet_parser.cpp
        src/netflow_exporter.cpp
        src/flow_database.cpp
    )
    
    target_include_directories(unit-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    
    target_link_libraries(unit-tests PRIVATE
        GTest::gtest
        GTest::gmock
        Threads::Threads
        RocksDB::rocksdb
        fmt::fmt
        spdlog::spdlog
        nlohmann_json::nlohmann_json
        ${PCAP_LIBRARY}
    )
    
    if(NDPI_FOUND)
        target_link_libraries(unit-tests PRIVATE ndpi)
        target_compile_definitions(unit-tests PRIVATE HAVE_NDPI)
    endif()
    
    # Test discovery
    include(GoogleTest)
    gtest_discover_tests(unit-tests
        DISCOVERY_TIMEOUT 30
        PROPERTIES
            LABELS "unit"
    )
    
    # Add custom test target
    add_custom_target(check
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --parallel ${CMAKE_BUILD_PARALLEL_LEVEL}
        DEPENDS unit-tests
        COMMENT "Running unit tests"
    )
endif()

# Benchmarks
if(ENABLE_BENCHMARKS)
    find_package(benchmark CONFIG REQUIRED)
    
    add_executable(benchmarks
        benchmarks/benchmark_main.cpp
        benchmarks/benchmark_siphash.cpp
        benchmarks/benchmark_packet_parsing.cpp
        benchmarks/benchmark_flow_operations.cpp
        # Source files needed for benchmarking
        src/siphash.cpp
        src/packet_parser.cpp
        src/flow_database.cpp
    )
    
    target_include_directories(benchmarks PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(benchmarks PRIVATE
