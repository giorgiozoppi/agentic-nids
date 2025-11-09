cmake_minimum_required(VERSION 3.10)
project(Agentic-NIDS C)

add_executable(my_app src/main.c)

set(NDPI_INCLUDE_DIR "/nDPI/src/include")
set(NDPI_LIB_DIR "/nDPI/src/lib")

target_include_directories(my_app PRIVATE ${NDPI_INCLUDE_DIR})
target_link_directories(my_app PRIVATE ${NDPI_LIB_DIR})
target_link_libraries(my_app PRIVATE ndpi pcap pthread)