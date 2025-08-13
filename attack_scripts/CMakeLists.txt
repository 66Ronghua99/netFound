cmake_minimum_required(VERSION 3.20)
project(attack_scripts CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

find_package(PcapPlusPlus REQUIRED)

add_executable(substitute_flow_headers substitute_flow_headers.cpp)
target_link_libraries(substitute_flow_headers PUBLIC PcapPlusPlus::Pcap++)


