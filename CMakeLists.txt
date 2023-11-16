cmake_minimum_required(VERSION 3.0.0)
project(lab-netstack VERSION 0.0.0)


set(CMAKE_CXX_STANDARD 17)
option(TEST_IP_ETHER_DEBUG "option for IP/Ethernet debug" OFF)
option(TEST_TCP_DEBUG "option for TCP debug" OFF)

if(TEST_IP_ETHER_DEBUG)
    add_definitions(-DIP_ETHER_DEBUG)
endif(TEST_IP_ETHER_DEBUG)

if(TEST_TCP_DEBUG)
    add_definitions(-DTCP_DEBUG)
endif(TEST_TCP_DEBUG)
add_subdirectory(src)