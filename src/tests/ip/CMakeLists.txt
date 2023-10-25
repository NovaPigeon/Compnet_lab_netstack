set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/ip)
link_libraries(lab-netstack pcap)
add_executable(host_manager host_manager.cpp)