set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/tcp)

link_libraries(lab-netstack pcap lab-netstack-socket)
add_executable(server server.cpp)
add_executable(client client.cpp)
add_executable(echo_client echo_client.cpp)
add_executable(echo_server echo_server.cpp)
add_executable(perf_client perf_client.cpp)
add_executable(perf_server perf_server.cpp)