set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(Threads)

add_library(lab-netstack
  device.cpp
  callback.cpp
  ARP.cpp
  IP.cpp
  route.cpp
  utils.cpp
  TCP.cpp
  socket.cpp
  unp.cpp
)

add_library(lab-netstack-socket
  socket.cpp
)

target_link_libraries(lab-netstack PRIVATE pcap ${CMAKE_THREAD_LIBS_INIT})