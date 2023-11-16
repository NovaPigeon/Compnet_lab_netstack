/**
 * @file type.h
 * @brief Library supporting ethernet type definitions.
 */

#ifndef NETSTACK_TYPE_H
#define NETSTACK_TYPE_H



#include <algorithm>
#include <arpa/inet.h>
#include <assert.h>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <map>
#include <mutex>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <queue>
#include <set>
#include <shared_mutex>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

typedef int dev_id;
typedef in_addr ip_addr_t;
typedef uint32_t tcp_seq_t;
typedef int fd_t;

/**
 * @brief Process a frame upon receiving it.
 *
 * @param buf Pointer to the frame .
 * @param len Length of the frame .
 * @param id ID of the device ( returned by ‘addDevice ‘) receiving
 * current frame.
 * @return 0 on success , -1 on error .
 * @see addDevice
 */
typedef int (*frameReceiveCallback)(const void *, int, int);

/**
 * @brief Process an IP packet upon receiving it. 
 * @param buf Pointer to the packet . 
 * @param len Length of the packet . 
 * @return 0 on success , -1 on error . 
 * @see addDevice
 */
typedef int (*IPPacketReceiveCallback)(const void *buf, int len);

#endif