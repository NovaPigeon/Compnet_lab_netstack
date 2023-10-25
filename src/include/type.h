/**
 * @file type.h
 * @brief Library supporting ethernet type definitions.
 */

#ifndef NETSTACK_TYPE_H
#define NETSTACK_TYPE_H

#include <netinet/ip.h>

typedef int dev_id;
typedef in_addr ip_addr_t;

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