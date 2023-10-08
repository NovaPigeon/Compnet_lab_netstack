/**
 * @file type.h
 * @brief Library supporting ethernet type definitions.
 */

#ifndef NETSTACK_TYPE_H
#define NETSTACK_TYPE_H

typedef int dev_id;

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

#endif