/**
 * @file callback.h
 * @brief Library includes call back functions when device receives frames.
 */
#ifndef NETSTACK_CALLBACK_H
#define NETSTACK_CALLBACK_H

#include"../include/type.h"

namespace ether_recv_callback{
    int recvFrameCallback(const void *frame,int len,dev_id id);
}

#endif
