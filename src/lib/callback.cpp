/**
 * @file callback.cpp
 * @brief Library includes call back functions when device receives frames.
 */

#include "../include/callback.h"
#include <cstdio>
#include <cstring>
#include <netinet/ether.h>
#include <pcap/pcap.h>
#include <malloc.h>

int ether_recv_callback::recvFrameCallback(const void *frame, int len, dev_id id)
{
    u_char *frame_=(u_char *)frame;
    u_char src_mac[ETHER_ADDR_LEN];
    u_char dst_mac[ETHER_ADDR_LEN];
    uint64_t check_sum=0;
    memcpy(dst_mac,frame_,ETHER_ADDR_LEN);
    memcpy(src_mac,frame_+ETHER_ADDR_LEN,ETHER_ADDR_LEN);
    uint16_t ethtype=ntohs(*(uint16_t *)(frame_+ETHER_ADDR_LEN*2));
    size_t payload_len=len-ETHER_CRC_LEN-ETHER_HDR_LEN;
    u_char *payload=(u_char *)malloc(payload_len);
    memcpy(payload,frame_+ETHER_HDR_LEN,payload_len);
    for(int i=0;i<payload_len;++i)
    {
        check_sum+=(uint64_t)payload[i];
    }
    free(payload);
    printf("Device %d receive frame.\n",id);
    printf("src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
    src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
    printf("dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
    dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
    printf("pay_load_check_sum: %ld\n",check_sum);
    printf("ethtype: %d\n\n",ethtype);
    return 0;
}

