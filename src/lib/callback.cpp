/**
 * @file callback.cpp
 * @brief Library includes call back functions when device receives frames.
 */

#include "../include/callback.h"
#include "../include/IP.h"
#include "../include/type.h"
#include "../include/utils.h"
#include "../include/debug.h"
#include <cstdio>
#include <cstring>
#include <netinet/ether.h>
#include <pcap/pcap.h>
#include <malloc.h>


int ether_recv_callback::recvFrameCallback(const void *frame, int len, dev_id id)
{
    u_char *frame_ = (u_char *)frame;
    u_char src_mac[ETHER_ADDR_LEN];
    u_char dst_mac[ETHER_ADDR_LEN];
    uint64_t check_sum = 0;
    memcpy(dst_mac, frame_, ETHER_ADDR_LEN);
    memcpy(src_mac, frame_ + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    uint16_t ethtype = ntohs(*(uint16_t *)(frame_ + ETHER_ADDR_LEN * 2));
    size_t payload_len = len - ETHER_CRC_LEN - ETHER_HDR_LEN;
    u_char *payload = (u_char *)malloc(payload_len);
    memset(payload,0,payload_len);
    memcpy(payload, frame_ + ETHER_HDR_LEN, payload_len);
    printf("[INFO] Device %d receive frame.\n"
           "src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n"
           "dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n"
           "pay_load: %s\n"
           "ethtype: 0x%x\n\n",
           id,
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
           payload,
           ethtype);
    free(payload);
    fflush(stdout);
    return 0;
}

int IP_recv_callback::recvIPCallback(const void *pkt, int len)
{
    IPPacket ip_pkt;
    memcpy(ip_pkt.header,pkt,IPHDR_LEN);
    u_char *payload=(u_char *)malloc(len-IPHDR_LEN);
    memcpy(payload,(u_char *)pkt+IPHDR_LEN,len-IPHDR_LEN);
    ip_pkt.IPntohs();
    char ip_src_str[IP_STR_LEN];
    char ip_dst_str[IP_STR_LEN];
    ip_addr_to_str(ip_pkt.header->ip_src,ip_src_str);
    ip_addr_to_str(ip_pkt.header->ip_dst,ip_dst_str);
    printf("[INFO] Receive IP Packet with length %d: \n"
           "IP version: %d\n"
           "Type of Service: 0x%02x\n"
           "Total Length: %d\n"
           "Identification for fragment: 0x%04x\n"
           "Time to live: %d\n"
           "Protocol: 0x%02x\n"
           "Header checksum: 0x%04x\n"
           "Source IP: %s\n"
           "Destination IP: %s\n"
           "Pay load: %s\n\n",
           len,
           ip_pkt.header->ip_v,
           ip_pkt.header->ip_tos,
           ip_pkt.header->ip_len,
           ip_pkt.header->ip_off,
           ip_pkt.header->ip_ttl,
           ip_pkt.header->ip_p,
           ip_pkt.header->ip_sum,
           ip_src_str,
           ip_dst_str,
           payload
           );
    dbg_printf("[INFO] Receive IP Packet with length %d: \n"
           "IP version: %d\n"
           "Type of Service: 0x%02x\n"
           "Total Length: %d\n"
           "Identification for fragment: 0x%04x\n"
           "Time to live: %d\n"
           "Protocol: 0x%02x\n"
           "Header checksum: 0x%04x\n"
           "Source IP: %s\n"
           "Destination IP: %s\n"
           "Pay load: %s\n\n",
           len,
           ip_pkt.header->ip_v,
           ip_pkt.header->ip_tos,
           ip_pkt.header->ip_len,
           ip_pkt.header->ip_off,
           ip_pkt.header->ip_ttl,
           ip_pkt.header->ip_p,
           ip_pkt.header->ip_sum,
           ip_src_str,
           ip_dst_str,
           payload);
    fflush(stdout);
    free(payload);
    return 0;
}
