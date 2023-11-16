#ifndef NETSTACK_ARP_H
#define NETSTACK_ARP_H


#include <netinet/ip.h>
#include <net/if_arp.h>
#include "../include/device.h"
#include "../include/type.h"

#define ARP_WAIT_TIME 20
#define ARP_RETRY_NUM 3

struct ARP_CONTENT
{
    arphdr hdr;
    u_char src_mac[6];
    ip_addr_t src_ip;
    u_char dst_mac[6];
    ip_addr_t dst_ip;
    void ARPhtons();
    void ARPntohs();
    ARP_CONTENT();
} __attribute__((__packed__));

typedef struct ARP_CONTENT ARP_CONTENT;

int sendARPRequest(Device *dev,ip_addr_t ip);
int sendARPReply(Device *dev, ip_addr_t ip);
int handleARPRequest(Device *dev, ARP_CONTENT *pkt);
int handleARPReply(Device *dev, ARP_CONTENT *pkt);

#endif
