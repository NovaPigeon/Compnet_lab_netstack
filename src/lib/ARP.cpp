#include "../include/ARP.h"
#include "../include/IP.h"
#include "../include/debug.h"
#include "../include/device.h"

ARP_CONTENT::ARP_CONTENT()
{
    hdr.ar_hln = (ETH_ALEN);
    hdr.ar_hrd = (ARPHRD_ETHER);
    hdr.ar_pln = (IPV4_ADDR_LEN);
    hdr.ar_pro = (ETHERTYPE_IP);
}

void ARP_CONTENT::ARPhtons()
{
    hdr.ar_op = htons(hdr.ar_op);
    hdr.ar_hrd = htons(hdr.ar_hrd);
    hdr.ar_pro = htons(hdr.ar_pro);
}

void ARP_CONTENT::ARPntohs()
{
    hdr.ar_op = ntohs(hdr.ar_op);
    hdr.ar_hrd = ntohs(hdr.ar_hrd);
    hdr.ar_pro = ntohs(hdr.ar_pro);
}

int sendARPRequest(Device *dev, ip_addr_t ip)
{
    struct ARP_CONTENT arp_pkt;
    arp_pkt.hdr.ar_op = ARPOP_REQUEST;
    arp_pkt.dst_ip=ip;
    arp_pkt.src_ip=dev->getDeviceIP();

    memcpy(arp_pkt.src_mac,dev->getDeviceMac(),ETH_ALEN);
    memset(arp_pkt.dst_mac,0,ETH_ALEN);
    
    arp_pkt.ARPhtons();

    char broadcast_mac[ETH_ALEN];
    memset(broadcast_mac,0xff,ETH_ALEN);
    dev->sendFrame(&arp_pkt,sizeof(arp_pkt),ETHERTYPE_ARP,broadcast_mac);

    char ip_str[IP_STR_LEN];
    ip_addr_to_str(ip, ip_str);
    dbg_printf("[INFO][sendARPRequest()] Device %s sends ARP request to IP %s\n",
               dev->getDeviceName(),
               ip_str);
    return 0;

}
int sendARPReply(Device *dev, ip_addr_t ip)
{
    struct ARP_CONTENT arp_pkt;
    arp_pkt.hdr.ar_op = ARPOP_REPLY;
    arp_pkt.dst_ip = ip;
    arp_pkt.src_ip = dev->getDeviceIP();
    std::string mac_str=dev->arpQueryMac(ip);
    char ip_str[IP_STR_LEN];
    ip_addr_to_str(ip,ip_str);
    if(mac_str.empty())
    {
        dbg_printf("[ERROR][sendARPReply()] Device %s did not cache IP %s\n",
                   dev->getDeviceName(),
                   ip_str
                   );
        return -1;
    }
    u_char mac[6];
    str_to_mac(mac_str.c_str(),mac);
    memcpy(arp_pkt.src_mac, dev->getDeviceMac(), ETH_ALEN);
    memcpy(arp_pkt.dst_mac,mac, ETH_ALEN);
    arp_pkt.ARPhtons();
    dev->sendFrame(&arp_pkt, sizeof(arp_pkt), ETHERTYPE_ARP, arp_pkt.dst_mac);
    dbg_printf("[INFO][sendARPReply()] Device %s sends ARP reply to IP %s\n",
               dev->getDeviceName(),
               ip_str);
    return 0;
}
int handleARPRequest(Device *dev,ARP_CONTENT *pkt)
{
    dbg_printf("[INFO][handleARPRequest()]\n");
    if(pkt->hdr.ar_op!=ARPOP_REQUEST ||
       pkt->dst_ip.s_addr!=dev->getDeviceIP().s_addr)
       {
            dbg_printf("[ERROR][handleARPRequest()] "
                       "Device %s: The ARP packet's parameters does not match\n"
                       "ar_op: %d; dst_ip: 0x%x; This ip: 0x%x",
                       dev->getDeviceName(),
                       pkt->hdr.ar_op,
                       pkt->dst_ip.s_addr,
                       dev->getDeviceIP().s_addr);
            return -1;
       }
    char src_mac[MAC_STR_LEN];
    mac_to_str(pkt->src_mac,src_mac);
    dev->arpInsert(pkt->src_ip,std::string(src_mac));
    sendARPReply(dev,pkt->src_ip);
    return 0;
}
int handleARPReply(Device *dev, ARP_CONTENT *pkt)
{
    dbg_printf("[INFO][handleARPReply()]\n");
    if (pkt->hdr.ar_op != ARPOP_REPLY ||
        memcmp(dev->getDeviceMac(),pkt->dst_mac,ETH_ALEN)!=0
    )
    {
        dbg_printf("[ERROR][handleARPReply()] "
                   "Device %s: The ARP packet's parameters does not match\n"
                   "ar_op: %d; dst_ip: 0x%x; This ip: 0x%x",
                   dev->getDeviceName(),
                   pkt->hdr.ar_op,
                   pkt->dst_ip.s_addr,
                   dev->getDeviceIP().s_addr);
        return -1;
    }
    char src_mac[MAC_STR_LEN];
    mac_to_str(pkt->src_mac, src_mac);
    dev->arpInsert(pkt->src_ip, std::string(src_mac));
    return 0;
}
