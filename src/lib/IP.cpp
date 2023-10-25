#include "../include/IP.h"
#include "../include/device.h"
#include "../include/utils.h"
#include "../include/debug.h"

/**
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

IPPacket::IPPacket()
{
    header=(ip *)malloc(IPHDR_LEN);
    memset(header,0,IPHDR_LEN);
    header->ip_v=IPHDR_VERSION;
    header->ip_hl=IPHDR_MIN_IHL;
    header->ip_tos=IPHDR_TOS;
    header->ip_id=IPHDR_IDF;
    header->ip_off=IPHDR_FRAG_OFFSET;
    header->ip_ttl=IPHDR_MAX_LIVE_TIME;
    header->ip_sum=0;
    pay_load=nullptr;
}

void IPPacket::IPhtons()
{
    header->ip_len = htons(header->ip_len);
    header->ip_id = htons(header->ip_id);
    header->ip_off = htons(header->ip_off);
    header->ip_sum = htons(header->ip_sum);
}
void IPPacket::IPntohs()
{
    header->ip_len = ntohs(header->ip_len);
    header->ip_id = ntohs(header->ip_id);
    header->ip_off = ntohs(header->ip_off);
    header->ip_sum = ntohs(header->ip_sum);
}

uint16_t IPPacket::computeIPCheckSum()
{
    header->ip_sum=0;
    header->ip_sum=computeCheckSum(header,IPHDR_LEN);
    return header->ip_sum;
}

bool IPPacket::checkIPCheckSum()
{
    uint16_t sum=computeCheckSum(header,IPHDR_LEN);
    return (sum==0);
}

IPPacket::~IPPacket()
{
    free(header);
}

/**
 * @brief Send an IP packet to specified host .
 * @param src Source IP address .
 * @param dest Destination IP address .
 * @param proto Value of ‘protocol ‘ field in IP header .
 * @param buf pointer to IP payload
 * @param len Length of IP payload
 * @return 0 on success , -1 on error .
 */
int DeviceManager::sendIPPacket(ip_addr_t src, ip_addr_t dest, int proto, void *buf, int len)
{
    char src_ip_str[IP_STR_LEN];
    char dst_ip_str[IP_STR_LEN];
    dbg_printf("[INFO][DeviceManager::sendIPPacket()]"
               "Send IP packet from ip %s to ip %s.\n",
               ip_addr_to_str(src,src_ip_str),
               ip_addr_to_str(dest,dst_ip_str));
    Device *dev=this->getDeviceByIP(src);
    if(dev==nullptr)
    {
        dbg_printf("[ERROR][DeviceManager::sendIPPacket()] "
                   "The source IP  %s does't in the host.\n",
                   ip_addr_to_str(src,src_ip_str));
        return -1;
    }
    ip_addr_t src_subnet_mask=dev->getDeviceSubnetMask();
    std::string mac_str;
    u_char mac[ETH_ALEN];
    ip_addr_t next_hop_ip;
    ip_addr_t tmp;
    tmp.s_addr=0xffffff00;
    if(in_same_subnet(src,dest,tmp))
    {
        mac_str=this->arpQueryMac(dest);
    }
    else
    {
        next_hop_ip=this->route_table.query_next_hop(dest);
        if(next_hop_ip.s_addr==0)
        {
            mac_str=arpQueryMac(dest);
            dev=this->getDeviceByIPPrefix(dest);
        }
        else
            mac_str=this->arpQueryMac(next_hop_ip);
    }
    str_to_mac(mac_str.c_str(),mac);
    IPPacket pkt;
    pkt.header->ip_src=src;
    pkt.header->ip_dst=dest;
    pkt.header->ip_p=proto;
    pkt.header->ip_len = len + IPHDR_LEN;
    pkt.pay_load=(u_char *)buf;
    pkt.computeIPCheckSum();
    pkt.IPhtons();
    u_char *pkt_buf=(u_char *)malloc(IPHDR_LEN+len);
    memcpy(pkt_buf,pkt.header,IPHDR_LEN);
    memcpy(pkt_buf+IPHDR_LEN,pkt.pay_load,len);
    //printf("%d\n", ((ip *)pkt_buf)->ip_len);
    dev->sendFrame(pkt_buf,IPHDR_LEN+len,ETHERTYPE_IP,mac);
    free(pkt_buf);
    return 0;
}

int DeviceManager::setIPPacketReceiveCallback(IPPacketReceiveCallback callback)
{
    this->IPcallback=callback;
    return 0;
}

int handleIPPacket(DeviceManager *manager, Device *dev, void *pkt, int len)
{
    dbg_printf("[INFO][handleIPPacket()]\n");
    if(len<IPHDR_LEN)
    {
        dbg_printf("[ERROR] The IP packet length %d is less than IP head len %d.\n",
                    len,IPHDR_LEN);
        return -1;
    }
    IPPacket ip_pkt;
    char ip_src_str[IP_STR_LEN];
    char ip_dst_str[IP_STR_LEN];
    char ip_dev_str[IP_STR_LEN];
    memcpy(ip_pkt.header,pkt,IPHDR_LEN);
    ip_pkt.IPntohs();
    ip_addr_to_str(ip_pkt.header->ip_src,ip_src_str);
    ip_addr_to_str(ip_pkt.header->ip_dst,ip_dst_str);
    ip_addr_to_str(dev->getDeviceIP(),ip_dev_str);
    if(!ip_pkt.checkIPCheckSum())
    {
        dbg_printf("[ERROR] Device %s with IP %s: IP packet check sum error.\n",
                   dev->getDeviceName(),
                   ip_dev_str);
        return -1;
    }
    if(ip_pkt.header->ip_dst.s_addr==dev->getDeviceIP().s_addr ||
       manager->getDeviceByIP(ip_pkt.header->ip_dst)!=nullptr)
    {
        dbg_printf("[INFO] Device %s with IP %s receive IP packet from IP %s.\n",
                    dev->getDeviceName(),
                    ip_dst_str,
                    ip_src_str);
        if(manager->IPcallback==nullptr)
        {
            dbg_printf("[ERROR] The IP callback have not been set.\n");
            return -1;
        }
        return manager->IPcallback(pkt, len);
    }
    ip_addr_t next_hop_ip=manager->route_table.query_next_hop(ip_pkt.header->ip_dst);
    if(next_hop_ip.s_addr==UINT32_MAX)
    {
        dbg_printf("[ERROR] Destination IP %s does not in the route table.\n",
                    ip_dst_str);
        return -1;
    }
    std::string next_hop_mac_str;
    Device *dev_new;
    if(next_hop_ip.s_addr==0)
    {
        next_hop_mac_str=manager->arpQueryMac(ip_pkt.header->ip_dst);
        dev_new = manager->getDeviceByIPPrefix(ip_pkt.header->ip_dst);
    }
    else
    {
        next_hop_mac_str=manager->arpQueryMac(next_hop_ip);
        dev_new = manager->getDeviceByIPPrefix(next_hop_ip);
    }
    u_char next_hop_mac[ETH_ALEN];
    str_to_mac(next_hop_mac_str.c_str(),next_hop_mac);

    ip_pkt.header->ip_ttl--;
    if(ip_pkt.header->ip_ttl==0)
    {
        dbg_printf("[ERROR] Device  with IP %s dropped IP packet from IP %s to IP %s.\n",
                    ip_dev_str,
                    ip_src_str,
                    ip_dst_str);
        return -1;
    }
    ip_pkt.computeIPCheckSum();
    ip_pkt.IPhtons();
    u_char *send_buf=(u_char *)malloc(len);
    memcpy(send_buf,ip_pkt.header,IPHDR_LEN);
    memcpy(send_buf+IPHDR_LEN,(u_char *)pkt+IPHDR_LEN,len-IPHDR_LEN);
    dbg_printf("[INFO] Device %s with IP %s forward IP packet from IP %s to IP %s with mac %s.\n",
               dev_new->getDeviceMac(),
               ip_dev_str,
               ip_src_str,
               ip_dst_str,
               next_hop_mac_str.c_str());
    int ret=dev_new->sendFrame(send_buf,len,ETHERTYPE_IP,next_hop_mac);
    free(send_buf);
    return ret;
}
