/**
 * @file ip.h 
 * @brief Library supporting sending / receiving IP packets encapsulated in an Ethernet II frame .
*/

#ifndef NETSTACK_IP_H
#define NETSTACK_IP_H


#include "../include/type.h"
#include <string>
#define IPV4_ADDR_LEN 4

const std::string IP_THIS_DEV_STR="0.0.0.0";
const std::string IP_BROADCAST_STR="255.255.255.255";

/* 
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
class IPPacket
{
public:
    ip *header;
    u_char *pay_load;
    IPPacket();
    ~IPPacket();
    void IPhtons();
    void IPntohs();
    uint16_t computeIPCheckSum();
    bool checkIPCheckSum();
};

#define IPHDR_VERSION 4
#define IPHDR_MIN_IHL 5
#define IPHDR_TOS 0
#define IPHDR_IDF 0
#define IPHDR_FRAG_OFFSET IP_DF
#define IPHDR_MAX_LIVE_TIME 16
#define IPHDR_PROTO 0
#define IPHDR_LEN 20




#endif