#ifndef NETSTACK_UTILS_H
#define NETSTACK_UTILS_H

#include <netinet/ip.h>
#include "../include/type.h"

#define IP_STR_LEN 30
#define MAC_STR_LEN 20

typedef struct
{
    ip_addr_t ip;
    ip_addr_t netmask;
    bool found;
}IP_Info;

char* mac_to_str(const u_char* mac,char* mac_str);
char* ip_addr_to_str(ip_addr_t ip,char* ip_str);
u_char* str_to_mac(const char* mac_str,u_char* mac);
uint16_t computeCheckSum(const void *data,int len);
bool in_same_subnet(const ip_addr_t ip1,const ip_addr_t ip2,const ip_addr_t subnet_mask);
void printbars(int n);
void dbg_printbars(int n);
IP_Info get_ip_addr_at_host(const char *dev_name);

struct ipcmp
{
    bool operator()(const ip_addr_t ip1, const ip_addr_t ip2) const;
};
#endif