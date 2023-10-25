#include "../include/utils.h"
#include "../include/IP.h"
#include "../include/debug.h"
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

char* mac_to_str(const u_char *mac, char *mac_str)
{
    memset(mac_str,MAC_STR_LEN,0);
    snprintf(mac_str,
             MAC_STR_LEN,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0],
             mac[1],
             mac[2],
             mac[3],
             mac[4],
             mac[5]);
    return mac_str;
}
char* ip_addr_to_str(ip_addr_t ip, char *ip_str)
{
    memset(ip_str,IP_STR_LEN,0);
    snprintf(ip_str, 
             IP_STR_LEN, 
             "%d.%d.%d.%d", 
             ip.s_addr & 0xff, 
             (ip.s_addr >> 8) & 0xff, 
             (ip.s_addr >> 16) & 0xff, 
             ip.s_addr >> 24);
    return ip_str;
}
u_char* str_to_mac(const char *mac_str, u_char *mac)
{
    std::istringstream iss(mac_str);
    int value;

    for (int i = 0; i < 6; i++)
    {
        iss >> std::hex >> value;
        mac[i] = static_cast<unsigned char>(value);
        iss.ignore(1, ':');
    }
    return mac;
}

uint16_t computeCheckSum(const void *data, int len)
{
    unsigned long sum = 0;
    uint16_t *addr=(uint16_t *)data;
    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
    }

    if (len > 0)
        sum += ((*addr) & htons(0xff00));
    
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;
    return ((uint16_t)sum);
}

bool in_same_subnet(const ip_addr_t ip1, const ip_addr_t ip2, const ip_addr_t subnet_mask)
{
    return ((ip1.s_addr & subnet_mask.s_addr)==(ip2.s_addr & subnet_mask.s_addr));
}

void printbars(int n)
{
    for (int i = 0; i < n; ++i)
        printf("-");
    printf("\n");
}

void dbg_printbars(int n)
{
    for (int i = 0; i < n; ++i)
        dbg_printf("-");
    dbg_printf("\n");
}

bool ipcmp::operator()(const ip_addr_t ip1,const ip_addr_t ip2) const
{
    return ip1.s_addr<ip2.s_addr;
}

IP_Info get_ip_addr_at_host(const char *dev_name)
{
    struct ifaddrs *ifa_list = NULL;
    getifaddrs(&ifa_list);
    struct ifaddrs *ifa_entry = ifa_list;
    ip_addr_t device_ip;
    ip_addr_t subnet_mask;
    bool found=false;
    while (ifa_entry != NULL)
    {
        if (ifa_entry->ifa_addr->sa_family == AF_INET &&      // IPv4
            strcmp(ifa_entry->ifa_name, dev_name) == 0 // correspond device name
        )
        {
            device_ip = ((sockaddr_in *)(ifa_entry->ifa_addr))->sin_addr;
            subnet_mask = ((sockaddr_in *)(ifa_entry->ifa_netmask))->sin_addr;
            found=true;
            break;
        }
        ifa_entry = ifa_entry->ifa_next;
    }
    freeifaddrs(ifa_list);
    return {device_ip,subnet_mask,found};
}
