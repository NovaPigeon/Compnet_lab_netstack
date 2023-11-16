#ifndef NETSTACK_ROUTE_H
#define NETSTACK_ROUTE_H



#include "../include/type.h"
#include <set>
#include <map>
#include <mutex>
#include <thread>
#include <shared_mutex>

#define RIP_MAX_DISTANCE 16
#define RIP_UPDATE_TIME 2
#define RIP_INVALID_TIME 6
#define RIP_FLUSH_TIME 4
#define RIP_REQUEST_CMD 1
#define RIP_REPLY_CMD 2
#define RIP_AFI_REQ 0
#define RIP_AFR_IP 2
#define MY_RIP_VERSION 3
#define MY_RIP_PROTO 0x0123
#define MAX_RIP_DISTANCE 16
#define TIMER_TICKS 1

/**
 * RIP-like Packet
 * |<-- 8 -->|<-- 8 -->|<----- 16 ------>|
 * +---------+---------+-----------------+
 * | command | version |    must_be_zero | -> head
 * +---------+---------+-----------------+
 * | address_family    |    must_be_zero |
 * +---------+---------+-----------------+
 * |                ip_addr              |
 * +---------+---------+-----------------+
 * |               subnet_mask           | -> entry
 * +---------+---------+-----------------+
 * |               next_hop_ip           |
 * +---------+---------+-----------------+
 * |                 metric              |
 * +---------+---------+-----------------+
 * entry[0]: sender info 
 * entry[1+]: route info
 */

struct RIPHead
{
    uint8_t command;
    uint8_t version;
    uint16_t must_be_zero;

}__attribute__((__packed__));

struct RIPEntry
{
    uint16_t address_family;
    uint16_t must_be_zero_1;
    ip_addr_t ip_addr;
    ip_addr_t subnet_mask;
    ip_addr_t next_hop_ip;
    uint32_t metric;
}__attribute__((__packed__));

#define RIP_HDR_SIZE 4UL
#define RIP_ENTRY_SIZE 20UL

class RouteItem
{
public:
    ip_addr_t next_hop;
    int distance;
    int invalid_timer;
    int flush_timer;
    bool valid;
    RouteItem()
    {
        invalid_timer = RIP_INVALID_TIME;
        flush_timer=RIP_FLUSH_TIME;
        valid=true;
    }
    RouteItem(ip_addr_t next_hop_,int distance_)
    {
        distance=distance_;
        next_hop.s_addr=next_hop_.s_addr;
        invalid_timer=RIP_INVALID_TIME;
        flush_timer=RIP_FLUSH_TIME;
        valid=true;
    }
    RouteItem &operator=(const RouteItem &item)
    {
        this->distance=item.distance;
        this->flush_timer=item.flush_timer;
        this->invalid_timer=item.invalid_timer;
        this->next_hop.s_addr=item.next_hop.s_addr;
        this->valid=item.valid;
        return *this;
    }
    RouteItem(const RouteItem &item)
    {
        this->distance = item.distance;
        this->flush_timer = item.flush_timer;
        this->invalid_timer = item.invalid_timer;
        this->next_hop.s_addr = item.next_hop.s_addr;
        this->valid = item.valid;
    }
};
class RouteKey
{
public:
    ip_addr_t dest_ip_prefix;
    ip_addr_t dest_ip_netmask;
    RouteKey()
    {
    }
    RouteKey(ip_addr_t ip_dest,ip_addr_t ip_netmask)
    {
        this->dest_ip_netmask.s_addr=ip_netmask.s_addr;
        this->dest_ip_prefix.s_addr=(ip_dest.s_addr & ip_netmask.s_addr);
    }
    RouteKey(const RouteKey &key)
    {
        this->dest_ip_netmask.s_addr=key.dest_ip_netmask.s_addr;
        this->dest_ip_prefix.s_addr=key.dest_ip_prefix.s_addr;
    }
    bool operator<(const RouteKey& key) const
    {
        if(dest_ip_netmask.s_addr<key.dest_ip_netmask.s_addr)
            return true;
        else if(dest_ip_netmask.s_addr>key.dest_ip_netmask.s_addr)
            return false;
        return (dest_ip_prefix.s_addr < key.dest_ip_prefix.s_addr);
    }
};

class RouteTable
{
public:
    ip_addr_t query_next_hop(ip_addr_t dest_ip);
    int set_route_item(ip_addr_t dest_ip,ip_addr_t subnet_mask,ip_addr_t next_hop,int distance);
    int delete_route_item(const RouteKey& key);
    void *construct_RIP_request(void *buf,size_t *len,ip_addr_t ip,ip_addr_t netmask);
    void *construct_RIP_response(void *buf,size_t *len,ip_addr_t ip,ip_addr_t netmask);
    void printRouteTable(int verbose);
    void route_table_update();
    void refreshRouteItem(ip_addr_t ip,ip_addr_t netmask,int distance);
    void *manager;
    std::map<RouteKey,RouteItem> route_table;
    std::shared_timed_mutex route_table_mutex;
};
#endif