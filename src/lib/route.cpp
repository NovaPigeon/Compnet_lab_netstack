#include "../include/route.h"
#include "../include/debug.h"
#include "../include/utils.h"
#include "../include/type.h"
#include "../include/device.h"
#include <string.h>
#include <unistd.h>
#include <vector>

ip_addr_t RouteTable::query_next_hop(ip_addr_t dest_ip)
{
    char ip_str[IP_STR_LEN];
    char next_hop_str[IP_STR_LEN];
    ip_addr_t next_hop;
    dbg_printf("[INFO][RouteTable::query_next_hop()] "
               "Query next hop at IP %s.\n",
               ip_addr_to_str(dest_ip, ip_str));
    this->route_table_mutex.lock_shared();
    auto iter = this->route_table.begin();
    ip_addr_t max_sub_net;
    max_sub_net.s_addr = 0;
    for (; iter != this->route_table.end(); iter++)
    {
        RouteKey key = iter->first;
        RouteItem item = iter->second;
        if (key.dest_ip_prefix.s_addr == (key.dest_ip_netmask.s_addr & dest_ip.s_addr))
        {
            if (key.dest_ip_netmask.s_addr > max_sub_net.s_addr)
            {
                next_hop.s_addr = item.next_hop.s_addr;
                max_sub_net.s_addr = key.dest_ip_netmask.s_addr;
            }
        }
    }
    if (iter == this->route_table.end() && max_sub_net.s_addr == 0)
    {
        dbg_printf("[ERROR][RouteTable::query_next_hop()] "
                   "The IP %s dosn't in route table.\n",
                   ip_addr_to_str(dest_ip, ip_str));
        next_hop.s_addr = UINT32_MAX;
    }
    else
    {
        dbg_printf("[INFO][RouteTable::query_next_hop()] "
                   "The IP %s has next hop %s.\n",
                   ip_addr_to_str(dest_ip, ip_str),
                   ip_addr_to_str(next_hop, next_hop_str));
    }
    this->route_table_mutex.unlock_shared();
    return next_hop;
}
int RouteTable::set_route_item(ip_addr_t dest_ip, ip_addr_t subnet_mask, ip_addr_t next_hop, int distance)
{
    RouteKey key(dest_ip, subnet_mask);
    RouteItem item(next_hop, distance);
    char ip_str[IP_STR_LEN];
    char next_hop_str[IP_STR_LEN];
    dbg_printf("[INFO][RouteTable::set_route_item()] "
               "Insert the route item with IP %s and next hop IP %s.\n",
               ip_addr_to_str(dest_ip, ip_str),
               ip_addr_to_str(next_hop, next_hop_str));
    if (item.distance == MAX_RIP_DISTANCE)
    {
        item.invalid_timer = 0;
        item.valid = false;
    }
    this->route_table_mutex.lock();
    this->route_table[key] = item;
    this->route_table_mutex.unlock();
    return 0;
}
int RouteTable::delete_route_item(const RouteKey &key)
{
    char ip_str[IP_STR_LEN];
    dbg_printf("[INFO][RouteTable::delete_route_item()] "
               "Delete the route item with IP prefix %s.\n",
               ip_addr_to_str(key.dest_ip_prefix, ip_str));
    this->route_table_mutex.lock();
    if (this->route_table.find(key) == this->route_table.end())
    {
        dbg_printf("[ERROR][RouteTable::delete_route_item()] "
                   "The route item with IP prefix %s does not exist.\n",
                   ip_addr_to_str(key.dest_ip_prefix, ip_str));
        this->route_table_mutex.unlock();
        return -1;
    }
    this->route_table.erase(key);
    this->route_table_mutex.unlock();
    this->printRouteTable(STDERR_FILENO);
    return 0;
}
/**
 * RIP Packet
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
void *RouteTable::construct_RIP_request(void *buf, size_t *len, ip_addr_t ip, ip_addr_t netmask)
{
    size_t pkt_len = (RIP_HDR_SIZE + RIP_ENTRY_SIZE);
    *len = pkt_len;
    memset(buf, 0, pkt_len);
    struct RIPHead *hdr = (struct RIPHead *)malloc(RIP_HDR_SIZE);
    hdr->command = RIP_REQUEST_CMD;
    hdr->must_be_zero = 0;
    hdr->version = MY_RIP_VERSION;
    memcpy(buf, hdr, RIP_HDR_SIZE);
    free(hdr);
    struct RIPEntry *entry = (struct RIPEntry *)malloc(RIP_ENTRY_SIZE);
    entry->address_family = RIP_AFI_REQ;
    entry->ip_addr.s_addr = ip.s_addr;
    entry->subnet_mask.s_addr = netmask.s_addr;
    entry->metric = 0;
    entry->must_be_zero_1 = 0;
    entry->next_hop_ip.s_addr = 0;
    memcpy((u_char *)buf + RIP_HDR_SIZE, entry, RIP_ENTRY_SIZE);
    free(entry);
    return buf;
}
void *RouteTable::construct_RIP_response(void *buf, size_t *len, ip_addr_t ip, ip_addr_t netmask)
{
    this->route_table_mutex.lock_shared();
    size_t route_table_nums = this->route_table.size();
    size_t pkt_len = RIP_HDR_SIZE + (route_table_nums + 1) * RIP_ENTRY_SIZE;
    *len = pkt_len;

    memset(buf, 0, pkt_len);
    struct RIPHead *hdr = (struct RIPHead *)malloc(RIP_HDR_SIZE);
    hdr->command = RIP_REPLY_CMD;
    hdr->must_be_zero = 0;
    hdr->version = MY_RIP_VERSION;
    memcpy(buf, hdr, RIP_HDR_SIZE);
    free(hdr);
    struct RIPEntry *entry = (struct RIPEntry *)malloc(RIP_ENTRY_SIZE);
    entry->address_family = RIP_AFR_IP;
    entry->ip_addr.s_addr = ip.s_addr;
    entry->subnet_mask.s_addr = netmask.s_addr;
    entry->metric = 0;
    entry->must_be_zero_1 = 0;
    entry->next_hop_ip.s_addr = 0;
    memcpy((u_char *)buf + RIP_HDR_SIZE, entry, RIP_ENTRY_SIZE);
    free(entry);

    int cnt = 1;
    for (auto iter : this->route_table)
    {
        RouteKey key = iter.first;
        RouteItem item = iter.second;
        struct RIPEntry *entry = (struct RIPEntry *)malloc(RIP_ENTRY_SIZE);
        entry->address_family = RIP_AFR_IP;
        entry->ip_addr.s_addr = key.dest_ip_prefix.s_addr;
        entry->subnet_mask.s_addr = key.dest_ip_netmask.s_addr;
        entry->metric = item.distance;
        entry->must_be_zero_1 = 0;
        entry->next_hop_ip.s_addr = item.next_hop.s_addr;
        memcpy((u_char *)buf + RIP_HDR_SIZE + cnt * RIP_ENTRY_SIZE, entry, RIP_ENTRY_SIZE);
        free(entry);
        cnt++;
    }
    this->route_table_mutex.unlock_shared();
    return buf;
}
void RouteTable::printRouteTable(int verbose)
{
    if (verbose == STDOUT_FILENO)
    {
        printbars(127);
        printf("| %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s |\n", "Destination IP", "Net Mask", "Next Hop IP", "Distance", "Invalid Timer", "Flush Timer", "Valid");
        printbars(127);
        this->route_table_mutex.lock_shared();
        if (this->route_table.empty())
        {
            printf("The route Table is empty.\n");
            this->route_table_mutex.unlock_shared();
            return;
        }
        for (auto route_itr : this->route_table)
        {
            RouteKey key = route_itr.first;
            RouteItem item = route_itr.second;
            char ip_dst_str[IP_STR_LEN];
            ip_addr_to_str(key.dest_ip_prefix, ip_dst_str);
            char ip_next_hop_str[IP_STR_LEN];
            ip_addr_to_str(item.next_hop, ip_next_hop_str);
            char ip_subnet_str[IP_STR_LEN];
            ip_addr_to_str(key.dest_ip_netmask, ip_subnet_str);
            printf("| %-15s | %-15s | %-15s | %-15d | %-15d | %-15d | %-15d |\n",
                   ip_dst_str, ip_subnet_str, ip_next_hop_str, item.distance, item.invalid_timer, item.flush_timer, item.valid);
            printbars(127);
        }
        this->route_table_mutex.unlock_shared();
        printf("\n");
    }
    else if (verbose == STDERR_FILENO)
    {
        dbg_printbars(127);
        dbg_printf("| %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s |\n", "Destination IP", "Net Mask", "Next Hop IP", "Distance", "Invalid Timer", "Flush Timer", "Valid");
        dbg_printbars(127);
        this->route_table_mutex.lock_shared();
        if (this->route_table.empty())
        {
            dbg_printf("The route Table is empty.\n");
            this->route_table_mutex.unlock_shared();
            return;
        }
        for (auto route_itr : this->route_table)
        {
            RouteKey key = route_itr.first;
            RouteItem item = route_itr.second;
            char ip_dst_str[IP_STR_LEN];
            ip_addr_to_str(key.dest_ip_prefix, ip_dst_str);
            char ip_next_hop_str[IP_STR_LEN];
            ip_addr_to_str(item.next_hop, ip_next_hop_str);
            char ip_subnet_str[IP_STR_LEN];
            ip_addr_to_str(key.dest_ip_netmask, ip_subnet_str);
            dbg_printf("| %-15s | %-15s | %-15s | %-15d | %-15d | %-15d | %-15d |\n",
                       ip_dst_str, ip_subnet_str, ip_next_hop_str, item.distance, item.invalid_timer, item.flush_timer, item.valid);
            dbg_printbars(127);
        }
        this->route_table_mutex.unlock_shared();
        dbg_printf("\n");
    }
}

void RouteTable::route_table_update()
{
    std::vector<RouteKey> to_delete;
    //this->printRouteTable(STDOUT_FILENO);
    this->route_table_mutex.lock_shared();
    if (this->route_table.empty())
    {
        this->route_table_mutex.unlock_shared();
        return;
    }
    for (auto iter : this->route_table)
    {
        RouteKey key = iter.first;
        RouteItem item = iter.second;

        if (item.valid == true)
        {
            item.invalid_timer--;
            if (item.invalid_timer == 0)
            {
                item.valid = false;
                item.distance = RIP_MAX_DISTANCE;
            }
        }
        else
        {
            item.flush_timer--;
            if (item.flush_timer == 0)
            {
                char ip_dst[IP_STR_LEN];
                char ip_next_hop[IP_STR_LEN];
                ip_addr_to_str(key.dest_ip_prefix, ip_dst);
                ip_addr_to_str(item.next_hop, ip_next_hop);
                dbg_printf("[INFO][RouteTable::route_table_update()] "
                       "The route item with dst_ip %s and next_hop %s has been out of time. Delete it.\n",
                       ip_dst,
                       ip_next_hop);
                to_delete.push_back(key);
                continue;
            }
        }
        this->route_table_mutex.unlock_shared();
        this->route_table_mutex.lock();
        this->route_table[key] = item;
        this->route_table_mutex.unlock();
        this->route_table_mutex.lock_shared();
    }
    this->route_table_mutex.unlock_shared();
    for (auto key : to_delete)
    {
        this->delete_route_item(key);
    }
}

void RouteTable::refreshRouteItem(ip_addr_t ip, ip_addr_t netmask, int distance)
{
    for (auto iter : this->route_table)
    {
        RouteKey key = iter.first;
        RouteItem item = iter.second;
        if (in_same_subnet(ip, key.dest_ip_prefix, key.dest_ip_netmask) && key.dest_ip_netmask.s_addr == netmask.s_addr)
        {
                item.flush_timer = RIP_FLUSH_TIME;
                item.invalid_timer = RIP_INVALID_TIME;
                item.valid = true;
                item.distance = distance;
                this->route_table_mutex.lock();
                this->route_table[key] = item;
                this->route_table_mutex.unlock();
                return;
            }
            
    }
}

int sendRIPRequest(DeviceManager *manager, Device *dev)
{
    void *buf;
    size_t len;
    buf = malloc(RIP_HDR_SIZE + RIP_ENTRY_SIZE);
    manager->route_table.construct_RIP_request(buf,
                                               &len,
                                               dev->getDeviceIP(),
                                               dev->getDeviceSubnetMask());
    void *broad_cast_mac = malloc(ETHER_ADDR_LEN);
    memset(broad_cast_mac, 0xff, ETHER_ADDR_LEN);
    dbg_printf("[INFO][sendRIPRequest()] Device %s send RIP request.\n", dev->getDeviceName());
    int ret = dev->sendFrame(buf, (int)len, MY_RIP_PROTO, broad_cast_mac);
    free(buf);
    free(broad_cast_mac);
    return ret;
}
int sendRIPReply(DeviceManager *manager, Device *dev)
{
    void *buf;
    size_t len = (manager->route_table.route_table.size() + 1) * RIP_ENTRY_SIZE + RIP_HDR_SIZE;
    buf = (u_char *)malloc(len);
    manager->route_table.construct_RIP_response(buf,
                                                &len,
                                                dev->getDeviceIP(),
                                                dev->getDeviceSubnetMask());
    void *broad_cast_mac = malloc(ETHER_ADDR_LEN);
    memset(broad_cast_mac, 0xff, ETHER_ADDR_LEN);
    int ret = dev->sendFrame(buf, (int)len, MY_RIP_PROTO, broad_cast_mac);
    dbg_printf("[INFO][sendRIPReply()] Device %s send RIP reply.\n", dev->getDeviceName());
    free(buf);
    free(broad_cast_mac);
    return ret;
}
int handleRIPRequest(DeviceManager *manager, Device *dev, void *pkt, int len)
{
    dbg_printf("[INFO][handleRIPRequest()]\n");
    struct RIPEntry sender_info;
    memcpy(&sender_info, (u_char *)pkt + RIP_HDR_SIZE, RIP_ENTRY_SIZE);
    // 如果有来自某一个 IP 地址的 RIP 回复，说明该设备还是活跃的，于是将其刷新为活跃状态
    if (manager->getDeviceByIPPrefix(sender_info.ip_addr) != nullptr)
        manager->route_table.refreshRouteItem(sender_info.ip_addr,sender_info.subnet_mask, 0);
    return sendRIPReply(manager, dev);
}
int handleRIPReply(DeviceManager *manager, Device *dev, void *pkt, int len)
{
    dbg_printf("[INFO][handleRIPReply()]\n");
    int num_router_items = (len - RIP_HDR_SIZE) / RIP_ENTRY_SIZE - 1;
    struct RIPEntry sender_info;
    memcpy(&sender_info, (u_char *)pkt + RIP_HDR_SIZE, RIP_ENTRY_SIZE);
    char sender_ip_str[IP_STR_LEN];
    ip_addr_to_str(sender_info.ip_addr, sender_ip_str);

    // 如果有来自某一个 IP 地址的 RIP 回复，说明该设备还是活跃的，于是将其刷新为活跃状态
    if (manager->getDeviceByIPPrefix(sender_info.ip_addr) != nullptr)
    {
        manager->route_table.refreshRouteItem(sender_info.ip_addr,sender_info.subnet_mask, 0);
    }
    // 遍历接下来的 RIP 表项
    for (int i = 0; i < num_router_items; ++i)
    {
        struct RIPEntry entry;
        memcpy(&entry, (u_char *)pkt + RIP_HDR_SIZE + (i + 1) * RIP_ENTRY_SIZE, RIP_ENTRY_SIZE);

        // 查看该表项是否在路由表中
        bool found = false;
        for (auto iter : manager->route_table.route_table)
        {
            RouteKey key = iter.first;
            RouteItem item = iter.second;
            // 如果该表项在路由表中
            if ((entry.ip_addr.s_addr & entry.subnet_mask.s_addr) ==
                (key.dest_ip_prefix.s_addr & key.dest_ip_netmask.s_addr))
            {
                found = true;
                // 如果该表项的 next_hop 在本机中，则返回，防止回环
                if (manager->getDeviceByIP(entry.next_hop_ip) != nullptr)
                    break;
                // 如果该表项的 next_hop 等于发送该 RIP request 的设备的 IP，需要替换该表项（更新状态）
                if (item.next_hop.s_addr == sender_info.ip_addr.s_addr)
                {
                    int dis = entry.metric >= RIP_MAX_DISTANCE ? RIP_MAX_DISTANCE : entry.metric + 1;
                    if (entry.metric == RIP_MAX_DISTANCE && item.distance == RIP_MAX_DISTANCE)
                        break;
                    manager->route_table.set_route_item(
                        entry.ip_addr,
                        entry.subnet_mask,
                        item.next_hop,
                        dis);
                }
                if (item.distance > entry.metric + 1 && entry.metric != RIP_MAX_DISTANCE)
                {
                    manager->route_table.set_route_item(
                        entry.ip_addr,
                        entry.subnet_mask,
                        sender_info.ip_addr,
                        entry.metric + 1);
                    manager->printRouteTable(STDERR_FILENO);
                }
                break;
            }
        }
        // 如果该表项不在路由表中
        if (found == false && entry.metric != RIP_MAX_DISTANCE && manager->getDeviceByIP(entry.next_hop_ip) == nullptr)
        {
            int metric;
            ip_addr_t next_hop;
            // 如果这是与设备直接相连的网络，只是被重新激活了，那需要将距离设置为 0，并将 nex_hop_ip 设为 0.0.0.0
            if( manager->getDeviceByIPPrefix(entry.ip_addr)!=nullptr)
            {
                metric=0;
                next_hop.s_addr=0;
            }
            else
            {
                metric=entry.metric+1;
                next_hop.s_addr=sender_info.ip_addr.s_addr;
            }
            manager->route_table.set_route_item(
                entry.ip_addr,
                entry.subnet_mask,
                next_hop,
                metric);
            manager->printRouteTable(STDERR_FILENO);
        }
    }
    return 0;
}

void DeviceManager::routeTableUpdate()
{
    while (this->is_run.load())
    {
        if (this->update_timer == 0)
        {
            for (auto dev : this->devices_list_)
            {
                std::thread t(sendRIPRequest, this, dev);
                t.detach();
            }
            this->update_timer = RIP_UPDATE_TIME;
        }
        this->update_timer--;
        this->route_table.route_table_update();
        sleep(TIMER_TICKS);
    }
    dbg_printf("[INFO][DeviceManager::routeTableUpdate()] Exit.\n");
    return;
}
