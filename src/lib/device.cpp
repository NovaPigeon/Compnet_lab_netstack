/**
 * @file device.cpp
 * @brief File supports network device management and 
 * sending/receiving Ethernet II frames.
 */

#include "../include/device.h"
#include "../include/type.h"
#include "../include/debug.h"
#include "../include/utils.h"
#include "../include/ARP.h"
#include "../include/IP.h"
#include <cstring>
#include <string.h>
#include <cstdio>
#include <pcap/pcap.h>
#include <linux/if_packet.h>
#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>

#define DEVICE_TIME_OUT 1000
#define MAX_SNAPLEN (1<<16)

Device::Device(char *dev_name,
       u_char *mac,
       dev_id id,
       DeviceManager *manager)
{

    this->dev_name_=dev_name;

    memcpy(this->mac_,mac,ETHER_ADDR_LEN);
    this->id_=id;
    this->manager_=manager;
    memset(this->ebuf_,0,PCAP_ERRBUF_SIZE);

    /* Get the correspond IP of the device. */
    struct ifaddrs *ifa_list=NULL;
    if(getifaddrs(&ifa_list)==-1)
    {
        dbg_printf("[ERROR][Device::Device()] getifaffrs() failed.\n");
        exit(-1);
    }
    struct ifaddrs *ifa_entry=ifa_list;
    while(ifa_entry!=NULL)
    {
        if(ifa_entry->ifa_addr->sa_family==AF_INET && //IPv4
           strcmp(ifa_entry->ifa_name,this->dev_name_)==0 //correspond device name
        ) 
        {
            this->device_ip_=((sockaddr_in *)(ifa_entry->ifa_addr))->sin_addr;
            this->subnet_mask_=((sockaddr_in *)(ifa_entry->ifa_netmask))->sin_addr;
            
            char subnet_mask_str[IP_STR_LEN];
            char dev_ip_str[IP_STR_LEN];
            memset(subnet_mask_str,IP_STR_LEN,0);
            memset(dev_ip_str,IP_STR_LEN,0);
            ip_addr_to_str(subnet_mask_,subnet_mask_str);
            ip_addr_to_str(device_ip_,dev_ip_str);
            dbg_printf("[INFO][Device::Device()] "
                       "The IP address of %s is %s, "
                       "subnet mask is %s\n",
                       this->dev_name_, 
                       dev_ip_str,
                       subnet_mask_str);
            break;
        }
        ifa_entry=ifa_entry->ifa_next;
    }
    freeifaddrs(ifa_list);

    this->handle_=pcap_open_live(
        dev_name,
        MAX_SNAPLEN,
        0,
        DEVICE_TIME_OUT,
        this->ebuf_
    );
    
    if(!this->handle_)
    {
        dbg_printf("[ERROR][Device::Device()] pcap_open_live() failed. %s\n",this->ebuf_);
        exit(-1);
    }

    this->is_run.store(true);

    this->receive_frame_thread_=new std::thread(deviceRecvFrame,this);
    this->device_mutex.lock();
    this->receive_call_back_=nullptr;
    this->device_mutex.unlock();
    //this->receive_frame_thread_->detach();
}

Device::~Device()
{
    this->is_run.store(false);
    if(this->handle_!=nullptr)
        pcap_close(this->handle_);
    
    memset(this->ebuf_,0,PCAP_ERRBUF_SIZE);
    free(this->dev_name_);
}

/**
 * @brief Encapsulate some data into an Ethernet II frame and send it.
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac MAC address of the destination.
 * @return 0 on success , -1 on error .
 * @see addDevice
 */
int Device::sendFrame(const void *buf, int len,
              int ethtype, const void *destmac)
{
    dbg_printf("[INFO][Device::sendFrame()] Device %s send ether frame with ethtype 0x%x.\n",
               this->getDeviceName(),
               ethtype);
    /* Check if the params are legal. */
    size_t eth_frame_len = ETHER_HDR_LEN + len + ETHER_CRC_LEN;
    if(eth_frame_len<=0 ||
       eth_frame_len>ETHER_MAX_LEN ||
       ethtype > (1<<16))
    {
        dbg_printf(
            "[Error][Device::sendFrame()]"
            "The params are illegel. "
            "len: %d; "
            "ethtype: 0x%x;\n",
            len,
            ethtype);
        return -1;
    }
    /* Construct the frame. */
    /**
     * The Ethernet II frame format:
     *  ------------------------- ------------------------ --------------------------+
     * | Destination MAC Address | Source MAC Address     | Ethernet Frame Type      |
     * |-------------------------|------------------------|--------------------------|
     * |        6 bytes          |         6 bytes        |        2 bytes           |
     * +-------------------------+------------------------+--------------------------+
     * |         Data (Payload)                                                |
     * |             Variable length (46 to 1500 bytes)                        |
     * +-----------------------------------------------------------------------+
     * | CRC Check Sum - 4 bytes                                               |
     * +-----------------------------------------------------------------------+
     */
    u_char *frame=(u_char *)malloc(eth_frame_len);
    uint16_t ethtype_to_net=htons((uint16_t)ethtype);
    memcpy(frame,destmac,ETHER_ADDR_LEN);
    memcpy(frame+ETHER_ADDR_LEN,this->mac_,ETHER_ADDR_LEN);
    memcpy(frame+ETHER_ADDR_LEN*2,&ethtype_to_net,ETHER_TYPE_LEN);
    memcpy(frame+ETHER_HDR_LEN,buf,len);

    /// @todo: check sum 
    for(int i=eth_frame_len-ETHER_CRC_LEN;i<eth_frame_len;++i)
    {
        frame[i]=0;
    }

    int is_send_success=pcap_sendpacket(this->handle_,frame,eth_frame_len);

    u_char *destmac_=(u_char*)destmac;
    free(frame);
    if(is_send_success==-1)
    {
        dbg_printf(
            "[Error][Device::sendFrame()]"
            "Packet send error."
            "device name: %s; "
            "destination: %02x:%02x:%02x:%02x:%02x:%02x; "
            "len: %d; "
            "ethtype: 0x%x;\n",
            this->dev_name_,
            destmac_[0],
            destmac_[1],
            destmac_[2],
            destmac_[3],
            destmac_[4],
            destmac_[5],
            len,
            ethtype);
        return -1;
    }
    return 0;
}

/**
 * @brief Register a callback function to be called each time an
 * Ethernet II frame was received .
 *
 * @param callback the callback function .
 * @return 0 on success , -1 on error .
 * @see frameReceiveCallback
 */
int Device::setFrameReceiveCallback(frameReceiveCallback callback)
{
    this->device_mutex.lock();
    this->receive_call_back_=callback;
    this->device_mutex.unlock();

    return 0;
}


/**
 * @brief Get the name of the device.
 * @return The name of the device.
 */
const char *Device::getDeviceName() const
{
    return (const char *)this->dev_name_;
}
/**
 * @brief Get the ID of the device.
 * @return The ID of the device.
 */
const int Device::getDeviceID() const
{
    return (const int)this->id_;
}

const u_char *Device::getDeviceMac() const
{
    return (const u_char *)this->mac_;
}

int Device::stopRecv()
{
    if(this->handle_)
    {
        dbg_printf("[INFO][Device::stopRecv()] Device %s stop receive.\n",this->dev_name_);
        pcap_breakloop(this->handle_);
        this->setFrameReceiveCallback(nullptr);
        return 0;
    }
    return -1;
}

ip_addr_t Device::getDeviceIP() const
{
    return this->device_ip_;
}
ip_addr_t Device::getDeviceSubnetMask() const
{
    return this->subnet_mask_;
}

std::string Device::arpQueryMac(ip_addr_t ip)
{
    return this->manager_->arpQueryMac(ip);
}
int Device::arpInsert(ip_addr_t ip, std::string mac)
{
    return this->manager_->arpInsert(ip,mac);
}

DeviceManager::DeviceManager()
{
    char ebuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, ebuf) != 0)
    {
        dbg_printf("[ERROR][DeviceManager::DeviceManager()]"
                   " pcap_init error: %s\n",
                   ebuf);
    }
    this->update_timer=RIP_UPDATE_TIME;
    this->route_thread=new std::thread(&DeviceManager::routeTableUpdate,this);
    this->is_run.store(true);
    this->route_thread->detach();
    this->IPcallback=nullptr;
    this->route_table.manager=(void *)this;
}
DeviceManager::~DeviceManager()
{
    this->manager_mutex.lock();
    this->is_run.store(false);
    if(this->route_thread->joinable())
        this->route_thread->join();
    //delete this->route_thread;
    while(!this->devices_list_.empty())
    {
        delete this->devices_list_.back();
        this->devices_list_.pop_back();
    }
    this->manager_mutex.unlock();
}

/**
 * Add a device to the library for sending/receiving packets.
 *
 * @param device Name of network device to send/receive packet on.
 * @return A non-negative-device-ID on success , -1 on error.
 */
dev_id DeviceManager::addDevice(const char *dev_name)
{
    char ebuf[PCAP_ERRBUF_SIZE];

    /* Adding device already in the manager is not allowed */
    if(this->findDevice(dev_name)!=nullptr)
    {
        dbg_printf("[ERROR][Device::addDevice()] The device added exists.\n");
        return -1;
    }

    pcap_if_t *devs;
    
    if(pcap_findalldevs(&devs,ebuf)==-1)
    {
        dbg_printf("[ERROR][Device::addDevice()] %s\n",ebuf);
        return -1;
    }

    bool is_found=false;

    /* The added device should be legal,
    that is, it should be searchable by pcap_findalldevs. */
    for(pcap_if_t *dev=devs;dev!=nullptr;dev=dev->next)
    {
        if(strcmp(dev->name,dev_name)==0)
        {
            for(pcap_addr *a=dev->addresses;a;a=a->next)
            {
                if(a->addr && 
                   a->addr->sa_family==AF_PACKET &&
                   ((sockaddr_ll *)a->addr)->sll_hatype==ARPHRD_ETHER)
                   {
                        is_found=true;
                        goto FOUND;
                   }
            }
        }
    }
    pcap_freealldevs(devs);
    dbg_printf("[ERROR][Device::addDevice()] "
               "%s is not a valid device.\n",
               dev_name);
    return -1;
FOUND:
    pcap_freealldevs(devs);

    /* Get mac of the device */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        dbg_printf("[ERROR][Device::addDevice()] "
                   "Failed to create socket while getting mac.\n");
        return -1;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
    {
        dbg_printf("[ERROR][Device::addDevice()] "
                   "Failed to retrieve MAC address.\n");
        close(sockfd);
        return -1;
    }
    close(sockfd);
    u_char *mac=(u_char *)malloc(ETHER_ADDR_LEN);
    memcpy(mac,(u_char *)ifr.ifr_hwaddr.sa_data,ETHER_ADDR_LEN);

    /* Open a new device */
    this->manager_mutex.lock();

    dev_id id=this->devices_list_.size();
    char *dev_name_cpy=(char *)malloc(strlen(dev_name)+1);
    memcpy(dev_name_cpy,dev_name,strlen(dev_name)+1);
    
    dbg_printf("[INFO][Device()::addDevice()] "
               "Add device %s, "
               "whose mac address is %02x:%02x:%02x:%02x:%02x:%02x.\n",
               dev_name,
               mac[0],
               mac[1],
               mac[2],
               mac[3],
               mac[4],
               mac[5]);
    
    Device *device=new Device(dev_name_cpy,mac,id,this);
    this->devices_list_.push_back(device);
    char mac_str[MAC_STR_LEN];
    ip_addr_t next_hop;
    next_hop.s_addr=0;
    this->arpInsert(device->getDeviceIP(),std::string(mac_to_str(mac,mac_str)));
    this->route_table.set_route_item(device->getDeviceIP(),
                                        device->getDeviceSubnetMask(),
                                        next_hop,
                                        0);
    free(mac);
    this->manager_mutex.unlock();
    return id;
}

/**
 * Find a device added by ‘addDevice ‘.
 *
 * @param dev_name device Name of the network device .
 * @return A pointer to the device holding the ID, nullptr  if no such device
 * was found .
 */
Device *DeviceManager::findDevice(const char *dev_name)
{
    this->manager_mutex.lock_shared();
    dev_id n_devices=this->devices_list_.size();
    for(dev_id i=0;i<n_devices;++i)
    {
        if(strcmp(devices_list_[i]->getDeviceName(),dev_name)==0)
        {
            int id=devices_list_[i]->getDeviceID();
            dbg_printf("[INFO][Device::findDevice()] "
                       "Device %s found with id %d.\n", 
            dev_name, 
            id);
            this->manager_mutex.unlock_shared();
            return  devices_list_[i];
        }
    }
    dbg_printf("[ERROR][Device::findDevice()] "
               "Device %s not found.\n",
               dev_name);
    this->manager_mutex.unlock_shared();
    return nullptr;
}

Device *DeviceManager::getDeviceByIPPrefix(ip_addr_t ip)
{
    this->manager_mutex.lock_shared();
    dev_id n_devices = this->devices_list_.size();
    char ip_str[IP_STR_LEN];
    ip_addr_t max_subnet;
    max_subnet.s_addr=0;
    int id=-1;
    for (dev_id i = 0; i < n_devices; ++i)
    {
        if (in_same_subnet(ip,devices_list_[i]->getDeviceIP(),devices_list_[i]->getDeviceSubnetMask()))
        {
            if(devices_list_[i]->getDeviceSubnetMask().s_addr>max_subnet.s_addr)
            {
                max_subnet.s_addr=devices_list_[i]->getDeviceSubnetMask().s_addr;
                id=i;
            }
        }
    }
    if(id!=-1)
    {
        const char *dev_name = devices_list_[id]->getDeviceName();
        dbg_printf("[INFO][Device::getDeviceByIPPrefix(ip)] "
                   "Device %s found with id %d and ip %s.\n",
                   dev_name,
                   id,
                   ip_addr_to_str(ip, ip_str));
        this->manager_mutex.unlock_shared();
        return devices_list_[id];
    }
    dbg_printf("[ERROR][Device::getDeviceByIPPrefix(ip)] "
               "Device with IP %s not found.\n",
               ip_addr_to_str(ip, ip_str));
    this->manager_mutex.unlock_shared();
    return nullptr;
}

Device *DeviceManager::getDeviceByIP(ip_addr_t ip)
{
    this->manager_mutex.lock_shared();
    dev_id n_devices = this->devices_list_.size();
    char ip_str[IP_STR_LEN];
    for (dev_id i = 0; i < n_devices; ++i)
    {
        if (devices_list_[i]->getDeviceIP().s_addr==ip.s_addr)
        {
            int id = devices_list_[i]->getDeviceID();
            const char *dev_name = devices_list_[i]->getDeviceName();
            dbg_printf("[INFO][Device::getDeviceByIP(ip)] "
                       "Device %s found with id %d and ip %s.\n",
                       dev_name,
                       id,
                       ip_addr_to_str(ip, ip_str));
            this->manager_mutex.unlock_shared();
            return devices_list_[i];
        }
    }
    dbg_printf("[ERROR][Device::getDeviceByIP(ip)] "
               "Device with IP %s not found.\n",
               ip_addr_to_str(ip, ip_str));
    this->manager_mutex.unlock_shared();
    return nullptr;
}

/**
 * Find a device added by ‘addDevice ‘.
 *
 * @param id device id of the network device .
 * @return A pointer to the device holding the ID, nullptr if no such device
 * was found .
 *
Device *DeviceManager::findDevice(dev_id id)
{   
    this->manager_mutex.lock_shared();
    if(id<0 || id>=this->devices_list_.size())
    {
        dbg_printf("[ERROR][Device::findDevice()] "
                   "Device %d not found.\n",
                   id);
        this->manager_mutex.unlock_shared();
        return nullptr;
    }
    Device *dev = this->devices_list_[id];
    this->manager_mutex.unlock_shared();
    return dev;
}*/

Device *DeviceManager::getDevice(dev_id id)
{
    if(id<0 || id>=this->devices_list_.size())
    {
        dbg_printf("[ERROR][DeviceManager::getDevice()] Invalid device ID: %d.\n",id);
        return nullptr;
    }
    return this->devices_list_[id];
}

void DeviceManager::printAllValidDevice() const
{
    pcap_if_t *devs;
    char ebuf[PCAP_ERRBUF_SIZE];
    int ret=pcap_findalldevs(&devs,ebuf);
    printf("All valid devices below: \n");
    for(auto *p=devs;p;p=p->next)
    {
        printf("device %s: %s\n", p->name, p->description);
        for (auto *a = p->addresses; a; a = a->next)
        {
            if (a->addr->sa_family == AF_PACKET)
            {
                struct sockaddr_ll *s = (struct sockaddr_ll *)a->addr;
                if (s->sll_hatype == ARPHRD_ETHER)
                {
                    printf("\tether: ");
                    for (int i = 0; i < s->sll_halen; i++)
                        printf("%02X%c", s->sll_addr[i], i + 1 < s->sll_halen ? ':' : '\n');
                }
            }
        }
        IP_Info info = get_ip_addr_at_host(p->name);
        if(info.found==true)
        {
            printf("\tinet: ");
            char ip_str[IP_STR_LEN];
            ip_addr_to_str(info.ip,ip_str);
            printf("%s\n",ip_str);
            char netmask_str[IP_STR_LEN];
            ip_addr_to_str(info.netmask, netmask_str);
            printf("\tnetmask: ");
            printf("%s\n", netmask_str);
        }
    }
    pcap_freealldevs(devs);
}

void DeviceManager::printAllAddedDevice() const
{
    int n_devices=this->devices_list_.size();
    if(n_devices!=0)
        printf("All added devices below: \n");
    else
        printf("No device added.\n");
    for(int i=0;i<n_devices;++i)
    {
        Device *dev=this->devices_list_[i];
        dev_id id=dev->getDeviceID();
        const char *name=dev->getDeviceName();
        const u_char *mac=dev->getDeviceMac();
        char mac_str[MAC_STR_LEN];
        char ip_str[IP_STR_LEN];
        char netmask_str[IP_STR_LEN];
        printf("device %d %s: \n\tether %s\n\tinet: %s\n\tnetmask: %s\n",
                id,
                name,
                mac_to_str(mac,mac_str),
                ip_addr_to_str(dev->getDeviceIP(),ip_str),
                ip_addr_to_str(dev->getDeviceSubnetMask(),netmask_str));
    }
}

void DeviceManager::printARPCache() const
{
    printf("[INFO][DeviceManager::printARPCache()]\n");
    printbars(67);
    printf("| %-30s | %-30s |\n","IP","MAC");
    printbars(67);
    for(auto arp_entry:this->arp_cache)
    {
        char ip_str[IP_STR_LEN];
        ip_addr_to_str(arp_entry.first,ip_str);
        printf("| %-30s | %-30s |\n", ip_str, arp_entry.second.c_str());
        printbars(67);
    }
}

void DeviceManager::printRouteTable(int verbose)
{
    if(verbose==STDOUT_FILENO)
        printf("[INFO][DeviceManager::printRouteTable()]\n");
    else if(verbose==STDERR_FILENO)
        dbg_printf("[INFO][DeviceManager::printRouteTable()]\n");
    this->route_table.printRouteTable(verbose);
}

std::string DeviceManager::arpQueryMac(ip_addr_t ip)
{
    char ip_str[IP_STR_LEN];
    ip_addr_to_str(ip, ip_str);
    //this->arp_cache_mutex.lock_shared();
    if(this->arp_cache.find(ip)!=this->arp_cache.end())
    {
        std::string mac=this->arp_cache.at(ip);
        dbg_printf("[INFO][DeviceManager::arpQueryMac()] "
                   "Successfully query IP %s at arp_cache, "
                   "return MAC %s.\n",
                   ip_str,
                   mac.c_str()
                   );
        //this->arp_cache_mutex.unlock_shared();
        return mac;
    }
    else
    {
        dbg_printf("[ERROR][DeviceManager::arpQueryMac()] "
                   "IP %s is not at arp_cache. I will send an ARP request.\n",
                   ip_str);
        for(auto dev:this->devices_list_)
            sendARPRequest(dev,ip);
        int timer=0;
        while(true)
        {
            sleep(1);
            timer+=1;
            if(timer>=ARP_WAIT_TIME)
                throw "ARP_OUT_OF_TIME";
            if(this->arp_cache.find(ip)!=this->arp_cache.end())
            {
                std::string mac=this->arp_cache.at(ip);
                //this->arp_cache_mutex.unlock_shared();
                return mac;
            }
        }
    };
}

int DeviceManager::arpInsert(ip_addr_t ip, std::string mac)
{
    char ip_str[IP_STR_LEN];
    ip_addr_to_str(ip, ip_str);
    this->arp_cache_mutex.lock();
    if (this->arp_cache.find(ip) != this->arp_cache.end())
    {
        dbg_printf("[ERROR][DeviceManager::arpInsert()] "
                   "IP %s is already in arp_cache.\n",
                   ip_str);
        this->arp_cache_mutex.unlock();
        return -1;
    }
    else
    {
        dbg_printf("[INFO][DeviceManager::arpInsert()] "
                   "Insert entry with IP %s and MAC %s in the arp_cache.\n",
                   ip_str,
                   mac.c_str());
        this->arp_cache[ip]=mac;
        this->arp_cache_mutex.unlock();
        //this->printARPCache();
        return 0;
    }
}

int DeviceManager::arpDelete(ip_addr_t ip,ip_addr_t netmask)
{
    char ip_str[IP_STR_LEN];
    //this->arp_cache_mutex.lock();
    bool found=false;
    for(auto entry: this->arp_cache)
    {
        if(in_same_subnet(ip,entry.first,netmask))
        {
            if(this->getDeviceByIP(entry.first)==nullptr)
            {
                found=true;
                dbg_printf("[INFO][DeviceManager::arpDelete()] "
                           "Delete entry with IP %s in the arp_cache.\n",
                           ip_addr_to_str(entry.first, ip_str));
                this->arp_cache.erase(ip);
                //this->arp_cache_mutex.unlock();
            }
        }
    }
    if(found)
    {
        dbg_printf("[ERROR][DeviceManager::arpDelete()] "
                   "IP %s is not in arp_cache.\n",
                   ip_str);
        //this->arp_cache_mutex.unlock();
        return -1;
    }
    return 0;
}

void deviceRecvPcapHandler(u_char *args, const pcap_pkthdr *head, const u_char *packet)
{
    Device *dev = reinterpret_cast<Device *>(args);
    if (dev->receive_call_back_ != nullptr)
    {
        if (dev->receive_call_back_(packet, head->caplen, dev->id_) == -1)
            pcap_breakloop(dev->handle_);
    }
    if(dev->is_run.load()==false)
    {
        pcap_breakloop(dev->handle_);
        return;
    }
    /* Obtain the componets of a Ethernet II frame. */
    u_char src_mac[ETHER_ADDR_LEN];
    u_char dst_mac[ETHER_ADDR_LEN];
    uint64_t check_sum = 0;
    memcpy(dst_mac, packet, ETHER_ADDR_LEN);
    memcpy(src_mac, packet + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    uint16_t ethtype = ntohs(*(uint16_t *)(packet + ETHER_ADDR_LEN * 2));
    size_t payload_len = head->caplen - ETHER_CRC_LEN - ETHER_HDR_LEN;
    u_char *payload = (u_char *)malloc(payload_len);
    memset(payload, 0, payload_len);
    memcpy(payload, packet + ETHER_HDR_LEN, payload_len);

    char src_mac_str[MAC_STR_LEN];
    std::string src_mac_str_=mac_to_str(src_mac,src_mac_str);
    char dst_mac_str[MAC_STR_LEN];
    std::string dst_mac_str_ = mac_to_str(dst_mac, dst_mac_str);
    char dev_mac_str[MAC_STR_LEN];
    std::string dev_mac_str_=mac_to_str(dev->getDeviceMac(),dev_mac_str);
    void *broad_cast_mac = malloc(ETHER_ADDR_LEN);
    memset(broad_cast_mac, 0xff, ETHER_ADDR_LEN);

    dbg_printf("\n[INFO][deviceRecvPcapHandler()] "
               "Device %s with mac %s capture an Ethernet frame from %s to %s with ETHERTYPE 0x%04x.\n",
               dev->getDeviceName(),
               dev_mac_str,
               src_mac_str,
               dst_mac_str,
               ethtype);
    if (head->caplen != head->len)
    {
        dbg_printf("[ERROR][deviceRecvPcapHandler()] Packet loss something.\n");
        return;
    }
    if(src_mac_str_==dev_mac_str_ )
    {
        dbg_printf("[INFO] The frame is from itself, drop it.\n");
        return;
    }
    bool is_match_dst_mac=(memcmp((void *)dst_mac,broad_cast_mac,ETHER_ADDR_LEN)==0)
                        ||(dst_mac_str_==dev_mac_str_);
    if(!is_match_dst_mac)
    {
        dbg_printf("[INFO] The frame's destination dosn't match, drop it.\n");
        return;
    }

    if(ethtype==ETHERTYPE_ARP)
    {
        ARP_CONTENT content;
        memcpy(&content,payload,sizeof(content));
        content.ARPntohs();
        if(content.hdr.ar_op==ARPOP_REQUEST)
        {
            dbg_printf("[INFO] The frame is ARP request packet.\n");
            handleARPRequest(dev,&content);
        }
        else if(content.hdr.ar_op==ARPOP_REPLY)
        {
            dbg_printf("[INFO] The frame is ARP reply packet.\n");
            handleARPReply(dev,&content);
        }
        else
        {
            dbg_printf("[ERROR] The frame is ARP, but ar_op is unknown.\n");
            return;
        }
    }
    else if(ethtype==MY_RIP_PROTO)
    {
        struct RIPHead *hdr=(struct RIPHead *)malloc(RIP_HDR_SIZE);
        memcpy(hdr,payload,RIP_HDR_SIZE);
        if(hdr->version==MY_RIP_VERSION)
        {
            if(hdr->command==RIP_REQUEST_CMD)
            {
                dbg_printf("[INFO] The frame is RIP request packet.\n");
                handleRIPRequest(dev->manager_,dev,payload,payload_len);
            }
            else if(hdr->command==RIP_REPLY_CMD)
            {
                dbg_printf("[INFO] The frame is RIP response packet.\n");
                handleRIPReply(dev->manager_,dev,payload,payload_len);
            }
        }
        free(hdr);
    }
    else if(ethtype=ETHERTYPE_IP)
    {
        handleIPPacket(dev->manager_,dev,payload,payload_len);
    }
    free(payload);
}
void deviceRecvFrame(Device *dev)
{
    if(dev->handle_==nullptr)
    {
        dbg_printf("[ERROR][deviceRecvFrame()] The handle of device is invalid.\n");
        return;
    }
    
    int ret=pcap_loop(dev->handle_,-1,deviceRecvPcapHandler,(u_char *)dev);
    if(ret==-1)
    {
        dbg_printf("[ERROR][deviceRecvFrame()] pcap_loop error.\n");
        return;
    }
}