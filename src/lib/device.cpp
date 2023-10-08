/**
 * @file device.cpp
 * @brief File supports network device management and 
 * sending/receiving Ethernet II frames.
 */

#include "../include/device.h"
#include "../include/type.h"
#include <cstring>
#include <cstdio>
#include <pcap/pcap.h>
#include <linux/if_packet.h>
#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>

#define DEBUG_ETHERNET

#ifdef DEBUG_ETHERNET
#define dbg_printf(...) printf(__VA_ARGS__)
#else
#define dbg_printf(...)
#endif

#define DEVICE_TIME_OUT 1000
#define MAX_SNAPLEN 1<<16

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

    this->receive_frame_thread_=new std::thread(deviceRecvFrame,this);
    this->device_mutex.lock();
    this->receive_call_back_=nullptr;
    this->device_mutex.unlock();
    this->receive_frame_thread_->detach();
}

Device::~Device()
{
    if(this->handle_!=nullptr)
        pcap_close(this->handle_);
    if(this->receive_frame_thread_->joinable())
        this->receive_frame_thread_->join();
    memset(this->ebuf_,0,PCAP_ERRBUF_SIZE);
    free(this->dev_name_);
}

/**
 * @brief Encapsulate some data into an Ethernet II frame and send it.
 *
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
    /* Check if the params are legal. */
    
    size_t eth_frame_len = ETHER_HDR_LEN + len + ETHER_CRC_LEN;
    if(eth_frame_len<ETHER_MIN_LEN ||
       eth_frame_len>ETHER_MAX_LEN ||
       ethtype > (1<<16))
    {
        dbg_printf(
            "[Error][Device::sendFrame()]"
            "The params are illegel."
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
    for(int i=eth_frame_len-4;i<eth_frame_len;++i)
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

int Device::stopRecv()
{
    if(this->handle_)
    {
        pcap_breakloop(this->handle_);
        this->setFrameReceiveCallback(nullptr);
        if(this->receive_frame_thread_->joinable())
            this->receive_frame_thread_->join();
        return 0;
    }
    return -1;
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
}
DeviceManager::~DeviceManager()
{
    this->manager_mutex.lock();
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

    u_char *mac = reinterpret_cast<u_char *>(ifr.ifr_hwaddr.sa_data);

    /* Open a new device */
    this->manager_mutex.lock();

    dev_id id=this->devices_list_.size();
    char *dev_name_cpy=(char *)malloc(strlen(dev_name)+1);
    memcpy(dev_name_cpy,dev_name,strlen(dev_name)+1);
    Device *device=new Device(dev_name_cpy,mac,id,this);
    this->devices_list_.push_back(device);
    dbg_printf("[INFO][Device()::addDevice] "
               "Add device %s, "
               "whose mac address is %02x:%02x:%02x:%02x:%02x:%02x.\n",
               dev_name,
               mac[0],
               mac[1],
               mac[2],
               mac[3],
               mac[4],
               mac[5]);
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
                       "Device %s found with id %d.", 
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
    printf("All devices below: \n");
    for(auto *p=devs;p;p=p->next)
    {
        dbg_printf("device %s: %s\n", p->name, p->description);
        for (auto *a = p->addresses; a; a = a->next)
        {
            if (a->addr->sa_family == AF_PACKET)
            {
                struct sockaddr_ll *s = (struct sockaddr_ll *)a->addr;
                if (s->sll_hatype == ARPHRD_ETHER)
                {
                    printf("\tMAC: ");
                    for (int i = 0; i < s->sll_halen; i++)
                        printf("%02X%c", s->sll_addr[i], i + 1 < s->sll_halen ? ':' : '\n');
                }
            }
        }
    }
    pcap_freealldevs(devs);
}

void deviceRecvPcapHandler(u_char *args, const pcap_pkthdr *head, const u_char *packet)
{
    Device *dev = reinterpret_cast<Device *>(args);
    if(dev->receive_call_back_!=nullptr)
    {
        if(dev->receive_call_back_(packet,head->caplen,dev->id_)==-1)
            pcap_breakloop(dev->handle_);
    }
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