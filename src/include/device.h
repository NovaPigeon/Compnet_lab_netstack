/**
 * @file device.h 
 * @brief Library supporting network device management.
 */

#ifndef NETSTACK_DEVICE_H
#define NETSTACK_DEVICE_H


#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <thread>
#include <vector>
#include <shared_mutex>
#include <string.h>
#include <map>
#include <atomic>
#include "../include/utils.h"
#include "../include/type.h"
#include "../include/IP.h"
#include "../include/route.h"
#include "../include/TCP.h"

class Device;
class DeviceManager;

/**
 * @class Device
 * @brief Device performs link layer frame IO.
 */
class Device
{
public:
    Device(char *dev_name,
           u_char *mac,
           dev_id id,
           DeviceManager *manager);
    ~Device();
    int sendFrame(const void *buf, int len,
                  int ethtype, const void *destmac);
    int setFrameReceiveCallback(frameReceiveCallback callback);
    int stopRecv();
    const char *getDeviceName() const;
    const int getDeviceID() const;
    const u_char *getDeviceMac() const;
    ip_addr_t getDeviceIP() const;
    ip_addr_t getDeviceSubnetMask() const;
    std::string arpQueryMac(ip_addr_t ip);
    int arpInsert(ip_addr_t ip, std::string mac);
    in_port_t allocPort(in_port_t port);
    int freePort(in_port_t port);

private:
    char *dev_name_;
    char ebuf_[PCAP_ERRBUF_SIZE];
    u_char mac_[ETHER_ADDR_LEN];
    ip_addr_t device_ip_;
    ip_addr_t subnet_mask_;
    pcap_t *handle_;
    DeviceManager *manager_;
    dev_id id_;
    std::atomic<bool> is_run;
    std::thread *receive_frame_thread_;
    frameReceiveCallback receive_call_back_;
    std::shared_timed_mutex device_mutex;

    std::shared_timed_mutex port_mutex;
    bool port_alloc[TCP_MAX_PORT+1];

    friend void deviceRecvFrame(Device *device);
    friend void deviceRecvPcapHandler(u_char *args, const pcap_pkthdr *head, const u_char *packet);
};

/**
 * @class DeviceManager
 * @brief Manage the devices.
 */
class DeviceManager
{
public:
    DeviceManager();
    ~DeviceManager();
    
    dev_id addDevice(const char * dev_name);
    Device *findDevice(const char * dev_name);
    
    Device *getDevice(dev_id id);
    Device *getDeviceByIP(ip_addr_t ip);
    Device *getDeviceByIPPrefix(ip_addr_t ip);
    
    void printAllValidDevice() const;
    void printAllAddedDevice() const;
    void printARPCache() const;
    void printRouteTable(int verbose);
    
    std::string arpQueryMac(ip_addr_t ip);
    int arpInsert(ip_addr_t ip,std::string mac);
    int arpDelete(ip_addr_t ip,ip_addr_t netmask);
    
    int sendIPPacket(ip_addr_t src, ip_addr_t dest, int proto, void *buf, int len);
    int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);
    
    TCB *findSocket(fd_t sockfd);
    TCB *findSocket(sockaddr_in *local_addr,sockaddr_in *remote_addr);
    RouteTable route_table;
    
    std::map<fd_t,ListenerSocket *> listeners;
    std::shared_mutex listners_mutex;
    
    std::map<fd_t,TCB *> sockets;
    std::shared_mutex sockets_mutex;

    std::atomic_bool is_set_up;
    
    bool sockfd_alloc[TCP_MAX_SOCK_FD+1];
    std::shared_mutex sockfds_alloc_mutex;

    bool freeSocket(TCB *sock);
    bool addLisenedSocket(fd_t listen_fd,TCB *sock);

    fd_t allocSocketfd();
    void setUpHost();
private:
    std::vector<Device *> devices_list_;
    std::shared_timed_mutex manager_mutex;
    std::map<ip_addr_t,std::string,ipcmp> arp_cache;
    std::shared_timed_mutex arp_cache_mutex;
    uint64_t update_timer;
    std::thread *route_thread;
    IPPacketReceiveCallback IPcallback;
    std::atomic<bool> is_run;
    void routeTableUpdate();
    friend int handleIPPacket(DeviceManager *manager, Device *dev, void *pkt, int len);
    friend int handleTCPPacket(Device *dev, void *pkt, int len);
};
void deviceRecvFrame(Device *device);
void deviceRecvPcapHandler(u_char *args, const pcap_pkthdr *head, const u_char *packet);

int sendRIPRequest(DeviceManager *manager,Device *dev);
int sendRIPReply(DeviceManager *manager,Device *dev);
int handleRIPRequest(DeviceManager *manager,Device *dev, void *pkt, int len);
int handleRIPReply(DeviceManager *manager, Device *dev, void *pkt, int len);

int handleIPPacket(DeviceManager *manager,Device *dev,void *pkt,int len);
int handleTCPPacket(Device *dev, void *pkt, int len);

dev_id addDevice(const char *dev_name);
Device *findDevice(const char *dev_name);

Device *getDevice(dev_id id);
Device *getDeviceByIP(ip_addr_t ip);
Device *getDeviceByIPPrefix(ip_addr_t ip);

void printAllValidDevice();
void printAllAddedDevice();
void printARPCache();
void printRouteTable(int verbose);

std::string arpQueryMac(ip_addr_t ip);
int arpInsert(ip_addr_t ip, std::string mac);
int arpDelete(ip_addr_t ip, ip_addr_t netmask);

int sendIPPacket(ip_addr_t src, ip_addr_t dest, int proto, void *buf, int len);
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);

TCB *findSocket(fd_t sockfd);
TCB *findSocket(sockaddr_in *local_addr, sockaddr_in *remote_addr);

bool freeSocket(TCB *sock);
bool addLisenedSocket(fd_t listen_fd, TCB *sock);

fd_t allocSocketfd();
void setUpHost();

void addSocket(fd_t sockfd,TCB* sock);
void addListener(ListenerSocket *l_sock);
ListenerSocket *getListener(fd_t sockfd);

void activateDeviceManager();
void deactivateHost();
#endif