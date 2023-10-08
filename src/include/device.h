/**
 * @file device.h 
 * @brief Library supporting network device management.
 */

#ifndef NETSTACK_DEVICE_H
#define NETSTACK_DEVICE_H

#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <thread>
#include <vector>
#include <shared_mutex>
#include <string.h>
#include "../include/type.h"
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

private:
    char *dev_name_;
    char ebuf_[PCAP_ERRBUF_SIZE];
    u_char mac_[ETHER_ADDR_LEN];
    pcap_t *handle_;
    DeviceManager *manager_;
    dev_id id_;
    std::thread *receive_frame_thread_;
    frameReceiveCallback receive_call_back_;
    std::shared_timed_mutex device_mutex;
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
    void printAllValidDevice() const;
    void printAllAddedDevice() const;
private:
    std::vector<Device *> devices_list_;
    std::shared_timed_mutex manager_mutex;
};
void deviceRecvFrame(Device *device);
void deviceRecvPcapHandler(u_char *args, const pcap_pkthdr *head, const u_char *packet);
#endif