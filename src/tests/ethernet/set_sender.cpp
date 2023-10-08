#include "../../include/device.h"
#include "../../include/type.h"
#include "../../include/callback.h"
#include <unistd.h>
#include <thread>
#include <chrono>
#include <stdlib.h>
#include <string>

#define SEND_WAIT_TIME 30
#define MY_ETH_TYPE 0x8888

int cnt=0;
DeviceManager m;
Device *dev;
int MySendFrame(Device *dev,int i,void *dst_mac_,int wait_time,u_int16_t ethtype)
{
    u_char *pay_load=(u_char *)malloc(ETH_DATA_LEN);
    memset(pay_load,0,ETH_DATA_LEN);
    const u_char *src_mac=dev->getDeviceMac();
    u_char *dst_mac=(u_char *)dst_mac_;
    int pay_load_len = snprintf((char *)pay_load, ETH_DATA_LEN,
                                "Hello! This is message %d from device %s with mac %02x:%02x:%02x:%02x:%02x:%02x.",
                                cnt,dev->getDeviceName(),src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
    if(pay_load_len<0 || pay_load_len>=ETH_DATA_LEN)
    {
        printf("[ERROR] Pay load construction error.\n");
        return -1;
    }
    int ret=dev->sendFrame(pay_load,pay_load_len,ethtype,dst_mac);
    if(ret==-1)
    {
        printf("[ERROR] Send frame rrror.\n"
               "Device %s send frame %d:\n"
               "src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n"
               "dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n"
               "pay_load: %s\n"
               "pay_load_len: %d\n"
               "ethtype: 0x%x\n\n",
               dev->getDeviceName(),
               cnt,
               src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
               dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
               pay_load,
               pay_load_len,
               ethtype);
        free(pay_load);
        return -1;
    }
    printf("[INFO] Device %s send frame %d:\n"
           "src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n"
           "dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n"
           "pay_load: %s\n"
           "pay_load_len: %d\n"
           "ethtype: 0x%x\n\n",
           dev->getDeviceName(),
           cnt,
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
           pay_load,
           pay_load_len,
           ethtype);
    free(pay_load);
    std::this_thread::sleep_for(std::chrono::milliseconds(wait_time));
    return 0;
}

int main(int argc,char **argv)
{
    if(argc!=4)
    {
        printf("[ERROR] usage: %s <dev_name> <dst_mac> <send_num>", argv[0]);
        return -1;
    }
    char *dev_name = argv[1];
    ether_addr dst_mac;
    if(!ether_aton_r(argv[2],&dst_mac))
    {
        printf("[ERROR] The dst_mac %s is invalid.\n",argv[2]);
        return -1;
    }
    int send_num = atoi(argv[3]);
    dev_id id = m.addDevice(dev_name);
    if (id == -1)
    {
        printf("[ERROR] %s: The device is invalid", argv[0]);
        return -1;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(SEND_WAIT_TIME*10));
    dev = m.getDevice(id);
    for(int i=0;i<send_num;++i)
    {
        cnt++;
        int ret=MySendFrame(dev,i,&dst_mac,SEND_WAIT_TIME,MY_ETH_TYPE);
    }

    return 0;
}